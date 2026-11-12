use std::fmt;

use bitwarden::secrets_manager::{
    SecretsManagerClient, projects::ProjectsListRequest, secrets::SecretIdentifiersByProjectRequest,
};
use serde::Serialize;
use uuid::Uuid;

#[derive(Clone, Debug, Serialize)]
pub(crate) struct Project {
    pub id: Uuid,
    pub name: String,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct Secret {
    pub id: Uuid,
    pub key: String,
    pub project_id: Uuid,
}

#[derive(Debug)]
pub(crate) struct InventoryError(&'static str);

impl fmt::Display for InventoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for InventoryError {}

// Keep the inventory boundary narrower than the SDK's value and mutation APIs.
pub(crate) trait InventoryApi {
    async fn projects(&self, organization_id: Uuid) -> Result<Vec<Project>, InventoryError>;
    async fn secrets(&self, project_id: Uuid) -> Result<Vec<Secret>, InventoryError>;
}

impl InventoryApi for SecretsManagerClient {
    async fn projects(&self, organization_id: Uuid) -> Result<Vec<Project>, InventoryError> {
        let response = self
            .projects()
            .list(&ProjectsListRequest { organization_id })
            .await
            .map_err(|_| InventoryError("projects_unavailable"))?;
        Ok(response
            .data
            .into_iter()
            .map(|project| Project {
                id: project.id,
                name: project.name,
            })
            .collect())
    }

    async fn secrets(&self, project_id: Uuid) -> Result<Vec<Secret>, InventoryError> {
        let response = self
            .secrets()
            .list_by_project(&SecretIdentifiersByProjectRequest { project_id })
            .await
            .map_err(|_| InventoryError("secrets_unavailable"))?;
        Ok(response
            .data
            .into_iter()
            .map(|secret| Secret {
                id: secret.id,
                key: secret.key,
                project_id,
            })
            .collect())
    }
}

pub(crate) async fn collect(
    api: &impl InventoryApi,
    organization_id: Uuid,
    project: Option<&str>,
) -> anyhow::Result<String> {
    let mut projects = api.projects(organization_id).await?;
    let Some(project) = project else {
        projects.sort_by(|a, b| (&a.name, a.id).cmp(&(&b.name, b.id)));
        return Ok(serde_json::to_string(&projects)?);
    };
    let id = Uuid::parse_str(project).ok();
    let mut matches = projects.iter().filter(|p| match id {
        Some(id) => p.id == id,
        None => p.name == project,
    });
    let selected = matches.next().ok_or(InventoryError("project_not_found"))?;
    if matches.next().is_some() {
        return Err(InventoryError("project_ambiguous").into());
    }
    let mut secrets = api.secrets(selected.id).await?;
    secrets.sort_by(|a, b| (&a.key, a.id).cmp(&(&b.key, b.id)));
    Ok(serde_json::to_string(&secrets)?)
}

pub(crate) async fn write(
    api: &impl InventoryApi,
    organization_id: Uuid,
    project: Option<&str>,
    output: &mut impl std::io::Write,
) -> anyhow::Result<()> {
    let json = collect(api, organization_id, project).await?;
    writeln!(output, "{json}")?;
    output.flush()?;
    Ok(())
}

pub(crate) fn error_json(error: &anyhow::Error) -> String {
    // Never format an SDK error chain: it can include credentials or response bodies.
    let code = error
        .downcast_ref::<InventoryError>()
        .map_or("inventory_failed", |error| error.0);
    serde_json::json!({"error": {"code": code}}).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitwarden::secrets_manager::ClientSettings;
    use serde_json::{Value, json};
    use std::{
        cell::RefCell,
        io::{Read, Write},
        net::TcpListener,
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, Ordering},
        },
        thread,
        time::Duration,
    };

    struct Fixture {
        projects: Vec<Project>,
        secrets: Vec<Secret>,
        calls: RefCell<Vec<String>>,
        fail: bool,
    }

    impl InventoryApi for Fixture {
        async fn projects(&self, _: Uuid) -> Result<Vec<Project>, InventoryError> {
            self.calls.borrow_mut().push("projects".into());
            Ok(self.projects.clone())
        }
        async fn secrets(&self, project_id: Uuid) -> Result<Vec<Secret>, InventoryError> {
            self.calls
                .borrow_mut()
                .push(format!("secrets:{project_id}"));
            if self.fail {
                Err(InventoryError("secrets_unavailable"))
            } else {
                Ok(self.secrets.clone())
            }
        }
    }

    fn fixture() -> Fixture {
        Fixture {
            projects: vec![Project {
                id: Uuid::from_u128(1),
                name: "Production API".into(),
            }],
            secrets: vec![],
            calls: RefCell::default(),
            fail: false,
        }
    }

    #[tokio::test]
    async fn records_escape_and_round_trip_without_extra_fields() {
        let mut api = fixture();
        let name = "space café \"quoted\"\ttab\nnewline";
        api.projects[0].name = name.into();
        api.secrets.push(Secret {
            id: Uuid::from_u128(2),
            key: name.into(),
            project_id: api.projects[0].id,
        });
        let projects = collect(&api, Uuid::nil(), None).await.unwrap();
        assert!(!projects.contains('\n'));
        assert!(!projects.contains('\t'));
        assert_eq!(
            serde_json::from_str::<Value>(&projects).unwrap(),
            json!([{"id": Uuid::from_u128(1), "name": name}])
        );
        let secrets = collect(&api, Uuid::nil(), Some(name)).await.unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&secrets).unwrap(),
            json!([{"id": Uuid::from_u128(2), "key": name, "project_id": Uuid::from_u128(1)}])
        );
    }

    #[tokio::test]
    async fn deterministic_order_and_duplicate_keys_are_preserved() {
        let mut api = fixture();
        api.projects.extend([
            Project {
                id: Uuid::from_u128(3),
                name: "Alpha".into(),
            },
            Project {
                id: Uuid::from_u128(2),
                name: "Alpha".into(),
            },
        ]);
        for (id, key) in [(4, "Zulu"), (3, "Alpha"), (2, "Alpha")] {
            api.secrets.push(Secret {
                id: Uuid::from_u128(id),
                key: key.into(),
                project_id: Uuid::from_u128(1),
            });
        }
        let first = collect(&api, Uuid::nil(), None).await.unwrap();
        api.projects.reverse();
        assert_eq!(first, collect(&api, Uuid::nil(), None).await.unwrap());
        let first = collect(&api, Uuid::nil(), Some("Production API"))
            .await
            .unwrap();
        api.secrets.reverse();
        assert_eq!(
            first,
            collect(&api, Uuid::nil(), Some("Production API"))
                .await
                .unwrap()
        );
        let parsed: Value = serde_json::from_str(&first).unwrap();
        assert_eq!(parsed[0]["id"], Uuid::from_u128(2).to_string());
        assert_eq!(parsed[1]["key"], "Alpha");
        assert_eq!(parsed.as_array().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn names_and_ids_require_an_accessible_unique_project() {
        let mut api = fixture();
        for project in ["Production API".to_owned(), Uuid::from_u128(1).to_string()] {
            assert_eq!(
                collect(&api, Uuid::nil(), Some(&project)).await.unwrap(),
                "[]"
            );
            assert_eq!(
                &*api.calls.borrow(),
                &["projects", &format!("secrets:{}", Uuid::from_u128(1))]
            );
            api.calls.borrow_mut().clear();
        }
        for missing in [
            "production api",
            " Production API",
            "missing",
            &Uuid::nil().to_string(),
        ] {
            let error = collect(&api, Uuid::nil(), Some(missing)).await.unwrap_err();
            assert_eq!(
                error_json(&error),
                r#"{"error":{"code":"project_not_found"}}"#
            );
            assert_eq!(&*api.calls.borrow(), &["projects"]);
            api.calls.borrow_mut().clear();
        }
        api.projects.push(Project {
            id: Uuid::from_u128(2),
            name: "Production API".into(),
        });
        let error = collect(&api, Uuid::nil(), Some("Production API"))
            .await
            .unwrap_err();
        assert!(error_json(&error).contains("project_ambiguous"));
        assert_eq!(&*api.calls.borrow(), &["projects"]);
        assert_eq!(
            collect(&api, Uuid::nil(), Some(&Uuid::from_u128(1).to_string()))
                .await
                .unwrap(),
            "[]"
        );
    }

    #[tokio::test]
    async fn failed_enumeration_is_not_an_empty_success() {
        let mut api = fixture();
        api.fail = true;
        let error = collect(&api, Uuid::nil(), Some("Production API"))
            .await
            .unwrap_err();
        assert!(error_json(&error).contains("secrets_unavailable"));
        api.projects.clear();
        assert_eq!(collect(&api, Uuid::nil(), None).await.unwrap(), "[]");
    }

    #[tokio::test]
    async fn successful_inventory_output_and_io_errors_use_the_safe_boundary() {
        struct FailingSink {
            fail_write: bool,
        }
        impl Write for FailingSink {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                if self.fail_write {
                    Err(std::io::Error::other(
                        "TOKEN_MARKER VALUE_MARKER NOTE_MARKER",
                    ))
                } else {
                    Ok(bytes.len())
                }
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Err(std::io::Error::other(
                    "TOKEN_MARKER VALUE_MARKER NOTE_MARKER",
                ))
            }
        }
        let api = fixture();
        for project in [None, Some("Production API")] {
            let mut output = Vec::new();
            write(&api, Uuid::nil(), project, &mut output)
                .await
                .unwrap();
            let expected = format!("{}\n", collect(&api, Uuid::nil(), project).await.unwrap());
            assert_eq!(output, expected.as_bytes());
            for fail_write in [true, false] {
                let error = write(&api, Uuid::nil(), project, &mut FailingSink { fail_write })
                    .await
                    .unwrap_err();
                assert_eq!(
                    error_json(&error),
                    r#"{"error":{"code":"inventory_failed"}}"#
                );
            }
        }
    }

    #[test]
    fn raw_errors_are_not_serialized() {
        let error =
            anyhow::anyhow!("TOKEN_MARKER VALUE_MARKER NOTE_MARKER").context("upstream body");
        assert_eq!(
            error_json(&error),
            r#"{"error":{"code":"inventory_failed"}}"#
        );
    }

    // Exercise the real SDK HTTP adapter, recording every request (including forbidden ones).
    // Empty identifier responses need no encryption key; no live token is used.
    #[tokio::test]
    async fn sdk_adapter_only_requests_identifier_endpoints_and_sanitizes_errors() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let done = Arc::new(AtomicBool::new(false));
        let recorded = requests.clone();
        let finished = done.clone();
        let server = thread::spawn(move || {
            while !finished.load(Ordering::SeqCst) {
                let Ok((mut stream, _)) = listener.accept() else {
                    thread::sleep(Duration::from_millis(5));
                    continue;
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut bytes = [0; 8192];
                let count = stream.read(&mut bytes).unwrap();
                let request = String::from_utf8_lossy(&bytes[..count]);
                let line = request.lines().next().unwrap().to_owned();
                let index = {
                    let mut requests = recorded.lock().unwrap();
                    requests.push(line.clone());
                    requests.len()
                };
                let (status, body) = if index > 2 {
                    (
                        "500 Internal Server Error",
                        r#"{"error":"TOKEN_MARKER VALUE_MARKER NOTE_MARKER"}"#,
                    )
                } else if line.contains("/projects/") {
                    (
                        "200 OK",
                        r#"{"secrets":[],"value":"VALUE_MARKER","note":"NOTE_MARKER"}"#,
                    )
                } else {
                    ("200 OK", r#"{"data":[],"token":"TOKEN_MARKER"}"#)
                };
                write!(stream, "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            }
        });
        let client = SecretsManagerClient::new(Some(ClientSettings {
            api_url: url,
            ..Default::default()
        }));
        let project = Uuid::from_u128(1);
        let projects = InventoryApi::projects(&client, Uuid::nil()).await;
        let secrets = InventoryApi::secrets(&client, project).await;
        let project_error = InventoryApi::projects(&client, Uuid::nil()).await;
        let secret_error = InventoryApi::secrets(&client, project).await;
        done.store(true, Ordering::SeqCst);
        server.join().unwrap();
        assert!(projects.unwrap().is_empty());
        assert!(secrets.unwrap().is_empty());
        assert_eq!(
            error_json(&project_error.unwrap_err().into()),
            r#"{"error":{"code":"projects_unavailable"}}"#
        );
        assert_eq!(
            error_json(&secret_error.unwrap_err().into()),
            r#"{"error":{"code":"secrets_unavailable"}}"#
        );
        assert_eq!(
            *requests.lock().unwrap(),
            vec![
                format!("GET /organizations/{}/projects HTTP/1.1", Uuid::nil()),
                format!("GET /projects/{project}/secrets HTTP/1.1"),
                format!("GET /organizations/{}/projects HTTP/1.1", Uuid::nil()),
                format!("GET /projects/{project}/secrets HTTP/1.1"),
            ]
        );
    }
}
