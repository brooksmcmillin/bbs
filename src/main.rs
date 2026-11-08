use std::{
    io::{Read, Write},
    str::FromStr,
};

use anyhow::{Context, Result, bail};
use bitwarden::secrets_manager::{
    AccessToken, AccessTokenLoginRequest, ClientSettings, SecretsManagerClient,
    projects::ProjectsListRequest,
    secrets::{
        SecretCreateRequest, SecretGetRequest, SecretIdentifiersByProjectRequest, SecretPutRequest,
    },
};
use clap::Parser;
use uuid::Uuid;
use zeroize::Zeroize;

#[derive(Debug, Parser)]
#[command(version, about = "A Bitwarden Secrets Manager command-line tool")]
struct Args {
    #[command(subcommand)]
    command: Command,

    /// Bitwarden Secrets Manager access token. Prefer BWS_ACCESS_TOKEN so it is not in argv.
    #[arg(long, global = true, env = "BWS_ACCESS_TOKEN", hide_env_values = true)]
    access_token: Option<String>,

    /// Bitwarden API URL, for self-hosted installations.
    #[arg(long, global = true, env = "BWS_API_URL")]
    api_url: Option<String>,

    /// Bitwarden identity URL, for self-hosted installations.
    #[arg(long, global = true, env = "BWS_IDENTITY_URL")]
    identity_url: Option<String>,
}

#[derive(Debug, clap::Subcommand)]
enum Command {
    /// View projects.
    Project {
        #[command(subcommand)]
        command: ProjectCommand,
    },

    /// Manage secrets.
    Secret {
        #[command(subcommand)]
        command: SecretCommand,
    },
}

#[derive(Debug, clap::Subcommand)]
enum ProjectCommand {
    /// List accessible projects with their names and IDs.
    List,
}

#[derive(Debug, clap::Subcommand)]
enum SecretCommand {
    /// Create a secret without putting its value in argv.
    Create {
        /// The key for the new secret.
        key: String,

        /// The project UUID or exact, case-sensitive name that will contain the new secret.
        project: String,

        /// Read the secret value exactly from standard input instead of prompting on the terminal.
        #[arg(long)]
        stdin: bool,

        /// An optional, non-secret note for the secret.
        #[arg(long)]
        note: Option<String>,

        /// Update the matching secret in this project instead of creating a duplicate.
        #[arg(long)]
        upsert: bool,
    },

    /// List all secret names in a project.
    List {
        /// The project UUID or exact, case-sensitive name whose secrets should be listed.
        project: String,

        /// Include each secret's ID and whether its value is empty. Values are not printed.
        #[arg(long)]
        metadata: bool,
    },
}

fn named_project_id<'a>(
    name: &str,
    projects: impl Iterator<Item = (&'a str, Uuid)>,
) -> Result<Uuid> {
    let mut matches = projects.filter(|(project_name, _)| *project_name == name);
    let Some((_, id)) = matches.next() else {
        bail!("no accessible project named {name:?}; use `bbs project list` to find projects")
    };
    if matches.next().is_some() {
        bail!(
            "multiple accessible projects named {name:?}; use a project UUID from `bbs project list`"
        )
    }
    Ok(id)
}

async fn resolve_project(
    client: &SecretsManagerClient,
    organization_id: Uuid,
    project: &str,
) -> Result<Uuid> {
    if let Ok(id) = Uuid::parse_str(project) {
        return Ok(id);
    }
    let projects = client
        .projects()
        .list(&ProjectsListRequest { organization_id })
        .await
        .context("list projects to resolve project name")?;
    named_project_id(
        project,
        projects.data.iter().map(|p| (p.name.as_str(), p.id)),
    )
}

async fn dispatch_secret(
    command: SecretCommand,
    resolve: impl AsyncFnOnce(&str) -> Result<Uuid>,
    execute: impl AsyncFnOnce(SecretCommand, Uuid) -> Result<()>,
) -> Result<()> {
    let project = match &command {
        SecretCommand::List { project, .. } | SecretCommand::Create { project, .. } => project,
    };
    let project_id = resolve(project).await?;
    execute(command, project_id).await
}

fn write_projects<'a>(
    projects: impl Iterator<Item = (&'a str, Uuid)>,
    output: &mut impl Write,
) -> std::io::Result<()> {
    let mut projects: Vec<_> = projects.collect();
    projects.sort_by(|left, right| left.0.cmp(right.0));
    for (name, id) in projects {
        writeln!(output, "{name}\t{id}")?;
    }
    Ok(())
}

fn secret_value(from_stdin: bool) -> Result<String> {
    if from_stdin {
        let mut value = String::new();
        std::io::stdin()
            .read_to_string(&mut value)
            .context("read secret value from standard input")?;
        return Ok(value);
    }

    rpassword::prompt_password("Secret value: ").context("read secret value from terminal")
}

fn single_match(mut matches: impl Iterator<Item = Uuid>) -> Result<Option<Uuid>> {
    let Some(secret_id) = matches.next() else {
        return Ok(None);
    };
    if matches.next().is_some() {
        bail!("multiple secrets with this key exist in the project; refusing to choose one")
    }
    Ok(Some(secret_id))
}

fn value_state(value: &str) -> &'static str {
    if value.is_empty() {
        "empty"
    } else {
        "non-empty"
    }
}

fn metadata_line(key: &str, id: Uuid, value: &str) -> String {
    format!("{key}\t{id}\t{}", value_state(value))
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let access_token = args
        .access_token
        .as_deref()
        .context("missing access token; set BWS_ACCESS_TOKEN")?;
    let _ = AccessToken::from_str(access_token).context("parse BWS_ACCESS_TOKEN")?;

    let mut settings = ClientSettings::default();
    if let Some(api_url) = args.api_url {
        settings.api_url = api_url.trim_end_matches('/').to_owned();
    }
    if let Some(identity_url) = args.identity_url {
        settings.identity_url = identity_url.trim_end_matches('/').to_owned();
    }

    let client = SecretsManagerClient::new(Some(settings));
    client
        .auth()
        .login_access_token(&AccessTokenLoginRequest {
            access_token: access_token.to_owned(),
            state_file: None,
        })
        .await
        .context("authenticate with Bitwarden Secrets Manager")?;

    let organization_id = client
        .get_access_token_organization()
        .context("access token is not associated with an organization")?;

    let command = match args.command {
        Command::Project {
            command: ProjectCommand::List,
        } => {
            let projects = client
                .projects()
                .list(&ProjectsListRequest {
                    organization_id: organization_id.into(),
                })
                .await
                .context("list projects")?
                .data;
            write_projects(
                projects
                    .iter()
                    .map(|project| (project.name.as_str(), project.id)),
                &mut std::io::stdout().lock(),
            )
            .context("write projects")?;
            return Ok(());
        }
        Command::Secret { command } => command,
    };
    dispatch_secret(
        command,
        async |project| resolve_project(&client, organization_id.into(), project).await,
        async |command, project_id| {
            execute_secret_command(&client, organization_id.into(), command, project_id).await
        },
    )
    .await
}

async fn execute_secret_command(
    client: &SecretsManagerClient,
    organization_id: Uuid,
    command: SecretCommand,
    project_id: Uuid,
) -> Result<()> {
    let (key, stdin, note, upsert) = match command {
        SecretCommand::List { metadata, .. } => {
            let identifiers = client
                .secrets()
                .list_by_project(&SecretIdentifiersByProjectRequest { project_id })
                .await
                .context("list project secrets")?;
            let mut identifiers = identifiers.data;
            identifiers.sort_by(|left, right| left.key.cmp(&right.key));

            for identifier in identifiers {
                if metadata {
                    let mut secret = client
                        .secrets()
                        .get(&SecretGetRequest { id: identifier.id })
                        .await
                        .context("get secret metadata")?;
                    let line = metadata_line(&secret.key, secret.id, &secret.value);
                    secret.value.zeroize();
                    println!("{line}");
                } else {
                    println!("{}", identifier.key);
                }
            }
            return Ok(());
        }
        SecretCommand::Create {
            key,
            stdin,
            note,
            upsert,
            ..
        } => (key, stdin, note, upsert),
    };

    let existing_secret_id = if upsert {
        let identifiers = client
            .secrets()
            .list_by_project(&SecretIdentifiersByProjectRequest { project_id })
            .await
            .context("list project secrets")?;
        single_match(
            identifiers
                .data
                .into_iter()
                .filter(|secret| secret.key == key)
                .map(|secret| secret.id),
        )?
    } else {
        None
    };

    let mut value = secret_value(stdin)?;
    let (operation, mut secret) = if let Some(secret_id) = existing_secret_id {
        let mut existing = client
            .secrets()
            .get(&SecretGetRequest { id: secret_id })
            .await
            .context("get existing secret")?;
        let note = note.unwrap_or_else(|| existing.note.clone());
        existing.value.zeroize();

        let mut request = SecretPutRequest {
            id: secret_id,
            organization_id,
            key: key.clone(),
            value: std::mem::take(&mut value),
            note,
            project_ids: Some(vec![project_id]),
            value_changed: true,
        };
        let result = client.secrets().update(&request).await;
        request.value.zeroize();
        ("updated", result.context("update secret")?)
    } else {
        let mut request = SecretCreateRequest {
            organization_id,
            key,
            value: std::mem::take(&mut value),
            note: note.unwrap_or_default(),
            project_ids: Some(vec![project_id]),
        };
        let result = client.secrets().create(&request).await;
        request.value.zeroize();
        ("created", result.context("create secret")?)
    };

    let project_id = secret
        .project_id
        .map(|id| id.to_string())
        .unwrap_or_else(|| "none".to_owned());
    println!(
        "{operation} secret {} (key: {}, project: {project_id})",
        secret.id, secret.key
    );
    secret.value.zeroize();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        Args, Command, ProjectCommand, SecretCommand, SecretsManagerClient, dispatch_secret,
        metadata_line, named_project_id, resolve_project, single_match, value_state,
        write_projects,
    };
    use clap::Parser;
    use uuid::Uuid;

    #[test]
    fn single_match_returns_the_one_match() {
        let secret_id = Uuid::from_u128(1);
        assert_eq!(
            single_match([secret_id].into_iter()).unwrap(),
            Some(secret_id)
        );
    }

    #[test]
    fn single_match_returns_none_for_no_matches() {
        assert_eq!(single_match(std::iter::empty()).unwrap(), None);
    }

    #[test]
    fn single_match_rejects_duplicate_matches() {
        assert!(single_match([Uuid::from_u128(1), Uuid::from_u128(2)].into_iter()).is_err());
    }

    #[test]
    fn value_state_distinguishes_empty_values() {
        assert_eq!(value_state(""), "empty");
        assert_eq!(value_state(" "), "non-empty");
    }

    #[test]
    fn metadata_line_does_not_include_the_value() {
        let id = Uuid::from_u128(1);
        assert_eq!(
            metadata_line("DATABASE_PASSWORD", id, ""),
            format!("DATABASE_PASSWORD\t{id}\tempty")
        );
        assert_eq!(
            metadata_line("DATABASE_PASSWORD", id, "not-for-output"),
            format!("DATABASE_PASSWORD\t{id}\tnon-empty")
        );
    }

    #[test]
    fn secret_create_preserves_options_and_global_flags() {
        let project_id = Uuid::from_u128(1);
        let args = Args::try_parse_from([
            "bbs",
            "secret",
            "create",
            "PASSWORD",
            &project_id.to_string(),
            "--stdin",
            "--upsert",
            "--note",
            "description",
            "--api-url",
            "https://example.com",
        ])
        .unwrap();
        assert_eq!(args.api_url.as_deref(), Some("https://example.com"));
        assert!(matches!(args.command, Command::Secret {
            command: SecretCommand::Create { key, project, stdin: true, upsert: true, note: Some(note) }
        } if key == "PASSWORD" && project == project_id.to_string() && note == "description"));
    }

    #[tokio::test]
    async fn project_uuid_does_not_require_project_lookup() {
        let id = Uuid::from_u128(1);
        let client = SecretsManagerClient::new(None);
        assert_eq!(
            resolve_project(&client, Uuid::nil(), &id.to_string())
                .await
                .unwrap(),
            id
        );
    }

    #[test]
    fn project_name_matching_is_exact_and_unique() {
        let id = Uuid::from_u128(1);
        let projects = [("Production API", id), ("Other", Uuid::from_u128(2))];
        assert_eq!(
            named_project_id("Production API", projects.into_iter()).unwrap(),
            id
        );
        for missing in ["production api", "Production", " Production API", "missing"] {
            let error = named_project_id(missing, projects.into_iter())
                .unwrap_err()
                .to_string();
            assert!(error.contains("no accessible project"));
        }
        let error = named_project_id(
            "Production API",
            [
                ("Production API", id),
                ("Production API", Uuid::from_u128(2)),
            ]
            .into_iter(),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("multiple accessible projects"));
        assert!(error.contains("project UUID"));
        assert!(named_project_id("missing", std::iter::empty()).is_err());
    }

    #[tokio::test]
    async fn failed_project_resolution_never_enters_secret_handler() {
        use std::cell::Cell;

        for argv in [
            vec!["bbs", "secret", "list", "Production API"],
            vec!["bbs", "secret", "list", "Production API", "--metadata"],
            vec!["bbs", "secret", "create", "PASSWORD", "Production API"],
            vec![
                "bbs",
                "secret",
                "create",
                "PASSWORD",
                "Production API",
                "--stdin",
                "--upsert",
            ],
        ] {
            for projects in [
                vec![],
                vec![
                    ("Production API", Uuid::from_u128(1)),
                    ("Production API", Uuid::from_u128(2)),
                ],
            ] {
                let Command::Secret { command } = Args::try_parse_from(&argv).unwrap().command
                else {
                    panic!("expected secret command")
                };
                let handler_calls = Cell::new(0);
                let error = dispatch_secret(
                    command,
                    async |name| named_project_id(name, projects.iter().copied()),
                    async |_, _| {
                        handler_calls.set(handler_calls.get() + 1);
                        panic!("secret operations and value input must not be reached")
                    },
                )
                .await
                .unwrap_err();
                assert_eq!(handler_calls.get(), 0);
                let expected = if projects.is_empty() {
                    "no accessible project"
                } else {
                    "multiple accessible projects"
                };
                assert!(error.to_string().contains(expected), "{error}");
            }
        }
    }

    #[tokio::test]
    async fn successful_resolution_dispatches_command_and_project_once() {
        use std::cell::Cell;

        let id = Uuid::from_u128(1);
        let calls = Cell::new(0);
        let Command::Secret { command } =
            Args::try_parse_from(["bbs", "secret", "list", "Production API", "--metadata"])
                .unwrap()
                .command
        else {
            panic!("expected secret command")
        };
        dispatch_secret(
            command,
            async |name| {
                assert_eq!(name, "Production API");
                Ok(id)
            },
            async |command, project_id| {
                calls.set(calls.get() + 1);
                assert_eq!(project_id, id);
                assert!(matches!(
                    command,
                    SecretCommand::List { metadata: true, .. }
                ));
                Ok(())
            },
        )
        .await
        .unwrap();
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn secret_commands_accept_project_names() {
        for argv in [
            vec!["bbs", "secret", "list", "Production API"],
            vec![
                "bbs",
                "secret",
                "create",
                "PASSWORD",
                "Production API",
                "--upsert",
            ],
        ] {
            let args = Args::try_parse_from(argv).unwrap();
            let Command::Secret { command } = args.command else {
                panic!("expected secret command")
            };
            let project = match command {
                SecretCommand::Create { project, .. } | SecretCommand::List { project, .. } => {
                    project
                }
            };
            assert_eq!(project, "Production API");
        }
    }

    #[test]
    fn project_list_output_is_sorted_and_tab_separated() {
        let alpha = Uuid::from_u128(1);
        let zulu = Uuid::from_u128(2);
        let mut output = Vec::new();
        write_projects(
            [("Zulu", zulu), ("Alpha API", alpha)].into_iter(),
            &mut output,
        )
        .unwrap();
        assert_eq!(
            output,
            format!("Alpha API\t{alpha}\nZulu\t{zulu}\n").as_bytes()
        );
    }

    #[test]
    fn project_list_output_is_empty_for_no_projects() {
        let mut output = Vec::new();
        write_projects(std::iter::empty(), &mut output).unwrap();
        assert!(output.is_empty());
    }

    #[test]
    fn project_list_accepts_global_flags() {
        for argv in [
            vec!["bbs", "--api-url", "https://example.com", "project", "list"],
            vec!["bbs", "project", "--api-url", "https://example.com", "list"],
            vec!["bbs", "project", "list", "--api-url", "https://example.com"],
        ] {
            let args = Args::try_parse_from(argv).unwrap();
            assert_eq!(args.api_url.as_deref(), Some("https://example.com"));
            assert!(matches!(
                args.command,
                Command::Project {
                    command: ProjectCommand::List
                }
            ));
        }
    }

    #[test]
    fn command_groups_require_a_subcommand() {
        for args in [vec!["bbs"], vec!["bbs", "secret"], vec!["bbs", "project"]] {
            assert!(Args::try_parse_from(args).is_err());
        }
    }

    #[test]
    fn list_metadata_flag_is_opt_in() {
        let project_id = "00000000-0000-0000-0000-000000000001";
        let metadata =
            Args::try_parse_from(["bbs", "secret", "list", "--metadata", project_id]).unwrap();
        assert!(matches!(
            metadata.command,
            Command::Secret {
                command: SecretCommand::List { metadata: true, .. }
            }
        ));

        let names_only = Args::try_parse_from(["bbs", "secret", "list", project_id]).unwrap();
        assert!(matches!(
            names_only.command,
            Command::Secret {
                command: SecretCommand::List {
                    metadata: false,
                    ..
                }
            }
        ));
    }
}
