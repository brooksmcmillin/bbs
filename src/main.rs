use std::{io::Read, str::FromStr};

use anyhow::{Context, Result, bail};
use bitwarden::secrets_manager::{
    AccessToken, AccessTokenLoginRequest, ClientSettings, SecretsManagerClient,
    secrets::{
        SecretCreateRequest, SecretGetRequest, SecretIdentifiersByProjectRequest, SecretPutRequest,
    },
};
use clap::Parser;
use uuid::Uuid;
use zeroize::Zeroize;

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Create a Bitwarden Secrets Manager secret without putting its value in argv"
)]
struct Args {
    /// The key for the new secret.
    key: String,

    /// The project UUID that will contain the new secret.
    project_id: Uuid,

    /// Read the secret value exactly from standard input instead of prompting on the terminal.
    #[arg(long)]
    stdin: bool,

    /// An optional, non-secret note for the secret.
    #[arg(long)]
    note: Option<String>,

    /// Update the matching secret in this project instead of creating a duplicate.
    #[arg(long)]
    upsert: bool,

    /// Bitwarden Secrets Manager access token. Prefer BWS_ACCESS_TOKEN so it is not in argv.
    #[arg(long, env = "BWS_ACCESS_TOKEN", hide_env_values = true)]
    access_token: Option<String>,

    /// Bitwarden API URL, for self-hosted installations.
    #[arg(long, env = "BWS_API_URL")]
    api_url: Option<String>,

    /// Bitwarden identity URL, for self-hosted installations.
    #[arg(long, env = "BWS_IDENTITY_URL")]
    identity_url: Option<String>,
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

    let existing_secret_id = if args.upsert {
        let identifiers = client
            .secrets()
            .list_by_project(&SecretIdentifiersByProjectRequest {
                project_id: args.project_id,
            })
            .await
            .context("list project secrets")?;
        single_match(
            identifiers
                .data
                .into_iter()
                .filter(|secret| secret.key == args.key)
                .map(|secret| secret.id),
        )?
    } else {
        None
    };

    let mut value = secret_value(args.stdin)?;
    let (operation, mut secret) = if let Some(secret_id) = existing_secret_id {
        let mut existing = client
            .secrets()
            .get(&SecretGetRequest { id: secret_id })
            .await
            .context("get existing secret")?;
        let note = args.note.unwrap_or_else(|| existing.note.clone());
        existing.value.zeroize();

        let mut request = SecretPutRequest {
            id: secret_id,
            organization_id: organization_id.into(),
            key: args.key,
            value: std::mem::take(&mut value),
            note,
            project_ids: Some(vec![args.project_id]),
            value_changed: true,
        };
        let result = client.secrets().update(&request).await;
        request.value.zeroize();
        ("updated", result.context("update secret")?)
    } else {
        let mut request = SecretCreateRequest {
            organization_id: organization_id.into(),
            key: args.key,
            value: std::mem::take(&mut value),
            note: args.note.unwrap_or_default(),
            project_ids: Some(vec![args.project_id]),
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
    use super::single_match;
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
}
