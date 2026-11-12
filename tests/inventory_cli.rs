use std::process::Command;

fn cli() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_bbs"));
    command.env_remove("BWS_ACCESS_TOKEN");
    command.env_remove("BWS_API_URL");
    command.env_remove("BWS_IDENTITY_URL");
    command
}

#[test]
fn json_runtime_errors_have_empty_stdout_and_no_token_details() {
    for args in [
        vec!["project", "list", "--json"],
        vec!["secret", "list", "--json", "--", "-project café\t\n\""],
    ] {
        for token in [None, Some("TOKEN_MARKER VALUE_MARKER NOTE_MARKER")] {
            let mut command = cli();
            command.args(&args);
            if let Some(token) = token {
                command.env("BWS_ACCESS_TOKEN", token);
            }
            let output = command.output().unwrap();
            assert_eq!(output.status.code(), Some(1));
            assert!(output.stdout.is_empty());
            assert_eq!(
                String::from_utf8(output.stderr).unwrap(),
                "{\"error\":{\"code\":\"inventory_failed\"}}\n"
            );
        }
    }
}

#[test]
fn metadata_and_json_conflict_before_authentication() {
    let output = cli()
        .args(["secret", "list", "--json", "--metadata", "Production API"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("cannot be used with")
    );
}

#[test]
fn json_mode_is_not_available_for_mutations() {
    let output = cli()
        .args(["secret", "create", "--json", "KEY", "Production API"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
}

#[test]
fn human_mode_keeps_its_existing_error_format() {
    let output = cli().args(["project", "list"]).output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("missing access token")
    );
}
