# bbs (Better Bitwarden Secrets)

Create a Bitwarden Secrets Manager secret without passing the **secret value** as a command-line argument. It uses Bitwarden's official Rust Secrets Manager SDK, so encryption and the Secrets Manager API protocol remain Bitwarden-managed.

## Install

```bash
cargo install --path .
```

## Use

Set the service-account token outside the command line:

```bash
export BWS_ACCESS_TOKEN='0...'
bbs DATABASE_PASSWORD 00000000-0000-0000-0000-000000000000
```

The default mode reads a hidden value from the controlling terminal.

To receive the value from standard input instead, use `--stdin`:

```bash
printf %s "$DATABASE_PASSWORD" |
  bbs --stdin DATABASE_PASSWORD 00000000-0000-0000-0000-000000000000
```

`--stdin` preserves input exactly, including a trailing newline. Use `printf`, rather than `echo`, when a trailing newline is unintended.

### Upsert

By default, the tool always creates a secret. Pass `--upsert` to find a secret with the requested key **in the specified project** and update its value instead:

```bash
bbs --upsert DATABASE_PASSWORD 00000000-0000-0000-0000-000000000000
```

If no match exists, it creates one. If duplicate matching keys already exist in the project, it stops without changing any secret rather than choosing arbitrarily. When updating, an omitted `--note` preserves the existing note.

For a self-hosted Bitwarden server, set `BWS_API_URL` and `BWS_IDENTITY_URL` (or use `--api-url` and `--identity-url`).

## Security properties

- The secret value is never an argv value, so it is absent from shell history and normal process-list inspection.
- The tool does not write the secret value to disk or print it.
- It asks the Bitwarden SDK to zero its source request value after the create request completes.

This does **not** make secret input universally invisible: another process can still observe a terminal, a pipe producer, or process memory; `BWS_ACCESS_TOKEN` also remains sensitive. Avoid placing values in CI logs, shell tracing (`set -x`), or environment variables when practical.
