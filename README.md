# bbs (Better Bitwarden Secrets)

A Bitwarden Secrets Manager command-line tool. It uses Bitwarden's official Rust Secrets Manager SDK, so encryption and the Secrets Manager API protocol remain Bitwarden-managed.

## Install

```bash
cargo install --path .
```

## Use

Set the service-account token outside the command line:

```bash
export BWS_ACCESS_TOKEN='0...'
bbs secret create DATABASE_PASSWORD 00000000-0000-0000-0000-000000000000
```

The default mode reads a hidden value from the controlling terminal.

To receive the value from standard input instead, use `--stdin`:

```bash
printf %s "$DATABASE_PASSWORD" |
  bbs secret create --stdin DATABASE_PASSWORD 00000000-0000-0000-0000-000000000000
```

`--stdin` preserves input exactly, including a trailing newline. Use `printf`, rather than `echo`, when a trailing newline is unintended.

### List projects

List the projects accessible to your service account:

```bash
bbs project list
```

Output is tab-separated as `name` and `id`, sorted alphabetically by name. Secret commands accept either a project UUID or its exact, case-sensitive name:

```bash
bbs secret list "Production API"
bbs secret create --upsert DATABASE_PASSWORD "Production API"
```

Quote names containing spaces. UUID inputs are used directly without listing projects; all other inputs are matched against accessible project names without trimming or partial matching. A UUID-shaped name is interpreted as an ID, so use that project's actual ID instead.

If no accessible project matches, the command errors. If multiple projects have the same name, it errors and asks you to use a UUID from `bbs project list` rather than choosing arbitrarily. Name resolution happens before reading secret values or performing secret operations.

Secret commands live under `bbs secret`: replace previous `bbs create` and `bbs list` invocations with `bbs secret create` and `bbs secret list`.

### List secret names

List every secret key in a project without retrieving or printing any secret values:

```bash
bbs secret list 00000000-0000-0000-0000-000000000000
```

The names are printed one per line, sorted alphabetically. This is useful for checking whether a secret exists without leaking its value.

To also show each secret's ID, whether its value is empty, and its note, use `--metadata`:

```bash
bbs secret list --metadata 00000000-0000-0000-0000-000000000000
```

Metadata output is tab-separated as `key`, `id`, either `empty` or `non-empty`, and `note`, sorted by key. The command retrieves each value only to determine its state; it never prints a value.

### Upsert

By default, the tool always creates a secret. Pass `--upsert` to find a secret with the requested key **in the specified project** and update its value instead:

```bash
bbs secret create --upsert DATABASE_PASSWORD 00000000-0000-0000-0000-000000000000
```

If no match exists, it creates one. If duplicate matching keys already exist in the project, it stops without changing any secret rather than choosing arbitrarily. When updating, an omitted `--note` preserves the existing note.

For a self-hosted Bitwarden server, set `BWS_API_URL` and `BWS_IDENTITY_URL` (or use `--api-url` and `--identity-url`).

## Security properties

- The secret value is never an argv value, so it is absent from shell history and normal process-list inspection.
- The tool does not write the secret value to disk or print it.
- It asks the Bitwarden SDK to zero its source request value after the create request completes.

This does **not** make secret input universally invisible: another process can still observe a terminal, a pipe producer, or process memory; `BWS_ACCESS_TOKEN` also remains sensitive. Avoid placing values in CI logs, shell tracing (`set -x`), or environment variables when practical.
