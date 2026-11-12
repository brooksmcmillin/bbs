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

### Identifier-only JSON inventory

For automation, use the following fixed commands (put `--` before project names
that might begin with a dash):

```bash
bbs project list --json
bbs secret list --json -- "Production API"
```

On success, exit status is 0 and stdout is one JSON array followed by a newline:

```json
[{"id":"00000000-0000-0000-0000-000000000001","name":"Production API"}]
```

```json
[{"id":"00000000-0000-0000-0000-000000000002","key":"DATABASE_PASSWORD","project_id":"00000000-0000-0000-0000-000000000001"}]
```

These are the only record fields. Projects sort by name then ID; secrets sort
by key then ID. Strings use JSON escaping, including quotes, tabs, newlines and
Unicode. Empty successful lists are `[]`; duplicate secret keys are preserved as
separate records so consumers can report them. `project_id` is the queried project.

JSON secret listing resolves both UUIDs and exact, case-sensitive names against
accessible projects first. An unknown/inaccessible name or UUID is an error, not
an empty secret list. Duplicate project names require a UUID; UUID-shaped names
are interpreted as IDs. No partial results are emitted if enumeration fails.

For a valid JSON-mode command, runtime failure exits 1 and writes only a safe
JSON error to stderr, for example:

```json
{"error":{"code":"project_not_found"}}
```

Codes are `project_not_found`, `project_ambiguous`, `projects_unavailable`,
`secrets_unavailable`, or `inventory_failed` (including authentication, token
configuration and output errors). Raw SDK error details are intentionally omitted.
Failures before output leave stdout empty. An output write/flush failure can
leave a partial result; consumers must discard stdout on any nonzero exit.
CLI syntax errors still use clap's normal diagnostics and exit status 2.
`--json` and `--metadata` are mutually exclusive; existing non-JSON commands are
unchanged.

Inventory calls only project and secret-identifier listing APIs, never secret
get/create/update APIs. It does not retrieve values or notes or determine
emptiness, validity or global existence. The legacy `--metadata` mode **does**
retrieve values and notes; it is not an inventory substitute. A read-capable BWS
token can still retrieve values through other commands: use a narrowly scoped
machine account, keep its token outside argv/logs, and enforce caller/project
authorization in the consuming service. These CLI tests do not establish live
Bitwarden availability or deployment readiness.

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
