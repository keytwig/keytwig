# keytwig

[![CI](https://github.com/keytwig/keytwig/actions/workflows/ci.yml/badge.svg)](https://github.com/keytwig/keytwig/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

One local vault for the secrets your projects and agents use. Agents use
secrets through `keytwig run`, which injects values into a child process and
masks them in stdout and stderr.

Sibling of [memtwig](https://github.com/memtwig/memtwig). Linux, macOS and
Windows (single static binary, no cgo). See [SECURITY.md](SECURITY.md) for the
threat model and reporting instructions.

## Install

- Linux or macOS (downloads and verifies the release archive)

  ```sh
  curl -fsSL https://raw.githubusercontent.com/keytwig/keytwig/main/scripts/install.sh | sh
  ```

  Set `KEYTWIG_INSTALL_DIR` to override `~/.local/bin` or `KEYTWIG_VERSION` to select a tag such as `v0.1.0`.

- Homebrew on Linux or macOS

  ```sh
  brew install memtwig/tap/keytwig
  ```

- Build with Go

  ```sh
  go install github.com/keytwig/keytwig/cmd/keytwig@latest
  ```

- [Prebuilt releases](https://github.com/keytwig/keytwig/releases) for Linux,
  macOS, and Windows on amd64 and arm64. Verify the archive against
  `checksums.txt`, extract it, and put the binary on your `PATH`.

## Quick start

```sh
keytwig init                     # identity bound to this machine, no prompts (or --passphrase / --keyring / --file)
keytwig scan                     # where credentials live today (names and paths only)
keytwig import --scan --dry-run  # what would be imported from your project .env files
keytwig import --scan
keytwig run -k STRIPE_SECRET_KEY -- ./deploy.sh
cd ~/code/shop && keytwig run -p -- npm run dev   # the project's own secrets, usual names
keytwig install all              # MCP server in Claude Code, Codex, Cursor, Windsurf, Hermes, Grok, Antigravity
```

## Agents

`keytwig install <claude|codex|cursor|windsurf|hermes|grok|antigravity|all>` (antigravity: standalone and T3-managed) registers `keytwig mcp --agent <harness>`
(config backed up as `*.keytwig.bak`). Tools exposed — none returns a value:

- `keytwig_http` — make an HTTP request injecting `{{NAME}}` placeholders directly (no shell), restricted by `[secrets.NAME] allowed_hosts`, response masked
- `keytwig_run` — run a shell command with secrets injected (`keys`, `file_keys`, or `project: true`); output masked
- `keytwig_list` — names, aliases, kind, `allowed_hosts`, expiry, and which env vars the current project gets
- `keytwig_import` — move a `.env` into the vault without values passing through the model
- `keytwig_status`

There is no get/set tool on purpose. Masking protects against accidents (logs,
stack traces, `env` dumps), not against an agent that deliberately transforms a
value (e.g. reverses it) before printing. Use `keytwig_http` when calling APIs
so secrets are scoped per host and never touch a shell.

`keytwig install claude` (and `keytwig install all`) also installs a `PreToolUse`
hook (`keytwig hook claude`) that blocks direct reads of `.env`, vault, and
credential files or raw env dumps (pass `--no-hooks` to skip).

### Per-agent and per-secret policies (`config.toml`)

```toml
[agents.hermes]
allow = ["ACME_*", "STRIPE_*"]
deny  = ["*_PROD"]

[agents.default]        # unnamed or unlisted agents
deny = ["STRIPE_*"]

[secrets.STRIPE_SECRET_KEY]
allowed_hosts = ["api.stripe.com"]
expires = "2026-12-31"
note = "Stripe live key"
```

Deny wins; aliases cannot dodge a deny. This is a guardrail between your own
agents, not isolation: anything running as your OS user can reach the vault.

## Projects

Import remembers which project folder uses which secret under which name.
`keytwig run -p` (from the project folder or any subfolder) injects exactly those.

`keytwig rewrite --scan` (dry run) / `--apply` replaces the plaintext values in
project `.env` files with `keytwig://NAME`; frameworks that let real env vars win
over `.env` (Next.js, Vite, dotenv) keep working under `keytwig run -p`.
`keytwig restore` puts the values back.

## What `scan` tells you

- every `.env` file, classified:
  - **harness**: folders owned by an agent harness (`.hermes`, `.claude`, `.codex`, OpenBot, … plus your own in `config.toml`). Those secrets stay where they are.
  - **app**: other dot-folders in your home (tool state)
  - **backup**: `.bak`, snapshots, `.moved-…` copies
  - **project**: everything else. Only these files are proposed for import.
- the same name in several files, and whether the copies carry the same value
- the **same value under different names** (compared by sha256 in memory, never printed)
- login/key files of CLIs and harnesses, and files readable by other users

## Deduplication

- Identical value, different names → stored once; the other names become **aliases**.
- Same name, different value per project (e.g. `DATABASE_URL`) → `import --scan` stores each one as `<PROJECT>__NAME`. Map it back at run time with `-k DATABASE_URL=BILLING__DATABASE_URL`.

## Protecting the identity

The vault is age-encrypted to an X25519 identity. How that identity is kept:

| mode | at rest | unattended agents | notes |
|---|---|---|---|
| `--machine` (default) | bound to this machine: TPM2 via systemd-creds on Linux, login Keychain on macOS, DPAPI/Credential Manager on Windows | yes, never prompts | a copied identity file or backup is useless elsewhere; a process already running as you can still use it. Losing the machine/TPM loses the vault unless you exported the identity |
| `--passphrase` | encrypted (scrypt) | after `keytwig unlock` (default 12h, `--ttl`) | works everywhere |
| `--keyring` | OS keyring: Keychain, Credential Manager, Secret Service | yes, while you are logged in | only as strong as your login keyring; on Linux with autologin the keyring is often saved **unencrypted** (`keytwig status` warns) |
| `--file` | plaintext 0600 file | yes | anyone who copies the file can open the vault |

Switch at any time with `keytwig protect --machine|--passphrase|--keyring|--file` (the vault is not re-encrypted).
Always keep an offline backup: `keytwig identity export --out FILE`.

## Commands

```sh
keytwig init [--machine|--passphrase|--keyring|--file]
keytwig status
keytwig protect --machine | --passphrase | --keyring | --file
keytwig unlock [--ttl 12h]  /  keytwig lock
keytwig identity export --out FILE
keytwig identity import FILE           # restore an exported identity
keytwig scan [dir...] [--all] [--json]
keytwig import <file> [--only A,B] [--prefix P] [--overwrite]
keytwig import --scan [dir...] [--dry-run] [--include-app]
printf %s "$V" | keytwig set NAME     # or interactive hidden prompt; never from argv
keytwig set NAME --file path/to/sa.json  # store a file secret (max 1 MiB)
keytwig ls [--json]                   # names, kind, aliases, source, last update — no values
keytwig rm NAME
keytwig run -k NAME -k VAR=NAME -- cmd
keytwig run --file-key SA=GCP_SA -- cmd  # mount file secret ephemerally (0600, wiped on exit)
keytwig run -p -- cmd                 # current project's secrets
keytwig http GET https://api.stripe.com/v1/charges -H 'Authorization: Bearer {{STRIPE_SECRET_KEY}}'
keytwig hook [claude|cursor]          # PreToolUse secret guard (stdin JSON)
keytwig rewrite [file...|--scan] [--apply]  /  keytwig restore ...
keytwig mcp [--agent NAME]
keytwig install <harness|all> [--dry-run] [--no-hooks]
keytwig uninstall <harness|all>       # remove keytwig's MCP registration (and Claude hook)
keytwig log [--agent X] [--limit N] [--json]
keytwig doctor                        # check local setup, permissions, expiry, harnesses
keytwig version
keytwig run --env-file app.env -- cmd # app.env: API_KEY=keytwig://STRIPE_SECRET_KEY
```

`run` replaces every stored value (6+ chars, also base64 / URL / JSON-encoded, and hex for 8+ chars)
in stdout/stderr with `‹keytwig:NAME›`, also across write boundaries.
`--no-redact` for interactive programs.

`keytwig log` reads `audit.jsonl` next to the encrypted vault. Entries record operation
metadata without secret values. Filter by agent or limit the number of
entries. Use `--json` for machine-readable output.

## Files

| | Linux | macOS | Windows |
|---|---|---|---|
| identity, config | `~/.config/keytwig/` | `~/Library/Application Support/keytwig/` | `%AppData%\keytwig\` |
| vault | `~/.local/share/keytwig/vault.age` | same as identity | same as identity |

`KEYTWIG_HOME` overrides both (tests, sandboxes).

`config.toml`:

```toml
harness = ["~/.local/share/my-agent"]   # added to the built-in list
ignore  = ["~/huge-folder"]             # not scanned
```

## Not yet

- an OS-level boundary between agents (separate user / daemon with per-agent tokens)
- adapters for harnesses with their own secret stores (browser logins stay there)
- Windows: file permissions rely on the user profile ACL, not 0600
