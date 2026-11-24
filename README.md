# keytwig

One local vault for the secrets your projects and agents use. Agents use
secrets through `keytwig run`: values are injected into the process and masked
in its output, so the model never reads them.

Sibling of [memtwig](https://github.com/memtwig/memtwig). Linux, macOS and
Windows (single static binary, no cgo).

## Quick start

```sh
keytwig init                     # identity bound to this machine, no prompts (or --passphrase / --keyring / --file)
keytwig scan                     # where credentials live today (names and paths only)
keytwig import --scan --dry-run  # what would be imported from your project .env files
keytwig import --scan
keytwig run -k STRIPE_SECRET_KEY -- ./deploy.sh
cd ~/code/shop && keytwig run -p -- npm run dev   # the project's own secrets, usual names
keytwig install all              # MCP server in Claude Code, Codex, Cursor, Hermes, Grok, Antigravity
```

## Agents

`keytwig install <claude|codex|cursor|hermes|grok|antigravity|all>` (antigravity: standalone and T3-managed) registers `keytwig mcp --agent <harness>`
(config backed up as `*.keytwig.bak`). Tools exposed — none returns a value:

- `keytwig_run` — run a shell command with secrets injected (`keys`, or `project: true`); output masked
- `keytwig_list` — names, aliases, and which env vars the current project gets
- `keytwig_import` — move a `.env` into the vault without values passing through the model
- `keytwig_status`

There is no get/set tool on purpose. Masking protects against accidents (logs,
stack traces, `env` dumps), not against an agent that deliberately transforms a
value (e.g. reverses it) before printing.

### Per-agent policies (`config.toml`)

```toml
[agents.hermes]
allow = ["SABATINO_*", "STRIPE_*"]
deny  = ["*_PROD"]

[agents.default]        # unnamed or unlisted agents
deny = ["STRIPE_*"]
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
- Same name, different value per project (e.g. `DATABASE_URL`) → not a duplicate: `import --scan` stores each one as `<PROJECT>__NAME`. Map it back at run time: `-k DATABASE_URL=PREVENTIVATORE__DATABASE_URL`.

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
keytwig scan [dir...] [--all] [--json]
keytwig import <file> [--only A,B] [--prefix P] [--overwrite]
keytwig import --scan [dir...] [--dry-run] [--include-app]
printf %s "$V" | keytwig set NAME     # or interactive hidden prompt; never from argv
keytwig ls [--json]                   # names, aliases, source, last update — no values
keytwig rm NAME
keytwig run -k NAME -k VAR=NAME -- cmd
keytwig run -p -- cmd                 # current project's secrets
keytwig rewrite [file...|--scan] [--apply]  /  keytwig restore ...
keytwig mcp [--agent NAME]
keytwig install <harness|all> [--dry-run]
keytwig run --env-file app.env -- cmd # app.env: API_KEY=keytwig://STRIPE_SECRET_KEY
```

`run` replaces every stored value (6+ chars, also base64 / URL / JSON-encoded)
in stdout/stderr with `‹keytwig:NAME›`, also across write boundaries.
`--no-redact` for interactive programs.

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
