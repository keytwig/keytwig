# Changelog

## [0.2.0] - 2026-11-24

- Per-secret `[secrets.NAME]` configuration with `allowed_hosts` (exact and wildcard subdomain matching, deny by default), `expires`, and `note`, plus expiry checks in `keytwig doctor`.
- Shell-free `keytwig_http` MCP tool and `keytwig http` CLI command with `{{NAME}}` placeholder injection, HTTPS enforcement, `allowed_hosts` checks, cross-host redirect protection, response masking, and audit logging.
- `keytwig_list` metadata (`kind`, `allowed_hosts`, `expires`) and updated MCP instructions preferring `keytwig_http`.
- `PreToolUse` secret guard (`keytwig hook claude|cursor`) blocking direct reads of `.env`, vault/identity, and credential files or raw env dumps, auto-registered for Claude Code by `keytwig install` (`--no-hooks` to opt out) and removed by `keytwig uninstall`.
- File-backed secrets (`keytwig set --file`, `keytwig run --file-key`, MCP `file_keys`) materialized ephemerally in `$XDG_RUNTIME_DIR` (`0600`) and zero-wiped on exit.
- Automatic `Basic` auth base64 redaction when matching `*_USER`/`*_USERNAME` and `*_PASS`/`*_PASSWORD` pairs are injected together.

## [0.1.0] - 2026-11-24

- Local age-encrypted vault with machine-bound, passphrase, keyring, and file identity modes, plus identity export and import.
- Secret discovery and import from project env files, with aliases and project-specific mappings.
- Secret injection into child processes and stream redaction in stdout and stderr.
- Local MCP integration with per-agent allow/deny rules, installation and removal commands, and an audit log without secret values.
- CLI diagnostics and version reporting, with binaries for Linux, macOS, and Windows.
