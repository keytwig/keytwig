# Security

Report vulnerabilities privately to [ciao@vittoriocompagno.com](mailto:ciao@vittoriocompagno.com) or through [GitHub private vulnerability reporting](https://github.com/keytwig/keytwig/security/advisories/new). Include the keytwig version, OS, and a minimal example using dummy secrets.

## Threat model

- The local vault is encrypted at rest with age. In machine mode, keytwig uses systemd-creds on Linux (TPM2 where available, with an encrypted login keyring as a fallback), the login Keychain on macOS, or DPAPI-backed Credential Manager on Windows. Passphrase mode encrypts the identity using a key derived with scrypt. The explicit `--file` mode stores the identity in plaintext.
- Stream redaction reduces accidental disclosure in logs, stack traces, environment dumps, and HTTP `Basic` auth headers (`*_USER`/`*_PASS` pairs). Per-agent allow/deny rules scope the keys keytwig will inject. The local audit log records operation metadata without secret values.
- `keytwig_http` / `keytwig http` avoids shell execution altogether, requires HTTPS (except localhost), enforces per-secret `[secrets.NAME] allowed_hosts` (secure by default: empty denies), blocks cross-host redirects when secrets are injected, and masks reflected secrets in headers and body.
- `keytwig hook` (`PreToolUse`) blocks direct agent reads of `.env` files, `identity.txt`, `vault.age`, known credential files, and raw environment dumps, steering agents to `keytwig_run` and `keytwig_http`.
- File-backed secrets (`--file` / `--file-key`) are materialized in an ephemeral `0o700` directory (`$XDG_RUNTIME_DIR` when available) with `0o600` permissions, overwritten with zeros, and deleted when the command exits.
- A shell command that receives a secret can deliberately transform or send it elsewhere. An agent running as the same OS user may be able to unlock or access the vault outside its configured policy. Use OS-level isolation for that threat.
- Unless explicitly invoked via `keytwig http` / `keytwig_http`, the keytwig binary makes zero network calls and sends zero telemetry. Commands launched through `keytwig run` can use the network on their own.
