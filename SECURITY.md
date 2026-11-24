# Security

Report vulnerabilities privately to [ciao@vittoriocompagno.com](mailto:ciao@vittoriocompagno.com) or through [GitHub private vulnerability reporting](https://github.com/keytwig/keytwig/security/advisories/new). Include the keytwig version, OS, and a minimal example using dummy secrets.

## Threat model

- The local vault is encrypted at rest with age. In machine mode, keytwig uses systemd-creds on Linux (TPM2 where available, with an encrypted login keyring as a fallback), the login Keychain on macOS, or DPAPI-backed Credential Manager on Windows. Passphrase mode encrypts the identity using a key derived with scrypt. The explicit `--file` mode stores the identity in plaintext.
- Stream redaction reduces accidental disclosure in logs, stack traces, and environment dumps. Per-agent allow/deny rules scope the keys keytwig will inject. The local audit log records operation metadata without secret values.
- A shell command that receives a secret can deliberately transform or send it elsewhere. An agent running as the same OS user may be able to unlock or access the vault outside its configured policy. Use OS-level isolation for that threat.
- The keytwig binary makes zero network calls and sends zero telemetry. Commands launched through it can use the network on their own.
