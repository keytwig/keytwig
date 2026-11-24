// Prompts for coding agents. Every command here exists in keytwig v0.1.0 (see the README command list).

export const installPrompt = `Install keytwig on this machine and connect it to my coding agents, following https://github.com/keytwig/keytwig#readme.
Never print, echo, or read a secret value; anything that needs one goes through \`keytwig run\`.
1. Install with \`brew install memtwig/tap/keytwig\` (or \`curl -fsSL https://raw.githubusercontent.com/keytwig/keytwig/main/scripts/install.sh | sh\`) and make sure \`keytwig\` is on PATH.
2. Run \`keytwig init\` (identity bound to this machine, no prompts). Remind me to run \`keytwig identity export --out FILE\` myself and keep that backup offline.
3. Run \`keytwig scan\` and \`keytwig import --scan --dry-run\`, show me the names it would import (never values), and run \`keytwig import --scan\` only after my OK.
4. Run \`keytwig install all\`, then \`keytwig doctor\`, and report which harnesses are connected.`;

export const projectPrompt = `Move this project's secrets into keytwig without reading any value.
1. From the project root run \`keytwig import --scan . --dry-run\` and list the names it would add.
2. After my OK run \`keytwig import --scan .\`, then \`keytwig rewrite --scan\` and show me which .env lines become \`keytwig://NAME\`. Apply with \`keytwig rewrite --scan --apply\` only after my OK.
3. Start the app with \`keytwig run -p -- <the project's dev command>\` and confirm it boots.
4. If anything breaks, run \`keytwig restore\` to put the values back.`;

export const auditPrompt = `Review how my agents use keytwig and tighten access. Never print a secret value.
1. Run \`keytwig log --limit 50\` and \`keytwig ls\`, and summarise which agent injected which names.
2. Propose \`[agents.<name>]\` allow/deny rules for keytwig's config.toml (deny wins; \`[agents.default]\` covers unlisted agents). Show me the diff before writing it.
3. Run \`keytwig status\` and \`keytwig doctor\` and report every warning, such as a plaintext identity file or an unencrypted keyring.`;
