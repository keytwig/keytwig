package vault

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"filippo.io/age"
	"github.com/zalando/go-keyring"
)

// ModeMachine binds the identity to this machine and user, with no prompt:
//   - Linux: sealed with systemd-creds (TPM2 + host key, scoped to the user)
//   - macOS: login Keychain
//   - Windows: Credential Manager (DPAPI, tied to the Windows account)
//
// A copy of the identity file or of a backup is useless on another machine.
// It does not stop a process already running as you on this machine; that
// is the price of letting agents work unattended.
const ModeMachine = "machine"

const machinePrefix = "machine:"

const credName = "keytwig-identity"

// machineBackend picks how ModeMachine works on this OS.
func machineBackend() (string, error) {
	switch runtime.GOOS {
	case "darwin", "windows":
		return "os-keyring", nil
	case "linux":
		if _, err := exec.LookPath("systemd-creds"); err == nil {
			// probe: encrypt+decrypt a dummy value
			if blob, err := credsEncrypt([]byte("probe")); err == nil {
				if out, err := credsDecrypt(blob); err == nil && string(out) == "probe" {
					return "systemd-creds", nil
				}
			}
		}
		if !KeyringStoredInPlaintext() {
			if err := keyring.Set(keyringService, "probe", "probe"); err == nil {
				keyring.Delete(keyringService, "probe")
				return "os-keyring", nil
			}
		}
		return "", errors.New("no machine-bound storage here (needs systemd-creds, or an encrypted login keyring): use --passphrase")
	}
	return "", fmt.Errorf("machine mode not supported on %s: use --passphrase", runtime.GOOS)
}

func credsEncrypt(plain []byte) ([]byte, error) {
	cmd := exec.Command("systemd-creds", "--user", "--name="+credName, "encrypt", "-", "-")
	cmd.Stdin = bytes.NewReader(plain)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("systemd-creds encrypt: %v %s", err, strings.TrimSpace(errb.String()))
	}
	return bytes.TrimSpace(out.Bytes()), nil
}

func credsDecrypt(blob []byte) ([]byte, error) {
	cmd := exec.Command("systemd-creds", "--user", "--name="+credName, "decrypt", "-", "-")
	cmd.Stdin = bytes.NewReader(blob)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("systemd-creds decrypt (was the identity created on another machine?): %v %s", err, strings.TrimSpace(errb.String()))
	}
	return out.Bytes(), nil
}

func machineStore(p Paths, id *age.X25519Identity) ([]byte, error) {
	backend, err := machineBackend()
	if err != nil {
		return nil, err
	}
	head := fmt.Sprintf("# keytwig identity, bound to this machine (%s)\n# public key: %s\n", backend, id.Recipient())
	switch backend {
	case "systemd-creds":
		blob, err := credsEncrypt([]byte(id.String()))
		if err != nil {
			return nil, err
		}
		if _, err := base64.StdEncoding.DecodeString(string(blob)); err != nil {
			return nil, errors.New("systemd-creds returned unexpected output")
		}
		return []byte(head + machinePrefix + "systemd-creds\n" + string(blob) + "\n"), nil
	default:
		user := keyringUser(p)
		if err := keyring.Set(keyringService, user, id.String()); err != nil {
			return nil, fmt.Errorf("OS keyring: %w", err)
		}
		return []byte(head + machinePrefix + "os-keyring:" + user + "\n"), nil
	}
}

func machineLoad(raw []byte) (*age.X25519Identity, error) {
	lines := strings.Split(string(raw), "\n")
	for i, l := range lines {
		l = strings.TrimSpace(l)
		if !strings.HasPrefix(l, machinePrefix) {
			continue
		}
		kind := strings.TrimPrefix(l, machinePrefix)
		switch {
		case kind == "systemd-creds":
			blob := strings.TrimSpace(strings.Join(lines[i+1:], ""))
			plain, err := credsDecrypt([]byte(blob))
			if err != nil {
				return nil, err
			}
			return parseIdentity(plain)
		case strings.HasPrefix(kind, "os-keyring:"):
			secret, err := keyring.Get(keyringService, strings.TrimPrefix(kind, "os-keyring:"))
			if err != nil {
				return nil, fmt.Errorf("read identity from OS keyring: %w", err)
			}
			return parseIdentity([]byte(secret))
		}
	}
	return nil, errors.New("machine identity file is malformed")
}

func machineCleanup(raw []byte) {
	for _, l := range strings.Split(string(raw), "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, machinePrefix+"os-keyring:") {
			keyring.Delete(keyringService, strings.TrimPrefix(l, machinePrefix+"os-keyring:"))
		}
	}
}

func isMachine(raw []byte) bool {
	for _, l := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), machinePrefix) {
			return true
		}
	}
	return false
}
