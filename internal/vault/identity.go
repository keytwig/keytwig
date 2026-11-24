package vault

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
	"github.com/zalando/go-keyring"
)

// Identity storage modes.
const (
	ModeFile       = "file"       // plaintext age identity, 0600
	ModePassphrase = "passphrase" // identity encrypted with a passphrase; `keytwig unlock` once per boot
	ModeKeyring    = "keyring"    // identity in the OS keyring (Secret Service / Keychain / Credential Manager)
)

const keyringService = "keytwig"
const keyringPrefix = "keyring:"

var ErrLocked = errors.New("keytwig is locked: run `keytwig unlock` in a terminal")

func keyringUser(p Paths) string {
	sum := sha256.Sum256([]byte(p.Vault))
	return "identity-" + hex.EncodeToString(sum[:6])
}

// runtimeCache is where an unlocked passphrase identity lives until its TTL
// expires. On Linux XDG_RUNTIME_DIR is a per-user tmpfs (also gone at
// reboot); elsewhere the per-user temp dir is used.
func runtimeCache(p Paths) string {
	dir := os.Getenv("KEYTWIG_RUNTIME_DIR")
	if dir == "" {
		dir = os.Getenv("XDG_RUNTIME_DIR")
	}
	if dir == "" {
		dir = filepath.Join(os.TempDir(), fmt.Sprintf("keytwig-%d", os.Getuid()))
	} else {
		dir = filepath.Join(dir, "keytwig")
	}
	return filepath.Join(dir, keyringUser(p))
}

// Status describes how the identity is stored.
type Status struct {
	Mode     string `json:"mode"`
	Locked   bool   `json:"locked"`
	Identity string `json:"identity_path"`
	Vault    string `json:"vault_path"`
	Warning  string `json:"warning,omitempty"`
}

func detectMode(raw []byte) string {
	s := string(raw)
	switch {
	case isMachine(raw):
		return ModeMachine
	case strings.Contains(s, armor.Header):
		return ModePassphrase
	case strings.Contains(s, "\n"+keyringPrefix) || strings.HasPrefix(s, keyringPrefix):
		return ModeKeyring
	default:
		return ModeFile
	}
}

func GetStatus(p Paths) (Status, error) {
	st := Status{Identity: p.Identity, Vault: p.Vault}
	raw, err := os.ReadFile(p.Identity)
	if errors.Is(err, os.ErrNotExist) {
		return st, ErrNotInitialized
	} else if err != nil {
		return st, err
	}
	st.Mode = detectMode(raw)
	_, err = loadIdentity(p)
	st.Locked = errors.Is(err, ErrLocked)
	if err != nil && !st.Locked {
		return st, err
	}
	switch st.Mode {
	case ModeFile:
		st.Warning = "identity is a plaintext file: anyone who copies it (backups, disk) can open the vault. Consider `keytwig protect --machine`."
	case ModeKeyring:
		if KeyringStoredInPlaintext() {
			st.Warning = "your login keyring has no password (typical with autologin), so it is saved unencrypted on disk: keyring mode adds no protection at rest."
		}
	}
	return st, nil
}

// KeyringStoredInPlaintext detects a gnome-keyring default keyring saved
// without encryption (header "[keyring]"), which happens with autologin.
func KeyringStoredInPlaintext() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return false
	}
	dir := filepath.Join(home, ".local", "share", "keyrings")
	name := "login"
	if b, err := os.ReadFile(filepath.Join(dir, "default")); err == nil {
		name = strings.TrimSpace(string(b))
	}
	f, err := os.Open(filepath.Join(dir, name+".keyring"))
	if err != nil {
		return false
	}
	defer f.Close()
	head := make([]byte, 9)
	n, _ := io.ReadFull(f, head)
	return string(head[:n]) == "[keyring]"
}

func loadIdentity(p Paths) (*age.X25519Identity, error) {
	raw, err := os.ReadFile(p.Identity)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotInitialized
	} else if err != nil {
		return nil, err
	}
	switch detectMode(raw) {
	case ModeMachine:
		return machineLoad(raw)
	case ModePassphrase:
		cached, err := os.ReadFile(runtimeCache(p))
		if err != nil {
			return nil, ErrLocked
		}
		if exp := cacheExpiry(cached); !exp.IsZero() && time.Now().After(exp) {
			os.Remove(runtimeCache(p))
			return nil, ErrLocked
		}
		return parseIdentity(cached)
	case ModeKeyring:
		secret, err := keyring.Get(keyringService, keyringUser(p))
		if err != nil {
			return nil, fmt.Errorf("read identity from system keyring: %w", err)
		}
		return parseIdentity([]byte(secret))
	default:
		return parseIdentity(raw)
	}
}

func plainIdentityFile(id *age.X25519Identity) []byte {
	return []byte(fmt.Sprintf("# keytwig identity — keep private, back it up offline\n# public key: %s\n%s\n", id.Recipient(), id))
}

// storeIdentity writes id in the given mode, replacing the current form.
func storeIdentity(p Paths, id *age.X25519Identity, mode string, passphrase []byte) error {
	switch mode {
	case ModeMachine:
		content, err := machineStore(p, id)
		if err != nil {
			return err
		}
		return writeAtomic(p.Identity, content, 0o600)
	case ModeFile:
		return writeAtomic(p.Identity, plainIdentityFile(id), 0o600)
	case ModePassphrase:
		if len(passphrase) < 8 {
			return errors.New("passphrase must be at least 8 characters")
		}
		r, err := age.NewScryptRecipient(string(passphrase))
		if err != nil {
			return err
		}
		var buf bytes.Buffer
		aw := armor.NewWriter(&buf)
		w, err := age.Encrypt(aw, r)
		if err != nil {
			return err
		}
		w.Write([]byte(id.String() + "\n"))
		if err := w.Close(); err != nil {
			return err
		}
		if err := aw.Close(); err != nil {
			return err
		}
		if err := writeAtomic(p.Identity, buf.Bytes(), 0o600); err != nil {
			return err
		}
		return writeCache(p, id, DefaultTTL) // stay unlocked in this session
	case ModeKeyring:
		user := keyringUser(p)
		if err := keyring.Set(keyringService, user, id.String()); err != nil {
			return fmt.Errorf("system keyring unavailable: %w", err)
		}
		back, err := keyring.Get(keyringService, user)
		if err != nil || back != id.String() {
			return errors.New("system keyring did not return the stored identity; nothing changed")
		}
		ptr := fmt.Sprintf("# keytwig identity is stored in the system keyring (service %q)\n# public key: %s\n%s%s\n", keyringService, id.Recipient(), keyringPrefix, user)
		return writeAtomic(p.Identity, []byte(ptr), 0o600)
	}
	return fmt.Errorf("unknown mode %q", mode)
}

// DefaultTTL is how long `keytwig unlock` lasts unless told otherwise.
const DefaultTTL = 12 * time.Hour

const expiresPrefix = "# expires: "

func cacheExpiry(raw []byte) time.Time {
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, expiresPrefix) {
			if n, err := strconv.ParseInt(strings.TrimSpace(line[len(expiresPrefix):]), 10, 64); err == nil {
				return time.Unix(n, 0)
			}
		}
	}
	return time.Time{}
}

func writeCache(p Paths, id *age.X25519Identity, ttl time.Duration) error {
	c := runtimeCache(p)
	if err := os.MkdirAll(filepath.Dir(c), 0o700); err != nil {
		return err
	}
	body := id.String() + "\n"
	if ttl > 0 {
		body = fmt.Sprintf("%s%d\n%s", expiresPrefix, time.Now().Add(ttl).Unix(), body)
	}
	return writeAtomic(c, []byte(body), 0o600)
}

// Protect switches the identity to another storage mode. The vault file is untouched.
func Protect(p Paths, mode string, passphrase []byte) error {
	id, err := loadIdentity(p)
	if err != nil {
		return err
	}
	old, _ := os.ReadFile(p.Identity)
	oldMode := detectMode(old)
	if err := storeIdentity(p, id, mode, passphrase); err != nil {
		return err
	}
	if back, err := loadIdentity(p); err != nil || back.String() != id.String() {
		_ = writeAtomic(p.Identity, old, 0o600)
		return errors.New("verification failed, previous identity restored")
	}
	if oldMode == ModeMachine && mode != ModeMachine {
		machineCleanup(old)
	}
	if oldMode == ModeKeyring && mode != ModeKeyring {
		_ = keyring.Delete(keyringService, keyringUser(p))
	}
	if oldMode == ModePassphrase && mode != ModePassphrase {
		_ = os.Remove(runtimeCache(p))
	}
	return nil
}

// Unlock decrypts a passphrase identity into the per-boot runtime cache.
func Unlock(p Paths, passphrase []byte, ttl time.Duration) error {
	raw, err := os.ReadFile(p.Identity)
	if err != nil {
		return err
	}
	if detectMode(raw) != ModePassphrase {
		return errors.New("identity is not passphrase-protected; nothing to unlock")
	}
	si, err := age.NewScryptIdentity(string(passphrase))
	if err != nil {
		return err
	}
	r, err := age.Decrypt(armor.NewReader(bytes.NewReader(raw)), si)
	if err != nil {
		return errors.New("wrong passphrase")
	}
	plain, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	id, err := parseIdentity(plain)
	if err != nil {
		return err
	}
	return writeCache(p, id, ttl)
}

// LockSession removes the unlocked identity from the runtime cache.
func LockSession(p Paths) (bool, error) {
	err := os.Remove(runtimeCache(p))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

// Export writes the plaintext identity to a new 0600 file (offline backup).
func Export(p Paths, out string) error {
	id, err := loadIdentity(p)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(plainIdentityFile(id)); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
