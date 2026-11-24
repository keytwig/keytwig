// Package vault stores secrets in a single age-encrypted JSON file.
package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"filippo.io/age"
)

// Secret is one stored value plus where it came from. Aliases are other
// names that carry the very same value (deduplicated).
type Secret struct {
	Value   string    `json:"value"`
	Source  string    `json:"source,omitempty"`
	Aliases []string  `json:"aliases,omitempty"`
	Created time.Time `json:"created"`
	Updated time.Time `json:"updated"`
}

type file struct {
	Version int                `json:"version"`
	Secrets map[string]*Secret `json:"secrets"`
	// Projects: project folder → env var name used there → stored secret name.
	// Lets `keytwig run --project` inject a project's secrets under their
	// original names, and `keytwig rewrite` put references back.
	Projects map[string]map[string]string `json:"projects,omitempty"`
}

// Paths tells where the identity and the encrypted vault live.
type Paths struct {
	Identity string
	Vault    string
	Config   string
}

// DefaultPaths honours KEYTWIG_HOME, otherwise XDG locations.
func DefaultPaths() (Paths, error) {
	if h := os.Getenv("KEYTWIG_HOME"); h != "" {
		return Paths{Identity: filepath.Join(h, "identity.txt"), Vault: filepath.Join(h, "vault.age"), Config: filepath.Join(h, "config.toml")}, nil
	}
	// Native locations: Linux ~/.config + ~/.local/share (XDG),
	// macOS ~/Library/Application Support, Windows %AppData%.
	cfg, err := os.UserConfigDir()
	if err != nil {
		return Paths{}, err
	}
	data := cfg
	if runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		data = os.Getenv("XDG_DATA_HOME")
		if data == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return Paths{}, err
			}
			data = filepath.Join(home, ".local", "share")
		}
	}
	return Paths{
		Identity: filepath.Join(cfg, "keytwig", "identity.txt"),
		Vault:    filepath.Join(data, "keytwig", "vault.age"),
		Config:   filepath.Join(cfg, "keytwig", "config.toml"),
	}, nil
}

// Vault is an open, decrypted vault.
type Vault struct {
	paths Paths
	id    *age.X25519Identity
	f     file
	alias map[string]string // alias → canonical
}

var ErrNotInitialized = errors.New("keytwig is not initialized: run `keytwig init`")

// Init creates identity (in the given mode) and an empty vault.
// Returns false if both already exist.
func Init(p Paths, mode string, passphrase []byte) (bool, error) {
	_, idErr := os.Stat(p.Identity)
	_, vErr := os.Stat(p.Vault)
	if idErr == nil && vErr == nil {
		return false, nil
	}
	if idErr == nil {
		return false, fmt.Errorf("identity exists but vault is missing (%s): restore the vault or remove the identity", p.Vault)
	}
	if vErr == nil {
		return false, fmt.Errorf("vault exists but identity is missing (%s): restore it from your backup", p.Identity)
	}
	if err := os.MkdirAll(filepath.Dir(p.Identity), 0o700); err != nil {
		return false, err
	}
	if err := os.MkdirAll(filepath.Dir(p.Vault), 0o700); err != nil {
		return false, err
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return false, err
	}
	if err := storeIdentity(p, id, mode, passphrase); err != nil {
		os.Remove(p.Identity)
		return false, err
	}
	v := &Vault{paths: p, id: id, f: file{Version: 1, Secrets: map[string]*Secret{}, Projects: map[string]map[string]string{}}, alias: map[string]string{}}
	return true, v.Save()
}

func parseIdentity(raw []byte) (*age.X25519Identity, error) {
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "AGE-SECRET-KEY-") {
			return age.ParseX25519Identity(line)
		}
	}
	return nil, errors.New("identity has no AGE-SECRET-KEY line")
}

// Open decrypts the vault.
func Open(p Paths) (*Vault, error) {
	id, err := loadIdentity(p)
	if err != nil {
		return nil, err
	}
	enc, err := os.ReadFile(p.Vault)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotInitialized
	} else if err != nil {
		return nil, err
	}
	r, err := age.Decrypt(bytes.NewReader(enc), id)
	if err != nil {
		return nil, fmt.Errorf("decrypt vault: %w", err)
	}
	plain, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	v := &Vault{paths: p, id: id, alias: map[string]string{}}
	if err := json.Unmarshal(plain, &v.f); err != nil {
		return nil, fmt.Errorf("vault is corrupt: %w", err)
	}
	if v.f.Secrets == nil {
		v.f.Secrets = map[string]*Secret{}
	}
	if v.f.Projects == nil {
		v.f.Projects = map[string]map[string]string{}
	}
	for name, s := range v.f.Secrets {
		for _, a := range s.Aliases {
			v.alias[a] = name
		}
	}
	return v, nil
}

// Save encrypts and atomically replaces the vault file.
func (v *Vault) Save() error {
	plain, err := json.Marshal(v.f)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, v.id.Recipient())
	if err != nil {
		return err
	}
	if _, err := w.Write(plain); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return writeAtomic(v.paths.Vault, buf.Bytes(), 0o600)
}

// Canonical resolves an alias to the name that owns the value.
func (v *Vault) Canonical(name string) string {
	if c, ok := v.alias[name]; ok {
		return c
	}
	return name
}

func (v *Vault) Get(name string) (*Secret, bool) {
	s, ok := v.f.Secrets[v.Canonical(name)]
	return s, ok
}

// FindByValue returns the canonical name already holding value.
func (v *Vault) FindByValue(value string) (string, bool) {
	for name, s := range v.f.Secrets {
		if s.Value == value {
			return name, true
		}
	}
	return "", false
}

// Set stores a value. Returns "added", "updated", "unchanged" or "alias of X"
// (when another name already holds the same value, no second copy is made).
func (v *Vault) Set(name, value, source string) string {
	now := time.Now().UTC()
	if s, ok := v.Get(name); ok {
		if s.Value == value {
			return "unchanged"
		}
		if c := v.Canonical(name); c != name {
			// an alias getting its own value splits off
			v.removeAlias(c, name)
		} else {
			s.Value, s.Updated = value, now
			if source != "" {
				s.Source = source
			}
			return "updated"
		}
	}
	if owner, ok := v.FindByValue(value); ok {
		s := v.f.Secrets[owner]
		s.Aliases = append(s.Aliases, name)
		sort.Strings(s.Aliases)
		v.alias[name] = owner
		return "alias of " + owner
	}
	v.f.Secrets[name] = &Secret{Value: value, Source: source, Created: now, Updated: now}
	return "added"
}

func (v *Vault) unlink(names map[string]bool) {
	for dir, m := range v.f.Projects {
		for env, n := range m {
			if names[n] {
				delete(m, env)
			}
		}
		if len(m) == 0 {
			delete(v.f.Projects, dir)
		}
	}
}

func (v *Vault) removeAlias(owner, alias string) {
	s := v.f.Secrets[owner]
	out := s.Aliases[:0]
	for _, a := range s.Aliases {
		if a != alias {
			out = append(out, a)
		}
	}
	s.Aliases = out
	delete(v.alias, alias)
}

// Delete removes a name. Deleting an alias keeps the value; deleting the
// owner removes the value and returns the aliases that went with it.
func (v *Vault) Delete(name string) (bool, []string) {
	if owner, ok := v.alias[name]; ok {
		v.removeAlias(owner, name)
		v.unlink(map[string]bool{name: true})
		return true, nil
	}
	s, ok := v.f.Secrets[name]
	if !ok {
		return false, nil
	}
	for _, a := range s.Aliases {
		delete(v.alias, a)
	}
	delete(v.f.Secrets, name)
	gone := map[string]bool{name: true}
	for _, a := range s.Aliases {
		gone[a] = true
	}
	v.unlink(gone)
	return true, s.Aliases
}

// Link records that in project dir, env var envName maps to secret name.
// Returns true if something changed.
func (v *Vault) Link(dir, envName, name string) bool {
	m := v.f.Projects[dir]
	if m == nil {
		m = map[string]string{}
		v.f.Projects[dir] = m
	}
	if m[envName] == name {
		return false
	}
	m[envName] = name
	return true
}

// Project returns the deepest linked project folder containing cwd and its
// env→secret map ("" if none).
func (v *Vault) Project(cwd string) (string, map[string]string) {
	best := ""
	for dir := range v.f.Projects {
		if (cwd == dir || strings.HasPrefix(cwd, dir+string(filepath.Separator))) && len(dir) > len(best) {
			best = dir
		}
	}
	if best == "" {
		return "", nil
	}
	return best, v.f.Projects[best]
}

// Projects returns all project links (read-only use).
func (v *Vault) Projects() map[string]map[string]string { return v.f.Projects }

// Names lists canonical names.
func (v *Vault) Names() []string {
	out := make([]string, 0, len(v.f.Secrets))
	for k := range v.f.Secrets {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Values returns canonical name→value (used for redaction placeholders).
func (v *Vault) Values() map[string]string {
	out := make(map[string]string, len(v.f.Secrets))
	for k, s := range v.f.Secrets {
		out[k] = s.Value
	}
	return out
}

// Env returns every name, aliases included, → value.
func (v *Vault) Env() map[string]string {
	out := v.Values()
	for a, owner := range v.alias {
		out[a] = v.f.Secrets[owner].Value
	}
	return out
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".keytwig-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
