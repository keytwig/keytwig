// Package envfile rewrites .env files in place: secret values become
// keytwig://NAME references (Rewrite) and back (Restore). Every other line
// is kept byte for byte. Values are never returned to the caller.
package envfile

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/keytwig/keytwig/internal/dotenv"
	"github.com/keytwig/keytwig/internal/vault"
)

const RefPrefix = "keytwig://"

var lineRe = regexp.MustCompile(`^(\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.]*)\s*=\s*)(.*)$`)

// Change is one line that would change; only names, never values.
type Change struct {
	Env    string `json:"env"`
	Secret string `json:"secret"`
}

type Result struct {
	Path    string   `json:"path"`
	Changes []Change `json:"changes"`
	Skipped []string `json:"skipped,omitempty"` // env names with a ref keytwig cannot resolve, or a value differing from the vault
	Written bool     `json:"written"`
}

func valueOf(raw string) string {
	es, _ := dotenv.Parse(strings.NewReader("X=" + raw))
	if len(es) == 0 {
		return ""
	}
	return es[0].Value
}

func quote(v string) string {
	if v != "" && !strings.ContainsAny(v, " \t#\"'\\\n$`") {
		return v
	}
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return `"` + r.Replace(v) + `"`
}

// Rewrite replaces values that keytwig holds for this file's project with
// keytwig://NAME. apply=false only reports.
func Rewrite(path string, v *vault.Vault, apply bool) (*Result, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	links := v.Projects()[filepath.Dir(abs)]
	return edit(abs, apply, func(env, raw string) (string, *Change, bool) {
		name, ok := links[env]
		if !ok {
			return "", nil, false
		}
		val := valueOf(raw)
		if strings.HasPrefix(val, RefPrefix) {
			return "", nil, false
		}
		s, ok := v.Get(name)
		if !ok || s.Value != val {
			return "", nil, true // value changed since import: leave it, report
		}
		return RefPrefix + name, &Change{Env: env, Secret: name}, false
	})
}

// Restore puts real values back in place of keytwig://NAME references.
func Restore(path string, v *vault.Vault, apply bool) (*Result, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	return edit(abs, apply, func(env, raw string) (string, *Change, bool) {
		val := valueOf(raw)
		if !strings.HasPrefix(val, RefPrefix) {
			return "", nil, false
		}
		name := strings.TrimPrefix(val, RefPrefix)
		s, ok := v.Get(name)
		if !ok {
			return "", nil, true
		}
		return quote(s.Value), &Change{Env: env, Secret: name}, false
	})
}

func edit(path string, apply bool, fn func(env, raw string) (string, *Change, bool)) (*Result, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	res := &Result{Path: path}
	lines := strings.SplitAfter(string(data), "\n")
	for i, line := range lines {
		body := strings.TrimRight(line, "\r\n")
		eol := line[len(body):]
		if t := strings.TrimSpace(body); t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		m := lineRe.FindStringSubmatch(body)
		if m == nil {
			continue
		}
		newVal, ch, skipped := fn(m[2], m[3])
		if skipped {
			res.Skipped = append(res.Skipped, m[2])
		}
		if ch == nil {
			continue
		}
		res.Changes = append(res.Changes, *ch)
		lines[i] = m[1] + newVal + eol
	}
	if apply && len(res.Changes) > 0 {
		tmp, err := os.CreateTemp(filepath.Dir(path), ".keytwig-env-*")
		if err != nil {
			return nil, err
		}
		defer os.Remove(tmp.Name())
		if err := tmp.Chmod(info.Mode().Perm()); err != nil {
			tmp.Close()
			return nil, err
		}
		if _, err := tmp.WriteString(strings.Join(lines, "")); err != nil {
			tmp.Close()
			return nil, err
		}
		if err := tmp.Close(); err != nil {
			return nil, err
		}
		if err := os.Rename(tmp.Name(), path); err != nil {
			return nil, err
		}
		res.Written = true
	}
	return res, nil
}
