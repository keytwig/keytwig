// Package dotenv parses KEY=value files without ever printing values.
package dotenv

import (
	"bufio"
	"io"
	"regexp"
	"strings"
)

type Entry struct {
	Name  string
	Value string
	Line  int
}

var lineRe = regexp.MustCompile(`^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.]*)\s*=\s*(.*)$`)

// Parse reads entries. Later duplicates override earlier ones, like most loaders.
func Parse(r io.Reader) ([]Entry, error) {
	var out []Entry
	idx := map[string]int{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	n := 0
	for sc.Scan() {
		n++
		line := sc.Text()
		if t := strings.TrimSpace(line); t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		m := lineRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		e := Entry{Name: m[1], Value: unquote(m[2]), Line: n}
		if i, ok := idx[e.Name]; ok {
			out[i] = e
			continue
		}
		idx[e.Name] = len(out)
		out = append(out, e)
	}
	return out, sc.Err()
}

func unquote(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 {
		switch v[0] {
		case '"':
			if end := strings.LastIndexByte(v, '"'); end > 0 {
				s := v[1:end]
				r := strings.NewReplacer(`\n`, "\n", `\"`, `"`, `\\`, `\`)
				return r.Replace(s)
			}
		case '\'':
			if end := strings.LastIndexByte(v, '\''); end > 0 {
				return v[1:end]
			}
		}
	}
	if i := strings.Index(v, " #"); i >= 0 {
		v = strings.TrimSpace(v[:i])
	}
	return v
}

var secretName = regexp.MustCompile(`(?i)(KEY|TOKEN|SECRET|PASS|PWD|AUTH|CRED|PRIVATE|DSN|DATABASE_URL|_URI$|WEBHOOK)`)

// client-side prefixes (VITE_, NEXT_PUBLIC_, ...) are shipped to browsers, so not secret
var notSecretName = regexp.MustCompile(`(?i)(^(VITE|NEXT_PUBLIC|PUBLIC|EXPO_PUBLIC|NUXT_PUBLIC|REACT_APP)_|PUBLISHABLE|PUBLIC_KEY$|SITE_KEY$|_USERNAME$|_USER$|KEY_ID$|_PATH$|_FILE$|_ORIGINS$|AUTH_URL$)`)

// LooksSecret guesses from the name alone.
func LooksSecret(name string) bool {
	return secretName.MatchString(name) && !notSecretName.MatchString(name)
}
