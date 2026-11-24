// Package audit writes and queries an append-only JSONL execution audit log.
// Secret values must never be stored in audit events.
package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/keytwig/keytwig/internal/redact"
)

const MaxCommandLen = 120

// Event records one `keytwig run` / `keytwig_run` execution.
type Event struct {
	Time       time.Time `json:"time"`
	Mode       string    `json:"mode"` // "cli" or "mcp"
	Agent      string    `json:"agent,omitempty"`
	Cwd        string    `json:"cwd,omitempty"`
	Command    string    `json:"command"`
	Injected   []string  `json:"injected,omitempty"`
	Denied     []string  `json:"denied,omitempty"`
	ExitCode   int       `json:"exit_code"`
	Redactions int       `json:"redactions"`
}

// RedactCommand passes cmd through the secret redactor (when secrets are provided),
// collapses whitespace, and truncates to MaxCommandLen runes.
func RedactCommand(cmd string, secrets map[string]string) string {
	if len(secrets) > 0 && cmd != "" {
		var buf bytes.Buffer
		w := redact.New(&buf, secrets)
		_, _ = w.Write([]byte(cmd))
		_ = w.Close()
		cmd = buf.String()
	}
	cmd = strings.Join(strings.Fields(cmd), " ")
	return truncateRunes(cmd, MaxCommandLen)
}

func truncateRunes(s string, max int) string {
	if max <= 0 || utf8.RuneCountInString(s) <= max {
		return s
	}
	r := []rune(s)
	if max <= 3 {
		return string(r[:max])
	}
	return string(r[:max-3]) + "..."
}

// Append appends ev as a single JSON line to path (dir 0700, file 0600).
func Append(path string, ev Event) error {
	if path == "" {
		return nil
	}
	if ev.Time.IsZero() {
		ev.Time = time.Now().UTC()
	}
	ev.Command = truncateRunes(strings.Join(strings.Fields(ev.Command), " "), MaxCommandLen)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	b, err := json.Marshal(ev)
	if err != nil {
		_ = f.Close()
		return err
	}
	b = append(b, '\n')
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// Read returns the last limit events from path, optionally filtered by agent.
// A non-positive limit returns all matching events.
func Read(path, agent string, limit int) ([]Event, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var out []Event
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var ev Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			return nil, err
		}
		if agent != "" && ev.Agent != agent {
			continue
		}
		out = append(out, ev)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out, nil
}
