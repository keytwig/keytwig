// Package mcp serves keytwig to agent harnesses over stdio (JSON-RPC 2.0).
// No tool ever returns a secret value; there is deliberately no "get" or
// "set" tool, so values never pass through the model.
package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/keytwig/keytwig/internal/config"
	"github.com/keytwig/keytwig/internal/dotenv"
	"github.com/keytwig/keytwig/internal/runner"
	"github.com/keytwig/keytwig/internal/vault"
)

type Server struct {
	Paths   vault.Paths
	Agent   string
	Version string
	Cwd     string
}

const Instructions = `keytwig holds this user's API keys, tokens and passwords. You never see values.
- To run something that needs a secret, call keytwig_run: the secrets are injected as environment variables into the command and masked in its output as ‹keytwig:NAME›. Refer to them in the command as $VAR (e.g. curl -H "Authorization: Bearer $STRIPE_SECRET_KEY").
- Inside a project folder, project=true injects that project's secrets under their usual names (DATABASE_URL, ...).
- keytwig_list shows which secrets exist (names only). Do not ask the user to paste secrets in chat and never write values into files, notes or messages.
- If a secret is missing, ask the user to add it themselves with ` + "`keytwig set NAME`" + ` in a terminal, or import an existing .env with keytwig_import.`

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (s *Server) ServeStdio(ctx context.Context, r io.Reader, w io.Writer) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	enc := json.NewEncoder(w)
	var mu sync.Mutex
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var req rpcRequest
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			mu.Lock()
			enc.Encode(rpcResponse{JSONRPC: "2.0", Error: &rpcError{Code: -32700, Message: "parse error"}})
			mu.Unlock()
			continue
		}
		if len(req.ID) == 0 || string(req.ID) == "null" {
			continue // notification
		}
		resp := s.handle(ctx, req)
		mu.Lock()
		err := enc.Encode(resp)
		mu.Unlock()
		if err != nil {
			return err
		}
	}
	return sc.Err()
}

func (s *Server) handle(ctx context.Context, req rpcRequest) rpcResponse {
	resp := rpcResponse{JSONRPC: "2.0", ID: req.ID}
	switch req.Method {
	case "initialize":
		resp.Result = map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "keytwig", "version": s.Version},
			"instructions":    Instructions,
		}
	case "ping":
		resp.Result = map[string]any{}
	case "tools/list":
		resp.Result = map[string]any{"tools": tools()}
	case "tools/call":
		var p struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			resp.Error = &rpcError{Code: -32602, Message: "invalid params"}
			return resp
		}
		text, isErr := s.call(ctx, p.Name, p.Arguments)
		resp.Result = map[string]any{
			"content": []map[string]any{{"type": "text", "text": text}},
			"isError": isErr,
		}
	default:
		resp.Error = &rpcError{Code: -32601, Message: "method not found: " + req.Method}
	}
	return resp
}

func obj(props map[string]any, required ...string) map[string]any {
	o := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		o["required"] = required
	}
	return o
}

func tools() []map[string]any {
	str := func(d string) map[string]any { return map[string]any{"type": "string", "description": d} }
	return []map[string]any{
		{
			"name":        "keytwig_list",
			"description": "List secrets available to you (names, aliases, linked projects). Never returns values.",
			"inputSchema": obj(map[string]any{"cwd": str("optional folder: also show which env vars its project gets")}),
		},
		{
			"name":        "keytwig_run",
			"description": "Run a shell command with secrets injected as environment variables. Every stored secret is masked in the output as ‹keytwig:NAME›. Use $VAR in the command to reference them.",
			"inputSchema": obj(map[string]any{
				"command":     str("shell command line (sh -c on Unix, cmd /C on Windows)"),
				"keys":        map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "secrets to inject: NAME or VAR=NAME"},
				"project":     map[string]any{"type": "boolean", "description": "inject the secrets of the project containing cwd, under their usual env names"},
				"cwd":         str("working directory (default: the server's)"),
				"timeout_sec": map[string]any{"type": "integer", "description": "default 120, max 1800"},
			}, "command"),
		},
		{
			"name":        "keytwig_import",
			"description": "Import secrets from a .env file into keytwig (values move file→vault without passing through you). Returns names and status only.",
			"inputSchema": obj(map[string]any{"path": str("path of the .env file")}, "path"),
		},
		{
			"name":        "keytwig_status",
			"description": "How keytwig is protected, whether it is unlocked, how many secrets it holds.",
			"inputSchema": obj(map[string]any{}),
		},
	}
}

func (s *Server) cfg() config.Config {
	c, _ := config.Load(s.Paths.Config)
	return c
}

func (s *Server) call(ctx context.Context, name string, args map[string]any) (string, bool) {
	str := func(k string) string { v, _ := args[k].(string); return v }
	switch name {
	case "keytwig_status":
		st, err := vault.GetStatus(s.Paths)
		if err != nil {
			return err.Error(), true
		}
		out := map[string]any{"mode": st.Mode, "locked": st.Locked, "agent": s.Agent}
		if st.Warning != "" {
			out["warning"] = st.Warning
		}
		if v, err := vault.Open(s.Paths); err == nil {
			out["values"], out["names"] = len(v.Names()), len(v.Env())
		}
		b, _ := json.MarshalIndent(out, "", "  ")
		return string(b), false

	case "keytwig_list":
		v, err := vault.Open(s.Paths)
		if err != nil {
			return err.Error(), true
		}
		cfg := s.cfg()
		type item struct {
			Name    string   `json:"name"`
			Aliases []string `json:"aliases,omitempty"`
		}
		var items []item
		for _, n := range v.Names() {
			sec, _ := v.Get(n)
			if !cfg.Allowed(s.Agent, append([]string{n}, sec.Aliases...)...) {
				continue
			}
			items = append(items, item{n, sec.Aliases})
		}
		out := map[string]any{"secrets": items}
		if cwd := s.resolveCwd(str("cwd")); cwd != "" {
			if dir, links := v.Project(cwd); dir != "" {
				envs := make([]string, 0, len(links))
				for e := range links {
					envs = append(envs, e)
				}
				sort.Strings(envs)
				out["project"] = map[string]any{"dir": dir, "env": envs}
			}
		}
		b, _ := json.MarshalIndent(out, "", "  ")
		return string(b), false

	case "keytwig_import":
		path := s.resolvePath(str("path"))
		if path == "" {
			return "path is required", true
		}
		return s.importFile(path)

	case "keytwig_run":
		command := str("command")
		if strings.TrimSpace(command) == "" {
			return "command is required", true
		}
		v, err := vault.Open(s.Paths)
		if err != nil {
			return err.Error(), true
		}
		var keys []string
		if arr, ok := args["keys"].([]any); ok {
			for _, k := range arr {
				if ks, ok := k.(string); ok {
					keys = append(keys, ks)
				}
			}
		}
		project, _ := args["project"].(bool)
		cwd := s.resolveCwd(str("cwd"))
		res, err := runner.Resolve(v, s.cfg(), runner.Spec{Keys: keys, Project: project, Cwd: cwd, Agent: s.Agent})
		if err != nil {
			return err.Error(), true
		}
		timeout := 120 * time.Second
		if t, ok := args["timeout_sec"].(float64); ok && t > 0 {
			timeout = time.Duration(min(t, 1800)) * time.Second
		}
		cctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		out := &capped{max: 64 * 1024}
		code, err := runner.Run(cctx, v, res, runner.Exec{Shell: command, Dir: cwd, Stdin: bytes.NewReader(nil), Stdout: out, Stderr: out})
		var b strings.Builder
		fmt.Fprintf(&b, "exit code: %d\n", code)
		if len(res.Injected) > 0 {
			fmt.Fprintf(&b, "injected: %s\n", strings.Join(res.Injected, ", "))
		}
		if len(res.Denied) > 0 {
			fmt.Fprintf(&b, "not allowed for this agent: %s\n", strings.Join(res.Denied, ", "))
		}
		if cctx.Err() == context.DeadlineExceeded {
			fmt.Fprintf(&b, "timed out after %s\n", timeout)
		}
		if err != nil {
			fmt.Fprintf(&b, "error: %v\n", err)
		}
		b.WriteString("--- output ---\n")
		b.WriteString(out.String())
		return b.String(), code != 0 || err != nil
	}
	return "unknown tool: " + name, true
}

func (s *Server) resolveCwd(c string) string {
	if c == "" {
		return s.Cwd
	}
	return s.resolvePath(c)
}

func (s *Server) resolvePath(p string) string {
	if p == "" {
		return ""
	}
	if strings.HasPrefix(p, "~/") {
		if h, err := os.UserHomeDir(); err == nil {
			p = filepath.Join(h, p[2:])
		}
	}
	if !filepath.IsAbs(p) {
		p = filepath.Join(s.Cwd, p)
	}
	return filepath.Clean(p)
}

// importFile mirrors `keytwig import FILE` (secret-looking names only).
func (s *Server) importFile(path string) (string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return err.Error(), true
	}
	entries, err := dotenv.Parse(f)
	f.Close()
	if err != nil {
		return err.Error(), true
	}
	unlock, err := vault.Lock(s.Paths)
	if err != nil {
		return err.Error(), true
	}
	defer unlock()
	v, err := vault.Open(s.Paths)
	if err != nil {
		return err.Error(), true
	}
	var lines []string
	changed := false
	dir := filepath.Dir(path)
	for _, e := range entries {
		if !dotenv.LooksSecret(e.Name) || e.Value == "" {
			continue
		}
		if sec, ok := v.Get(e.Name); ok && sec.Value != e.Value {
			lines = append(lines, e.Name+": conflict, a different value is already stored (user can resolve with the keytwig CLI)")
			continue
		}
		st := v.Set(e.Name, e.Value, path)
		if v.Link(dir, e.Name, e.Name) || st != "unchanged" {
			changed = true
		}
		lines = append(lines, e.Name+": "+st)
	}
	if changed {
		if err := v.Save(); err != nil {
			return err.Error(), true
		}
	}
	if len(lines) == 0 {
		return "no secret-looking entries found", false
	}
	return strings.Join(lines, "\n"), false
}

// capped keeps the first max bytes of output.
type capped struct {
	mu        sync.Mutex
	buf       bytes.Buffer
	max       int
	truncated bool
}

func (c *capped) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if room := c.max - c.buf.Len(); room > 0 {
		if len(p) > room {
			c.buf.Write(p[:room])
			c.truncated = true
		} else {
			c.buf.Write(p)
		}
	} else if len(p) > 0 {
		c.truncated = true
	}
	return len(p), nil
}

func (c *capped) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.truncated {
		return c.buf.String() + "\n[output truncated]"
	}
	return c.buf.String()
}
