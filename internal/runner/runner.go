// Package runner resolves which secrets a command gets and runs it with
// its output masked. Shared by the CLI and the MCP server.
package runner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"

	"github.com/keytwig/keytwig/internal/config"
	"github.com/keytwig/keytwig/internal/dotenv"
	"github.com/keytwig/keytwig/internal/redact"
	"github.com/keytwig/keytwig/internal/vault"
)

const RefPrefix = "keytwig://"

// Spec says which secrets to inject.
type Spec struct {
	Keys     []string // NAME or VAR=NAME
	FileKeys []string // NAME or VAR=NAME written to ephemeral 0600 files
	EnvFile  string   // KEY=value lines, keytwig://NAME resolved
	All      bool     // every secret (aliases included)
	Project  bool     // the secrets linked to the project folder containing Cwd
	Cwd      string
	Agent    string
}

// FileMount describes one file-backed secret to materialize during Run.
type FileMount struct {
	SecretName string
	Filename   string
	Content    string
}

// Resolution is what will be injected: env var → value, plus the names used.
type Resolution struct {
	Env        map[string]string
	Files      map[string]FileMount
	Injected   []string // env var names, sorted
	ProjectDir string
	Denied     []string // secret names refused by policy (only reported with All/Project)
}

// Resolve applies Spec against the vault and the agent policy.
func Resolve(v *vault.Vault, cfg config.Config, s Spec) (*Resolution, error) {
	r := &Resolution{Env: map[string]string{}, Files: map[string]FileMount{}}
	get := func(name string, strict bool) (string, bool, error) {
		sec, ok := v.Get(name)
		if !ok {
			return "", false, fmt.Errorf("secret %s not found (see `keytwig ls`)", name)
		}
		canon := v.Canonical(name)
		if !cfg.Allowed(s.Agent, append([]string{canon}, sec.Aliases...)...) {
			if strict {
				return "", false, fmt.Errorf("secret %s is not allowed for agent %q (config.toml [agents])", name, s.Agent)
			}
			r.Denied = append(r.Denied, name)
			return "", false, nil
		}
		return sec.Value, true, nil
	}
	if s.All {
		names := make([]string, 0)
		for k := range v.Env() {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			if val, ok, _ := get(k, false); ok {
				r.Env[k] = val
			}
		}
	}
	if s.Project {
		dir, links := v.Project(s.Cwd)
		if dir == "" {
			return nil, fmt.Errorf("no project linked to %s (import its .env first)", s.Cwd)
		}
		r.ProjectDir = dir
		for env, name := range links {
			val, ok, err := get(name, false)
			if err != nil {
				return nil, err
			}
			if ok {
				r.Env[env] = val
			}
		}
	}
	if s.EnvFile != "" {
		f, err := os.Open(s.EnvFile)
		if err != nil {
			return nil, err
		}
		entries, err := dotenv.Parse(f)
		f.Close()
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if strings.HasPrefix(e.Value, RefPrefix) {
				val, _, err := get(strings.TrimPrefix(e.Value, RefPrefix), true)
				if err != nil {
					return nil, err
				}
				r.Env[e.Name] = val
			} else {
				r.Env[e.Name] = e.Value
			}
		}
	}
	for _, spec := range s.Keys {
		spec = strings.TrimSpace(spec)
		if spec == "" {
			continue
		}
		varName, name := spec, spec
		if i := strings.IndexByte(spec, '='); i > 0 {
			varName, name = spec[:i], spec[i+1:]
		}
		val, _, err := get(name, true)
		if err != nil {
			return nil, err
		}
		r.Env[varName] = val
	}
	for _, spec := range s.FileKeys {
		spec = strings.TrimSpace(spec)
		if spec == "" {
			continue
		}
		varName, name := spec, spec
		if i := strings.IndexByte(spec, '='); i > 0 {
			varName, name = spec[:i], spec[i+1:]
		}
		val, _, err := get(name, true)
		if err != nil {
			return nil, err
		}
		sec, _ := v.Get(name)
		r.Files[varName] = FileMount{
			SecretName: v.Canonical(name),
			Filename:   sec.Filename,
			Content:    val,
		}
	}
	seenInj := map[string]bool{}
	for k := range r.Env {
		seenInj[k] = true
		r.Injected = append(r.Injected, k)
	}
	for k := range r.Files {
		if !seenInj[k] {
			seenInj[k] = true
			r.Injected = append(r.Injected, k)
		}
	}
	sort.Strings(r.Injected)
	return r, nil
}

// Exec describes the process to run.
type Exec struct {
	Argv     []string // program and args; or
	Shell    string   // a shell command line (sh -c / cmd /C)
	Dir      string
	Stdin    io.Reader
	Stdout   io.Writer
	Stderr   io.Writer
	NoRedact bool
	// ForwardSignals relays Ctrl-C etc. to the child (CLI use).
	ForwardSignals bool
}

// RunResult reports the child's exit code and how many secret redactions occurred.
type RunResult struct {
	ExitCode   int
	Redactions int
}

// Run executes with res.Env added and every vault value masked in output.
// Returns the child's exit code and redaction count.
func Run(ctx context.Context, v *vault.Vault, res *Resolution, e Exec) (RunResult, error) {
	var cmd *exec.Cmd
	switch {
	case e.Shell != "":
		if runtime.GOOS == "windows" {
			cmd = exec.CommandContext(ctx, "cmd", "/C", e.Shell)
		} else {
			cmd = exec.CommandContext(ctx, "sh", "-c", e.Shell)
		}
	case len(e.Argv) > 0:
		cmd = exec.CommandContext(ctx, e.Argv[0], e.Argv[1:]...)
	default:
		return RunResult{ExitCode: 1}, errors.New("no command")
	}
	configureCmd(cmd)
	cmd.Dir = e.Dir
	cmd.Stdin = e.Stdin

	var cleanupFiles func()
	filePaths := map[string]string{}
	if len(res.Files) > 0 {
		var err error
		filePaths, cleanupFiles, err = mountFileSecrets(res.Files)
		if err != nil {
			return RunResult{ExitCode: 1}, err
		}
		defer cleanupFiles()
	}

	cmd.Env = os.Environ()
	for _, k := range res.Injected {
		if p, ok := filePaths[k]; ok {
			cmd.Env = append(cmd.Env, k+"="+p)
			continue
		}
		if val, ok := res.Env[k]; ok {
			cmd.Env = append(cmd.Env, k+"="+val)
		}
	}
	var outW, errW *redact.Writer
	if e.NoRedact {
		cmd.Stdout, cmd.Stderr = e.Stdout, e.Stderr
	} else {
		secrets := redactSecrets(v, res)
		outW, errW = redact.New(e.Stdout, secrets), redact.New(e.Stderr, secrets)
		cmd.Stdout, cmd.Stderr = outW, errW
	}
	if err := cmd.Start(); err != nil {
		return RunResult{ExitCode: 127}, err
	}
	var sigs chan os.Signal
	if e.ForwardSignals {
		sigs = make(chan os.Signal, 4)
		signal.Notify(sigs, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
		go func() {
			for s := range sigs {
				signalProcess(cmd, s)
			}
		}()
	}
	werr := cmd.Wait()
	if sigs != nil {
		signal.Stop(sigs)
		close(sigs)
	}
	redactions := 0
	if outW != nil {
		_ = outW.Close()
		_ = errW.Close()
		redactions = outW.Count() + errW.Count()
	}
	if werr != nil {
		var ee *exec.ExitError
		if errors.As(werr, &ee) {
			code := ee.ExitCode()
			if code < 0 {
				code = 1
			}
			return RunResult{ExitCode: code, Redactions: redactions}, nil
		}
		return RunResult{ExitCode: 1, Redactions: redactions}, werr
	}
	return RunResult{ExitCode: 0, Redactions: redactions}, nil
}

func redactSecrets(v *vault.Vault, res *Resolution) map[string]string {
	out := v.Values()
	if res == nil || len(res.Env) == 0 {
		return out
	}
	redact.AddBasicAuthPairs(out, res.Env)
	return out
}

func mountBaseDir() string {
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
		if st, err := os.Stat(d); err == nil && st.IsDir() {
			return d
		}
	}
	return os.TempDir()
}

func sanitizeMountFilename(fm FileMount) string {
	name := strings.TrimSpace(fm.Filename)
	if name != "" {
		name = filepath.Base(name)
	}
	if name == "" || name == "." || name == ".." || name == "/" || name == `\` {
		name = fm.SecretName + ".secret"
	}
	return name
}

func mountFileSecrets(files map[string]FileMount) (map[string]string, func(), error) {
	root, err := os.MkdirTemp(mountBaseDir(), "keytwig-mount-*")
	if err != nil && mountBaseDir() != os.TempDir() {
		root, err = os.MkdirTemp(os.TempDir(), "keytwig-mount-*")
	}
	if err != nil {
		return nil, nil, err
	}
	_ = os.Chmod(root, 0o700)

	var created []string
	cleanup := func() {
		for _, p := range created {
			wipeFile(p)
		}
		_ = os.RemoveAll(root)
	}

	keys := make([]string, 0, len(files))
	for k := range files {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	paths := make(map[string]string, len(keys))
	for i, k := range keys {
		fm := files[k]
		sub := filepath.Join(root, fmt.Sprintf("f%d", i))
		if err := os.MkdirAll(sub, 0o700); err != nil {
			cleanup()
			return nil, nil, err
		}
		fp := filepath.Join(sub, sanitizeMountFilename(fm))
		f, err := os.OpenFile(fp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			cleanup()
			return nil, nil, err
		}
		_, werr := f.WriteString(fm.Content)
		cerr := f.Close()
		if werr != nil {
			cleanup()
			return nil, nil, werr
		}
		if cerr != nil {
			cleanup()
			return nil, nil, cerr
		}
		created = append(created, fp)
		paths[k] = fp
	}
	return paths, cleanup, nil
}

func wipeFile(path string) {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return
	}
	if st, err := f.Stat(); err == nil && st.Size() > 0 {
		zeros := make([]byte, st.Size())
		_, _ = f.WriteAt(zeros, 0)
		_ = f.Sync()
	}
	_ = f.Close()
}
