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
	Keys    []string // NAME or VAR=NAME
	EnvFile string   // KEY=value lines, keytwig://NAME resolved
	All     bool     // every secret (aliases included)
	Project bool     // the secrets linked to the project folder containing Cwd
	Cwd     string
	Agent   string
}

// Resolution is what will be injected: env var → value, plus the names used.
type Resolution struct {
	Env        map[string]string
	Injected   []string // env var names, sorted
	ProjectDir string
	Denied     []string // secret names refused by policy (only reported with All/Project)
}

// Resolve applies Spec against the vault and the agent policy.
func Resolve(v *vault.Vault, cfg config.Config, s Spec) (*Resolution, error) {
	r := &Resolution{Env: map[string]string{}}
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
	for k := range r.Env {
		r.Injected = append(r.Injected, k)
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
	cmd.Env = os.Environ()
	for _, k := range res.Injected {
		cmd.Env = append(cmd.Env, k+"="+res.Env[k])
	}
	var outW, errW *redact.Writer
	if e.NoRedact {
		cmd.Stdout, cmd.Stderr = e.Stdout, e.Stderr
	} else {
		secrets := v.Values()
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
