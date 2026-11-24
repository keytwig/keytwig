// Package scan finds credentials spread across a machine. It reads values
// only in memory to compare them (via hashes) and never returns them.
package scan

import (
	"crypto/sha256"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"

	"github.com/keytwig/keytwig/internal/dotenv"
)

// File classes. Only "project" files are proposed for import: harness and
// app files belong to the tool that wrote them, backups are copies.
const (
	ClassHarness = "harness"
	ClassBackup  = "backup"
	ClassApp     = "app"
	ClassProject = "project"
)

type EnvFile struct {
	Path        string   `json:"path"`
	Class       string   `json:"class"`
	Mode        string   `json:"mode"`
	LooseMode   bool     `json:"loose_mode"`
	SecretNames []string `json:"secret_names"`
	OtherKeys   int      `json:"other_keys"`
	Refs        int      `json:"keytwig_refs"`
}

type ToolFile struct {
	Path      string `json:"path"`
	Kind      string `json:"kind"`
	Mode      string `json:"mode"`
	LooseMode bool   `json:"loose_mode"`
}

type NameUse struct {
	Name           string   `json:"name"`
	Files          []string `json:"files"`
	DistinctValues int      `json:"distinct_values"`
	InVault        string   `json:"in_vault"` // "", "same", "partial", "different"
}

// ValueGroup: one value stored under several names (dedup candidates).
type ValueGroup struct {
	Names    []string `json:"names"`
	Copies   int      `json:"copies"`
	InVault  bool     `json:"in_vault"`
	Projects bool     `json:"in_project_files"`
}

type Report struct {
	Roots        []string     `json:"roots"`
	EnvFiles     []EnvFile    `json:"env_files"`
	ToolFiles    []ToolFile   `json:"tool_files"`
	Names        []NameUse    `json:"names"`
	SameValue    []ValueGroup `json:"same_value"`
	Entries      int          `json:"secret_entries"`
	UniqueValues int          `json:"unique_values"`
	// unique values that sit only in project files and are not in the vault yet
	ToImport int `json:"to_import"`
}

// Options configure a scan.
type Options struct {
	Harness []string // absolute folders owned by harnesses
	Ignore  []string // absolute folders to skip
	Home    string
}

// Classify assigns a class to an env file path.
func Classify(path string, o Options) string {
	path = filepath.Clean(path)
	for _, h := range o.Harness {
		if pathHasPrefix(path, filepath.Clean(h)) {
			return ClassHarness
		}
	}
	if backupRe.MatchString(path) {
		return ClassBackup
	}
	if o.Home != "" {
		home := filepath.Clean(o.Home)
		rel, err := filepath.Rel(home, path)
		if err != nil && runtime.GOOS == "windows" && pathHasPrefix(path, home) {
			rel = strings.TrimPrefix(path[len(home):], string(filepath.Separator))
			err = nil
		}
		if err == nil && rel != "." && strings.HasPrefix(rel, ".") && !strings.HasPrefix(rel, "..") {
			return ClassApp
		}
	}
	return ClassProject
}

func pathHasPrefix(path, dir string) bool {
	if runtime.GOOS == "windows" {
		if strings.EqualFold(path, dir) {
			return true
		}
		prefix := dir
		if !strings.HasSuffix(prefix, string(filepath.Separator)) {
			prefix += string(filepath.Separator)
		}
		return len(path) >= len(prefix) && strings.EqualFold(path[:len(prefix)], prefix)
	}
	if path == dir {
		return true
	}
	prefix := dir
	if !strings.HasSuffix(prefix, string(filepath.Separator)) {
		prefix += string(filepath.Separator)
	}
	return strings.HasPrefix(path, prefix)
}

var pruneDirs = map[string]bool{
	"node_modules": true, ".git": true, ".cache": true, ".next": true, ".venv": true,
	"venv": true, "site-packages": true, "__pycache__": true, ".npm": true, "Trash": true,
	"vendor": true, "dist": true, "target": true,
}

var prunePaths = []string{
	"/.local/share/docker", "/.local/share/containers", "/go/pkg/mod", "/.cargo/registry",
	"/.rustup", "/.local/go", "/.mozilla", "/.config/google-chrome", "/.config/chromium",
	"/.config/BraveSoftware", "/snap", "/.local/share/Steam", "/.steam", "/.local/opt",
	"/.hermes/cache", "/.local/share/Trash",
}

var exampleRe = regexp.MustCompile(`(?i)(example|sample|esempio|template|dist|\.lock)$`)
var backupRe = regexp.MustCompile(`(?i)(bak|backup|snapshot|\.moved-|\.orig|\.old|pre-)`)

// IsEnvName reports whether a file basename looks like an env file (excluding examples/templates/locks).
func IsEnvName(base string) bool {
	if base == "go.env" || exampleRe.MatchString(base) {
		return false
	}
	return base == ".env" || strings.HasPrefix(base, ".env.") || strings.HasSuffix(base, ".env")
}

// tool credential files, matched on the path suffix
var toolFiles = []struct{ suffix, kind string }{
	{"/.claude/.credentials.json", "claude login"},
	{"/.codex/auth.json", "codex login"},
	{"/.grok/auth.json", "grok login"},
	{"/.hermes/auth.json", "hermes login"},
	{"/.pi/agent/auth.json", "pi login"},
	{"/.config/gh/hosts.yml", "github cli"},
	{"/.docker/config.json", "docker registry"},
	{"/.netrc", "netrc"},
	{"/.npmrc", "npm token"},
	{"/.pypirc", "pypi token"},
	{"/.git-credentials", "git credentials"},
	{"/.aws/credentials", "aws"},
	{"/.kube/config", "kubernetes"},
	{"/.config/gcloud/application_default_credentials.json", "gcloud"},
	{"/com.vercel.cli/auth.json", "vercel cli"},
	{"/secure-token-storage.json", "token storage"},
	{"/acp_token.json", "acp token"},
}

var keyFileRe = regexp.MustCompile(`(?i)(\.jks|\.p12|\.pfx|\.keystore|^id_(rsa|ed25519|ecdsa|dsa)|_ed25519|_rsa|key\.pem|\.token)$`)

// ClassifyTool reports the credential kind if path matches a well-known tool credential or key file.
func ClassifyTool(path string) string {
	slash := filepath.ToSlash(path)
	for _, t := range toolFiles {
		if strings.HasSuffix(slash, t.suffix) {
			if t.kind == "npm token" && !fileContains(path, "_auth") {
				return ""
			}
			return t.kind
		}
	}
	base := filepath.Base(path)
	if base == "debug.keystore" { // Android debug keystores are public by design
		return ""
	}
	if keyFileRe.MatchString(base) && !strings.HasSuffix(base, ".pub") {
		return "key file"
	}
	return ""
}

type valueRef struct {
	file  string
	class string
	hash  [32]byte
}

// Run walks roots. vaultHashes maps name→hash of the value in keytwig (may be nil).
func Run(roots []string, vaultHashes map[string][32]byte, o Options) (*Report, error) {
	rep := &Report{Roots: roots}
	uses := map[string][]valueRef{}
	for _, root := range roots {
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				if d != nil && d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if d.IsDir() {
				if path != root && pruneDirs[d.Name()] {
					return fs.SkipDir
				}
				for _, ig := range o.Ignore {
					if path == ig {
						return fs.SkipDir
					}
				}
				slash := filepath.ToSlash(path)
				for _, p := range prunePaths {
					if strings.HasSuffix(slash, p) {
						return fs.SkipDir
					}
				}
				return nil
			}
			if d.Type()&fs.ModeSymlink != 0 || !d.Type().IsRegular() {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			mode := info.Mode().Perm()
			// Unix permission bits mean nothing on Windows (ACLs).
			loose := runtime.GOOS != "windows" && mode&0o044 != 0
			if IsEnvName(d.Name()) {
				ef, refs := readEnv(path)
				if ef == nil {
					return nil
				}
				ef.Mode, ef.LooseMode = mode.String(), loose
				ef.Class = Classify(path, o)
				if len(ef.SecretNames) == 0 && ef.OtherKeys == 0 && ef.Refs == 0 {
					return nil
				}
				rep.EnvFiles = append(rep.EnvFiles, *ef)
				for name, h := range refs {
					uses[name] = append(uses[name], valueRef{file: path, class: ef.Class, hash: h})
				}
				return nil
			}
			if kind := ClassifyTool(path); kind != "" {
				rep.ToolFiles = append(rep.ToolFiles, ToolFile{Path: path, Kind: kind, Mode: mode.String(), LooseMode: loose})
			}
			return nil
		})
	}
	inVault := map[[32]byte]bool{}
	for _, h := range vaultHashes {
		inVault[h] = true
	}
	type hv struct {
		names   map[string]bool
		copies  int
		project bool
	}
	byValue := map[[32]byte]*hv{}
	for name, refs := range uses {
		for _, r := range refs {
			rep.Entries++
			g := byValue[r.hash]
			if g == nil {
				g = &hv{names: map[string]bool{}}
				byValue[r.hash] = g
			}
			g.names[name] = true
			g.copies++
			if r.class == ClassProject {
				g.project = true
			}
		}
	}
	rep.UniqueValues = len(byValue)
	for h, g := range byValue {
		if g.project && !inVault[h] {
			rep.ToImport++
		}
		if len(g.names) < 2 {
			continue
		}
		vg := ValueGroup{Copies: g.copies, InVault: inVault[h], Projects: g.project}
		for n := range g.names {
			vg.Names = append(vg.Names, n)
		}
		sort.Strings(vg.Names)
		rep.SameValue = append(rep.SameValue, vg)
	}
	sort.Slice(rep.SameValue, func(i, j int) bool {
		return strings.Join(rep.SameValue[i].Names, ",") < strings.Join(rep.SameValue[j].Names, ",")
	})
	for name, refs := range uses {
		distinct := map[[32]byte]bool{}
		nu := NameUse{Name: name}
		for _, r := range refs {
			distinct[r.hash] = true
			nu.Files = append(nu.Files, r.file)
		}
		nu.DistinctValues = len(distinct)
		if vh, ok := vaultHashes[name]; ok {
			switch {
			case distinct[vh] && len(distinct) == 1:
				nu.InVault = "same"
			case distinct[vh]:
				nu.InVault = "partial"
			default:
				nu.InVault = "different"
			}
		}
		sort.Strings(nu.Files)
		rep.Names = append(rep.Names, nu)
	}
	sort.Slice(rep.Names, func(i, j int) bool {
		if len(rep.Names[i].Files) != len(rep.Names[j].Files) {
			return len(rep.Names[i].Files) > len(rep.Names[j].Files)
		}
		return rep.Names[i].Name < rep.Names[j].Name
	})
	sort.Slice(rep.EnvFiles, func(i, j int) bool { return rep.EnvFiles[i].Path < rep.EnvFiles[j].Path })
	sort.Slice(rep.ToolFiles, func(i, j int) bool { return rep.ToolFiles[i].Path < rep.ToolFiles[j].Path })
	return rep, nil
}

func readEnv(path string) (*EnvFile, map[string][32]byte) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil
	}
	defer f.Close()
	entries, err := dotenv.Parse(f)
	if err != nil {
		return nil, nil
	}
	ef := &EnvFile{Path: path}
	refs := map[string][32]byte{}
	for _, e := range entries {
		if strings.HasPrefix(e.Value, "keytwig://") {
			ef.Refs++
			continue
		}
		if dotenv.LooksSecret(e.Name) && e.Value != "" {
			ef.SecretNames = append(ef.SecretNames, e.Name)
			refs[e.Name] = Hash(e.Value)
		} else {
			ef.OtherKeys++
		}
	}
	sort.Strings(ef.SecretNames)
	return ef, refs
}

// fileContains checks a marker (e.g. "_auth") in small files; content is never returned.
func fileContains(path, marker string) bool {
	b, err := os.ReadFile(path)
	if err != nil || len(b) > 1<<20 {
		return false
	}
	return strings.Contains(string(b), marker)
}

// Hash is used only to compare values in memory; never printed.
func Hash(v string) [32]byte { return sha256.Sum256([]byte(v)) }
