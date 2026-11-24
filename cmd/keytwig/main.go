package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/keytwig/keytwig/internal/config"
	"github.com/keytwig/keytwig/internal/dotenv"
	"github.com/keytwig/keytwig/internal/envfile"
	"github.com/keytwig/keytwig/internal/install"
	kmcp "github.com/keytwig/keytwig/internal/mcp"
	"github.com/keytwig/keytwig/internal/runner"
	"github.com/keytwig/keytwig/internal/scan"
	"github.com/keytwig/keytwig/internal/vault"
)

var version = "dev"

var nameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func main() {
	root := &cobra.Command{
		Use:           "keytwig",
		Short:         "One local vault for every agent's secrets; values never reach the model",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(initCmd(), statusCmd(), protectCmd(), unlockCmd(), lockCmd(), identityCmd(),
		scanCmd(), importCmd(), setCmd(), lsCmd(), rmCmd(), runCmd(),
		rewriteCmd(), restoreCmd(), mcpCmd(), installCmd())
	if err := root.Execute(); err != nil {
		var ee *exitError
		if errors.As(err, &ee) {
			os.Exit(ee.code)
		}
		fmt.Fprintln(os.Stderr, "keytwig:", err)
		os.Exit(1)
	}
}

type exitError struct{ code int }

func (e *exitError) Error() string { return fmt.Sprintf("exit %d", e.code) }

func paths() vault.Paths {
	p, err := vault.DefaultPaths()
	if err != nil {
		fmt.Fprintln(os.Stderr, "keytwig:", err)
		os.Exit(1)
	}
	return p
}

// mutate opens the vault under lock, applies fn, and saves if fn says so.
func mutate(fn func(v *vault.Vault) (bool, error)) error {
	p := paths()
	unlock, err := vault.Lock(p)
	if err != nil {
		return err
	}
	defer unlock()
	v, err := vault.Open(p)
	if err != nil {
		return err
	}
	changed, err := fn(v)
	if err != nil {
		return err
	}
	if changed {
		return v.Save()
	}
	return nil
}

// readPassphrase prompts on the terminal (never echoes), or reads one line
// from stdin when fromStdin is set (automation, tests).
func readPassphrase(prompt string, confirm, fromStdin bool) ([]byte, error) {
	if fromStdin {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && err != io.EOF {
			return nil, err
		}
		return []byte(strings.TrimRight(line, "\r\n")), nil
	}
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return nil, errors.New("a passphrase must be typed in a terminal (or use --passphrase-stdin)")
	}
	fmt.Fprint(os.Stderr, prompt)
	a, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	if confirm {
		fmt.Fprint(os.Stderr, "repeat: ")
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, err
		}
		if string(a) != string(b) {
			return nil, errors.New("passphrases do not match")
		}
	}
	return a, nil
}

var machineFlag bool

func modeFlags(c *cobra.Command, pass, kr, file *bool, stdin *bool) {
	c.Flags().BoolVar(&machineFlag, "machine", false, "bind the identity to this machine, no prompts (TPM on Linux, Keychain on macOS, DPAPI on Windows) — default for init")
	c.Flags().BoolVar(pass, "passphrase", false, "protect the identity with a passphrase; `keytwig unlock` once per boot")
	c.Flags().BoolVar(kr, "keyring", false, "keep the identity in the system keyring (protected by your login password)")
	if file != nil {
		c.Flags().BoolVar(file, "file", false, "plaintext identity file (no protection at rest)")
	}
	c.Flags().BoolVar(stdin, "passphrase-stdin", false, "read the passphrase from stdin instead of the terminal")
}

func pickMode(pass, kr, file bool) (string, error) {
	n := 0
	mode := vault.ModeMachine
	if machineFlag {
		n++
	}
	if pass {
		n++
		mode = vault.ModePassphrase
	}
	if kr {
		n++
		mode = vault.ModeKeyring
	}
	if file {
		n++
		mode = vault.ModeFile
	}
	if n > 1 {
		return "", errors.New("choose only one of --machine, --passphrase, --keyring, --file")
	}
	return mode, nil
}

func initCmd() *cobra.Command {
	var pass, kr, file, stdin bool
	c := &cobra.Command{
		Use:   "init",
		Short: "Create the identity and an empty encrypted vault",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			mode, err := pickMode(pass, kr, file)
			if err != nil {
				return err
			}
			var pp []byte
			if mode == vault.ModePassphrase {
				if pp, err = readPassphrase("new passphrase: ", true, stdin); err != nil {
					return err
				}
			}
			p := paths()
			created, err := vault.Init(p, mode, pp)
			if err != nil {
				return err
			}
			if !created {
				fmt.Println("already initialized")
			} else {
				fmt.Println("initialized, identity mode:", mode)
			}
			return printStatus(p)
		},
	}
	modeFlags(c, &pass, &kr, &file, &stdin)
	return c
}

func printStatus(p vault.Paths) error {
	st, err := vault.GetStatus(p)
	if err != nil {
		return err
	}
	state := "unlocked"
	if st.Locked {
		state = "locked (run `keytwig unlock`)"
	}
	fmt.Println("  identity:", st.Mode+",", state)
	fmt.Println("  identity file:", shortPath(st.Identity))
	fmt.Println("  vault:", shortPath(st.Vault))
	if !st.Locked {
		if v, err := vault.Open(p); err == nil {
			fmt.Println("  secrets:", len(v.Names()), "values,", len(v.Env()), "names")
		}
	}
	if st.Warning != "" {
		fmt.Println("  warning:", st.Warning)
	}
	fmt.Println("  backup: `keytwig identity export --out FILE` and keep it offline; without the identity the vault cannot be opened")
	return nil
}

func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show how the identity is protected and whether it is unlocked",
		Args:  cobra.NoArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return printStatus(paths()) },
	}
}

func protectCmd() *cobra.Command {
	var pass, kr, file, stdin bool
	c := &cobra.Command{
		Use:   "protect (--machine | --passphrase | --keyring | --file)",
		Short: "Change how the identity is stored; the vault itself is not re-encrypted",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !pass && !kr && !file && !machineFlag {
				return errors.New("choose one of --machine, --passphrase, --keyring, --file")
			}
			mode, err := pickMode(pass, kr, file)
			if err != nil {
				return err
			}
			p := paths()
			var pp []byte
			if mode == vault.ModePassphrase {
				if pp, err = readPassphrase("new passphrase: ", true, stdin); err != nil {
					return err
				}
			}
			if mode == vault.ModeKeyring && vault.KeyringStoredInPlaintext() {
				fmt.Fprintln(os.Stderr, "warning: your login keyring is saved unencrypted (autologin?); keyring mode will not protect the identity at rest")
			}
			if err := vault.Protect(p, mode, pp); err != nil {
				return err
			}
			fmt.Println("identity mode:", mode)
			return printStatus(p)
		},
	}
	modeFlags(c, &pass, &kr, &file, &stdin)
	return c
}

func unlockCmd() *cobra.Command {
	var stdin bool
	var ttl time.Duration
	c := &cobra.Command{
		Use:   "unlock",
		Short: "Unlock a passphrase-protected identity for a while (default 12h)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			pp, err := readPassphrase("passphrase: ", false, stdin)
			if err != nil {
				return err
			}
			if err := vault.Unlock(paths(), pp, ttl); err != nil {
				return err
			}
			if ttl > 0 {
				fmt.Printf("unlocked for %s (or until `keytwig lock`)\n", ttl)
			} else {
				fmt.Println("unlocked until `keytwig lock`")
			}
			return nil
		},
	}
	c.Flags().BoolVar(&stdin, "passphrase-stdin", false, "read the passphrase from stdin")
	c.Flags().DurationVar(&ttl, "ttl", vault.DefaultTTL, "how long to stay unlocked (0 = until `keytwig lock`)")
	return c
}

func lockCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "lock",
		Short: "Forget the unlocked identity for this boot",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ok, err := vault.LockSession(paths())
			if err != nil {
				return err
			}
			if ok {
				fmt.Println("locked")
			} else {
				fmt.Println("nothing to lock")
			}
			return nil
		},
	}
}

func identityCmd() *cobra.Command {
	c := &cobra.Command{Use: "identity", Short: "Identity backup"}
	var out string
	exp := &cobra.Command{
		Use:   "export --out FILE",
		Short: "Write the plaintext identity to a new 0600 file for an offline backup",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if out == "" {
				return errors.New("--out is required")
			}
			if err := vault.Export(paths(), out); err != nil {
				return err
			}
			fmt.Println("written", out, "— move it offline (password manager, USB) and delete it here")
			return nil
		},
	}
	exp.Flags().StringVar(&out, "out", "", "destination file (must not exist)")
	c.AddCommand(exp)
	return c
}

func scanOptions() (scan.Options, error) {
	cfg, err := config.Load(paths().Config)
	if err != nil {
		return scan.Options{}, fmt.Errorf("config: %w", err)
	}
	home, _ := os.UserHomeDir()
	return scan.Options{Harness: cfg.HarnessPaths(), Ignore: cfg.IgnorePaths(), Home: home}, nil
}

func runScan(args []string) (*scan.Report, error) {
	roots := args
	if len(roots) == 0 {
		h, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		roots = []string{h}
	}
	for i, r := range roots {
		if a, err := filepath.Abs(r); err == nil {
			roots[i] = a
		}
	}
	var vh map[string][32]byte
	if v, err := vault.Open(paths()); err == nil {
		vh = map[string][32]byte{}
		for k, val := range v.Env() {
			vh[k] = scan.Hash(val)
		}
	}
	o, err := scanOptions()
	if err != nil {
		return nil, err
	}
	return scan.Run(roots, vh, o)
}

func scanCmd() *cobra.Command {
	var asJSON, all bool
	c := &cobra.Command{
		Use:   "scan [dir...]",
		Short: "Find credentials spread across the machine (names and paths only, never values)",
		RunE: func(cmd *cobra.Command, args []string) error {
			rep, err := runScan(args)
			if err != nil {
				return err
			}
			if asJSON {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(rep)
			}
			printScan(rep, all)
			return nil
		},
	}
	c.Flags().BoolVar(&asJSON, "json", false, "machine-readable output")
	c.Flags().BoolVar(&all, "all", false, "list every secret name, not only the repeated ones")
	return c
}

func shortPath(p string) string {
	if h, err := os.UserHomeDir(); err == nil && strings.HasPrefix(p, h+"/") {
		return "~/" + p[len(h)+1:]
	}
	return p
}

func printScan(rep *scan.Report, all bool) {
	byClass := map[string]int{}
	loose := 0
	for _, f := range rep.EnvFiles {
		byClass[f.Class]++
		if f.LooseMode {
			loose++
		}
	}
	fmt.Printf("env files: %d — project %d, harness %d, app %d, backup %d\n",
		len(rep.EnvFiles), byClass[scan.ClassProject], byClass[scan.ClassHarness], byClass[scan.ClassApp], byClass[scan.ClassBackup])
	fmt.Printf("secret entries: %d → unique values: %d → from project files, not yet in keytwig: %d\n",
		rep.Entries, rep.UniqueValues, rep.ToImport)
	fmt.Printf("tool credential files: %d\n", len(rep.ToolFiles))
	fmt.Println("harness/app files stay where they are; backups are copies. Only project files are proposed for import.")
	fmt.Println()

	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "CLASS\tENV FILE\tSECRETS\tOTHER\tNOTE")
	order := map[string]int{scan.ClassProject: 0, scan.ClassApp: 1, scan.ClassHarness: 2, scan.ClassBackup: 3}
	files := append([]scan.EnvFile{}, rep.EnvFiles...)
	sort.SliceStable(files, func(i, j int) bool { return order[files[i].Class] < order[files[j].Class] })
	for _, f := range files {
		note := ""
		if f.Refs > 0 {
			note = fmt.Sprintf("%d keytwig refs", f.Refs)
		}
		if f.LooseMode {
			note = strings.TrimPrefix(note+", readable by others ("+f.Mode+")", ", ")
		}
		fmt.Fprintf(tw, "%s\t%s\t%d\t%d\t%s\n", f.Class, shortPath(f.Path), len(f.SecretNames), f.OtherKeys, note)
	}
	tw.Flush()

	fmt.Println()
	tw = tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "SECRET NAME\tCOPIES\tVALUES\tKEYTWIG")
	shown := 0
	for _, n := range rep.Names {
		if !all && len(n.Files) < 2 {
			continue
		}
		vals := "same"
		if n.DistinctValues > 1 {
			vals = fmt.Sprintf("%d different", n.DistinctValues)
		}
		in := "—"
		switch n.InVault {
		case "same":
			in = "imported"
		case "partial":
			in = "one version imported"
		case "different":
			in = "differs from vault"
		}
		fmt.Fprintf(tw, "%s\t%d\t%s\t%s\n", n.Name, len(n.Files), vals, in)
		shown++
	}
	tw.Flush()
	if shown == 0 {
		fmt.Println("(no secret name appears in more than one file)")
	}

	if len(rep.SameValue) > 0 {
		fmt.Println("\nSAME VALUE UNDER DIFFERENT NAMES (stored once in keytwig, the other names become aliases)")
		for _, g := range rep.SameValue {
			mark := ""
			if g.InVault {
				mark = "  [in keytwig]"
			}
			fmt.Printf("  %s  (%d copies)%s\n", strings.Join(g.Names, " = "), g.Copies, mark)
		}
	}

	if len(rep.ToolFiles) > 0 {
		fmt.Println()
		tw = tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "TOOL FILE\tKIND\tNOTE")
		for _, t := range rep.ToolFiles {
			note := ""
			if t.LooseMode {
				note = "readable by others (" + t.Mode + ")"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\n", shortPath(t.Path), t.Kind, note)
		}
		tw.Flush()
	}
	if loose > 0 {
		fmt.Printf("\n%d env files are readable by group/others: chmod 600 them.\n", loose)
	}
}

type importRow struct{ name, status string }

var nonName = regexp.MustCompile(`[^A-Z0-9]+`)

// projectPrefix: the folder holding the env file, as an env-safe name
// (~/code/preventivatore-demo/.env → PREVENTIVATORE_DEMO).
func projectPrefix(file string) string {
	dir := filepath.Base(filepath.Dir(file))
	p := strings.Trim(nonName.ReplaceAllString(strings.ToUpper(dir), "_"), "_")
	if p == "" || (p[0] >= '0' && p[0] <= '9') {
		p = "P_" + p
	}
	return p
}

func importCmd() *cobra.Command {
	var only []string
	var allKeys, overwrite, fromScan, dryRun, includeApp bool
	var prefix string
	c := &cobra.Command{
		Use:   "import <file> | import --scan [dir...]",
		Short: "Import secrets (prints names and status only). --scan imports every project .env at once, deduplicated",
		RunE: func(cmd *cobra.Command, args []string) error {
			want := map[string]bool{}
			for _, o := range only {
				if o = strings.TrimSpace(o); o != "" {
					want[o] = true
				}
			}
			keep := func(name string) bool {
				if len(want) > 0 {
					return want[name]
				}
				return allKeys || dotenv.LooksSecret(name)
			}

			// collect name → value → files
			type cand struct {
				env    string              // name as written in the files
				values map[string][]string // value → files
			}
			cands := map[string]*cand{}
			var order []string
			add := func(file string) error {
				f, err := os.Open(file)
				if err != nil {
					return err
				}
				entries, err := dotenv.Parse(f)
				f.Close()
				if err != nil {
					return err
				}
				for _, e := range entries {
					if !keep(e.Name) || e.Value == "" {
						continue
					}
					name := prefix + e.Name
					c := cands[name]
					if c == nil {
						c = &cand{env: e.Name, values: map[string][]string{}}
						cands[name] = c
						order = append(order, name)
					}
					c.values[e.Value] = append(c.values[e.Value], file)
				}
				return nil
			}

			if fromScan {
				rep, err := runScan(args)
				if err != nil {
					return err
				}
				n := 0
				for _, f := range rep.EnvFiles {
					if f.Class == scan.ClassProject || (includeApp && f.Class == scan.ClassApp) {
						if err := add(f.Path); err != nil {
							return err
						}
						n++
					}
				}
				fmt.Printf("reading %d project env files (harness, app and backup files are left alone)\n\n", n)
			} else {
				if len(args) != 1 {
					return errors.New("give one file, or use --scan")
				}
				src, err := filepath.Abs(args[0])
				if err != nil {
					return err
				}
				if err := add(src); err != nil {
					return err
				}
			}
			sort.Strings(order)

			var rows []importRow
			counts := map[string]int{}
			err := mutate(func(v *vault.Vault) (bool, error) {
				changed := false
				for _, name := range order {
					c := cands[name]
					if !nameRe.MatchString(name) {
						rows = append(rows, importRow{name, "skipped: invalid name"})
						counts["skipped"]++
						continue
					}
					if len(c.values) > 1 {
						// same name, different value per project (e.g. DATABASE_URL):
						// not a duplicate. Store each as <PROJECT>__NAME.
						if !fromScan {
							rows = append(rows, importRow{name, "skipped: file defines it twice"})
							continue
						}
						vals := make([]string, 0, len(c.values))
						for val := range c.values {
							vals = append(vals, val)
						}
						sort.Slice(vals, func(i, j int) bool { return c.values[vals[i]][0] < c.values[vals[j]][0] })
						for _, val := range vals {
							file := c.values[val][0]
							scoped := projectPrefix(file) + "__" + name
							if s, ok := v.Get(scoped); ok && s.Value != val && !overwrite {
								rows = append(rows, importRow{scoped, "conflict: different value already in keytwig (use --overwrite)"})
								counts["conflict"]++
								continue
							}
							st := v.Set(scoped, val, file)
							if st != "unchanged" {
								changed = true
							}
							for _, f := range c.values[val] {
								if v.Link(filepath.Dir(f), c.env, scoped) {
									changed = true
								}
							}
							key := st
							if strings.HasPrefix(st, "alias of") {
								key = "alias"
							}
							counts[key]++
							counts["scoped"]++
							rows = append(rows, importRow{scoped, st + " (differs per project)"})
						}
						continue
					}
					var value, file string
					for val, files := range c.values {
						value, file = val, files[0]
					}
					if s, ok := v.Get(name); ok && s.Value != value && !overwrite {
						rows = append(rows, importRow{name, "conflict: different value already in keytwig (use --overwrite or --prefix)"})
						counts["conflict"]++
						continue
					}
					st := v.Set(name, value, file)
					if st != "unchanged" {
						changed = true
					}
					for _, f := range c.values[value] {
						if v.Link(filepath.Dir(f), c.env, name) {
							changed = true
						}
					}
					key := st
					if strings.HasPrefix(st, "alias of") {
						key = "alias"
					}
					counts[key]++
					rows = append(rows, importRow{name, st})
				}
				return changed && !dryRun, nil
			})
			if err != nil {
				return err
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
			for _, r := range rows {
				fmt.Fprintf(tw, "%s\t%s\n", r.name, r.status)
			}
			tw.Flush()
			if len(rows) == 0 {
				fmt.Println("nothing to import (use --all-keys to include non-secret names)")
				return nil
			}
			fmt.Printf("\nadded %d, aliases (same value, stored once) %d, updated %d, unchanged %d, conflicts %d\n",
				counts["added"], counts["alias"], counts["updated"], counts["unchanged"], counts["conflict"])
			if counts["scoped"] > 0 {
				fmt.Printf("%d names differ per project and were stored as <PROJECT>__NAME; map them back with -k NAME=<PROJECT>__NAME\n", counts["scoped"])
			}
			if dryRun {
				fmt.Println("dry run: nothing was written")
			}
			return nil
		},
	}
	c.Flags().StringSliceVar(&only, "only", nil, "import only these names")
	c.Flags().BoolVar(&allKeys, "all-keys", false, "also import names that do not look secret")
	c.Flags().BoolVar(&overwrite, "overwrite", false, "replace values that differ from the vault")
	c.Flags().StringVar(&prefix, "prefix", "", "prefix added to every imported name")
	c.Flags().BoolVar(&fromScan, "scan", false, "scan dirs (default ~) and import every project env file")
	c.Flags().BoolVar(&includeApp, "include-app", false, "with --scan, also import app files (dot-folders that are not harnesses)")
	c.Flags().BoolVar(&dryRun, "dry-run", false, "show what would happen without writing")
	return c
}

func setCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "set <NAME>",
		Short: "Store a secret read from a hidden prompt or from stdin (never from arguments)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if !nameRe.MatchString(name) {
				return fmt.Errorf("invalid name %q: use letters, digits and _", name)
			}
			var value string
			if term.IsTerminal(int(os.Stdin.Fd())) {
				fmt.Fprintf(os.Stderr, "value for %s: ", name)
				b, err := term.ReadPassword(int(os.Stdin.Fd()))
				fmt.Fprintln(os.Stderr)
				if err != nil {
					return err
				}
				value = string(b)
			} else {
				b, err := io.ReadAll(bufio.NewReader(os.Stdin))
				if err != nil {
					return err
				}
				value = strings.TrimRight(string(b), "\r\n")
			}
			if value == "" {
				return errors.New("empty value, nothing stored")
			}
			var st string
			if err := mutate(func(v *vault.Vault) (bool, error) {
				st = v.Set(name, value, "manual")
				return st != "unchanged", nil
			}); err != nil {
				return err
			}
			fmt.Printf("%s %s\n", name, st)
			return nil
		},
	}
}

func lsCmd() *cobra.Command {
	var asJSON bool
	c := &cobra.Command{
		Use:   "ls",
		Short: "List secret names (no values)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			v, err := vault.Open(paths())
			if err != nil {
				return err
			}
			type item struct {
				Name    string   `json:"name"`
				Aliases []string `json:"aliases,omitempty"`
				Source  string   `json:"source"`
				Updated string   `json:"updated"`
			}
			var items []item
			for _, n := range v.Names() {
				s, _ := v.Get(n)
				items = append(items, item{n, s.Aliases, s.Source, s.Updated.Local().Format("2006-01-02 15:04")})
			}
			if asJSON {
				return json.NewEncoder(os.Stdout).Encode(items)
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "NAME\tALIASES\tUPDATED\tSOURCE")
			for _, it := range items {
				al := strings.Join(it.Aliases, ", ")
				if al == "" {
					al = "—"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", it.Name, al, it.Updated, shortPath(it.Source))
			}
			tw.Flush()
			return nil
		},
	}
	c.Flags().BoolVar(&asJSON, "json", false, "machine-readable output")
	return c
}

func rmCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rm <NAME>...",
		Short: "Delete secrets (deleting an alias keeps the value under its other names)",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var missing []string
			err := mutate(func(v *vault.Vault) (bool, error) {
				changed := false
				for _, n := range args {
					ok, gone := v.Delete(n)
					if !ok {
						missing = append(missing, n)
						continue
					}
					changed = true
					if len(gone) > 0 {
						fmt.Printf("%s deleted (with aliases %s)\n", n, strings.Join(gone, ", "))
					} else {
						fmt.Println(n, "deleted")
					}
				}
				return changed, nil
			})
			if err != nil {
				return err
			}
			if len(missing) > 0 {
				return fmt.Errorf("not found: %s", strings.Join(missing, ", "))
			}
			return nil
		},
	}
}

func agentName(flag string) string {
	if flag != "" {
		return flag
	}
	return os.Getenv("KEYTWIG_AGENT")
}

func loadConfig() config.Config {
	c, err := config.Load(paths().Config)
	if err != nil {
		fmt.Fprintln(os.Stderr, "keytwig: config:", err)
		os.Exit(1)
	}
	return c
}

func runCmd() *cobra.Command {
	var keys []string
	var envFile, agent string
	var all, project, noRedact bool
	c := &cobra.Command{
		Use:   "run [flags] -- <command> [args...]",
		Short: "Run a command with secrets injected as env vars; their values are masked in its output",
		Long: `Run a command with secrets injected as environment variables.

  -k NAME            inject NAME
  -k VAR=NAME        inject secret NAME as env var VAR
  -p, --project      inject the secrets of the project containing the current folder, under their usual names
  --env-file F       read KEY=value lines; values written as keytwig://NAME are resolved
  --all              inject every secret (aliases included)

Every stored value (6+ chars, also base64/URL/JSON-encoded) is replaced in
stdout/stderr with ‹keytwig:NAME›. Agent policies from config.toml apply
(--agent or KEYTWIG_AGENT).`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, err := vault.Open(paths())
			if err != nil {
				return err
			}
			cwd, _ := os.Getwd()
			res, err := runner.Resolve(v, loadConfig(), runner.Spec{
				Keys: keys, EnvFile: envFile, All: all, Project: project, Cwd: cwd, Agent: agentName(agent),
			})
			if err != nil {
				return err
			}
			if len(res.Denied) > 0 {
				fmt.Fprintf(os.Stderr, "keytwig: not allowed for this agent: %s\n", strings.Join(res.Denied, ", "))
			}
			code, err := runner.Run(context.Background(), v, res, runner.Exec{
				Argv: args, Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr,
				NoRedact: noRedact, ForwardSignals: true,
			})
			if err != nil {
				return err
			}
			if code != 0 {
				return &exitError{code}
			}
			return nil
		},
	}
	c.Flags().StringSliceVarP(&keys, "key", "k", nil, "secret to inject: NAME or VAR=NAME (repeatable, comma-separated)")
	c.Flags().BoolVarP(&project, "project", "p", false, "inject the current project's secrets under their usual names")
	c.Flags().StringVar(&envFile, "env-file", "", "env file whose keytwig://NAME values are resolved")
	c.Flags().BoolVar(&all, "all", false, "inject every secret")
	c.Flags().BoolVar(&noRedact, "no-redact", false, "do not mask secrets in output (interactive programs)")
	c.Flags().StringVar(&agent, "agent", "", "agent name for policies (default $KEYTWIG_AGENT)")
	return c
}

func envFileCmd(use, short string, fn func(string, *vault.Vault, bool) (*envfile.Result, error)) *cobra.Command {
	var apply, fromScan bool
	c := &cobra.Command{
		Use:   use,
		Short: short,
		RunE: func(cmd *cobra.Command, args []string) error {
			files := args
			if fromScan {
				rep, err := runScan(nil)
				if err != nil {
					return err
				}
				files = nil
				for _, f := range rep.EnvFiles {
					if f.Class == scan.ClassProject {
						files = append(files, f.Path)
					}
				}
			}
			if len(files) == 0 {
				return errors.New("give one or more files, or --scan")
			}
			p := paths()
			unlock, err := vault.Lock(p)
			if err != nil {
				return err
			}
			defer unlock()
			v, err := vault.Open(p)
			if err != nil {
				return err
			}
			total := 0
			for _, f := range files {
				r, err := fn(f, v, apply)
				if err != nil {
					return fmt.Errorf("%s: %w", f, err)
				}
				if len(r.Changes) == 0 && len(r.Skipped) == 0 {
					continue
				}
				fmt.Println(shortPath(r.Path))
				for _, ch := range r.Changes {
					fmt.Printf("  %s → keytwig://%s\n", ch.Env, ch.Secret)
				}
				for _, sk := range r.Skipped {
					fmt.Printf("  %s skipped (value differs from keytwig, or unknown reference)\n", sk)
				}
				total += len(r.Changes)
			}
			if total == 0 {
				fmt.Println("nothing to change")
			} else if !apply {
				fmt.Printf("\n%d lines would change. Dry run: add --apply to write.\n", total)
			} else {
				fmt.Printf("\n%d lines changed.\n", total)
			}
			return nil
		},
	}
	c.Flags().BoolVar(&apply, "apply", false, "write the files (default: dry run)")
	c.Flags().BoolVar(&fromScan, "scan", false, "all project .env files found by scan")
	return c
}

func rewriteCmd() *cobra.Command {
	c := envFileCmd("rewrite [file...] [--scan] [--apply]",
		"Replace secret values in .env files with keytwig://NAME references (dry run by default)", envfile.Rewrite)
	c.Long = `Replace secret values in project .env files with keytwig://NAME references,
so the plaintext copy disappears from disk. Only values imported from that very
file's project and still identical to keytwig are touched. Then start the app with:

  keytwig run --project -- npm run dev

Most frameworks (Next.js, Vite, dotenv) let real environment variables win over
.env, so the injected values are used. Undo any time with ` + "`keytwig restore`" + `.`
	return c
}

func restoreCmd() *cobra.Command {
	return envFileCmd("restore [file...] [--scan] [--apply]",
		"Put real values back in place of keytwig://NAME references (dry run by default)", envfile.Restore)
}

func mcpCmd() *cobra.Command {
	var agent string
	c := &cobra.Command{
		Use:   "mcp",
		Short: "Serve keytwig to agent harnesses over stdio (MCP); never returns secret values",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cwd, _ := os.Getwd()
			s := &kmcp.Server{Paths: paths(), Agent: agentName(agent), Version: version, Cwd: cwd}
			return s.ServeStdio(context.Background(), os.Stdin, os.Stdout)
		},
	}
	c.Flags().StringVar(&agent, "agent", "", "agent name for policies (default $KEYTWIG_AGENT)")
	return c
}

func installCmd() *cobra.Command {
	var dryRun bool
	c := &cobra.Command{
		Use:   "install <" + strings.Join(install.Supported, "|") + "|all>",
		Short: "Register the keytwig MCP server in an agent harness (backs up the config first)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			res, err := install.Install(args[0], "", "", dryRun)
			for _, r := range res {
				state := "configured"
				switch {
				case !r.Changed:
					state = r.Note
				case dryRun:
					state = "would configure"
				}
				fmt.Printf("%-8s %s  %s\n", r.Harness, state, shortPath(r.Path))
				if r.Changed && r.Note != "" && !dryRun {
					fmt.Println("         " + r.Note)
				}
			}
			if len(res) == 0 && err == nil {
				fmt.Println("no supported harness found")
			}
			return err
		},
	}
	c.Flags().BoolVar(&dryRun, "dry-run", false, "show what would change")
	return c
}
