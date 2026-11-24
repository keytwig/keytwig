package vault

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testPaths(t *testing.T) Paths {
	dir := t.TempDir()
	t.Setenv("KEYTWIG_RUNTIME_DIR", filepath.Join(dir, "run"))
	return Paths{Identity: filepath.Join(dir, "id.txt"), Vault: filepath.Join(dir, "v.age")}
}

func TestRoundTripEncrypted(t *testing.T) {
	p := testPaths(t)
	if ok, err := Init(p, ModeFile, nil); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if ok, _ := Init(p, ModeFile, nil); ok {
		t.Fatal("second init should be a no-op")
	}
	v, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if st := v.Set("TOKEN", "plaintext-canary-42", "test"); st != "added" {
		t.Fatal(st)
	}
	if err := v.Save(); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(p.Vault)
	if strings.Contains(string(raw), "plaintext-canary-42") || strings.Contains(string(raw), "TOKEN") {
		t.Fatal("vault file is not encrypted")
	}
	v2, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if s, ok := v2.Get("TOKEN"); !ok || s.Value != "plaintext-canary-42" {
		t.Fatal("value lost")
	}
}

func TestAliasesDeduplicate(t *testing.T) {
	p := testPaths(t)
	Init(p, ModeFile, nil)
	v, _ := Open(p)
	v.Set("STRIPE_SECRET_KEY", "sk_same_value", "a")
	if st := v.Set("STRIPE_SECRET_KEY_PROD", "sk_same_value", "b"); st != "alias of STRIPE_SECRET_KEY" {
		t.Fatal(st)
	}
	if len(v.Names()) != 1 || len(v.Env()) != 2 {
		t.Fatalf("names %v env %d", v.Names(), len(v.Env()))
	}
	v.Save()
	v, _ = Open(p)
	if s, ok := v.Get("STRIPE_SECRET_KEY_PROD"); !ok || s.Value != "sk_same_value" {
		t.Fatal("alias lookup failed after reopen")
	}
	// alias gets its own value → splits off
	if st := v.Set("STRIPE_SECRET_KEY_PROD", "sk_other", "c"); st != "added" {
		t.Fatal(st)
	}
	if len(v.Names()) != 2 {
		t.Fatal(v.Names())
	}
	// deleting an alias keeps the owner
	v.Set("ALIAS2", "sk_same_value", "")
	if ok, _ := v.Delete("ALIAS2"); !ok {
		t.Fatal("delete alias")
	}
	if _, ok := v.Get("STRIPE_SECRET_KEY"); !ok {
		t.Fatal("owner gone")
	}
}

func TestPassphraseLockUnlockTTL(t *testing.T) {
	p := testPaths(t)
	if _, err := Init(p, ModePassphrase, []byte("correct horse")); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(p.Identity)
	if strings.Contains(string(raw), "AGE-SECRET-KEY") {
		t.Fatal("identity stored in plaintext")
	}
	if _, err := Open(p); err != nil {
		t.Fatal("should be unlocked right after init:", err)
	}
	LockSession(p)
	if _, err := Open(p); !errors.Is(err, ErrLocked) {
		t.Fatal("expected locked, got", err)
	}
	if err := Unlock(p, []byte("wrong pass"), time.Hour); err == nil {
		t.Fatal("wrong passphrase accepted")
	}
	if err := Unlock(p, []byte("correct horse"), time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(p); err != nil {
		t.Fatal(err)
	}
	// expired TTL locks again
	if err := Unlock(p, []byte("correct horse"), time.Nanosecond); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond) // expiry has second resolution
	if _, err := Open(p); !errors.Is(err, ErrLocked) {
		t.Fatal("expected expiry to lock, got", err)
	}
}

func TestProtectSwitchesModesKeepingVault(t *testing.T) {
	p := testPaths(t)
	Init(p, ModeFile, nil)
	v, _ := Open(p)
	v.Set("K", "value-123456", "")
	v.Save()
	if err := Protect(p, ModePassphrase, []byte("long enough")); err != nil {
		t.Fatal(err)
	}
	if err := Protect(p, ModeFile, nil); err != nil {
		t.Fatal(err)
	}
	v, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if s, ok := v.Get("K"); !ok || s.Value != "value-123456" {
		t.Fatal("vault unreadable after mode switch")
	}
	if err := Protect(p, ModePassphrase, []byte("short")); err == nil {
		t.Fatal("short passphrase accepted")
	}
}

func TestKeyringMode(t *testing.T) {
	if os.Getenv("KEYTWIG_TEST_KEYRING") == "" {
		t.Skip("set KEYTWIG_TEST_KEYRING=1 to test against the real OS keyring")
	}
	p := testPaths(t)
	if _, err := Init(p, ModeKeyring, nil); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(p.Identity)
	if strings.Contains(string(raw), "AGE-SECRET-KEY") {
		t.Fatal("identity file should only point to the keyring")
	}
	if _, err := Open(p); err != nil {
		t.Fatal(err)
	}
	if err := Protect(p, ModeFile, nil); err != nil { // also removes the keyring entry
		t.Fatal(err)
	}
}

func TestMachineMode(t *testing.T) {
	if os.Getenv("KEYTWIG_TEST_MACHINE") == "" {
		t.Skip("set KEYTWIG_TEST_MACHINE=1 to test TPM/Keychain/DPAPI binding")
	}
	p := testPaths(t)
	if _, err := Init(p, ModeMachine, nil); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(p.Identity)
	if strings.Contains(string(raw), "AGE-SECRET-KEY") {
		t.Fatal("machine identity stored in plaintext")
	}
	v, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	v.Set("K", "machine-bound-value", "")
	v.Save()
	if err := Protect(p, ModeFile, nil); err != nil {
		t.Fatal(err)
	}
	if err := Protect(p, ModeMachine, nil); err != nil {
		t.Fatal(err)
	}
	if v, err = Open(p); err != nil {
		t.Fatal(err)
	}
	if s, _ := v.Get("K"); s == nil || s.Value != "machine-bound-value" {
		t.Fatal("value lost")
	}
}
