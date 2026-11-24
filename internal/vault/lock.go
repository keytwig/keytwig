package vault

import (
	"errors"
	"fmt"
	"os"
	"time"
)

// Lock takes an exclusive lock next to the vault file for read-modify-write.
// A lock older than 30s is treated as stale (crashed writer).
func Lock(p Paths) (func(), error) {
	path := p.Vault + ".lock"
	deadline := time.Now().Add(10 * time.Second)
	for {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			fmt.Fprintf(f, "%d\n", os.Getpid())
			f.Close()
			return func() { os.Remove(path) }, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		if st, serr := os.Stat(path); serr == nil && time.Since(st.ModTime()) > 30*time.Second {
			os.Remove(path)
			continue
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("vault is locked by another keytwig process (%s)", path)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
