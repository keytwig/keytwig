//go:build windows

package vault

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Lock takes an exclusive lock next to the vault file for read-modify-write.
// Each holder writes a unique PID+timestamp token so unlock removes only its own lock.
func Lock(p Paths) (func(), error) {
	path := p.Vault + ".lock"
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	token := fmt.Sprintf("%d-%d\n", os.Getpid(), time.Now().UnixNano())
	deadline := time.Now().Add(10 * time.Second)
	for {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			_, werr := f.WriteString(token)
			cerr := f.Close()
			if werr != nil {
				_ = os.Remove(path)
				return nil, werr
			}
			if cerr != nil {
				_ = os.Remove(path)
				return nil, cerr
			}
			var once sync.Once
			return func() {
				once.Do(func() {
					if b, err := os.ReadFile(path); err == nil && string(b) == token {
						_ = os.Remove(path)
					}
				})
			}, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		if st, serr := os.Stat(path); serr == nil && time.Since(st.ModTime()) > 30*time.Second {
			_ = os.Remove(path)
			continue
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("vault is locked by another keytwig process (%s)", path)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
