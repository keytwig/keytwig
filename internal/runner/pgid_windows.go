//go:build windows

package runner

import (
	"os"
	"os/exec"
)

func configureCmd(_ *exec.Cmd) {}

func signalProcess(cmd *exec.Cmd, sig os.Signal) {
	if cmd.Process != nil {
		_ = cmd.Process.Signal(sig)
	}
}
