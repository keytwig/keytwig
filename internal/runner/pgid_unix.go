//go:build unix

package runner

import (
	"os"
	"os/exec"
	"syscall"
	"time"
)

func configureCmd(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = 2 * time.Second
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}

func signalProcess(cmd *exec.Cmd, sig os.Signal) {
	if cmd.Process == nil {
		return
	}
	if s, ok := sig.(syscall.Signal); ok {
		if err := syscall.Kill(-cmd.Process.Pid, s); err == nil {
			return
		}
	}
	_ = cmd.Process.Signal(sig)
}
