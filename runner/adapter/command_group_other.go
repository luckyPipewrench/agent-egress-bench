//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris

package adapter

import (
	"os/exec"
	"time"
)

func configureMCPCommand(cmd *exec.Cmd) {
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		return nil
	}
	cmd.WaitDelay = 5 * time.Second
}
