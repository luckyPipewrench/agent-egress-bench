//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris

package main

import "os/exec"

// Managed shell launchers are Unix-oriented, but the runner itself remains
// buildable on other platforms. Those platforms use the normal direct-process
// cancellation path and WaitDelay bound.
func configureManagedCommand(_ *exec.Cmd) {}

func killManagedCommand(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}
