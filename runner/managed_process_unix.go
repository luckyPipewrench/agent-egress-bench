//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package main

import (
	"os/exec"
	"syscall"
)

// configureManagedCommand gives each managed launcher a private process group.
// A launcher may exec or fork the server it starts, so teardown must be able to
// signal the server and its descendants without touching the runner's group.
func configureManagedCommand(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// killManagedCommand SIGKILLs the managed command's process group. Setpgid
// makes the direct child's PID the group ID, so the negative PID reaches the
// launcher, server, and any inherited-stdio descendants. A failed group send
// falls back to the direct child.
func killManagedCommand(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
		_ = cmd.Process.Kill()
	}
}
