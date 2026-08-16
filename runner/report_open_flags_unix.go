//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package main

import (
	"errors"
	"syscall"
)

// extraArtifactOpenFlags are the per-platform flags added to a rooted artifact
// open.
//
// O_NOFOLLOW refuses a symlink in the kernel, so the type check and the open are
// one operation rather than two moments something can be swapped between.
//
// O_NONBLOCK is what keeps a named pipe from hanging the report. Opening a FIFO
// read-only waits for a writer, so without this the open never returned and the
// command sat until it was killed. It has no effect on a regular file.
//
// Neither flag exists everywhere, which is the only reason this is per-platform.
// The confinement that actually matters is os.Root, and that is portable.
const extraArtifactOpenFlags = syscall.O_NOFOLLOW | syscall.O_NONBLOCK

// isRefusedLink reports whether the kernel refused the open because the name was
// a symlink. O_NOFOLLOW surfaces that as ELOOP, which is a refusal rather than a
// read failure and is reported to the operator as such.
func isRefusedLink(err error) bool {
	return errors.Is(err, syscall.ELOOP)
}
