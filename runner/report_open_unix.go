//go:build !windows

package main

import (
	"errors"
	"os"
	"syscall"
)

// openNoFollow opens a report artifact without following a symlink.
//
// O_NOFOLLOW makes the kernel refuse the open itself, so the check and the use
// are the same operation and nothing can be swapped in between them.
//
// O_NONBLOCK is the other half. Opening a FIFO read-only waits for a writer, so
// a named pipe left in the directory hung the report at the open before any
// type check could run. With it the open returns and the caller's type check
// rejects the pipe. It has no effect on a regular file.
func openNoFollow(path string) (*os.File, error) {
	handle, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		// A symlink surfaces as ELOOP. Report it as the type refusal it is
		// rather than as an unreadable file, so the report says what was wrong.
		if errors.Is(err, syscall.ELOOP) {
			return nil, errNotRegularArtifact
		}
		return nil, err
	}
	return handle, nil
}
