//go:build !(aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris)

package main

import "os"

// openNoFollow opens a report artifact, refusing a link where it can.
//
// This is the fallback for every target that is not one of the Unix systems
// with the no-follow and non-blocking open flags: Windows, Plan 9, and the wasm
// targets. It is tagged as the negation of that list rather than as one named
// platform, because narrowing the Unix file to explicit targets and naming this
// one after Windows left Plan 9 with no implementation at all and broke its
// build. The filename carries no platform suffix for the same reason: Go would
// apply one implicitly and reintroduce the gap.
//
// Windows has no O_NOFOLLOW, so the release build refused to compile the POSIX
// spelling for this platform at all. It also has no FIFO, which is the other
// thing the POSIX flags guard against, so the availability half of that problem
// does not arise here.
//
// What remains is weaker and the difference is worth stating rather than
// hiding: this checks the path and then opens it, so a reparse point swapped in
// between the two calls would be followed. The caller checks the type of the
// opened handle as well, which catches a directory or a device, and the report
// is generated from a directory the operator names. Closing the remaining
// window needs the Windows reparse-point flag, which the standard library does
// not expose through OpenFile.
func openNoFollow(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errNotRegularArtifact
	}
	return os.Open(path)
}
