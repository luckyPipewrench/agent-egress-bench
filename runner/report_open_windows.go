//go:build windows

package main

import "os"

// openNoFollow opens a report artifact, refusing a link where it can.
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
