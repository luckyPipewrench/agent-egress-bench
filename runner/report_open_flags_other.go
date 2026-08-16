//go:build !(aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris)

package main

// extraArtifactOpenFlags is empty on targets without the POSIX open flags:
// Windows, Plan 9, and the wasm targets.
//
// Those platforms are not left unprotected by that. The confinement comes from
// os.Root, which holds a handle to the artifact directory and refuses any name
// resolving outside it, including through a Windows reparse point. That is the
// property the earlier per-platform code was reaching for and did not achieve:
// it checked the path and then opened it, which a writer could step between.
//
// This file is tagged as the negation of the supported Unix list rather than
// naming a platform, and its name carries no platform suffix, because Go would
// apply one implicitly and leave Plan 9 with no definition at all.
const extraArtifactOpenFlags = 0

// isRefusedLink is always false here. These targets have no O_NOFOLLOW, so a
// link is never refused by the open itself; os.Root still refuses one that
// leaves the artifact directory, and the type check on the returned descriptor
// catches the rest.
func isRefusedLink(error) bool {
	return false
}
