// Copyright 2026 Agent Egress Bench contributors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// target-sandbox runs a benchmark target with filesystem access restricted to
// explicitly supplied inputs and one scratch directory.
package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

const usage = "usage: target-sandbox WRITABLE-DIR READABLE-PATH... -- COMMAND [ARG...]"

func readAccess() uint64 {
	return unix.LANDLOCK_ACCESS_FS_EXECUTE |
		unix.LANDLOCK_ACCESS_FS_READ_FILE |
		unix.LANDLOCK_ACCESS_FS_READ_DIR
}

func writeAccessForABI(abi uintptr) uint64 {
	access := uint64(
		unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
			unix.LANDLOCK_ACCESS_FS_REMOVE_DIR |
			unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
			unix.LANDLOCK_ACCESS_FS_MAKE_CHAR |
			unix.LANDLOCK_ACCESS_FS_MAKE_DIR |
			unix.LANDLOCK_ACCESS_FS_MAKE_REG |
			unix.LANDLOCK_ACCESS_FS_MAKE_SOCK |
			unix.LANDLOCK_ACCESS_FS_MAKE_FIFO |
			unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
			unix.LANDLOCK_ACCESS_FS_MAKE_SYM)
	if abi >= 2 {
		access |= unix.LANDLOCK_ACCESS_FS_REFER
	}
	if abi >= 3 {
		access |= unix.LANDLOCK_ACCESS_FS_TRUNCATE
	}
	return access
}

func landlockABI() (uintptr, error) {
	abi, _, errno := unix.RawSyscall6(
		unix.SYS_LANDLOCK_CREATE_RULESET,
		0,
		0,
		unix.LANDLOCK_CREATE_RULESET_VERSION,
		0,
		0,
		0,
	)
	if errno != 0 {
		return 0, errno
	}
	return abi, nil
}

func restrictFilesystem(writable string, readable []string) error {
	abi, err := landlockABI()
	if err != nil {
		return fmt.Errorf("query Landlock ABI: %w", err)
	}
	if abi < 1 {
		return errors.New("kernel reported no supported Landlock ABI")
	}
	writeAccess := writeAccessForABI(abi)
	access := writeAccess | readAccess()
	ruleset := unix.LandlockRulesetAttr{Access_fs: access}
	rulesetFD, _, errno := unix.RawSyscall6(
		unix.SYS_LANDLOCK_CREATE_RULESET,
		uintptr(unsafe.Pointer(&ruleset)),
		unsafe.Sizeof(ruleset),
		0,
		0,
		0,
		0,
	)
	if errno != 0 {
		return fmt.Errorf("create Landlock ruleset: %w", errno)
	}
	defer unix.Close(int(rulesetFD)) //nolint:errcheck // best-effort after a failed setup

	allowedPaths := append([]string{writable, "/dev/null"}, readable...)
	for index, allowedPath := range allowedPaths {
		pathInfo, statErr := os.Stat(allowedPath)
		if statErr != nil {
			return fmt.Errorf("inspect allowed path %s: %w", allowedPath, statErr)
		}
		pathFD, openErr := unix.Open(allowedPath, unix.O_PATH|unix.O_CLOEXEC, 0)
		if openErr != nil {
			return fmt.Errorf("open allowed path %s: %w", allowedPath, openErr)
		}
		allowedAccess := readAccess()
		if !pathInfo.IsDir() {
			allowedAccess &^= unix.LANDLOCK_ACCESS_FS_READ_DIR
		}
		if index == 0 {
			allowedAccess = access
		} else if allowedPath == "/dev/null" {
			allowedAccess = unix.LANDLOCK_ACCESS_FS_WRITE_FILE
			if abi >= 3 {
				allowedAccess |= unix.LANDLOCK_ACCESS_FS_TRUNCATE
			}
		}
		pathRule := unix.LandlockPathBeneathAttr{
			Allowed_access: allowedAccess,
			Parent_fd:      int32(pathFD), // #nosec G115 -- kernel file descriptors fit int32
		}
		_, _, errno = unix.RawSyscall6(
			unix.SYS_LANDLOCK_ADD_RULE,
			rulesetFD,
			unix.LANDLOCK_RULE_PATH_BENEATH,
			uintptr(unsafe.Pointer(&pathRule)),
			0,
			0,
			0,
		)
		_ = unix.Close(pathFD)
		if errno != 0 {
			return fmt.Errorf("add Landlock writable rule for %s: %w", allowedPath, errno)
		}
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("set no_new_privs: %w", err)
	}
	_, _, errno = unix.RawSyscall(unix.SYS_LANDLOCK_RESTRICT_SELF, rulesetFD, 0, 0)
	if errno != 0 {
		return fmt.Errorf("restrict process with Landlock: %w", errno)
	}
	return nil
}

func closeInheritedDescriptors() error {
	if err := unix.CloseRange(3, ^uint(0), unix.CLOSE_RANGE_CLOEXEC); err != nil {
		return fmt.Errorf("mark inherited descriptors close-on-exec: %w", err)
	}
	return nil
}

func readablePaths(configured, command []string) []string {
	paths := append([]string(nil), configured...)
	values := append([]string(nil), command...)
	values = append(values, os.Getenv("SSL_CERT_FILE"))
	for _, value := range values {
		if !filepath.IsAbs(value) {
			continue
		}
		info, err := os.Stat(value)
		if err != nil {
			continue
		}
		if !info.IsDir() {
			value = filepath.Dir(value)
		}
		paths = append(paths, value)
	}
	return paths
}

func isolatedEnvironment(writable string) []string {
	environment := []string{
		"HOME=" + writable,
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"TMPDIR=" + writable,
	}
	for _, name := range []string{"AEB_MCP_STDIO_UPSTREAM_ADDR", "SSL_CERT_FILE"} {
		if value, ok := os.LookupEnv(name); ok && !strings.ContainsRune(value, '\x00') {
			environment = append(environment, name+"="+value)
		}
	}
	return environment
}

func restrictDelegationChannels() error {
	// Classic BPF over struct seccomp_data: offset 0 = syscall nr, offset 4 =
	// arch, offset 16 = args[0] low 32 bits (the socket domain on little-endian
	// amd64/arm64, the only architectures this program builds for). The filter
	// enforces the native architecture, denies socket(AF_UNIX, ...), and denies
	// io_uring_setup so the target cannot create an AF_UNIX socket through an
	// asynchronous socket opcode that bypasses the ordinary socket syscall.
	//
	// A non-native arch is killed outright. That already covers 32-bit i386
	// (AUDIT_ARCH_I386) and AArch32 (AUDIT_ARCH_ARM), but on amd64 the x32 ABI
	// reuses AUDIT_ARCH_X86_64 and only sets __X32_SYSCALL_BIT (0x40000000) in
	// the syscall number, so it would slip past an arch-only check and could
	// create an AF_UNIX socket through the x32 socket entry. x32SyscallFloor is
	// that bit on amd64 and a never-matching sentinel on arm64; any nr at or
	// above it is killed, closing the compat-ABI hole without touching native
	// numbers (which are far below it). EPERM (not kill) is used for the AF_UNIX
	// case specifically so glibc degrades gracefully when it probes optional
	// Unix services such as nscd; a deliberate wrong-ABI syscall is hostile and
	// dies.
	filters := []unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 4},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 1, K: nativeAuditArch},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_KILL_PROCESS},
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0},
		{Code: unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K, Jf: 1, K: x32SyscallFloor},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_KILL_PROCESS},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 4, K: unix.SYS_SOCKET},
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 16},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 1, K: unix.AF_UNIX},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 1, K: unix.SYS_IO_URING_SETUP},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW},
	}
	program := unix.SockFprog{
		Len:    uint16(len(filters)), // #nosec G115 -- fixed filter is well below uint16
		Filter: &filters[0],
	}
	if err := unix.Prctl(unix.PR_SET_SECCOMP, unix.SECCOMP_MODE_FILTER, uintptr(unsafe.Pointer(&program)), 0, 0); err != nil {
		return fmt.Errorf("install delegation-channel seccomp filter: %w", err)
	}
	runtime.KeepAlive(filters)
	return nil
}

func run(args []string) error {
	separator := -1
	for index, arg := range args {
		if arg == "--" {
			separator = index
			break
		}
	}
	if separator < 2 || separator+1 >= len(args) {
		return errors.New(usage)
	}
	writable, err := os.Stat(args[0])
	if err != nil {
		return fmt.Errorf("inspect writable directory: %w", err)
	}
	if !writable.IsDir() {
		return errors.New("writable path must be a directory")
	}
	runtime.LockOSThread()
	command := args[separator+1:]
	if err := restrictFilesystem(args[0], readablePaths(args[1:separator], command)); err != nil {
		return err
	}
	if err := restrictDelegationChannels(); err != nil {
		return err
	}
	if err := closeInheritedDescriptors(); err != nil {
		return err
	}
	return unix.Exec(command[0], command, isolatedEnvironment(args[0]))
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "target-sandbox: %v\n", err)
		os.Exit(127)
	}
}
