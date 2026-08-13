// Copyright 2026 Agent Egress Bench contributors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestSandboxHelperProcess(t *testing.T) {
	if os.Getenv("AEB_TARGET_SANDBOX_HELPER") != "1" {
		return
	}
	writable := os.Getenv("AEB_TARGET_SANDBOX_WRITABLE")
	denied := os.Getenv("AEB_TARGET_SANDBOX_DENIED")
	runtime.LockOSThread()
	if err := restrictFilesystem(writable, []string{"/usr", "/bin", "/lib", "/lib64", "/etc/hosts"}); err != nil {
		_, _ = os.Stderr.WriteString(err.Error())
		os.Exit(125)
	}
	command := "if cat \"$2/secret\" >/dev/null 2>&1; then exit 70; fi; " +
		"printf probe > /dev/null && printf allowed > \"$1/allowed\" && " +
		"if printf denied > \"$2/denied\" 2>/dev/null; then exit 71; fi"
	if err := unix.Exec("/bin/sh", []string{"sh", "-c", command, "sh", writable, denied}, []string{
		"PATH=/usr/bin:/bin",
	}); err != nil {
		_, _ = os.Stderr.WriteString(err.Error())
		os.Exit(126)
	}
}

func TestRestrictsWritesOutsideScratchDirectory(t *testing.T) {
	root := t.TempDir()
	writable := filepath.Join(root, "writable")
	denied := filepath.Join(root, "denied")
	if err := os.Mkdir(writable, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(denied, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(denied, "secret"), []byte("credential"), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(t.Context(), os.Args[0], "-test.run=TestSandboxHelperProcess")
	command.Env = append(os.Environ(),
		"AEB_TARGET_SANDBOX_HELPER=1",
		"AEB_TARGET_SANDBOX_WRITABLE="+writable,
		"AEB_TARGET_SANDBOX_DENIED="+denied,
	)
	output, err := command.CombinedOutput()
	var setupErr *exec.ExitError
	if errors.As(err, &setupErr) && setupErr.ExitCode() == 125 {
		t.Fatalf("Landlock is unavailable on the test kernel: %s", output)
	}
	if err != nil {
		t.Fatalf("sandbox helper failed: %v; output=%s", err, output)
	}
	if _, err := os.Stat(filepath.Join(writable, "allowed")); err != nil {
		t.Fatalf("allowed write did not complete: %v; output=%s", err, output)
	}
	if _, err := os.Stat(filepath.Join(denied, "denied")); !os.IsNotExist(err) {
		t.Fatalf("denied write exists or stat failed unexpectedly: %v", err)
	}
}

func TestInheritedDescriptorIsClosedBeforeTargetExec(t *testing.T) {
	if os.Getenv("AEB_TARGET_SANDBOX_FD_HELPER") == "1" {
		if err := closeInheritedDescriptors(); err != nil {
			t.Fatal(err)
		}
		if err := unix.Exec("/bin/sh", []string{"sh", "-c", "test ! -e /proc/self/fd/3"}, []string{
			"PATH=/usr/bin:/bin",
		}); err != nil {
			t.Fatal(err)
		}
	}

	file, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	command := exec.CommandContext(t.Context(), os.Args[0], "-test.run=TestInheritedDescriptorIsClosedBeforeTargetExec")
	command.Env = append(os.Environ(), "AEB_TARGET_SANDBOX_FD_HELPER=1")
	command.ExtraFiles = []*os.File{file}
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("inherited descriptor remained available: %v; output=%s", err, output)
	}
}

func TestIsolatedEnvironmentDropsCIControlPaths(t *testing.T) {
	t.Setenv("GITHUB_ENV", "/tmp/attacker-target")
	t.Setenv("GITHUB_TOKEN", "not-a-real-token")
	t.Setenv("AEB_MCP_STDIO_UPSTREAM_ADDR", "127.0.0.1:1234")
	t.Setenv("SSL_CERT_FILE", "/tmp/fixture-ca.pem")
	environment := isolatedEnvironment("/tmp/target-state")
	joined := strings.Join(environment, "\n")
	for _, forbidden := range []string{"GITHUB_ENV=", "GITHUB_TOKEN="} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("isolated environment retained %s", forbidden)
		}
	}
	for _, required := range []string{
		"HOME=/tmp/target-state",
		"TMPDIR=/tmp/target-state",
		"AEB_MCP_STDIO_UPSTREAM_ADDR=127.0.0.1:1234",
		"SSL_CERT_FILE=/tmp/fixture-ca.pem",
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("isolated environment missing %s", required)
		}
	}
}

func TestUnixSocketsDeniedWithoutBreakingTCP(t *testing.T) {
	if os.Getenv("AEB_TARGET_SANDBOX_SOCKET_HELPER") == "1" {
		// Pin the goroutine so the socket() call runs on the same thread the
		// per-thread seccomp filter was installed on, matching run()'s
		// LockOSThread-then-exec sequence in production.
		runtime.LockOSThread()
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			t.Fatal(err)
		}
		if err := restrictDelegationChannels(); err != nil {
			t.Fatal(err)
		}
		fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err == nil {
			_ = unix.Close(fd)
			t.Fatal("Unix socket creation unexpectedly succeeded")
		}
		if !errors.Is(err, unix.EPERM) {
			t.Fatalf("Unix socket creation returned %v, want EPERM", err)
		}
		fd, err = unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatalf("TCP socket creation failed: %v", err)
		}
		_ = unix.Close(fd)
		return
	}

	command := exec.CommandContext(t.Context(), os.Args[0], "-test.run=TestUnixSocketsDeniedWithoutBreakingTCP")
	command.Env = append(os.Environ(), "AEB_TARGET_SANDBOX_SOCKET_HELPER=1")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("socket restriction helper failed: %v; output=%s", err, output)
	}
}

func TestUnixSocketListenerCannotBeReachedThroughSandbox(t *testing.T) {
	if os.Getenv("AEB_TARGET_SANDBOX_DIAL_HELPER") == "1" {
		runtime.LockOSThread()
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			t.Fatal(err)
		}
		if err := restrictDelegationChannels(); err != nil {
			t.Fatal(err)
		}
		var dialer net.Dialer
		connection, err := dialer.DialContext(t.Context(), "unix", os.Getenv("AEB_TARGET_SANDBOX_SOCKET"))
		if err == nil {
			_ = connection.Close()
			t.Fatal("sandbox reached a host Unix socket")
		}
		if !errors.Is(err, syscall.EPERM) {
			t.Fatalf("Unix socket dial returned %v, want EPERM", err)
		}
		return
	}

	socketDir, err := os.MkdirTemp("/tmp", "aeb-unix-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	socketPath := filepath.Join(socketDir, "helper.sock")
	var listenConfig net.ListenConfig
	listener, err := listenConfig.Listen(t.Context(), "unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	command := exec.CommandContext(t.Context(), os.Args[0], "-test.run=TestUnixSocketListenerCannotBeReachedThroughSandbox")
	command.Env = append(os.Environ(),
		"AEB_TARGET_SANDBOX_DIAL_HELPER=1",
		"AEB_TARGET_SANDBOX_SOCKET="+socketPath,
	)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("Unix-socket denial helper failed: %v; output=%s", err, output)
	}
}

// TestX32CompatSyscallsAreKilled proves the seccomp filter closes the x32 compat
// path, which reuses AUDIT_ARCH_X86_64 and would otherwise let socket(AF_UNIX)
// through under an arch-only check. seccomp evaluates the raw syscall number
// before dispatch, so this is deterministic regardless of whether the kernel has
// the x32 ABI compiled in. The bypass only exists on amd64.
func TestX32CompatSyscallsAreKilled(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("x32 compat range only shares the native audit arch on amd64")
	}
	if os.Getenv("AEB_TARGET_SANDBOX_X32_HELPER") == "1" {
		runtime.LockOSThread()
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			t.Fatal(err)
		}
		if err := restrictDelegationChannels(); err != nil {
			t.Fatal(err)
		}
		// A syscall number carrying __X32_SYSCALL_BIT must be killed before it
		// dispatches. If seccomp lets it through, we reach the explicit exit and
		// the parent flags the bypass.
		_, _, _ = unix.RawSyscall(x32SyscallFloor, 0, 0, 0)
		os.Exit(111)
	}

	command := exec.CommandContext(t.Context(), os.Args[0], "-test.run=TestX32CompatSyscallsAreKilled")
	command.Env = append(os.Environ(), "AEB_TARGET_SANDBOX_X32_HELPER=1")
	err := command.Run()
	if err == nil {
		t.Fatal("x32 compat syscall was not blocked by the sandbox")
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("unexpected helper failure: %v", err)
	}
	if exitErr.ExitCode() == 111 {
		t.Fatal("x32 compat syscall executed instead of being killed")
	}
	// SECCOMP_RET_KILL_PROCESS terminates via signal (SIGSYS), which reports as
	// signaled rather than a normal exit. A plain exit here would mean the helper
	// failed to install the filter (t.Fatal, exit 1) rather than being killed,
	// so require the signal to avoid a false pass.
	status, ok := exitErr.Sys().(syscall.WaitStatus)
	if !ok {
		t.Fatalf("could not read helper wait status from %v", err)
	}
	if !status.Signaled() {
		t.Fatalf("helper exited (code %d) instead of being killed by seccomp", exitErr.ExitCode())
	}
}

func TestIOUringSetupIsDenied(t *testing.T) {
	if os.Getenv("AEB_TARGET_SANDBOX_IO_URING_HELPER") == "1" {
		runtime.LockOSThread()
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			t.Fatal(err)
		}
		if err := restrictDelegationChannels(); err != nil {
			t.Fatal(err)
		}
		var params [256]byte
		fd, _, errno := unix.RawSyscall6(
			unix.SYS_IO_URING_SETUP,
			1,
			uintptr(unsafe.Pointer(&params[0])),
			0,
			0,
			0,
			0,
		)
		if errno == 0 {
			_ = unix.Close(int(fd))
			t.Fatal("io_uring_setup unexpectedly succeeded")
		}
		if !errors.Is(errno, unix.EPERM) {
			t.Fatalf("io_uring_setup returned %v, want EPERM", errno)
		}
		return
	}

	command := exec.CommandContext(t.Context(), os.Args[0], "-test.run=TestIOUringSetupIsDenied")
	command.Env = append(os.Environ(), "AEB_TARGET_SANDBOX_IO_URING_HELPER=1")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("io_uring denial helper failed: %v; output=%s", err, output)
	}
}
