package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestStartShellCommandRequiresAllReadyAddrs(t *testing.T) {
	proxyAddr, err := freeLoopbackAddr()
	if err != nil {
		t.Fatal(err)
	}
	scanAddr, err := freeLoopbackAddr()
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	managed := &managedProcesses{}
	defer managed.Close()

	err = managed.startShellCommand(ctx, "managed proxy", managedProcessHelperCommand(), []string{
		"AEB_MANAGED_PROCESS_HELPER=listen-proxy",
		"AEB_PROXY_ADDR=" + proxyAddr,
	}, 300*time.Millisecond, proxyAddr, scanAddr)
	if err == nil {
		t.Fatal("expected startup to fail until both proxy and scan listeners are ready")
	}
	if !strings.Contains(err.Error(), scanAddr) {
		t.Fatalf("error = %q, want missing scan address %q", err, scanAddr)
	}
	if got := len(managed.cmds); got != 0 {
		t.Fatalf("managed command count after failed readiness = %d, want 0", got)
	}
}

// A managed launcher can exit after it has spawned a child that inherited the
// runner's stdout/stderr pipe. In a container without an init reaping that
// child, a bare Process.Kill only kills the launcher and Cmd.Wait blocks on the
// still-open pipe. Close must signal the full private process group and return
// before WaitDelay is needed as a last resort.
func TestManagedProcessesCloseKillsOrphanHoldingOutputPipe(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("managed subprocess teardown relies on a POSIX shell and process groups")
	}
	proxyAddr, err := freeLoopbackAddr()
	if err != nil {
		t.Fatal(err)
	}
	readyFile := t.TempDir() + "/orphan-ready"

	ctx, cancel := context.WithCancel(context.Background())
	managed := &managedProcesses{cancel: cancel}
	command := managedProcessHelperCommand()
	err = managed.startShellCommand(ctx, "managed proxy", command, []string{
		"AEB_MANAGED_PROCESS_HELPER=orphan-output",
		"AEB_PROXY_ADDR=" + proxyAddr,
		"AEB_MANAGED_PROCESS_READY_FILE=" + readyFile,
	}, 2*time.Second, proxyAddr)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if len(managed.cmds) != 1 {
		cancel()
		t.Fatalf("managed command count = %d, want 1", len(managed.cmds))
	}
	cmd := managed.cmds[0]
	defer func() {
		// Cleanup if a regression causes Close to time out through WaitDelay:
		// the test helper child deliberately keeps the inherited pipe open.
		killManagedCommand(cmd)
		cancel()
	}()

	if err := waitForFile(readyFile, time.Second); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	managed.Close()
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("Close took %v; process-group kill should finish before WaitDelay", elapsed)
	}
	if len(managed.cmds) != 0 {
		t.Fatalf("managed command count after Close = %d, want 0", len(managed.cmds))
	}
}

func TestManagedOutputTailIsBounded(t *testing.T) {
	tail := newManagedOutputTail(8)
	if _, err := tail.Write([]byte("12345")); err != nil {
		t.Fatal(err)
	}
	if _, err := tail.Write([]byte("67890")); err != nil {
		t.Fatal(err)
	}

	if got := tail.String(); got != "34567890" {
		t.Fatalf("tail = %q, want last 8 bytes", got)
	}
}

func TestManagedProcessHelper(t *testing.T) {
	mode := os.Getenv("AEB_MANAGED_PROCESS_HELPER")
	if mode == "" {
		return
	}
	if mode == "hold-output" {
		select {}
	}
	if mode != "listen-proxy" && mode != "orphan-output" {
		t.Fatalf("unknown helper mode %q", mode)
	}

	ln, err := net.Listen("tcp", os.Getenv("AEB_PROXY_ADDR"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	if mode == "orphan-output" {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			t.Fatal(acceptErr)
		}
		_ = conn.Close()
		child := exec.Command(os.Args[0], "-test.run=TestManagedProcessHelper")
		child.Env = append(os.Environ(), "AEB_MANAGED_PROCESS_HELPER=hold-output")
		child.Stdout = os.Stdout
		child.Stderr = os.Stderr
		if startErr := child.Start(); startErr != nil {
			t.Fatal(startErr)
		}
		if writeErr := os.WriteFile(os.Getenv("AEB_MANAGED_PROCESS_READY_FILE"), []byte("ready"), 0o600); writeErr != nil {
			t.Fatal(writeErr)
		}
		return
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		_ = conn.Close()
	}
}

func managedProcessHelperCommand() string {
	return fmt.Sprintf("exec %s -test.run=TestManagedProcessHelper", strconv.Quote(os.Args[0]))
}

func waitForFile(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return nil
		} else if !os.IsNotExist(err) {
			return err
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for %s", path)
}

// A torn-down run must abandon the readiness wait at once. Without honouring the
// context the poll loop blocks for the full timeout, so a canceled benchmark
// hangs instead of exiting.
func TestWaitForTCPAddrs_HonoursCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	err := waitForTCPAddrs(ctx, []string{"127.0.0.1:1"}, 10*time.Second)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected an error when the context is already canceled")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want it to wrap context.Canceled", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("waited %v before returning; a canceled run must not block for the timeout", elapsed)
	}
}
