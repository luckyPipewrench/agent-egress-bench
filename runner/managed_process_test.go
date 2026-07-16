package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
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
	if os.Getenv("AEB_MANAGED_PROCESS_HELPER") == "" {
		return
	}
	if os.Getenv("AEB_MANAGED_PROCESS_HELPER") != "listen-proxy" {
		t.Fatalf("unknown helper mode %q", os.Getenv("AEB_MANAGED_PROCESS_HELPER"))
	}

	ln, err := net.Listen("tcp", os.Getenv("AEB_PROXY_ADDR"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

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
