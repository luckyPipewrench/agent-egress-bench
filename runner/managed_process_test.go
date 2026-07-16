package main

import (
	"context"
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
