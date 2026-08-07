package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/luckyPipewrench/agent-egress-bench/runner/adapter"
)

// A managed gateway must actually start the gateway process, wait until its
// declared ready address is listening, and run the fixture-registration command
// to completion before the adapter drives any case. Both the listening socket
// and the registration side effect are observed here; neither is assumed.
func TestStartManagedGatewayStartsProcessAndRunsRegistration(t *testing.T) {
	gatewayAddr, err := freeLoopbackAddr()
	if err != nil {
		t.Fatal(err)
	}
	registerMarker := filepath.Join(t.TempDir(), "registered")
	deregisterMarker := filepath.Join(t.TempDir(), "deregistered")

	env := []string{
		"AEB_MANAGED_PROCESS_HELPER=listen-proxy",
		"AEB_PROXY_ADDR=" + gatewayAddr,
		"AEB_REGISTER_MARKER=" + registerMarker,
		"AEB_DEREGISTER_MARKER=" + deregisterMarker,
	}
	gateway := adapter.GatewayRuntime{
		StartCommand: managedProcessHelperCommand(),
		ReadyAddr:    gatewayAddr,
	}
	registration := adapter.FixtureRegistration{
		RegisterCommand:   `touch "$AEB_REGISTER_MARKER"`,
		DeregisterCommand: `touch "$AEB_DEREGISTER_MARKER"`,
	}

	mg, err := startManagedGateway(gateway, registration, env, 3*time.Second)
	if err != nil {
		t.Fatalf("startManagedGateway: %v", err)
	}

	dialCtx, dialCancel := context.WithTimeout(context.Background(), time.Second)
	conn, dialErr := (&net.Dialer{}).DialContext(dialCtx, "tcp", gatewayAddr)
	dialCancel()
	if dialErr != nil {
		mg.Close()
		t.Fatalf("gateway not listening on ready addr after start: %v", dialErr)
	}
	_ = conn.Close()

	if _, statErr := os.Stat(registerMarker); statErr != nil {
		mg.Close()
		t.Fatalf("registration command did not run: %v", statErr)
	}

	mg.Close()

	if _, statErr := os.Stat(deregisterMarker); statErr != nil {
		t.Fatalf("deregistration command did not run on Close: %v", statErr)
	}
}

// A gateway whose ready address never comes up must fail the whole start rather
// than hand back a half-open lifecycle the adapter would then drive blind.
func TestStartManagedGatewayFailsWhenReadyAddrNeverListens(t *testing.T) {
	unusedAddr, err := freeLoopbackAddr()
	if err != nil {
		t.Fatal(err)
	}
	gateway := adapter.GatewayRuntime{
		StartCommand: `sleep 5`,
		ReadyAddr:    unusedAddr,
	}

	mg, err := startManagedGateway(gateway, adapter.FixtureRegistration{}, nil, 300*time.Millisecond)
	if err == nil {
		mg.Close()
		t.Fatal("expected startManagedGateway to fail when ready addr never listens")
	}
}
