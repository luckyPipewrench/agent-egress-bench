package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"time"

	"github.com/luckyPipewrench/agent-egress-bench/runner/fixture"
)

type managedProcesses struct {
	proxyAddr  string
	scanAddr   string
	mcpHTTPURL string
	cancel     context.CancelFunc
	cmds       []*exec.Cmd
}

func startManagedProcesses(proxyCmd, mcpHTTPCmd string, fm *fixture.Manager, timeout time.Duration) (*managedProcesses, error) {
	if fm == nil {
		return nil, fmt.Errorf("managed commands require fixtures")
	}
	ctx, cancel := context.WithCancel(context.Background())
	managed := &managedProcesses{cancel: cancel}

	env := managedFixtureEnv(fm)
	if proxyCmd != "" {
		proxyAddr, err := freeLoopbackAddr()
		if err != nil {
			managed.Close()
			return nil, fmt.Errorf("allocate managed proxy listener: %w", err)
		}
		scanAddr, err := freeLoopbackAddr()
		if err != nil {
			managed.Close()
			return nil, fmt.Errorf("allocate managed scan API listener: %w", err)
		}
		managed.proxyAddr = proxyAddr
		managed.scanAddr = scanAddr
		proxyEnv := append(env, "AEB_PROXY_ADDR="+proxyAddr, "AEB_SCAN_ADDR="+scanAddr)
		if err := managed.startShellCommand(ctx, "managed proxy", proxyCmd, proxyEnv, proxyAddr, timeout); err != nil {
			managed.Close()
			return nil, err
		}
	}
	if mcpHTTPCmd != "" {
		mcpAddr, err := freeLoopbackAddr()
		if err != nil {
			managed.Close()
			return nil, fmt.Errorf("allocate managed MCP HTTP listener: %w", err)
		}
		managed.mcpHTTPURL = "http://" + mcpAddr + "/"
		mcpEnv := append(env, "AEB_MCP_HTTP_ADDR="+mcpAddr, "AEB_MCP_HTTP_URL="+managed.mcpHTTPURL)
		if err := managed.startShellCommand(ctx, "managed MCP HTTP", mcpHTTPCmd, mcpEnv, mcpAddr, timeout); err != nil {
			managed.Close()
			return nil, err
		}
	}
	return managed, nil
}

func managedFixtureEnv(fm *fixture.Manager) []string {
	return []string{
		"AEB_HTTP_FIXTURE_ADDR=" + fm.HTTP().Addr(),
		"AEB_TLS_FIXTURE_ADDR=" + fm.TLS().Addr(),
		"AEB_TLS_CA_FILE=" + fm.TLS().CAFile(),
		"AEB_TLS_CA_KEY_FILE=" + fm.TLS().KeyFile(),
		"AEB_WS_FIXTURE_ADDR=" + fm.WS().Addr(),
		"AEB_DNS_FIXTURE_ADDR=" + fm.DNS().Addr(),
		"AEB_MCP_HTTP_FIXTURE_ADDR=" + fm.MCPHTTP().Addr(),
		"AEB_MCP_HTTP_FIXTURE_URL=" + fm.MCPHTTP().URL(),
	}
}

func (m *managedProcesses) startShellCommand(ctx context.Context, name, command string, extraEnv []string, readyAddr string, timeout time.Duration) error {
	cmd := exec.CommandContext(ctx, "sh", "-c", command) //nolint:gosec // command supplied by benchmark operator
	cmd.Env = append(os.Environ(), extraEnv...)
	var stderr bytes.Buffer
	cmd.Stdout = &stderr
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start %s command: %w", name, err)
	}
	m.cmds = append(m.cmds, cmd)
	if err := waitForTCP(readyAddr, timeout); err != nil {
		return fmt.Errorf("%s command did not listen on %s: %w; output: %s", name, readyAddr, err, truncateManagedOutput(stderr.String()))
	}
	return nil
}

func (m *managedProcesses) Close() {
	if m.cancel != nil {
		m.cancel()
	}
	for _, cmd := range m.cmds {
		_ = cmd.Wait()
	}
}

func freeLoopbackAddr() (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		return "", err
	}
	return addr, nil
}

func waitForTCP(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		lastErr = err
		time.Sleep(100 * time.Millisecond)
	}
	return lastErr
}

func truncateManagedOutput(s string) string {
	if len(s) <= 2048 {
		return s
	}
	return s[len(s)-2048:]
}
