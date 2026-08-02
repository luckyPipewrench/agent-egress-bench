package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/luckyPipewrench/agent-egress-bench/runner/fixture"
)

const maxManagedOutputBytes = 2048

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
		if err := managed.startShellCommand(ctx, "managed proxy", proxyCmd, proxyEnv, timeout, proxyAddr, scanAddr); err != nil {
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
		if err := managed.startShellCommand(ctx, "managed MCP HTTP", mcpHTTPCmd, mcpEnv, timeout, mcpAddr); err != nil {
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

func (m *managedProcesses) startShellCommand(ctx context.Context, name, command string, extraEnv []string, timeout time.Duration, readyAddrs ...string) error {
	cmd := exec.CommandContext(ctx, "sh", "-c", command) //nolint:gosec // command supplied by benchmark operator
	cmd.Env = append(os.Environ(), extraEnv...)
	output := newManagedOutputTail(maxManagedOutputBytes)
	cmd.Stdout = output
	cmd.Stderr = output
	configureManagedCommand(cmd)
	// The server can outlive a kill of its direct parent and keep the inherited
	// stdout/stderr pipe open. In an environment with no init to reap the orphan
	// (containers, CI runners), Wait would otherwise block forever on that pipe.
	// WaitDelay bounds that wait: Wait force-closes the pipe and returns.
	cmd.WaitDelay = 5 * time.Second
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start %s command: %w", name, err)
	}
	if err := waitForTCPAddrs(ctx, readyAddrs, timeout); err != nil {
		stopStartedCommand(cmd)
		return fmt.Errorf("%s command did not listen on %s: %w; output: %s", name, strings.Join(readyAddrs, ", "), err, output.String())
	}
	// A command that failed readiness has already been stopped and waited above.
	// Retain only successfully started commands so Close never signals a stale PID
	// a second time during error cleanup.
	m.cmds = append(m.cmds, cmd)
	return nil
}

func (m *managedProcesses) Close() {
	if m.cancel != nil {
		m.cancel()
	}
	// Kill every command first, then wait for each. Killing and waiting in one
	// loop makes total teardown additive (up to one WaitDelay per command);
	// killing all up front bounds it to a single WaitDelay regardless of count.
	for _, cmd := range m.cmds {
		killManagedCommand(cmd)
	}
	for _, cmd := range m.cmds {
		_ = cmd.Wait()
	}
	m.cmds = nil
}

func stopStartedCommand(cmd *exec.Cmd) {
	killManagedCommand(cmd)
	_ = cmd.Wait()
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

func waitForTCPAddrs(ctx context.Context, addrs []string, timeout time.Duration) error {
	if len(addrs) == 0 {
		return fmt.Errorf("no listeners configured")
	}
	deadline := time.Now().Add(timeout)
	ready := make(map[string]bool, len(addrs))
	lastErrs := make(map[string]error, len(addrs))
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("canceled waiting for %s: %w", strings.Join(addrs, ", "), err)
		}
		for _, addr := range addrs {
			if ready[addr] {
				continue
			}
			if err := probeTCP(addr); err != nil {
				lastErrs[addr] = err
				continue
			}
			ready[addr] = true
		}
		if len(ready) == len(addrs) {
			return nil
		}
		// Sleep, but surrender immediately if the run is torn down: a canceled
		// benchmark should not sit here until the full timeout expires.
		select {
		case <-ctx.Done():
			return fmt.Errorf("canceled waiting for %s: %w", strings.Join(addrs, ", "), ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}

	var pending []string
	for _, addr := range addrs {
		if ready[addr] {
			continue
		}
		if lastErrs[addr] != nil {
			pending = append(pending, fmt.Sprintf("%s (%v)", addr, lastErrs[addr]))
		} else {
			pending = append(pending, addr)
		}
	}
	return fmt.Errorf("timed out waiting for %s", strings.Join(pending, ", "))
}

func probeTCP(addr string) error {
	conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
	if err != nil {
		return err
	}
	_ = conn.Close()
	return nil
}

type managedOutputTail struct {
	mu    sync.Mutex
	limit int
	buf   []byte
}

func newManagedOutputTail(limit int) *managedOutputTail {
	return &managedOutputTail{limit: limit}
}

func (b *managedOutputTail) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	written := len(p)
	if b.limit <= 0 {
		return written, nil
	}
	if len(p) >= b.limit {
		b.buf = append(b.buf[:0], p[len(p)-b.limit:]...)
		return written, nil
	}
	b.buf = append(b.buf, p...)
	if over := len(b.buf) - b.limit; over > 0 {
		copy(b.buf, b.buf[over:])
		b.buf = b.buf[:b.limit]
	}
	return written, nil
}

func (b *managedOutputTail) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return string(append([]byte(nil), b.buf...))
}
