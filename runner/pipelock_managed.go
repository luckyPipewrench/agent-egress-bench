package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/luckyPipewrench/agent-egress-bench/runner/fixture"
	"gopkg.in/yaml.v3"
)

type managedPipelock struct {
	proxyAddr  string
	scanAddr   string
	mcpHTTPURL string
	configPath string
	cancel     context.CancelFunc
	cmds       []*exec.Cmd
}

func startManagedPipelock(bin, configPath string, fm *fixture.Manager, timeout time.Duration) (*managedPipelock, error) {
	if bin == "" {
		return nil, nil
	}
	if configPath == "" {
		return nil, fmt.Errorf("--pipelock-config is required with --pipelock-bin")
	}
	proxyAddr, err := freeLoopbackAddr()
	if err != nil {
		return nil, fmt.Errorf("allocate proxy listener: %w", err)
	}
	scanAddr, err := freeLoopbackAddr()
	if err != nil {
		return nil, fmt.Errorf("allocate scan API listener: %w", err)
	}
	mcpAddr, err := freeLoopbackAddr()
	if err != nil {
		return nil, fmt.Errorf("allocate MCP HTTP listener: %w", err)
	}
	tmpConfig, err := writeManagedPipelockConfig(configPath, scanAddr, fm.TLS().CAFile(), fm.TLS().KeyFile())
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	managed := &managedPipelock{
		proxyAddr:  proxyAddr,
		scanAddr:   scanAddr,
		mcpHTTPURL: "http://" + mcpAddr + "/",
		configPath: tmpConfig,
		cancel:     cancel,
	}
	if err := managed.startRun(ctx, bin, proxyAddr, tmpConfig, fm.TLS().CAFile(), timeout); err != nil {
		managed.Close()
		return nil, err
	}
	if err := managed.startMCPHTTP(ctx, bin, mcpAddr, fm.MCPHTTP().URL(), tmpConfig, timeout); err != nil {
		managed.Close()
		return nil, err
	}
	return managed, nil
}

func (m *managedPipelock) startRun(ctx context.Context, bin, proxyAddr, configPath, caFile string, timeout time.Duration) error {
	cmd := exec.CommandContext(ctx, bin, "run", "--config", configPath, "--listen", proxyAddr) //nolint:gosec // explicit user-selected binary
	cmd.Env = append(os.Environ(), "SSL_CERT_FILE="+caFile)
	var stderr bytes.Buffer
	cmd.Stdout = &stderr
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start pipelock run: %w", err)
	}
	m.cmds = append(m.cmds, cmd)
	if err := waitForTCP(proxyAddr, timeout); err != nil {
		return fmt.Errorf("pipelock run did not become ready: %w; output: %s", err, truncateManagedOutput(stderr.String()))
	}
	return nil
}

func (m *managedPipelock) startMCPHTTP(ctx context.Context, bin, listenAddr, upstreamURL, configPath string, timeout time.Duration) error {
	cmd := exec.CommandContext(ctx, bin, "mcp", "proxy", "--config", configPath, "--listen", listenAddr, "--upstream", upstreamURL) //nolint:gosec // explicit user-selected binary
	var stderr bytes.Buffer
	cmd.Stdout = &stderr
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start pipelock MCP HTTP listener: %w", err)
	}
	m.cmds = append(m.cmds, cmd)
	if err := waitForHTTP("http://"+listenAddr+"/health", timeout); err != nil {
		return fmt.Errorf("pipelock MCP HTTP listener did not become ready: %w; output: %s", err, truncateManagedOutput(stderr.String()))
	}
	return nil
}

func (m *managedPipelock) Close() {
	if m.cancel != nil {
		m.cancel()
	}
	for _, cmd := range m.cmds {
		_ = cmd.Wait()
	}
	if m.configPath != "" {
		_ = os.Remove(m.configPath)
	}
}

func writeManagedPipelockConfig(srcPath, scanAddr, caCert, caKey string) (string, error) {
	data, err := os.ReadFile(srcPath) //nolint:gosec // explicit benchmark config path
	if err != nil {
		return "", fmt.Errorf("read pipelock config: %w", err)
	}
	var root map[string]interface{}
	if err := yaml.Unmarshal(data, &root); err != nil {
		return "", fmt.Errorf("parse pipelock config: %w", err)
	}
	scanAPI := mapValue(root, "scan_api")
	scanAPI["listen"] = scanAddr
	tlsInterception := mapValue(root, "tls_interception")
	tlsInterception["enabled"] = true
	tlsInterception["ca_cert"] = caCert
	tlsInterception["ca_key"] = caKey

	out, err := yaml.Marshal(root)
	if err != nil {
		return "", fmt.Errorf("marshal managed pipelock config: %w", err)
	}
	f, err := os.CreateTemp("", "aeb-pipelock-*.yaml")
	if err != nil {
		return "", fmt.Errorf("create managed pipelock config: %w", err)
	}
	if _, err := f.Write(out); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return "", fmt.Errorf("write managed pipelock config: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(f.Name())
		return "", fmt.Errorf("close managed pipelock config: %w", err)
	}
	return f.Name(), nil
}

func mapValue(root map[string]interface{}, key string) map[string]interface{} {
	if existing, ok := root[key].(map[string]interface{}); ok {
		return existing
	}
	next := make(map[string]interface{})
	root[key] = next
	return next
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

func waitForHTTP(rawURL string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 500 * time.Millisecond}
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := client.Get(rawURL)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 500 {
				return nil
			}
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
