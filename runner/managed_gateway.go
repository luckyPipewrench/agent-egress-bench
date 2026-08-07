package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/luckyPipewrench/agent-egress-bench/runner/adapter"
	"github.com/luckyPipewrench/agent-egress-bench/runner/fixture"
)

// buildManagedGatewayAdapter loads a gateway plugin, and — when the plugin
// declares a start command — allocates the gateway's listen address, starts the
// gateway process wired to the benchmark fixture as upstream, and registers the
// fixture. It returns the adapter plus the managed gateway (nil when the plugin
// points at an operator-started gateway) so the caller can tear it down.
//
// The gateway address and the fixture addresses are injected as $AEB_* values
// at load time because the loader hard-fails on any unresolved $AEB_* variable
// and the addresses are allocated at run time, not known to the process
// environment in advance.
func buildManagedGatewayAdapter(pluginPath string, fm *fixture.Manager, timeout time.Duration) (adapter.Adapter, *managedGateway, error) {
	if fm == nil {
		return nil, nil, fmt.Errorf("mcp-gateway adapter requires fixtures")
	}

	// Decide managed-versus-operator from the raw plugin, before injecting any
	// runtime value. An operator-started gateway supplies its own address through
	// the process environment; only a runner-managed gateway gets a runner-allocated
	// AEB_GATEWAY_ADDR/URL, so an operator's $AEB_GATEWAY_URL is never overwritten.
	managed, err := adapter.GatewayPluginDeclaresStartCommand(pluginPath)
	if err != nil {
		return nil, nil, err
	}

	env := fixtureEnvMap(fm)
	if managed {
		gatewayAddr, allocErr := freeLoopbackAddr()
		if allocErr != nil {
			return nil, nil, fmt.Errorf("allocate gateway listener: %w", allocErr)
		}
		env["AEB_GATEWAY_ADDR"] = gatewayAddr
		env["AEB_GATEWAY_URL"] = "http://" + gatewayAddr + "/"
	}

	plugin, err := adapter.LoadGatewayPluginWithEnv(pluginPath, env)
	if err != nil {
		return nil, nil, err
	}

	var gw *managedGateway
	if managed {
		gw, err = startManagedGateway(plugin.Gateway, plugin.FixtureRegistration, envSlice(env), timeout)
		if err != nil {
			return nil, nil, err
		}
	}

	adapt, err := adapter.NewMCPGatewayAdapter(plugin, fm)
	if err != nil {
		gw.Close()
		return nil, nil, err
	}
	return adapt, gw, nil
}

// fixtureEnvMap builds the $AEB_* fixture environment interpolated into every
// gateway plugin and inherited by any managed gateway process: the benchmark
// fixture addresses. The runtime-allocated gateway address is added separately
// and only for a runner-managed gateway.
func fixtureEnvMap(fm *fixture.Manager) map[string]string {
	env := map[string]string{}
	for _, kv := range managedFixtureEnv(fm) {
		if k, v, ok := strings.Cut(kv, "="); ok {
			env[k] = v
		}
	}
	return env
}

func envSlice(env map[string]string) []string {
	out := make([]string, 0, len(env))
	for k, v := range env {
		out = append(out, k+"="+v)
	}
	return out
}

// managedGateway owns a gateway process the runner started plus the fixture
// deregistration command to run when the run ends. It exists so an operator does
// not have to hand-start the gateway and hand-wire it to the runner's
// dynamically-allocated upstream fixture before a case can be driven.
type managedGateway struct {
	procs      *managedProcesses
	deregister string
	env        []string
	timeout    time.Duration
	closeOnce  sync.Once
}

// startManagedGateway launches the gateway from its declared start command,
// waits until its ready address is listening, then runs the fixture
// registration command to completion. A failure at any step tears the whole
// thing down and returns an error rather than a half-open lifecycle.
func startManagedGateway(gateway adapter.GatewayRuntime, registration adapter.FixtureRegistration, env []string, timeout time.Duration) (*managedGateway, error) {
	if gateway.StartCommand == "" {
		return nil, fmt.Errorf("gateway start_command is required to manage a gateway lifecycle")
	}
	if gateway.ReadyAddr == "" {
		return nil, fmt.Errorf("gateway ready_addr is required to wait for gateway readiness")
	}

	ctx, cancel := context.WithCancel(context.Background())
	procs := &managedProcesses{cancel: cancel}
	if err := procs.startShellCommand(ctx, "managed gateway", gateway.StartCommand, env, timeout, gateway.ReadyAddr); err != nil {
		procs.Close()
		return nil, err
	}

	mg := &managedGateway{procs: procs, deregister: registration.DeregisterCommand, env: env, timeout: timeout}
	if registration.RegisterCommand != "" {
		if err := runGatewayCommand(ctx, "fixture registration", registration.RegisterCommand, env, timeout); err != nil {
			mg.Close()
			return nil, err
		}
	}
	return mg, nil
}

// Close deregisters the fixture on a best-effort basis, then stops the gateway
// process. Deregistration runs first so the gateway is still up to accept it.
func (m *managedGateway) Close() {
	if m == nil {
		return
	}
	m.closeOnce.Do(func() {
		if m.deregister != "" {
			if err := runGatewayCommand(context.Background(), "fixture deregistration", m.deregister, m.env, m.timeout); err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "gateway deregistration failed: %v\n", err)
			}
		}
		m.procs.Close()
	})
}

// runGatewayCommand runs a one-shot gateway lifecycle command to completion. A
// nonzero exit is an error: a registration that did not take must not be
// mistaken for a gateway that is pointed at the benchmark fixture.
func runGatewayCommand(ctx context.Context, name, command string, env []string, timeout time.Duration) error {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, "sh", "-c", command) //nolint:gosec // command supplied by benchmark operator
	cmd.Env = append(os.Environ(), env...)
	output := newManagedOutputTail(maxManagedOutputBytes)
	cmd.Stdout = output
	cmd.Stderr = output
	configureManagedCommand(cmd)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s command failed: %w; output: %s", name, err, output.String())
	}
	return nil
}
