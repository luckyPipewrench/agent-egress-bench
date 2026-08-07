package adapter

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
)

// GatewayPlugin describes how a vendor-neutral MCP gateway can be exercised.
// Commands and registration fields are declarative in PR1; the adapter uses
// the client endpoint and deny signals to execute one Streamable HTTP call.
type GatewayPlugin struct {
	Name                string              `json:"name"`
	Transport           string              `json:"transport"`
	Gateway             GatewayRuntime      `json:"gateway"`
	FixtureRegistration FixtureRegistration `json:"fixture_registration"`
	Client              GatewayClient       `json:"client"`
	DenySignals         DenySignals         `json:"deny_signals"`
}

type GatewayRuntime struct {
	StartCommand   string   `json:"start_command"`
	ReadyAddr      string   `json:"ready_addr"`
	EnvPassthrough []string `json:"env_passthrough"`
}

type FixtureRegistration struct {
	Method             string `json:"method"`
	RegisterCommand    string `json:"register_command"`
	DeregisterCommand  string `json:"deregister_command"`
	ConfigTemplatePath string `json:"config_template_path"`
	APIEndpoint        string `json:"api_endpoint"`
}

type GatewayClient struct {
	Endpoint string            `json:"endpoint"`
	Headers  map[string]string `json:"headers"`
}

type DenySignals struct {
	JSONRPCErrorCodeRange [2]int   `json:"jsonrpc_error_code_range"`
	HTTPStatusCodes       []int    `json:"http_status_codes"`
	ToolFilteredFromList  bool     `json:"tool_filtered_from_list"`
	ConnectionClosedNoOut bool     `json:"connection_closed_no_output"`
	NonZeroExit           bool     `json:"non_zero_exit"`
	CustomBodyMarkers     []string `json:"custom_body_markers"`
}

var aebVariable = regexp.MustCompile(`\$AEB_[A-Za-z0-9_]+`)

// LoadGatewayPlugin loads a gateway plugin and substitutes only $AEB_* values
// from the process environment. Substituted text is returned as ordinary string
// data; it is never evaluated as a shell expression by this loader.
func LoadGatewayPlugin(path string) (GatewayPlugin, error) {
	return LoadGatewayPluginWithEnv(path, nil)
}

// LoadGatewayPluginWithEnv loads a gateway plugin and substitutes $AEB_* values,
// preferring the supplied runtime env map and falling back to the process
// environment. The runner allocates the gateway listen address at run time, so
// those values are not in the process environment and must be passed here.
func LoadGatewayPluginWithEnv(path string, env map[string]string) (GatewayPlugin, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return GatewayPlugin{}, fmt.Errorf("read gateway plugin %q: %w", path, err)
	}
	var plugin GatewayPlugin
	if err := json.Unmarshal(data, &plugin); err != nil {
		return GatewayPlugin{}, fmt.Errorf("parse gateway plugin %q: %w", path, err)
	}
	if err := plugin.interpolateAEBEnvironment(env); err != nil {
		return GatewayPlugin{}, fmt.Errorf("interpolate gateway plugin %q: %w", path, err)
	}
	return plugin, nil
}

func (p *GatewayPlugin) interpolateAEBEnvironment(env map[string]string) error {
	var err error
	interpolate := func(value *string) {
		if err != nil {
			return
		}
		*value, err = interpolateAEBString(*value, env)
	}
	interpolate(&p.Name)
	interpolate(&p.Transport)
	interpolate(&p.Gateway.StartCommand)
	interpolate(&p.Gateway.ReadyAddr)
	for i := range p.Gateway.EnvPassthrough {
		interpolate(&p.Gateway.EnvPassthrough[i])
	}
	interpolate(&p.FixtureRegistration.Method)
	interpolate(&p.FixtureRegistration.RegisterCommand)
	interpolate(&p.FixtureRegistration.DeregisterCommand)
	interpolate(&p.FixtureRegistration.ConfigTemplatePath)
	interpolate(&p.FixtureRegistration.APIEndpoint)
	interpolate(&p.Client.Endpoint)
	if len(p.Client.Headers) > 0 {
		rebuilt := make(map[string]string, len(p.Client.Headers))
		for key, value := range p.Client.Headers {
			interpolatedKey, keyErr := interpolateAEBString(key, env)
			if keyErr != nil {
				return keyErr
			}
			interpolatedValue, valueErr := interpolateAEBString(value, env)
			if valueErr != nil {
				return valueErr
			}
			rebuilt[interpolatedKey] = interpolatedValue
		}
		p.Client.Headers = rebuilt
	}
	for i := range p.DenySignals.CustomBodyMarkers {
		interpolate(&p.DenySignals.CustomBodyMarkers[i])
	}
	return err
}

func interpolateAEBString(value string, env map[string]string) (string, error) {
	var missing string
	interpolated := aebVariable.ReplaceAllStringFunc(value, func(variable string) string {
		name := variable[1:]
		if replacement, ok := env[name]; ok {
			return replacement
		}
		if replacement, ok := os.LookupEnv(name); ok {
			return replacement
		}
		missing = name
		return variable
	})
	if missing != "" {
		return "", fmt.Errorf("required environment variable %s is not set", missing)
	}
	return interpolated, nil
}
