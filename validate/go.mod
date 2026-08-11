module github.com/luckyPipewrench/agent-egress-bench/validate

go 1.25.0

require (
	github.com/luckyPipewrench/agent-egress-bench/capability-registry v0.0.0
	github.com/santhosh-tekuri/jsonschema/v6 v6.0.3
	gopkg.in/yaml.v3 v3.0.1
)

require golang.org/x/text v0.40.0 // indirect

replace github.com/luckyPipewrench/agent-egress-bench/capability-registry => ../capability-registry
