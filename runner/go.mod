module github.com/luckyPipewrench/agent-egress-bench/runner

go 1.26.0

require (
	github.com/luckyPipewrench/agent-egress-bench/capability-registry v0.0.0
	github.com/miekg/dns v1.1.72
	github.com/santhosh-tekuri/jsonschema/v6 v6.0.3
	golang.org/x/net v0.60.0
	golang.org/x/sys v0.48.0
	gopkg.in/yaml.v3 v3.0.1
)

replace github.com/luckyPipewrench/agent-egress-bench/capability-registry => ../capability-registry

require (
	golang.org/x/mod v0.41.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	golang.org/x/tools v0.49.0 // indirect
)
