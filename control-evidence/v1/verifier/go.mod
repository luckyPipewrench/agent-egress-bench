module github.com/luckyPipewrench/agent-egress-bench/control-evidence/v1/verifier

go 1.25.0

require (
	github.com/luckyPipewrench/agent-egress-bench/capability-registry v0.0.0
	github.com/cyberphone/json-canonicalization v0.0.0-20231011164504-785e29786b46
	github.com/santhosh-tekuri/jsonschema/v6 v6.0.2
)

replace github.com/luckyPipewrench/agent-egress-bench/capability-registry => ../../../capability-registry

require golang.org/x/text v0.39.0 // indirect
