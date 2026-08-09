module github.com/luckyPipewrench/agent-egress-bench/runner

go 1.25.0

require (
	github.com/luckyPipewrench/agent-egress-bench/capability-registry v0.0.0
	github.com/miekg/dns v1.1.72
	golang.org/x/net v0.56.0
	gopkg.in/yaml.v3 v3.0.1
)

replace github.com/luckyPipewrench/agent-egress-bench/capability-registry => ../capability-registry

require (
	golang.org/x/mod v0.31.0 // indirect
	golang.org/x/sync v0.19.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
	golang.org/x/tools v0.40.0 // indirect
)
