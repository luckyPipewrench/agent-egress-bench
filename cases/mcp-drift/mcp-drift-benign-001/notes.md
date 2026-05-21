# Notes — mcp-drift-benign-001

## Attack pattern

This is the *negative* case for the rug-pull detector — it should fire a warn,
not a block. Treating addition as identical to mutation would generate constant
operator-fatigue and push deployments to turn drift detection off entirely.

## Detection logic

A correct detector observes:

1. Baseline at session start: `{get_weather, get_forecast}` with their hashes.
2. New tools/list response after restart: `{get_weather, get_forecast, get_air_quality}`.
3. Existing tools' hashes are unchanged. One new tool appears.
4. Verdict: **warn**, not block. The new tool needs review but isn't an
   attack on the established baseline.

Pipelock's implementation: `ToolBaseline.CheckAndUpdate` returns
`(driftDetected=false, prevHash="")` for new entries (because there is no
prior hash to compare against). The session-binding layer separately observes
that the known-tools set has grown and emits a `warn` receipt with
`layer=mcp_tool_baseline` and `pattern=baseline_tool_count_increased`.

## Why this matters

In production this case happens every time a vendor ships a release with a
new tool — and is far more common than rug-pull. If the detector blocks
benign additions, operators disable it, and the detector might as well not
exist.

## Vendor differences

Some vendors may emit `allow` here if their drift detector only fires on
mutation. That's acceptable — the receipt `verdict` MUST be one of
`{warn, allow}`. **Block here is wrong.** False-positive risk is medium
because vendors that conflate "tool count changed" with "tool mutated"
will trip.

## Source

OWASP ASI04 (Supply Chain). General MCP server release behaviour.
