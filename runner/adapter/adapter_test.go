package adapter

import (
	"testing"
	"time"
)

type runOnlyAdapter struct{}

func (runOnlyAdapter) Run(Case, time.Duration) Result { return Result{} }

func TestAdapterRemainsRunOnlyCompatible(t *testing.T) {
	var _ Adapter = runOnlyAdapter{}
}

func TestDryRunAdapter(t *testing.T) {
	a := DryRunAdapter{}

	tests := []struct {
		name     string
		expected string
	}{
		{"block case", "block"},
		{"allow case", "allow"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := Case{ID: "test-001", ExpectedVerdict: tt.expected}
			result := a.Run(c, 10*time.Second)

			if result.Err != nil {
				t.Fatalf("unexpected error: %v", result.Err)
			}
			if result.Verdict != tt.expected {
				t.Errorf("verdict = %q, want %q", result.Verdict, tt.expected)
			}
			if result.Evidence == nil {
				t.Error("evidence should not be nil")
			}
			if !result.DeliveryProven || !result.VerdictObserved {
				t.Fatalf("synthetic result = %+v, want delivery and verdict proof", result)
			}
		})
	}
}

func TestSyntheticAdaptersDeclareAndProveAllCorpusTuples(t *testing.T) {
	c := Case{Transport: "mcp_http", InputType: "mcp_tool_result", ExpectedVerdict: "block"}
	for _, tt := range []struct {
		name string
		a    Adapter
	}{
		{name: "dryrun", a: DryRunAdapter{}},
		{name: "null", a: NullAdapter{}},
		{name: "blockall", a: BlockAllAdapter{}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, ok := SupportsTuple(tt.a, c); !ok {
				t.Fatal("synthetic adapter did not declare its corpus tuple")
			}
			result := tt.a.Run(c, time.Second)
			if !result.DeliveryProven || !result.VerdictObserved {
				t.Fatalf("result = %+v, want explicit synthetic delivery and observation proof", result)
			}
		})
	}
}
