package adapter

import (
	"testing"
	"time"
)

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
		})
	}
}
