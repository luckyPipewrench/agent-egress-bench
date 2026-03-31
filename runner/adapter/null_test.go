package adapter

import (
	"testing"
	"time"
)

func TestNullAdapter(t *testing.T) {
	a := NullAdapter{}
	tests := []struct {
		name     string
		expected string
	}{
		{"malicious case returns allow", "block"},
		{"benign case returns allow", "allow"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := Case{ID: "test-null-001", ExpectedVerdict: tt.expected}
			result := a.Run(c, 10*time.Second)
			if result.Err != nil {
				t.Fatalf("unexpected error: %v", result.Err)
			}
			if result.Verdict != "allow" {
				t.Errorf("verdict = %q, want \"allow\"", result.Verdict)
			}
			if result.Evidence == nil {
				t.Error("evidence should not be nil")
			}
		})
	}
}
