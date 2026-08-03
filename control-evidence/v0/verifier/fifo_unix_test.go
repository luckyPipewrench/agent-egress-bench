//go:build !windows && !plan9 && !js && !wasip1

package verifier

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestContextFIFOIsRejectedWithoutOpening(t *testing.T) {
	packageDir := filepath.Join("..", "conformance", "golden", "g01-vendor-time")
	contextPath := filepath.Join(t.TempDir(), "context.fifo")
	if err := syscall.Mkfifo(contextPath, 0o600); err != nil {
		t.Skipf("FIFO unsupported: %v", err)
	}
	done := make(chan Result, 1)
	go func() { done <- Verify(packageDir, contextPath) }()
	select {
	case result := <-done:
		if result.Outcome != outcomeUnverifiable || result.Reason != "context_unavailable" {
			t.Fatalf("Verify() = %#v, want unverifiable context_unavailable", result)
		}
	case <-time.After(time.Second):
		t.Fatal("Verify blocked opening a FIFO context")
	}
}
