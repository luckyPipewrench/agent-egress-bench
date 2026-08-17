//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestBuyerReportRefusesSpecialFilesWithoutBlocking(t *testing.T) {
	// Opening a FIFO read-only waits for a writer, so a named pipe named after
	// an artifact hung the report at the open, before any type check could run.
	// The command sat until it was killed. Checking the path first cannot fix
	// that, because the block happens inside the open itself.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "raw-summary.json"), []byte(`{"tool":"example-tool"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(dir, "command.txt"), 0o600); err != nil {
		t.Skipf("cannot create a FIFO here: %v", err)
	}

	done := make(chan struct{})
	var report *buyerReport
	var loadErr error
	go func() {
		defer close(done)
		report, loadErr = loadBuyerReport(dir)
	}()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		// Not t.Fatal, because the loader goroutine still holds the shared
		// variables below and failing from this side would race it. Not a
		// second wait either: if a blocking open is ever reintroduced that
		// goroutine never finishes, and waiting for it would hang the test
		// binary instead of failing it in bounded time.
		t.Error("loadBuyerReport blocked on a FIFO artifact")
		return
	}
	if loadErr != nil {
		t.Fatalf("loadBuyerReport = %v, want the run accepted with the pipe refused", loadErr)
	}
	if !strings.Contains(report.command, "not a regular file") {
		t.Errorf("command.txt status = %q, want it named as not a regular file", report.command)
	}
}
