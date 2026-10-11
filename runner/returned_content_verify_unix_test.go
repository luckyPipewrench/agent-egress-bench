//go:build linux

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestVerifyReturnedContentRefusesFIFOAndOversizedFiles(t *testing.T) {
	for _, kind := range []string{"fifo", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			if err := retainMCPHTTPExchanges(dir, "diagnostic-test", syntheticExchangeRecord()); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "diagnostic-test-0-exchange.bin")
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if kind == "fifo" {
				if err := syscall.Mkfifo(path, 0o600); err != nil {
					t.Fatal(err)
				}
			} else {
				file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
				if err != nil {
					t.Fatal(err)
				}
				if err := file.Truncate(maxReportArtifactBytes + 1); err != nil {
					t.Fatal(err)
				}
				_ = file.Close()
			}
			if err := verifyReturnedContentDirectory(dir); err == nil {
				t.Fatal("unsafe artifact accepted")
			}
		})
	}
}
