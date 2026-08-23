package cappedread

import (
	"errors"
	"io"
	"strings"
	"testing"
)

func TestReadDetectsTruncation(t *testing.T) {
	const cap = int64(8)
	securityRelevantSuffix := "BLOCK"
	tests := []struct {
		name          string
		body          string
		wantBody      string
		wantObserved  int64
		wantTruncated bool
	}{
		{
			name:          "exactly at cap is complete",
			body:          "12345678",
			wantBody:      "12345678",
			wantObserved:  cap,
			wantTruncated: false,
		},
		{
			name:          "one byte over cap is truncated",
			body:          "123456789",
			wantBody:      "12345678",
			wantObserved:  cap + 1,
			wantTruncated: true,
		},
		{
			name:          "security relevant suffix after cap cannot become a prefix verdict",
			body:          "benign--" + strings.Repeat("padding", 4) + securityRelevantSuffix,
			wantBody:      "benign--",
			wantObserved:  cap + 1,
			wantTruncated: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Read(strings.NewReader(tc.body), cap)
			if err != nil {
				t.Fatalf("Read: %v", err)
			}
			if string(got.Bytes) != tc.wantBody {
				t.Fatalf("Bytes = %q, want %q", got.Bytes, tc.wantBody)
			}
			if got.ObservedBytes != tc.wantObserved {
				t.Fatalf("ObservedBytes = %d, want %d", got.ObservedBytes, tc.wantObserved)
			}
			if got.Truncated != tc.wantTruncated {
				t.Fatalf("Truncated = %t, want %t", got.Truncated, tc.wantTruncated)
			}
			if tc.wantTruncated && strings.Contains(string(got.Bytes), securityRelevantSuffix) {
				t.Fatalf("truncated prefix unexpectedly contains security suffix %q", securityRelevantSuffix)
			}
		})
	}
}

func TestReadReturnsReadError(t *testing.T) {
	want := errors.New("read failed")
	got, err := Read(errReader{err: want}, 8)
	if !errors.Is(err, want) {
		t.Fatalf("Read error = %v, want %v", err, want)
	}
	if got.Truncated {
		t.Fatal("Truncated = true after read error, want false")
	}
}

type errReader struct {
	err error
}

func (r errReader) Read([]byte) (int, error) {
	return 0, r.err
}

var _ io.Reader = errReader{}
