// Package cappedread reads bounded responses without mistaking a prefix for a complete body.
package cappedread

import (
	"fmt"
	"io"
	"math"
)

// Result records a capped read. Bytes holds at most Cap bytes. ObservedBytes
// includes the one extra byte read to distinguish a complete body at the cap
// from a truncated body.
type Result struct {
	Bytes         []byte
	ObservedBytes int64
	Truncated     bool
}

// Read reads up to cap bytes plus one sentinel byte. A body exactly cap bytes
// long is complete; a body that supplies the sentinel byte is truncated.
func Read(r io.Reader, cap int64) (Result, error) {
	if cap < 0 {
		return Result{}, fmt.Errorf("negative read cap %d", cap)
	}
	if cap == math.MaxInt64 {
		return Result{}, fmt.Errorf("read cap %d cannot reserve a sentinel byte", cap)
	}

	data, err := io.ReadAll(io.LimitReader(r, cap+1))
	result := Result{ObservedBytes: int64(len(data))}
	if err != nil {
		return result, err
	}
	if result.ObservedBytes > cap {
		result.Truncated = true
		result.Bytes = data[:cap]
		return result, nil
	}
	result.Bytes = data
	return result, nil
}
