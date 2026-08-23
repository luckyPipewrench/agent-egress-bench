package adapter

import (
	"errors"
	"fmt"
	"io"

	"github.com/luckyPipewrench/agent-egress-bench/runner/internal/cappedread"
)

type truncatedResponseError struct {
	cap      int64
	observed int64
}

func (e *truncatedResponseError) Error() string {
	return fmt.Sprintf("response body exceeded %d-byte cap; observed %d bytes", e.cap, e.observed)
}

func readCappedResponse(r io.Reader, cap int64) ([]byte, error) {
	result, err := cappedread.Read(r, cap)
	if err != nil {
		return nil, err
	}
	if result.Truncated {
		return nil, &truncatedResponseError{cap: cap, observed: result.ObservedBytes}
	}
	return result.Bytes, nil
}

func cappedResponseEvidence(err error) map[string]interface{} {
	var truncated *truncatedResponseError
	if !errors.As(err, &truncated) {
		return nil
	}
	return map[string]interface{}{
		"response_truncated":           true,
		"response_cap_bytes":           truncated.cap,
		"response_bytes_observed":      truncated.observed,
		"response_truncation_observed": fmt.Sprintf("response exceeded %d-byte cap after %d bytes", truncated.cap, truncated.observed),
	}
}
