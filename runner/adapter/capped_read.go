package adapter

import (
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/luckyPipewrench/agent-egress-bench/runner/internal/cappedread"
)

// decisionBodyCap bounds a response body the runner must read completely in
// order to decide a verdict. It is deliberately far above any body a target
// legitimately returns on a decision path, because truncation here is fatal:
// a deny marker past the cap would be silently missed and the case would score
// as a miss the target did not earn. The former 4096-byte bound was set to
// limit memory, not to bound a decision, and the benchmark's own example target
// config permits fetch responses three orders of magnitude larger.
const decisionBodyCap = 1 << 20

// observationBodyCap bounds a response body the runner reads for context rather
// than for the verdict. Truncation here is recorded and tolerated.
const observationBodyCap = 1 << 20

type truncatedResponseError struct {
	cap      int64
	observed int64
}

func (e *truncatedResponseError) Error() string {
	return fmt.Sprintf("response body exceeded %d-byte cap; observed %d bytes", e.cap, e.observed)
}

// readCappedResponse reads a body the caller needs in full to decide a verdict.
// Truncation is an error, because scoring a decision from a prefix reports a
// measurement the runner did not make.
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

// readObservedResponse reads a body whose content cannot change the verdict the
// caller is about to return. A read error is still an error, but truncation is
// reported to the caller instead of failing the case, so a large legitimate
// response does not make an otherwise complete run unpublishable.
//
// Callers must only use this where the verdict is already determined by status
// and delivery proof. Using it where a deny marker in the body could flip the
// outcome would reintroduce the silent-prefix fail-open this package exists to
// close.
func readObservedResponse(r io.Reader, cap int64) ([]byte, bool, error) {
	result, err := cappedread.Read(r, cap)
	if err != nil {
		return nil, false, err
	}
	return result.Bytes, result.Truncated, nil
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

// noteObservedTruncation records that a non-decision body was truncated, so an
// operator reading the row can tell a complete observation from a partial one
// even though the verdict did not depend on it.
func noteObservedTruncation(evidence map[string]interface{}, truncated bool, cap int64) map[string]interface{} {
	if !truncated {
		return evidence
	}
	if evidence == nil {
		evidence = map[string]interface{}{}
	}
	evidence["observation_truncated"] = true
	evidence["observation_cap_bytes"] = cap
	return evidence
}

// bodyDecidesVerdict reports whether classifyHTTPResponse consults the response
// body to decide this status. Only 400, 403, and 502 reach hasDenyMarker; every
// other status is decided by the status alone, and 2xx through 3xx returns allow
// without reading the body at all.
//
// Truncation matters exactly where this returns true. Where it returns false, a
// large legitimate body cannot change the outcome, so failing the case would
// refuse valid traffic and make an otherwise complete run unpublishable without
// protecting anything.
func bodyDecidesVerdict(statusCode int) bool {
	switch statusCode {
	case http.StatusBadRequest, http.StatusForbidden, http.StatusBadGateway:
		return true
	default:
		return false
	}
}

// readClassifiedResponse reads a body that classifyHTTPResponse will inspect.
// Truncation is fatal only for the statuses whose verdict depends on the body,
// and is recorded and tolerated otherwise.
func readClassifiedResponse(r io.Reader, statusCode int, cap int64) ([]byte, bool, error) {
	body, truncated, err := readObservedResponse(r, cap)
	if err != nil {
		return nil, false, err
	}
	if truncated && bodyDecidesVerdict(statusCode) {
		return nil, true, &truncatedResponseError{cap: cap, observed: int64(len(body)) + 1}
	}
	return body, truncated, nil
}
