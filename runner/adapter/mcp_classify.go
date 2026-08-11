package adapter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

func classifyMCPErrorLine(respLine, caseID string) (Result, bool, string) {
	var rpcResp struct {
		ID    interface{} `json:"id"`
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if jsonErr := json.Unmarshal([]byte(respLine), &rpcResp); jsonErr != nil || rpcResp.Error == nil {
		return Result{}, false, ""
	}
	code := rpcResp.Error.Code
	responseID := jsonRPCIDString(rpcResp.ID)
	if code >= -32099 && code <= -32000 {
		return Result{
			Verdict: "block",
			Evidence: map[string]interface{}{
				"error_code":    code,
				"error_message": rpcResp.Error.Message,
			},
		}, true, responseID
	}
	if code <= -32600 {
		return Result{Err: fmt.Errorf("case %s: JSON-RPC protocol error %d: %s", caseID, code, rpcResp.Error.Message)}, true, responseID
	}
	return Result{}, false, responseID
}

func classifyMCPBudgetErrorLine(respLine, caseID string) (Result, bool, string) {
	result, handled, responseID := classifyMCPErrorLine(respLine, caseID)
	if !handled || result.Err == nil {
		return result, handled, responseID
	}

	var rpcResp struct {
		ID    interface{} `json:"id"`
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if jsonErr := json.Unmarshal([]byte(respLine), &rpcResp); jsonErr != nil || rpcResp.Error == nil {
		return result, handled, responseID
	}
	if !isBudgetLimitProtocolError(rpcResp.Error.Code, rpcResp.Error.Message) {
		return result, handled, responseID
	}
	return Result{
		Verdict: "block",
		Evidence: map[string]interface{}{
			"error_code":    rpcResp.Error.Code,
			"error_message": rpcResp.Error.Message,
		},
	}, true, jsonRPCIDString(rpcResp.ID)
}

func isBudgetLimitProtocolError(code int, message string) bool {
	if code > -32600 {
		return false
	}
	msg := normalizeBudgetErrorMessage(message)
	hasBudgetPhrase := strings.Contains(msg, "budget") || strings.Contains(msg, "quota")
	hasCallLimitPhrase := strings.Contains(msg, "call limit") ||
		strings.Contains(msg, "call limits") ||
		strings.Contains(msg, "too many tool calls") ||
		strings.Contains(msg, "too many calls")
	hasExceeded := strings.Contains(msg, "exceed") ||
		strings.Contains(msg, "over") ||
		strings.Contains(msg, "too many") ||
		strings.Contains(msg, "maximum") ||
		strings.Contains(msg, "max ") ||
		strings.Contains(msg, "reached")
	return hasExceeded && (hasBudgetPhrase || hasCallLimitPhrase)
}

func normalizeBudgetErrorMessage(message string) string {
	msg := strings.ToLower(message)
	replacer := strings.NewReplacer(
		"-", " ",
		"_", " ",
		":", " ",
		"/", " ",
		"\t", " ",
		"\n", " ",
		"\r", " ",
	)
	return strings.Join(strings.Fields(replacer.Replace(msg)), " ")
}

// classifyMCPHTTPBlock preserves the proxy adapter's legacy deny range.
func classifyMCPHTTPBlock(body []byte) *Result {
	return classifyMCPHTTPBlockForRange(body, [2]int{-32099, -32000}, "mcp_http_listener")
}

// classifyMCPHTTPBlockForRange normalizes JSON-RPC error responses from an MCP
// Streamable HTTP endpoint. A zero range disables code-range deny matching.
func classifyMCPHTTPBlockForRange(body []byte, denyRange [2]int, productSurface string) *Result {
	lines := bytes.Split(bytes.TrimSpace(body), []byte("\n"))
	for _, line := range lines {
		line = bytes.TrimSpace(bytes.TrimPrefix(line, []byte("data:")))
		if len(line) == 0 {
			continue
		}
		var rpcResp struct {
			Error *struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if jsonErr := json.Unmarshal(line, &rpcResp); jsonErr != nil || rpcResp.Error == nil {
			continue
		}
		code := rpcResp.Error.Code
		if denyRange != [2]int{} && code >= denyRange[0] && code <= denyRange[1] {
			return &Result{
				Verdict: "block",
				Evidence: map[string]interface{}{
					"product_surface": productSurface,
					"error_code":      code,
					"error_message":   rpcResp.Error.Message,
				},
			}
		}
		if code <= -32600 {
			return &Result{
				Err:      fmt.Errorf("JSON-RPC protocol error %d: %s", code, rpcResp.Error.Message),
				Evidence: map[string]interface{}{"product_surface": productSurface},
			}
		}
		return &Result{
			Err:      fmt.Errorf("JSON-RPC error %d: %s", code, rpcResp.Error.Message),
			Evidence: map[string]interface{}{"product_surface": productSurface},
		}
	}
	return nil
}
