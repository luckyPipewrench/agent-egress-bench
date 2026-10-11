package adapter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// MCPHTTPExchanges is a private diagnostic of the requests actually attempted.
// It omits URLs and headers, including authentication and issued session tokens.
const (
	mcpExchangeCountCap = 256
	mcpExchangeByteCap  = 8 << 20
)

type MCPHTTPExchanges struct {
	CaseID            string `json:"case_id"`
	captureIncomplete bool
	retainedBytes     int
	Complete          bool              `json:"complete"`
	PlannedMethods    []string          `json:"planned_methods"`
	Exchanges         []MCPHTTPExchange `json:"exchanges"`
}

type MCPHTTPExchange struct {
	Request   []byte `json:"request"`
	Response  []byte `json:"response"`
	Status    int    `json:"status"`
	MediaType string `json:"media_type"`
	Complete  bool   `json:"complete"`
}

type exchangeContextKey struct{}

func (p *ProxyAdapter) SetRetainMCPHTTPExchanges(enabled bool) {
	p.retainMCPHTTPExchanges = enabled
}

func (p *ProxyAdapter) recordMCPHTTPExchanges(ctx context.Context, c Case) (context.Context, func(bool) *MCPHTTPExchanges) {
	if !p.retainMCPHTTPExchanges {
		return ctx, func(bool) *MCPHTTPExchanges { return nil }
	}
	record := &MCPHTTPExchanges{CaseID: c.ID, PlannedMethods: []string{"initialize"}}
	switch c.InputType {
	case "mcp_tool_definition":
		record.PlannedMethods = append(record.PlannedMethods, "tools/list")
	case "mcp_tool_result":
		record.PlannedMethods = append(record.PlannedMethods, "tools/list", "tools/call")
	case "mcp_tool_sequence_temporal":
		record.PlannedMethods = append(record.PlannedMethods, "notifications/initialized", "tools/list", "tools/list")
	default:
		messages, ok := c.Payload["jsonrpc_messages"].([]interface{})
		if !ok {
			messages = []interface{}{c.Payload}
		}
		for _, message := range messages {
			if object, ok := message.(map[string]interface{}); ok {
				method, _ := object["method"].(string)
				if len(record.PlannedMethods) == mcpExchangeCountCap || len(method) > 256 {
					record.captureIncomplete = true
					break
				}
				record.PlannedMethods = append(record.PlannedMethods, method)
			}
		}
	}
	return context.WithValue(ctx, exchangeContextKey{}, record), func(complete bool) *MCPHTTPExchanges {
		record.Complete = complete && !record.captureIncomplete
		for _, exchange := range record.Exchanges {
			record.Complete = record.Complete && exchange.Complete
		}
		return record
	}
}

// The transport observes the same reads the verdict path performs. It never
// drains extra bytes, changes a response, or retains unbounded streaming data.
type mcpExchangeTransport struct{}

func (mcpExchangeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	record, _ := req.Context().Value(exchangeContextKey{}).(*MCPHTTPExchanges)
	if record == nil {
		return http.DefaultTransport.RoundTrip(req)
	}
	if len(record.Exchanges) >= mcpExchangeCountCap || record.retainedBytes >= mcpExchangeByteCap {
		record.captureIncomplete = true
		return http.DefaultTransport.RoundTrip(req)
	}
	index := len(record.Exchanges)
	record.Exchanges = append(record.Exchanges, MCPHTTPExchange{})
	entry := &record.Exchanges[index]
	if req.GetBody != nil {
		body, err := req.GetBody()
		if err == nil {
			entry.Request, err = readCappedResponse(body, int64(min(decisionBodyCap, mcpExchangeByteCap-record.retainedBytes)))
			_ = body.Close()
		}
		if err != nil {
			record.captureIncomplete = true
		}
	} else {
		record.captureIncomplete = true
	}
	record.retainedBytes += len(entry.Request)
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	entry.Status = resp.StatusCode
	entry.MediaType = boundedMediaType(resp.Header.Get("Content-Type"))
	resp.Body = &exchangeBody{ReadCloser: resp.Body, entry: entry, record: record}
	return resp, nil
}

type exchangeBody struct {
	io.ReadCloser
	entry    *MCPHTTPExchange
	record   *MCPHTTPExchanges
	overflow bool
}

func (b *exchangeBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	remaining := decisionBodyCap - len(b.entry.Response)
	if b.record != nil {
		remaining = min(remaining, mcpExchangeByteCap-b.record.retainedBytes)
	}
	retained := n
	if retained > remaining {
		retained = remaining
		b.overflow = true
	}
	b.entry.Response = append(b.entry.Response, p[:retained]...)
	if b.record != nil {
		b.record.retainedBytes += retained
		b.record.captureIncomplete = b.record.captureIncomplete || b.overflow
	}
	if err == io.EOF {
		b.entry.Complete = !b.overflow
	}
	return n, err
}

// ValidateMCPHTTPExchanges uses the adapter's response decoder and correlation
// rules. Success means a complete, structurally valid observation, not a score
// or an authenticated claim that the target produced it.
func ValidateMCPHTTPExchanges(record *MCPHTTPExchanges) error {
	if record == nil || !record.Complete || len(record.Exchanges) < 2 || len(record.Exchanges) > mcpExchangeCountCap || len(record.Exchanges) != len(record.PlannedMethods) {
		return fmt.Errorf("incomplete MCP HTTP exchange sequence")
	}
	var lastMethod string
	retainedBytes := 0
	for i, entry := range record.Exchanges {
		retainedBytes += len(entry.Request) + len(entry.Response)
		if retainedBytes > mcpExchangeByteCap {
			return fmt.Errorf("exchange sequence exceeds retained byte limit")
		}
		if !entry.Complete || entry.Status < 100 || entry.Status > 599 || len(entry.Request) == 0 {
			return fmt.Errorf("exchange %d: incomplete request/response", i)
		}
		if boundedMediaType(entry.MediaType) != entry.MediaType {
			return fmt.Errorf("exchange %d: invalid media type", i)
		}
		var request struct {
			JSONRPC string          `json:"jsonrpc"`
			Method  string          `json:"method"`
			ID      json.RawMessage `json:"id"`
		}
		if err := json.Unmarshal(entry.Request, &request); err != nil || request.JSONRPC != "2.0" || request.Method == "" {
			return fmt.Errorf("exchange %d: malformed JSON-RPC request", i)
		}
		if request.Method != record.PlannedMethods[i] {
			return fmt.Errorf("exchange %d: method does not match planned sequence", i)
		}
		if i == 0 && request.Method != "initialize" {
			return fmt.Errorf("exchange sequence lacks initialize")
		}
		lastMethod = request.Method
		// Notifications and HTTP-level refusals have no correlated JSON-RPC
		// response requirement in the existing adapter contract.
		if len(request.ID) == 0 || entry.Status >= 300 {
			continue
		}
		var id string
		if json.Unmarshal(request.ID, &id) != nil || id == "" {
			return fmt.Errorf("exchange %d: invalid request identity", i)
		}
		// The adapter's first compatibility handshake is decided from status
		// and its declared session-token header, not a JSON-RPC result body.
		if i == 0 && request.Method == "initialize" && id == "aeb-listener-session-setup" {
			continue
		}
		decoded, err := decodeGatewayResponse(entry.MediaType, entry.Response, id)
		if err != nil {
			return fmt.Errorf("exchange %d: %w", i, err)
		}
		if request.Method == "initialize" && !validMCPInitializeResponse(decoded) {
			return fmt.Errorf("exchange %d: invalid initialize response", i)
		}
	}
	if lastMethod == "initialize" || lastMethod == "notifications/initialized" {
		return fmt.Errorf("exchange sequence lacks a case request")
	}
	return nil
}

// DecodeMCPHTTPExchanges refuses unknown fields and trailing input.
func DecodeMCPHTTPExchanges(body []byte) (*MCPHTTPExchanges, error) {
	var record MCPHTTPExchanges
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return nil, err
	}
	if err := decoder.Decode(new(interface{})); err != io.EOF {
		return nil, fmt.Errorf("trailing exchange data")
	}
	return &record, ValidateMCPHTTPExchanges(&record)
}
