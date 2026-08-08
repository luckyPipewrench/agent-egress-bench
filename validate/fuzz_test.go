package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func FuzzValidateCaseFile(f *testing.F) {
	f.Add([]byte(`{
		"schema_version": 3,
		"id": "fuzz",
		"category": "url",
		"title": "fuzz seed",
		"description": "valid seed case",
		"input_type": "url",
		"transport": "fetch_proxy",
		"payload": {"method": "GET", "url": "https://example.com"},
		"expected_verdict": "block",
		"severity": "low",
		"capability_tags": ["url_dlp"],
		"requires": [],
		"false_positive_risk": "low",
		"why_expected": "seed",
		"notes": "",
		"source": ""
	}`))
	f.Add([]byte(`{"schema_version": 3,"id":"fuzz","payload":{"jsonrpc_messages":[{"jsonrpc":"2.0"}]}}`))
	f.Add([]byte(`not json`))
	f.Add([]byte(`[]`))

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		caseDir := filepath.Join(dir, "url")
		if err := os.MkdirAll(caseDir, 0o750); err != nil {
			t.Fatalf("mkdir case dir: %v", err)
		}
		path := filepath.Join(caseDir, "fuzz.json")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("write fuzz case: %v", err)
		}
		_ = validateFile(path, make(map[string]string))
	})
}

func FuzzValidatePayload(f *testing.F) {
	f.Add("url", []byte(`{"method":"GET","url":"https://example.com"}`))
	f.Add("mcp_tool_call", []byte(`{"jsonrpc_messages":[{"jsonrpc":"2.0","method":"tools/list","id":1}]}`))
	f.Add("websocket_frame", []byte(`{"url":"wss://example.com/ws","frames":[{"opcode":"text","payload":"hello"}]}`))
	f.Add("a2a_agent_card", []byte(`{"agent_card":{"name":"seed","skills":[]}}`))
	f.Add("url", []byte(`{"method":false,"url":3}`))

	f.Fuzz(func(t *testing.T, inputType string, data []byte) {
		payload := decodeObjectForFuzz(data)
		_ = validatePayload(inputType, payload)
	})
}

func decodeObjectForFuzz(data []byte) map[string]interface{} {
	var payload map[string]interface{}
	if err := json.Unmarshal(data, &payload); err != nil || payload == nil {
		return map[string]interface{}{}
	}
	return payload
}
