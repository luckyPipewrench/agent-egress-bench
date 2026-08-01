package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type receiptObservation struct {
	produced     string
	verifiable   string
	reason       string
	evidenceFile string
}

type receiptRecord struct {
	file       string
	line       int
	caseID     string
	identifier string
}

type verifyResult struct {
	verifiable string
	reason     string
}

func observeReceipts(p Profile, casesByID map[string]Case, rows []CaseResult) map[string]receiptObservation {
	out := make(map[string]receiptObservation, len(rows))
	if p.ReceiptEvidence == nil {
		return out
	}
	for _, row := range rows {
		out[row.CaseID] = receiptObservation{
			produced:   "no",
			verifiable: "no",
		}
	}

	decl := *p.ReceiptEvidence
	if reason := validateReceiptEvidenceDeclaration(decl); reason != "" {
		for _, row := range rows {
			out[row.CaseID] = receiptObservation{produced: "no", verifiable: "no", reason: reason}
		}
		return out
	}

	files, err := evidenceFiles(p.profileDir, decl)
	if err != nil {
		reason := "receipt evidence unavailable: " + err.Error()
		for _, row := range rows {
			out[row.CaseID] = receiptObservation{produced: "no", verifiable: "no", reason: reason}
		}
		return out
	}
	records, err := readReceiptRecords(files, decl)
	if err != nil {
		reason := "receipt evidence unreadable: " + err.Error()
		for _, row := range rows {
			out[row.CaseID] = receiptObservation{produced: "no", verifiable: "no", reason: reason}
		}
		return out
	}

	verifyCache := make(map[string]verifyResult)
	for _, row := range rows {
		candidates := correlateReceiptRecords(row.CaseID, casesByID[row.CaseID], records, decl)
		switch len(candidates) {
		case 0:
			out[row.CaseID] = receiptObservation{
				produced:   "no",
				verifiable: "no",
				reason:     "no matching receipt found",
			}
		case 1:
			record := candidates[0]
			vr, ok := verifyCache[record.file]
			if !ok {
				vr = runReceiptVerifier(record.file, decl)
				verifyCache[record.file] = vr
			}
			out[row.CaseID] = receiptObservation{
				produced:     "yes",
				verifiable:   vr.verifiable,
				reason:       vr.reason,
				evidenceFile: record.file,
			}
		default:
			out[row.CaseID] = receiptObservation{
				produced:   "no",
				verifiable: "no",
				reason:     fmt.Sprintf("ambiguous receipt correlation: %d matching records", len(candidates)),
			}
		}
	}
	return out
}

func validateReceiptEvidenceDeclaration(decl ReceiptEvidenceDeclaration) string {
	var missing []string
	if strings.TrimSpace(decl.EvidenceDir) == "" {
		missing = append(missing, "evidence_dir")
	}
	if strings.TrimSpace(decl.FileGlob) == "" {
		missing = append(missing, "file_glob")
	}
	if strings.TrimSpace(decl.DetailJSONPointer) == "" {
		missing = append(missing, "detail_json_pointer")
	}
	if strings.TrimSpace(decl.DetailEncoding) == "" {
		missing = append(missing, "detail_encoding")
	}
	if strings.TrimSpace(decl.RecordIdentifierJSONPointer) == "" && strings.TrimSpace(decl.RecordCaseIDJSONPointer) == "" {
		missing = append(missing, "record_identifier_json_pointer or record_case_id_json_pointer")
	}
	if strings.TrimSpace(decl.CaseIdentifierJSONPointer) == "" && strings.TrimSpace(decl.RecordCaseIDJSONPointer) == "" {
		missing = append(missing, "case_identifier_json_pointer or record_case_id_json_pointer")
	}
	if len(decl.VerifyCommand) == 0 {
		missing = append(missing, "verify_command")
	}
	if len(decl.ValidExitCodes) == 0 {
		missing = append(missing, "valid_exit_codes")
	}
	if len(missing) > 0 {
		return "receipt_evidence declaration missing " + strings.Join(missing, ", ")
	}
	if decl.DetailEncoding != "object" && decl.DetailEncoding != "json_string" && decl.DetailEncoding != "object_or_json_string" {
		return fmt.Sprintf("receipt_evidence detail_encoding %q is not object, json_string, or object_or_json_string", decl.DetailEncoding)
	}
	if decl.VerifyTimeoutSeconds < 0 {
		return "receipt_evidence verify_timeout_seconds must be >= 0"
	}
	return ""
}

func evidenceFiles(profileDir string, decl ReceiptEvidenceDeclaration) ([]string, error) {
	dir := resolveProfilePath(profileDir, os.ExpandEnv(decl.EvidenceDir))
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading evidence_dir %q: %w", dir, err)
	}
	matches, err := filepath.Glob(filepath.Join(dir, os.ExpandEnv(decl.FileGlob)))
	if err != nil {
		return nil, fmt.Errorf("expanding file_glob %q: %w", decl.FileGlob, err)
	}
	entryNames := make(map[string]bool, len(entries))
	for _, entry := range entries {
		entryNames[filepath.Join(dir, entry.Name())] = true
	}
	filtered := matches[:0]
	for _, match := range matches {
		if entryNames[match] {
			filtered = append(filtered, match)
		}
	}
	sort.Strings(filtered)
	return filtered, nil
}

func readReceiptRecords(files []string, decl ReceiptEvidenceDeclaration) ([]receiptRecord, error) {
	var records []receiptRecord
	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			return nil, fmt.Errorf("opening %s: %w", file, err)
		}
		scanner := bufio.NewScanner(f)
		lineNo := 0
		for scanner.Scan() {
			lineNo++
			line := bytes.TrimSpace(scanner.Bytes())
			if len(line) == 0 {
				continue
			}
			var root interface{}
			if err := json.Unmarshal(line, &root); err != nil {
				_ = f.Close()
				return nil, fmt.Errorf("%s:%d: parsing JSONL record: %w", file, lineNo, err)
			}
			if decl.JSONLRecordType != "" {
				rawType, ok := jsonPointer(root, "/type")
				if !ok || stringValue(rawType) != decl.JSONLRecordType {
					continue
				}
			}
			detail, ok := jsonPointer(root, decl.DetailJSONPointer)
			if !ok {
				continue
			}
			decoded, err := decodeReceiptDetail(detail, decl.DetailEncoding)
			if err != nil {
				_ = f.Close()
				return nil, fmt.Errorf("%s:%d: decoding detail: %w", file, lineNo, err)
			}
			record := receiptRecord{file: file, line: lineNo}
			if decl.RecordCaseIDJSONPointer != "" {
				record.caseID = stringValueAt(decoded, decl.RecordCaseIDJSONPointer)
			}
			if decl.RecordIdentifierJSONPointer != "" {
				record.identifier = stringValueAt(decoded, decl.RecordIdentifierJSONPointer)
			}
			if record.caseID == "" && record.identifier == "" {
				continue
			}
			records = append(records, record)
		}
		if err := scanner.Err(); err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("reading %s: %w", file, err)
		}
		if err := f.Close(); err != nil {
			return nil, fmt.Errorf("closing %s: %w", file, err)
		}
	}
	return records, nil
}

func correlateReceiptRecords(caseID string, c Case, records []receiptRecord, decl ReceiptEvidenceDeclaration) []receiptRecord {
	var candidates []receiptRecord
	for _, record := range records {
		if record.caseID != "" && record.caseID == caseID {
			candidates = append(candidates, record)
		}
	}
	if len(candidates) > 0 || decl.CaseIdentifierJSONPointer == "" {
		return candidates
	}

	caseDoc := caseAsDocument(c)
	caseIdentifier := stringValueAt(caseDoc, decl.CaseIdentifierJSONPointer)
	if caseIdentifier == "" {
		return nil
	}
	for _, record := range records {
		if identifiersMatch(caseIdentifier, record.identifier) {
			candidates = append(candidates, record)
		}
	}
	return candidates
}

func runReceiptVerifier(evidenceFile string, decl ReceiptEvidenceDeclaration) verifyResult {
	timeout := time.Duration(decl.VerifyTimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	args := make([]string, len(decl.VerifyCommand))
	for i, arg := range decl.VerifyCommand {
		args[i] = expandVerifierArg(arg, evidenceFile)
	}
	if strings.TrimSpace(args[0]) == "" {
		return verifyResult{verifiable: "no", reason: "verifier command is empty"}
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	output, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return verifyResult{verifiable: "no", reason: fmt.Sprintf("verifier timed out after %s", timeout)}
	}
	exitCode, exitOK := commandExitCode(err)
	if err != nil && !exitOK {
		return verifyResult{verifiable: "no", reason: "verifier could not run: " + err.Error()}
	}
	if containsInt(decl.ValidExitCodes, exitCode) {
		return verifyResult{verifiable: "yes"}
	}
	if containsInt(decl.PartialExitCodes, exitCode) {
		return verifyResult{verifiable: "partial"}
	}
	reason := fmt.Sprintf("verifier exit code %d", exitCode)
	if trimmed := strings.TrimSpace(string(output)); trimmed != "" {
		reason += ": " + firstLine(trimmed)
	}
	return verifyResult{verifiable: "no", reason: reason}
}

func decodeReceiptDetail(detail interface{}, encoding string) (interface{}, error) {
	switch encoding {
	case "object":
		if _, ok := detail.(map[string]interface{}); !ok {
			return nil, fmt.Errorf("detail is %T, want object", detail)
		}
		return detail, nil
	case "json_string":
		s, ok := detail.(string)
		if !ok {
			return nil, fmt.Errorf("detail is %T, want JSON string", detail)
		}
		var out interface{}
		if err := json.Unmarshal([]byte(s), &out); err != nil {
			return nil, err
		}
		return out, nil
	case "object_or_json_string":
		if _, ok := detail.(map[string]interface{}); ok {
			return detail, nil
		}
		if s, ok := detail.(string); ok {
			var out interface{}
			if err := json.Unmarshal([]byte(s), &out); err != nil {
				return nil, err
			}
			return out, nil
		}
		return nil, fmt.Errorf("detail is %T, want object or JSON string", detail)
	default:
		return nil, fmt.Errorf("unsupported detail_encoding %q", encoding)
	}
}

func identifiersMatch(caseIdentifier, recordIdentifier string) bool {
	if caseIdentifier == "" || recordIdentifier == "" {
		return false
	}
	if caseIdentifier == recordIdentifier {
		return true
	}
	caseURL, caseErr := url.Parse(caseIdentifier)
	recordURL, recordErr := url.Parse(recordIdentifier)
	if caseErr != nil || recordErr != nil || caseURL.Scheme == "" || recordURL.Scheme == "" {
		return false
	}
	if !strings.EqualFold(caseURL.Scheme, recordURL.Scheme) {
		return false
	}
	if !strings.EqualFold(caseURL.Host, recordURL.Host) {
		return false
	}
	if caseURL.EscapedPath() != recordURL.EscapedPath() {
		return false
	}
	return queryCompatible(caseURL.Query(), recordURL.Query())
}

func queryCompatible(caseQuery, recordQuery url.Values) bool {
	if len(caseQuery) != len(recordQuery) {
		return false
	}
	for key, caseVals := range caseQuery {
		recordVals, ok := recordQuery[key]
		if !ok || len(recordVals) != len(caseVals) {
			return false
		}
		for i, caseVal := range caseVals {
			recordVal := recordVals[i]
			if caseVal == recordVal || isRedactedValue(caseVal) || isRedactedValue(recordVal) {
				continue
			}
			return false
		}
	}
	return true
}

func isRedactedValue(v string) bool {
	lower := strings.ToLower(v)
	return strings.Contains(lower, "redacted")
}

func jsonPointer(v interface{}, pointer string) (interface{}, bool) {
	if pointer == "" {
		return v, true
	}
	if !strings.HasPrefix(pointer, "/") {
		return nil, false
	}
	cur := v
	for _, rawPart := range strings.Split(pointer[1:], "/") {
		part := strings.ReplaceAll(strings.ReplaceAll(rawPart, "~1", "/"), "~0", "~")
		switch typed := cur.(type) {
		case map[string]interface{}:
			next, ok := typed[part]
			if !ok {
				return nil, false
			}
			cur = next
		case []interface{}:
			idx, err := strconv.Atoi(part)
			if err != nil || idx < 0 || idx >= len(typed) {
				return nil, false
			}
			cur = typed[idx]
		default:
			return nil, false
		}
	}
	return cur, true
}

func stringValueAt(v interface{}, pointer string) string {
	raw, ok := jsonPointer(v, pointer)
	if !ok {
		return ""
	}
	return stringValue(raw)
}

func stringValue(v interface{}) string {
	switch typed := v.(type) {
	case string:
		return typed
	case fmt.Stringer:
		return typed.String()
	case float64:
		if typed == float64(int64(typed)) {
			return strconv.FormatInt(int64(typed), 10)
		}
		return strconv.FormatFloat(typed, 'f', -1, 64)
	default:
		return ""
	}
}

func caseAsDocument(c Case) map[string]interface{} {
	return map[string]interface{}{
		"schema_version":      c.SchemaVersion,
		"id":                  c.ID,
		"category":            c.Category,
		"title":               c.Title,
		"description":         c.Description,
		"input_type":          c.InputType,
		"transport":           c.Transport,
		"payload":             c.Payload,
		"expected_verdict":    c.ExpectedVerdict,
		"severity":            c.Severity,
		"capability_tags":     stringsSliceAsInterface(c.CapabilityTags),
		"requires":            stringsSliceAsInterface(c.Requires),
		"false_positive_risk": c.FPRisk,
		"why_expected":        c.WhyExpected,
		"safe_example":        c.SafeExample,
		"notes":               c.Notes,
		"source":              c.Source,
	}
}

func stringsSliceAsInterface(in []string) []interface{} {
	out := make([]interface{}, len(in))
	for i, v := range in {
		out[i] = v
	}
	return out
}

func commandExitCode(err error) (int, bool) {
	if err == nil {
		return 0, true
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), true
	}
	return 0, false
}

func expandVerifierArg(arg, evidenceFile string) string {
	arg = os.ExpandEnv(arg)
	arg = strings.ReplaceAll(arg, "{evidence_file}", evidenceFile)
	return arg
}

func resolveProfilePath(profileDir, path string) string {
	if filepath.IsAbs(path) || profileDir == "" {
		return path
	}
	return filepath.Join(profileDir, path)
}

func containsInt(values []int, needle int) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func firstLine(s string) string {
	line := strings.SplitN(s, "\n", 2)[0]
	if len(line) > 200 {
		return line[:200]
	}
	return line
}
