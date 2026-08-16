package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	capabilityregistry "github.com/luckyPipewrench/agent-egress-bench/capability-registry"
)

const absentFact = "Absent from run artifacts"

// reportArtifactNames is every file the report reads. Each one is individually
// optional, because a partial run should still be reported honestly. A
// directory holding none of them is a different situation: it is not a run
// artifact directory at all, and rendering it produced a report whose every
// line said the fact was absent while the command exited zero. An operator who
// pointed at the wrong path read that as a report of a run rather than as the
// mistake it was, so an empty directory is refused instead of rendered.
var reportArtifactNames = []string{
	"raw-summary.json",
	"run-metadata.json",
	"run-bundle.json",
	"execution-decision.json",
	"results.jsonl",
	"command.txt",
	"entrypoint-command.txt",
}

// reportSelfConsistentPrefix opens every successful validation string. The
// eligibility predicate matches on it, so the producers and the consumer share
// one constant: when these were separate literals a rename left the predicate
// testing for a string nothing produced, and eligibility silently never
// resolved.
const reportSelfConsistentPrefix = "Self-consistent:"

var reportRestrictedClaims = []*regexp.Regexp{
	regexp.MustCompile(`(?i)leaderboards?`),
	regexp.MustCompile(`(?i)certif(?:ied|ication|ications|ies|y)`),
	regexp.MustCompile(`(?i)proofstamp`),
	regexp.MustCompile(`(?i)neutral benchmark`),
	regexp.MustCompile(`(?i)proven secure`),
	regexp.MustCompile(`(?i)no bypass(?:es)?\b`),
	regexp.MustCompile(`(?i)unbypassable`),
	regexp.MustCompile(`(?i)insurance discount`),
	regexp.MustCompile(`(?i)\bFIPS\b`),
	regexp.MustCompile(`(?i)all prox(?:y|ies)[- ]based`),
}

type reportDocument struct {
	name   string
	data   map[string]interface{}
	status string
}

type reportNA struct {
	caseID string
	reason string
}

type buyerReport struct {
	dir        string
	summary    reportDocument
	metadata   reportDocument
	bundle     reportDocument
	decision   reportDocument
	results    []reportNA
	resultErr  string
	rowCounts  reportRowCounts
	command    string
	entrypoint string
}

func generateBuyerReport(dir, outputPath string) error {
	report, err := loadBuyerReport(dir)
	if err != nil {
		return err
	}
	var out bytes.Buffer
	report.renderMarkdown(&out)
	if outputPath == "-" {
		_, err = os.Stdout.Write(out.Bytes())
		return err
	}
	if err := os.WriteFile(outputPath, out.Bytes(), 0o600); err != nil {
		return fmt.Errorf("writing report to %s: %w", outputPath, err)
	}
	return nil
}

func loadBuyerReport(dir string) (*buyerReport, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("reading report artifact directory: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("report input is not a directory: %s", dir)
	}
	r := &buyerReport{dir: dir}
	r.summary = loadReportDocument(dir, "raw-summary.json")
	r.metadata = loadReportDocument(dir, "run-metadata.json")
	r.bundle = loadReportDocument(dir, "run-bundle.json")
	r.decision = loadReportDocument(dir, "execution-decision.json")
	r.results, r.rowCounts, r.resultErr = loadNotApplicable(filepath.Join(dir, "results.jsonl"))
	r.command = loadReportText(dir, "command.txt")
	r.entrypoint = loadReportText(dir, "entrypoint-command.txt")
	if !r.hasFact() {
		return nil, fmt.Errorf("no run artifacts in %s: expected at least one of %s to carry a fact", dir, strings.Join(reportArtifactNames, ", "))
	}
	return r, nil
}

// hasFact reports whether anything in the directory yielded something to say.
//
// This is asked AFTER loading on purpose. Every version of it asked beforehand
// was a guess about the input that the input then got around: a check for
// presence let a zero-byte file through, a check for non-zero size let a
// symlink and then a JSON object of `{}` through, and each fix only moved the
// boundary. Asking afterwards ends the family, because the question is no
// longer what the input looks like but whether a single fact came out of it.
//
// An empty result is not a report. Rendering one produced a document whose
// every line read as absent while the command exited zero, so somebody who
// mistyped a path was handed a report of a run that was never found.
//
// One fact is enough, which keeps a genuinely partial run reportable. Refusing
// those would push an operator toward reconstructing directories by hand to get
// a report at all, and a guard people work around protects nothing.
func (r *buyerReport) hasFact() bool {
	for _, doc := range []reportDocument{r.summary, r.metadata, r.bundle, r.decision} {
		if len(doc.data) > 0 {
			return true
		}
	}
	// A results file that parsed cleanly with zero rows read as "Readable" and
	// said nothing about any case, so the row count is the fact here, not the
	// parse result.
	if r.resultErr == "Readable" && r.rowCounts.total > 0 {
		return true
	}
	for _, text := range []string{r.command, r.entrypoint} {
		if text != absentFact && !strings.HasPrefix(text, "Invalid in run artifacts") && text != "Unreadable run artifact" {
			return true
		}
	}
	return false
}

// openRegularArtifact opens a report input without following a symlink and
// confirms the type of the descriptor it actually opened.
//
// Checking the path and then opening it are two different questions about two
// different moments. An earlier version called Lstat and then read the path, so
// anything able to write the directory could swap a regular file for a symlink
// between the two calls and put a file from outside the run into the report, or
// swap in a FIFO and hang the read forever. A report directory that arrived in
// an archive is exactly where that matters.
//
// O_NOFOLLOW makes the open itself refuse a symlink, and Stat on the open file
// describes that descriptor rather than whatever the name points at now, so
// there is no window between the check and the use.
//
// O_NONBLOCK is the other half and is not optional. Opening a FIFO read-only
// waits for a writer, so a named pipe left in the directory hung the report
// indefinitely at the open, before any type check could run. Measured: the
// command sat until killed. With O_NONBLOCK the open returns immediately, the
// type check sees a pipe, and the artifact is refused. It has no effect on a
// regular file.
func openRegularArtifact(dir, name string) (*os.File, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	return openRootedArtifact(root, name)
}

// openRootedArtifact opens one artifact beneath an already-open directory and
// confirms the type of the descriptor it actually opened.
//
// os.Root is what makes this safe on every platform. It holds a handle to the
// artifact directory and refuses any name that resolves outside it, so neither
// a link nor a swapped ancestor directory can pull a file from elsewhere into
// the report. An earlier version reached for that with per-platform opens and
// only ever covered the final path component, and its non-Unix fallback checked
// the path and then opened it, which is two moments a writer can step between.
//
// The platform flags on top are a narrower job: refusing a symlink outright
// where the kernel can, and not blocking on a named pipe. Checking the type on
// the returned descriptor rather than on the name is what closes the gap on the
// platforms that have neither flag.
func openRootedArtifact(root *os.Root, name string) (*os.File, error) {
	// Ask the directory about the entry itself before opening it. os.Root
	// confines resolution to the directory but still follows a link that stays
	// inside it, so on the targets without O_NOFOLLOW a link to a sibling file
	// would be opened and the report would describe the wrong artifact. Lstat is
	// root-relative and does not follow the final component, so it answers that
	// question on every platform.
	if info, statErr := root.Lstat(name); statErr == nil && !info.Mode().IsRegular() {
		return nil, errNotRegularArtifact
	} else if statErr != nil {
		return nil, statErr
	}
	handle, err := root.OpenFile(name, os.O_RDONLY|extraArtifactOpenFlags, 0)
	if err != nil {
		// A symlink refused by the kernel is a type refusal rather than a read
		// failure, and is reported as one. Everything else, including a name
		// os.Root rejected for escaping the directory, is returned as the error
		// it is: an earlier version matched the standard library's English
		// escape message to classify it, which would have gone quietly wrong the
		// first time that wording changed. Both paths refuse; only the wording
		// the operator sees differs, so the fragile half is not worth keeping.
		if isRefusedLink(err) {
			return nil, errNotRegularArtifact
		}
		return nil, err
	}
	info, err := handle.Stat()
	if err != nil {
		_ = handle.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		_ = handle.Close()
		return nil, errNotRegularArtifact
	}
	return handle, nil
}

// readRegularArtifact reads a report input, refusing anything that is not a
// regular file. The report states facts about a run, and a file outside the run
// directory is not one.
func readRegularArtifact(dir, name string) ([]byte, error) {
	handle, err := openRegularArtifact(dir, name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = handle.Close() }()
	return io.ReadAll(handle)
}

var errNotRegularArtifact = errors.New("run artifact is not a regular file")

func loadReportDocument(dir, name string) reportDocument {
	doc := reportDocument{name: name}
	data, err := readRegularArtifact(dir, name)
	if os.IsNotExist(err) {
		doc.status = absentFact
		return doc
	}
	if errors.Is(err, errNotRegularArtifact) {
		doc.status = "Invalid in run artifacts: not a regular file"
		return doc
	}
	if err != nil {
		doc.status = "Unreadable run artifact"
		return doc
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&doc.data); err != nil {
		doc.status = "Malformed JSON: " + safeReportText(err.Error())
		return doc
	}
	if doc.data == nil {
		doc.status = "Invalid in run artifacts: expected a JSON object"
		return doc
	}
	if err := ensureJSONEOF(dec); err != nil {
		doc.data = nil
		doc.status = "Malformed JSON: " + safeReportText(err.Error())
		return doc
	}
	doc.status = "Readable"
	return doc
}

func ensureJSONEOF(dec *json.Decoder) error {
	var extra interface{}
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return err
	}
	return nil
}

func loadReportText(dir, name string) string {
	data, err := readRegularArtifact(dir, name)
	if os.IsNotExist(err) {
		return absentFact
	}
	if errors.Is(err, errNotRegularArtifact) {
		return "Invalid in run artifacts: not a regular file"
	}
	if err != nil {
		return "Unreadable run artifact"
	}
	value := strings.TrimSpace(string(data))
	if value == "" {
		return "Invalid in run artifacts: empty file"
	}
	return safeReportText(value)
}

// reportRowCounts is what results.jsonl actually contains, as opposed to what
// the summary declares about it. Comparing the two is the only way the report
// can tell a reader the scope arithmetic holds.
type reportRowCounts struct {
	total         int
	applicable    int
	unreachable   int
	notApplicable int
	errors        int
}

func loadNotApplicable(path string) ([]reportNA, reportRowCounts, string) {
	var counts reportRowCounts
	// Streams rather than reading whole, so it opens the descriptor itself, and
	// it uses the same no-follow open as the other readers: the type is checked
	// on the descriptor that will actually be read, never on the path.
	f, err := openRegularArtifact(filepath.Dir(path), filepath.Base(path))
	if os.IsNotExist(err) {
		return nil, counts, absentFact
	}
	if errors.Is(err, errNotRegularArtifact) {
		return nil, counts, "Invalid in run artifacts: not a regular file"
	}
	if err != nil {
		return nil, counts, "Unreadable run artifact"
	}
	defer f.Close()

	var out []reportNA
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	line := 0
	for scanner.Scan() {
		line++
		var row map[string]interface{}
		dec := json.NewDecoder(strings.NewReader(scanner.Text()))
		dec.UseNumber()
		if err := dec.Decode(&row); err != nil {
			return out, counts, fmt.Sprintf("Malformed JSONL at line %d", line)
		}
		// One object per line, and nothing after it. Trailing JSON on a row is
		// malformed input, not a row with extra decoration to ignore.
		if err := ensureJSONEOF(dec); err != nil {
			return out, counts, fmt.Sprintf("Malformed JSONL at line %d", line)
		}
		counts.total++
		actual, _ := row["actual_verdict"].(string)
		switch actual {
		case "not_applicable":
			counts.notApplicable++
		case "unreachable":
			counts.unreachable++
		case "error":
			counts.errors++
			counts.applicable++
		case "allow", "block", "skip", "warn":
			counts.applicable++
		default:
			// Counting an unrecognized verdict as applicable would let a row
			// reading "banana" inflate the denominator of every rate while the
			// arithmetic still reconciled.
			return out, counts, fmt.Sprintf("Malformed JSONL at line %d", line)
		}
		if actual != "not_applicable" {
			continue
		}
		caseID, ok := row["case_id"].(string)
		if !ok || strings.TrimSpace(caseID) == "" {
			caseID = "Invalid in run artifacts"
		}
		reason := absentFact
		if notes, ok := row["notes"].(string); ok {
			const prefix = "not applicable: "
			if strings.HasPrefix(notes, prefix) && strings.TrimSpace(strings.TrimPrefix(notes, prefix)) != "" {
				reason = strings.TrimSpace(strings.TrimPrefix(notes, prefix))
			}
		}
		out = append(out, reportNA{safeReportText(caseID), safeReportText(reason)})
	}
	if err := scanner.Err(); err != nil {
		return out, counts, "Unreadable run artifact"
	}
	sort.Slice(out, func(i, j int) bool { return out[i].caseID < out[j].caseID })
	return out, counts, "Readable"
}

func safeReportText(value string) string {
	for _, pattern := range reportRestrictedClaims {
		if pattern.MatchString(value) {
			return "Artifact value withheld by claim-language gate"
		}
	}
	value = strings.ReplaceAll(value, "\x00", "")
	return value
}

func nestedValue(data map[string]interface{}, path ...string) (interface{}, bool) {
	var current interface{} = data
	for _, key := range path {
		object, ok := current.(map[string]interface{})
		if !ok {
			return nil, false
		}
		current, ok = object[key]
		if !ok || current == nil {
			return nil, false
		}
	}
	return current, true
}

// firstReportFact returns the first candidate that is actually present. A fact
// the operator never declared reads as an explicit absence rather than an empty
// line, because a blank in a reproduction section is indistinguishable from a
// rendering bug.
func firstReportFact(candidates ...string) string {
	for _, c := range candidates {
		if c != "" && c != absentFact {
			return c
		}
	}
	return absentFact
}

func reportString(doc reportDocument, path ...string) string {
	if doc.data == nil {
		return absentFact
	}
	value, ok := nestedValue(doc.data, path...)
	if !ok {
		return absentFact
	}
	s, ok := value.(string)
	if !ok || strings.TrimSpace(s) == "" {
		return "Invalid in run artifacts"
	}
	return safeReportText(s)
}

func reportBool(doc reportDocument, path ...string) string {
	if doc.data == nil {
		return absentFact
	}
	value, ok := nestedValue(doc.data, path...)
	if !ok {
		return absentFact
	}
	b, ok := value.(bool)
	if !ok {
		return "Invalid in run artifacts"
	}
	return strconv.FormatBool(b)
}

func reportNumber(doc reportDocument, path ...string) string {
	if doc.data == nil {
		return absentFact
	}
	value, ok := nestedValue(doc.data, path...)
	if !ok {
		return absentFact
	}
	switch number := value.(type) {
	case json.Number:
		if _, err := number.Float64(); err != nil {
			return "Invalid in run artifacts"
		}
		return number.String()
	default:
		return "Invalid in run artifacts"
	}
}

func reportPercent(doc reportDocument, path ...string) string {
	if doc.data == nil {
		return absentFact
	}
	value, ok := nestedValue(doc.data, path...)
	if !ok {
		return absentFact
	}
	number, ok := value.(json.Number)
	if !ok {
		return "Invalid in run artifacts"
	}
	f, err := number.Float64()
	if err != nil || f < 0 || f > 1 {
		return "Invalid in run artifacts"
	}
	return strconv.FormatFloat(f*100, 'f', 2, 64) + "%"
}

func reportStringList(doc reportDocument, path ...string) []string {
	if doc.data == nil {
		return []string{absentFact}
	}
	value, ok := nestedValue(doc.data, path...)
	if !ok {
		return []string{absentFact}
	}
	items, ok := value.([]interface{})
	if !ok {
		return []string{"Invalid in run artifacts"}
	}
	if len(items) == 0 {
		return []string{"None declared"}
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		s, ok := item.(string)
		if !ok || strings.TrimSpace(s) == "" {
			out = append(out, "Invalid in run artifacts")
			continue
		}
		out = append(out, safeReportText(s))
	}
	sort.Strings(out)
	return out
}

func markdownInline(value string) string {
	replacer := strings.NewReplacer("\\", "\\\\", "`", "\\`", "*", "\\*", "_", "\\_", "[", "\\[", "]", "\\]", "<", "&lt;", ">", "&gt;", "\n", " ")
	return replacer.Replace(value)
}

func (r *buyerReport) renderMarkdown(w io.Writer) {
	line := func(format string, args ...interface{}) { _, _ = fmt.Fprintf(w, format+"\n", args...) }
	bullet := func(label, value string) { line("- %s: %s", label, markdownInline(value)) }
	list := func(items []string) {
		for _, item := range items {
			line("  - %s", markdownInline(item))
		}
	}

	line("# Agent Egress Bench Run Report")
	line("")
	if reportNumber(r.summary, "schema_version") == "5" {
		line("This report renders facts retained by one Gauntlet run. It does not combine outcome scores or assign a grade, rank, or pass mark.")
	} else {
		line("This report renders facts retained by one Gauntlet run. It does not combine the four metrics or assign a grade, rank, or pass mark.")
	}
	line("")
	line("## Artifact input status")
	line("")
	bullet("raw-summary.json", r.summary.status)
	bullet("results.jsonl", r.resultErr)
	bullet("run-metadata.json", r.metadata.status)
	bullet("run-bundle.json", r.bundle.status)
	bullet("execution-decision.json", r.decision.status)
	line("")
	if problem := r.v4RegistryBindingError(); problem != "" {
		line("## Result unavailable")
		line("")
		line("This active result is uninterpretable: %s.", markdownInline(problem))
		return
	}
	line("## Method identity")
	line("")
	bullet("Repository", firstReportFact(
		reportString(r.summary, "method_repository"),
		reportString(r.metadata, "corpus_repository")))
	bullet("Exact commit", firstReportFact(
		reportString(r.summary, "method_commit"),
		reportString(r.metadata, "corpus_git_sha")))
	bullet("Corpus version", reportString(r.summary, "corpus_version"))
	bullet("Gauntlet version", reportString(r.summary, "gauntlet_version"))
	bullet("Scoring version", reportString(r.summary, "scoring_version"))
	bullet("Runner version", reportString(r.summary, "runner_version"))
	bullet("Run date", reportString(r.summary, "date"))
	bullet("corpus_sha256", reportString(r.summary, "corpus_sha256"))
	line("")
	line("## Target identity")
	line("")
	bullet("Product", reportString(r.summary, "tool"))
	bullet("Version", reportString(r.summary, "tool_version"))
	bullet("Declared configuration", firstReportFact(
		reportString(r.summary, "target_config_ref")))
	bullet("Declared configuration digest", firstReportFact(
		reportString(r.summary, "target_config_sha256")))
	line("")
	line("## Capability profile and adapter")
	line("")
	bullet("tool_profile_sha256", reportString(r.summary, "tool_profile_sha256"))
	bullet("Registry ID", reportString(r.summary, "capability_registry", "id"))
	bullet("Registry format", reportNumber(r.summary, "capability_registry", "format"))
	bullet("Registry revision", reportNumber(r.summary, "capability_registry", "revision"))
	bullet("Registry SHA-256", reportString(r.summary, "capability_registry", "sha256"))
	line("- Reporting labels:")
	list(reportStringList(r.summary, "reported_claims"))
	line("- Exercised transports (this run):")
	list(reportStringList(r.summary, "exercised", "transports"))
	line("- Exercised categories (this run):")
	list(reportStringList(r.summary, "exercised", "categories"))
	line("- Exercised capability tags (this run):")
	list(reportStringList(r.summary, "exercised", "capability_tags"))
	bullet("Adapter identity", r.adapterIdentity())
	bullet("Adapter owner", firstReportFact(reportString(r.summary, "adapter_owner")))
	line("")
	line("## Scope")
	line("")
	bullet("Total cases", reportCount(r.summary, "case_count", "total"))
	bullet("Routed cases", reportCount(r.summary, "case_count", "applicable"))
	if _, present := reportIntegerValue(r.summary, "case_count", "unreachable"); present {
		bullet("Unreachable cases", reportCount(r.summary, "case_count", "unreachable"))
	}
	bullet("Not-applicable cases", reportCount(r.summary, "case_count", "not_applicable"))
	bullet("Error cases", reportCount(r.summary, "case_count", "errors"))
	line("- Not-applicable case IDs and reasons:")
	declaredNA, declaredNAOK := reportIntegerValue(r.summary, "case_count", "not_applicable")
	if r.resultErr != "Readable" {
		list([]string{r.resultErr})
	} else if !declaredNAOK {
		list([]string{"Invalid: the summary does not carry a usable not-applicable count"})
	} else if declaredNA != len(r.results) {
		list([]string{fmt.Sprintf("Invalid: the summary declares %d not-applicable cases but results.jsonl contains %d", declaredNA, len(r.results))})
	} else if len(r.results) == 0 {
		list([]string{"None recorded"})
	} else {
		for _, item := range r.results {
			line("  - `%s`: %s", markdownInline(item.caseID), markdownInline(item.reason))
		}
	}
	line("")
	line("## Metric vector")
	line("")
	if reportNumber(r.summary, "schema_version") == "5" {
		line("Each score stands on its own. Full-corpus scores retain historical N/A rows as misses; error and unreachable rows are excluded and make the measurement incomplete. Applicable-only scores cover only the routed cases this adapter delivered AND observed, so error rows are counted as routed but are excluded from every score denominator.")
		line("")
		line("### Full corpus")
		line("")
		bullet("Containment", reportPercent(r.summary, "scores", "full", "containment"))
		bullet("False-positive rate", reportPercent(r.summary, "scores", "full", "false_positive_rate"))
		line("")
		line("### Applicable-only observed cases")
		line("")
		bullet("Containment", reportPercent(r.summary, "scores", "applicable", "containment"))
		bullet("False-positive rate", reportPercent(r.summary, "scores", "applicable", "false_positive_rate"))
		line("")
		line("### Non-scoring field-presence diagnostics")
		line("")
		line("These observations report only whether a blocked malicious result carried a named field. They do not establish correct detection or proof.")
		line("")
		bullet("Full corpus label present", reportPercent(r.summary, "diagnostics", "full", "classification_present_rate"))
		bullet("Full corpus structured field present", reportPercent(r.summary, "diagnostics", "full", "structured_evidence_present_rate"))
		bullet("Applicable label present", reportPercent(r.summary, "diagnostics", "applicable", "classification_present_rate"))
		bullet("Applicable structured field present", reportPercent(r.summary, "diagnostics", "applicable", "structured_evidence_present_rate"))
	} else {
		line("Each metric stands on its own. Full-corpus scores retain historical N/A rows as misses; error and unreachable rows are excluded and make the measurement incomplete. Applicable-only scores cover only the routed cases this adapter delivered AND observed, so error rows are counted as routed but are excluded from every score denominator.")
		line("")
		line("### Full corpus")
		line("")
		bullet("Containment", reportPercent(r.summary, "scores", "full", "containment"))
		bullet("Detection", reportPercent(r.summary, "scores", "full", "detection"))
		bullet("Evidence", reportPercent(r.summary, "scores", "full", "evidence"))
		bullet("False-positive rate", reportPercent(r.summary, "scores", "full", "false_positive_rate"))
		line("")
		line("### Applicable-only observed cases")
		line("")
		bullet("Containment", reportPercent(r.summary, "scores", "applicable", "containment"))
		bullet("Detection", reportPercent(r.summary, "scores", "applicable", "detection"))
		bullet("Evidence", reportPercent(r.summary, "scores", "applicable", "evidence"))
		bullet("False-positive rate", reportPercent(r.summary, "scores", "applicable", "false_positive_rate"))
	}
	line("")
	line("## Execution and bundle status")
	line("")
	bullet("Execution status", reportString(r.decision, "execution_status"))
	bullet("Execution blocked", reportBool(r.decision, "blocked"))
	bullet("Execution publication eligibility", reportBool(r.decision, "publication_eligible"))
	line("- Execution failures:")
	list(reportStringList(r.decision, "failures"))
	line("- Execution review notes:")
	list(reportStringList(r.decision, "review_notes"))
	bullet("Run-bundle declared validation status", reportString(r.bundle, "bundle_status"))
	bullet("Run-bundle publication eligibility", reportBool(r.bundle, "publication_eligible"))
	line("- Run-bundle noncanonical reasons:")
	list(reportStringList(r.bundle, "noncanonical_reasons"))
	bullet("Publication eligibility recorded by the run", r.publicationEligibility())
	bullet("Run-bundle digest and binding recheck", r.bundleValidation())
	bullet("Execution-decision consistency", r.decisionValidation())
	line("")
	line("These three lines are an internal consistency check. Every input to them, including the digests they compare against, comes from the supplied artifact directory, so they show the retained files agree with each other. They do not authenticate the bundle against anything outside it, and a directory edited as a whole would still reconcile. Independent assurance needs a signature over the bundle from a key the reader already trusts, which this corpus does not yet produce.")
	line("")
	line("## Non-claims")
	line("")
	line("This result does not establish:")
	line("")
	line("- a formal conformance status, accreditation, or pass mark;")
	line("- legal or regulatory compliance;")
	line("- insurance eligibility or pricing;")
	line("- security outside the exercised capability profile;")
	line("- absence of evasions, including variants of classes exercised here.")
	line("")
	line("## Reproduce the run")
	line("")
	line("Run the retained entrypoint command from a checkout of the repository and exact commit listed above. The entrypoint records the runner command and material files used by this result.")
	line("")
	redactedEntrypoint := redactReportCommand(r.entrypoint)
	redactedCommand := redactReportCommand(r.command)
	line("Credential-shaped values in the commands below are replaced with %s. Read them before publishing anyway: local paths and hostnames are preserved so the run can be reproduced, and no denylist recognizes every secret.", redactedValue)
	if reportCommandContainsLocalDetail(redactedEntrypoint) || reportCommandContainsLocalDetail(redactedCommand) {
		line("")
		line("These commands contain absolute paths or URLs from the machine that ran them.")
	}
	line("")
	line("### Entrypoint command")
	line("")
	renderIndented(w, redactedEntrypoint)
	line("")
	line("### Recorded runner command")
	line("")
	renderIndented(w, redactedCommand)
	line("")
	line("### Retained material")
	line("")
	for _, material := range r.materialList() {
		line("- %s", markdownInline(material))
	}
}

func (r *buyerReport) publicationEligibility() string {
	decisionValue, decisionPresent := nestedValue(r.decision.data, "publication_eligible")
	bundleValue, bundlePresent := nestedValue(r.bundle.data, "publication_eligible")
	decision, decisionBool := decisionValue.(bool)
	bundle, bundleBool := bundleValue.(bool)
	if !decisionPresent || !bundlePresent || !decisionBool || !bundleBool {
		return absentFact
	}
	if decision != bundle {
		return "Invalid: execution decision and run bundle disagree"
	}
	if decision {
		if !strings.HasPrefix(r.bundleValidation(), reportSelfConsistentPrefix) ||
			!strings.HasPrefix(r.decisionValidation(), reportSelfConsistentPrefix) {
			return "Not established because retained validation checks are not valid"
		}
		return "Recorded eligible by both retained decisions"
	}
	return "Recorded not eligible by both retained decisions"
}

func renderIndented(w io.Writer, value string) {
	for _, part := range strings.Split(value, "\n") {
		_, _ = fmt.Fprintf(w, "    %s\n", part)
	}
}

func (r *buyerReport) adapterIdentity() string {
	// The runner records the selected adapter in the summary. Reading it there
	// beats recovering it from the command line, which a wrapper script or a
	// quoted invocation can hide, and which nothing hashes.
	if id := reportString(r.summary, "adapter_id"); id != "" && id != absentFact {
		return safeReportText(id)
	}
	return absentFact
}

var reportEvidenceFiles = map[string]string{
	"case_index":              "case-index.json",
	"command":                 "command.txt",
	"corpus_manifest":         "corpus-manifest.txt",
	"entrypoint_command":      "entrypoint-command.txt",
	"pipelock_release":        "pipelock-release.json",
	"pipelock_version_output": "pipelock-version.txt",
	"raw_summary":             "raw-summary.json",
	"release_checksums":       "checksums.txt",
	"results":                 "results.jsonl",
	"run_metadata":            "run-metadata.json",
	"runner_stderr":           "runner.stderr",
	"stats":                   "make-stats.txt",
}

func (r *buyerReport) evidenceFiles() map[string]string {
	files := make(map[string]string, len(reportEvidenceFiles)+3)
	for key, name := range reportEvidenceFiles {
		files[key] = name
	}
	if schema := reportNumber(r.summary, "schema_version"); schema == "4" || schema == "5" {
		files["tool_profile"] = "tool-profile.json"
		files["capability_registry"] = "capability-registry.json"
		files["receipt_profile"] = "receipt-profile.json"
	}
	return files
}

func (r *buyerReport) bundleValidation() string {
	if r.bundle.data == nil {
		return absentFact
	}
	if reportNumber(r.bundle, "schema_version") != "1" {
		return "Invalid: run-bundle schema version is absent or unsupported"
	}
	status := reportString(r.bundle, "bundle_status")
	if status != "complete" && status != "partial" {
		return "Invalid: run-bundle status is absent or unsupported"
	}
	if reportBool(r.bundle, "publication_eligible") == "Invalid in run artifacts" || reportBool(r.bundle, "publication_eligible") == absentFact {
		return "Invalid: run-bundle publication eligibility is absent or malformed"
	}
	value, ok := nestedValue(r.bundle.data, "evidence_sha256")
	hashes, okObject := value.(map[string]interface{})
	if !ok || !okObject || len(hashes) == 0 {
		return "Invalid: evidence digest map is absent or malformed"
	}
	var failures []string
	if status == "complete" {
		if r.summary.data == nil {
			failures = append(failures, "raw-summary.json is not readable JSON")
		}
		if r.metadata.data == nil {
			failures = append(failures, "run-metadata.json is not readable JSON")
		}
		failures = append(failures, r.summaryScopeFailures()...)
		for key := range r.evidenceFiles() {
			if _, present := hashes[key]; !present {
				failures = append(failures, key+" digest is absent from a complete bundle")
			}
		}
		if candidate, present := nestedValue(r.bundle.data, "candidate_scope"); !present {
			failures = append(failures, "candidate_scope is absent from a complete bundle")
		} else if candidateMap, object := candidate.(map[string]interface{}); !object {
			failures = append(failures, "candidate_scope is malformed")
		} else if r.summary.data != nil && r.metadata.data != nil {
			keys := []string{"scoring_version", "runner_version", "tool", "tool_version", "corpus_version", "corpus_sha256", "tool_profile_sha256", "case_count", "scores"}
			if schema := reportNumber(r.summary, "schema_version"); schema == "4" || schema == "5" {
				keys = append(keys, "capability_registry")
			}
			if reportNumber(r.summary, "schema_version") == "5" {
				keys = append(keys, "benchmark_manifest_sha256", "diagnostics")
			}
			for _, key := range keys {
				candidateValue, candidatePresent := candidateMap[key]
				summaryValue, summaryPresent := r.summary.data[key]
				if !candidatePresent || !summaryPresent || candidateValue == nil || summaryValue == nil || !reportValuesEqual(candidateValue, summaryValue) {
					failures = append(failures, "candidate_scope."+key+" does not match raw-summary.json")
				}
			}
			candidateCommit, candidateCommitPresent := candidateMap["corpus_git_sha"]
			metadataCommit, metadataCommitPresent := r.metadata.data["corpus_git_sha"]
			if !candidateCommitPresent || !metadataCommitPresent || candidateCommit == nil || metadataCommit == nil || !reportValuesEqual(candidateCommit, metadataCommit) {
				failures = append(failures, "candidate_scope.corpus_git_sha does not match run-metadata.json")
			}
		}
	}
	for key, raw := range hashes {
		expected, ok := raw.(string)
		if !ok || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(expected) {
			failures = append(failures, key+" has an invalid digest")
			continue
		}
		name, known := r.evidenceFiles()[key]
		if !known {
			failures = append(failures, key+" has no report filename mapping")
			continue
		}
		data, err := readRegularArtifact(r.dir, name)
		if err != nil {
			failures = append(failures, name+" is absent or unreadable")
			continue
		}
		actual := sha256.Sum256(data)
		if hex.EncodeToString(actual[:]) != expected {
			failures = append(failures, name+" digest does not match")
		}
	}
	if len(failures) > 0 {
		sort.Strings(failures)
		return safeReportText("Invalid: " + strings.Join(failures, "; "))
	}
	if status == "partial" {
		return fmt.Sprintf("Incomplete: partial bundle with %d retained evidence digests matching", len(hashes))
	}
	return fmt.Sprintf("%s %d retained evidence digests match the bundle", reportSelfConsistentPrefix, len(hashes))
}

func (r *buyerReport) v4RegistryBindingError() string {
	if schema := reportNumber(r.summary, "schema_version"); schema != "4" && schema != "5" {
		return ""
	}
	value, present := nestedValue(r.summary.data, "capability_registry")
	if !present {
		return "active capability_registry is absent"
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return "active capability_registry is malformed"
	}
	var reference capabilityregistry.Reference
	if err := json.Unmarshal(encoded, &reference); err != nil {
		return "active capability_registry is malformed"
	}
	snapshot, err := readRegularArtifact(r.dir, "capability-registry.json")
	if err != nil {
		return "active capability registry snapshot is absent or unreadable"
	}
	resolved, err := capabilityregistry.ResolveRaw(reference, snapshot)
	if err != nil {
		return "active capability registry snapshot does not match the result"
	}
	// One read, one set of bytes. loadProfile takes a path and reads it again
	// with the symlink-following standard call, so validating through it and
	// hashing through the no-follow read could describe two different files: a
	// link could satisfy the registry check from outside the directory while the
	// digest was computed on something else.
	profileBytes, err := readRegularArtifact(r.dir, "tool-profile.json")
	if err != nil {
		return "active tool profile is invalid"
	}
	var profile Profile
	if decodeErr := decodeStrictJSON(profileBytes, &profile); decodeErr != nil {
		return "active tool profile is invalid"
	}
	if profile.CapabilityRegistry != reference {
		return "active tool profile registry reference does not match the result"
	}
	if capabilityregistry.SHA256(profileBytes) != reportString(r.summary, "tool_profile_sha256") {
		return "active tool profile digest does not match the result"
	}
	reported, err := reportRegistryLabels(r.summary, "reported_claims")
	if err != nil || resolved.ValidateActiveIDs("reported_claim", reported) != nil {
		return "active reported_claims are not active IDs in the retained registry"
	}
	if !sameStrings(profile.Claims, reported) {
		return "active tool profile claims do not match reported_claims"
	}
	tags, err := reportRegistryLabels(r.summary, "exercised", "capability_tags")
	if err != nil || resolved.ValidateActiveIDs("exercised capability_tag", tags) != nil {
		return "active exercised capability_tags are not active IDs in the retained registry"
	}
	return r.v4ReceiptProfileBindingError(reference)
}

// v4ReceiptProfileBindingError confirms that the retained receipt profile is
// attached to this exact v4 run. A matching bundle digest only says the profile
// was retained intact; it cannot establish that the retained profile describes
// the summary, tool profile, and registry snapshot beside it.
func (r *buyerReport) v4ReceiptProfileBindingError(reference capabilityregistry.Reference) string {
	data, err := readRegularArtifact(r.dir, "receipt-profile.json")
	if err != nil {
		return "v4 receipt profile is absent or unreadable"
	}
	var receipt ReceiptProfile
	if err := decodeStrictJSON(data, &receipt); err != nil {
		return "v4 receipt profile is malformed"
	}
	if issues := ValidateReceiptProfile(receipt); len(issues) != 0 {
		return "v4 receipt profile is invalid"
	}
	if receipt.SchemaVersion != v4SchemaVersion {
		return "v4 receipt profile schema version does not match the result"
	}
	if receipt.Tool != reportString(r.summary, "tool") || receipt.ToolVersion != reportString(r.summary, "tool_version") {
		return "v4 receipt profile tool identity does not match the result"
	}
	if receipt.CorpusVersion != reportString(r.summary, "corpus_version") || receipt.CorpusSHA256 != reportString(r.summary, "corpus_sha256") {
		return "v4 receipt profile corpus identity does not match the result"
	}
	if receipt.ToolProfileSHA256 != reportString(r.summary, "tool_profile_sha256") {
		return "v4 receipt profile tool profile digest does not match the result"
	}
	if receipt.CapabilityRegistry != reference {
		return "v4 receipt profile registry reference does not match the result"
	}
	return ""
}

func reportRegistryLabels(doc reportDocument, path ...string) ([]string, error) {
	value, ok := nestedValue(doc.data, path...)
	if !ok {
		return nil, fmt.Errorf("absent labels")
	}
	items, ok := value.([]interface{})
	if !ok {
		return nil, fmt.Errorf("labels are not an array")
	}
	seen := make(map[string]struct{}, len(items))
	labels := make([]string, 0, len(items))
	for _, item := range items {
		label, ok := item.(string)
		if !ok || label == "" {
			return nil, fmt.Errorf("label is invalid")
		}
		if _, duplicate := seen[label]; duplicate {
			return nil, fmt.Errorf("duplicate label")
		}
		seen[label] = struct{}{}
		labels = append(labels, label)
	}
	return labels, nil
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func (r *buyerReport) summaryScopeFailures() []string {
	total, totalOK := reportIntegerValue(r.summary, "case_count", "total")
	applicable, applicableOK := reportIntegerValue(r.summary, "case_count", "applicable")
	unreachable, unreachableOK := reportIntegerValue(r.summary, "case_count", "unreachable")
	notApplicable, notApplicableOK := reportIntegerValue(r.summary, "case_count", "not_applicable")
	errors, errorsOK := reportIntegerValue(r.summary, "case_count", "errors")
	if !totalOK || !applicableOK || !notApplicableOK || !errorsOK {
		return []string{"summary case counts are absent or malformed"}
	}
	// Frozen v3 records predate the explicit unreachable count. They are read
	// under their frozen semantics, where absence means no emitted unreachable
	// row, rather than being rewritten to the active runner's output shape.
	if !unreachableOK {
		unreachable = 0
	}
	var failures []string
	if applicable+unreachable+notApplicable != total {
		failures = append(failures, "summary applicable, unreachable, and not-applicable counts do not sum to total")
	}
	if errors > applicable {
		failures = append(failures, "summary error count exceeds applicable count")
	}
	reasonsValue, reasonsPresent := nestedValue(r.summary.data, "case_count", "not_applicable_reasons")
	reasons, reasonsObject := reasonsValue.(map[string]interface{})
	if !reasonsPresent || !reasonsObject {
		failures = append(failures, "summary not-applicable reasons are absent or malformed")
		return failures
	}
	reasonTotal := 0
	for reason, raw := range reasons {
		if strings.TrimSpace(reason) == "" {
			failures = append(failures, "summary has an empty not-applicable reason")
			continue
		}
		number, numberOK := raw.(json.Number)
		if !numberOK {
			failures = append(failures, "summary not-applicable reason count is malformed")
			continue
		}
		// Atoi returns an int directly and reports ErrRange on overflow, so
		// there is no widening conversion to bound. The previous round-trip
		// check was correct but static analysis cannot see that it is.
		parsed, err := strconv.Atoi(number.String())
		if err != nil || parsed < 0 {
			failures = append(failures, "summary not-applicable reason count is malformed")
			continue
		}
		reasonTotal += parsed
	}
	if reasonTotal != notApplicable {
		failures = append(failures, "summary not-applicable reasons do not sum to the not-applicable count")
	}
	if r.resultErr != "Readable" {
		// Nothing downstream can be checked against rows that could not be
		// read. Skipping the comparison silently would let an unreadable
		// results file render as a self-consistent bundle.
		failures = append(failures, fmt.Sprintf("results.jsonl could not be validated: %s", r.resultErr))
	}
	if r.resultErr == "Readable" {
		if len(r.results) != notApplicable {
			failures = append(failures, "results.jsonl not-applicable rows do not match the summary count")
		}
		// The summary declares these; results.jsonl is the evidence for them.
		// A declaration the rows do not support is the failure a reader most
		// needs named, because every rate above is computed from it.
		for _, c := range []struct {
			label            string
			declared, actual int
		}{
			{"total", total, r.rowCounts.total},
			{"applicable", applicable, r.rowCounts.applicable},
			{"unreachable", unreachable, r.rowCounts.unreachable},
			{"error", errors, r.rowCounts.errors},
		} {
			if declared, actual := c.declared, c.actual; declared != actual {
				failures = append(failures, fmt.Sprintf(
					"summary declares %d %s cases but results.jsonl contains %d", declared, c.label, actual))
			}
		}
	}
	return failures
}

func reportValuesEqual(left, right interface{}) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}

func reportIntegerValue(doc reportDocument, path ...string) (int, bool) {
	if doc.data == nil {
		return 0, false
	}
	value, ok := nestedValue(doc.data, path...)
	if !ok {
		return 0, false
	}
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	parsed, err := strconv.Atoi(number.String())
	if err != nil || parsed < 0 {
		return 0, false
	}
	return parsed, true
}

func reportCount(doc reportDocument, path ...string) string {
	value, ok := reportIntegerValue(doc, path...)
	if !ok {
		if doc.data == nil {
			return absentFact
		}
		if _, present := nestedValue(doc.data, path...); !present {
			return absentFact
		}
		return "Invalid in run artifacts"
	}
	return strconv.Itoa(value)
}

func (r *buyerReport) decisionValidation() string {
	if r.decision.data == nil || r.bundle.data == nil {
		return absentFact
	}
	if reportNumber(r.decision, "schema_version") != "1" {
		return "Invalid: execution-decision schema version is absent or unsupported"
	}
	blockedValue, blockedOK := nestedValue(r.decision.data, "blocked")
	blocked, blockedBool := blockedValue.(bool)
	status := reportString(r.decision, "execution_status")
	eligibleValue, eligibleOK := nestedValue(r.decision.data, "publication_eligible")
	eligible, eligibleBool := eligibleValue.(bool)
	if !blockedOK || !blockedBool || !eligibleOK || !eligibleBool || (status != "complete" && status != "blocked") {
		return "Invalid: execution decision fields are absent or malformed"
	}
	if (status == "complete") == blocked {
		return "Invalid: execution status and blocked flag contradict each other"
	}
	if blocked && eligible {
		return "Invalid: a blocked execution is marked publication-eligible"
	}
	decisionID := reportString(r.decision, "local_run_id")
	bundleID := reportString(r.bundle, "local_run_id")
	if decisionID == absentFact || bundleID == absentFact || decisionID != bundleID {
		return "Invalid: local run identifiers do not match"
	}
	decisionHashes, decisionOK := nestedValue(r.decision.data, "evidence_sha256")
	bundleHashes, bundleOK := nestedValue(r.bundle.data, "evidence_sha256")
	if !decisionOK || !bundleOK {
		return "Invalid: evidence digest map is absent"
	}
	decisionJSON, _ := json.Marshal(decisionHashes)
	bundleJSON, _ := json.Marshal(bundleHashes)
	if !bytes.Equal(decisionJSON, bundleJSON) {
		return "Invalid: execution and bundle evidence digests differ"
	}
	return reportSelfConsistentPrefix + " run identifier and evidence digests match the bundle"
}

func (r *buyerReport) materialList() []string {
	if r.bundle.data == nil {
		return []string{absentFact}
	}
	value, ok := nestedValue(r.bundle.data, "evidence_sha256")
	hashes, okObject := value.(map[string]interface{})
	if !ok || !okObject || len(hashes) == 0 {
		return []string{absentFact}
	}
	var items []string
	for key, raw := range hashes {
		name, known := r.evidenceFiles()[key]
		if !known {
			name = key
		}
		digest, ok := raw.(string)
		if !ok {
			digest = "Invalid in run artifacts"
		}
		items = append(items, name+" (sha256 "+safeReportText(digest)+")")
	}
	sort.Strings(items)
	return items
}
