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
	"math"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	capabilityregistry "github.com/luckyPipewrench/agent-egress-bench/capability-registry"
)

const absentFact = "Absent from run artifacts"

const (
	frozenV5SummaryV4ReceiptSummarySHA256 = "1e182405cdff08f8f0e8835c7c0aed7047b4c0e2fbd539f22c390175d5507b64"
	frozenV5SummaryV4ReceiptSHA256        = "2beeb7194b0e1a5f610198e2d4e29ddb793f8213177627cb9f0de4775f36481b"
)

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
	raw    []byte
	status string
}

type reportNA struct {
	caseID string
	reason string
}

type reportFailure struct {
	caseID   string
	expected string
	actual   string
}

type buyerReport struct {
	dir        string
	summary    reportDocument
	metadata   reportDocument
	bundle     reportDocument
	decision   reportDocument
	results    []reportNA
	failures   []reportFailure
	resultErr  string
	rowCounts  reportRowCounts
	command    string
	entrypoint string
}

type reportCategoryProfile struct {
	rows           []reportCategoryProfileRow
	maliciousTotal int
	benignTotal    int
	unavailable    string
}

type reportCategoryProfileRow struct {
	category     string
	blocked      int
	malicious    int
	falseBlocked int
	benign       int
}

type reportProfileCase struct {
	category string
	expected string
}

type reportProfileResult struct {
	caseID   string
	expected string
	actual   string
	observed bool
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

// generatePublicationLockup emits neutral, copy-ready presentation text from
// the same retained facts the buyer report verifies. It deliberately carries
// no publisher logo, badge, or pass/fail judgment. Assurance labels are explicit
// publisher declarations, while these method and scope facts must remain
// adjacent to any displayed score.
func generatePublicationLockup(dir, outputPath string, assurances []string, evidenceURL string) error {
	report, err := loadBuyerReport(dir)
	if err != nil {
		return err
	}
	if reportNumber(report.summary, "schema_version") != "5" {
		return fmt.Errorf("publication lockup requires a v5 summary")
	}
	if failures := report.summaryScopeFailures(); len(failures) > 0 {
		return fmt.Errorf("publication lockup scope is invalid: %s", strings.Join(failures, "; "))
	}
	if report.rowCounts.scored != report.rowCounts.total {
		return fmt.Errorf("publication lockup requires every result row to carry a score")
	}
	if failures := report.publicationScoreFailures(); len(failures) > 0 {
		return fmt.Errorf("publication lockup scores are invalid: %s", strings.Join(failures, "; "))
	}
	if bindingError := report.v4RegistryBindingError(); bindingError != "" {
		return fmt.Errorf("publication lockup registry binding is invalid: %s", bindingError)
	}
	if len(assurances) == 0 {
		return fmt.Errorf("publication lockup requires at least one publisher-declared assurance label")
	}
	allowedAssurance := map[string]bool{
		"self-run": true, "artifact-validated": true, "independently-executed": true,
		"transparency-registered": true, "challenge-verified": true,
	}
	seenAssurance := make(map[string]bool, len(assurances))
	for _, assurance := range assurances {
		if !allowedAssurance[assurance] || seenAssurance[assurance] {
			return fmt.Errorf("publication lockup assurance label is invalid or duplicated: %q", assurance)
		}
		seenAssurance[assurance] = true
	}
	if seenAssurance["artifact-validated"] && !report.publicationEligible() {
		return fmt.Errorf("publication lockup artifact-validated label requires a complete self-consistent AEB bundle")
	}
	if reason := report.retainedPublicationRefusal(); reason != "" {
		return fmt.Errorf("publication lockup refuses retained publication decision: %s", reason)
	}
	parsedEvidenceURL, parseErr := url.Parse(evidenceURL)
	if parseErr != nil || parsedEvidenceURL.Scheme != "https" || parsedEvidenceURL.Host == "" || parsedEvidenceURL.User != nil {
		return fmt.Errorf("publication lockup requires a public HTTPS evidence URL")
	}
	if safeReportText(evidenceURL) != evidenceURL {
		return fmt.Errorf("publication lockup evidence URL contains restricted claim language")
	}

	required := map[string]string{
		"tool":                        reportString(report.summary, "tool"),
		"tool version":                reportString(report.summary, "tool_version"),
		"method repository":           reportString(report.summary, "method_repository"),
		"method commit":               reportString(report.summary, "method_commit"),
		"corpus version":              reportString(report.summary, "corpus_version"),
		"scoring version":             reportString(report.summary, "scoring_version"),
		"benchmark manifest digest":   reportString(report.summary, "benchmark_manifest_sha256"),
		"profile digest":              reportString(report.summary, "tool_profile_sha256"),
		"adapter":                     reportString(report.summary, "adapter_id"),
		"adapter owner":               reportString(report.summary, "adapter_owner"),
		"target configuration":        reportString(report.summary, "target_config_ref"),
		"target configuration digest": reportString(report.summary, "target_config_sha256"),
		"date":                        reportString(report.summary, "date"),
		"run id":                      reportString(report.metadata, "local_run_id"),
		"measurement status":          reportString(report.summary, "measurement_status"),
		"total":                       reportNumber(report.summary, "case_count", "total"),
		"applicable":                  reportNumber(report.summary, "case_count", "applicable"),
		"unreachable":                 reportNumber(report.summary, "case_count", "unreachable"),
		"not applicable":              reportNumber(report.summary, "case_count", "not_applicable"),
		"errors":                      reportNumber(report.summary, "case_count", "errors"),
		"containment":                 reportPercent(report.summary, "scores", "full", "containment"),
		"false-positive rate":         reportPercent(report.summary, "scores", "full", "false_positive_rate"),
	}
	if receipt, ok := report.receiptProfile(); ok && receipt.SchemaVersion == activeReceiptProfileSchemaVersion {
		required["corpus Git observation"] = receipt.CorpusGitStatus
		required["tool version observation"] = receipt.ObservedToolVersion.Status
	}
	for name, value := range required {
		if value == absentFact || value == "Invalid in run artifacts" || value == "Artifact value withheld by claim-language gate" || strings.TrimSpace(value) == "" {
			return fmt.Errorf("publication lockup requires %s", name)
		}
	}
	if required["measurement status"] != measurementStatusMeasured {
		return fmt.Errorf("publication lockup refuses measurement status %q", required["measurement status"])
	}
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(required["method commit"]) {
		return fmt.Errorf("publication lockup requires a full lowercase Git commit")
	}
	for _, name := range []string{"benchmark manifest digest", "profile digest", "target configuration digest"} {
		if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(required[name]) {
			return fmt.Errorf("publication lockup requires a valid %s", name)
		}
	}
	if metadataRepository := reportString(report.metadata, "corpus_repository"); metadataRepository != required["method repository"] {
		return fmt.Errorf("publication lockup method repository does not match run metadata")
	}
	if metadataCommit := reportString(report.metadata, "corpus_git_sha"); metadataCommit != required["method commit"] {
		return fmt.Errorf("publication lockup method commit does not match run metadata")
	}
	for _, doc := range []reportDocument{report.bundle, report.decision} {
		if len(doc.data) > 0 && reportString(doc, "local_run_id") != required["run id"] {
			return fmt.Errorf("publication lockup run id does not match %s", doc.name)
		}
	}

	registryID := reportString(report.summary, "capability_registry", "id")
	registryFormat := reportNumber(report.summary, "capability_registry", "format")
	registryRevision := reportNumber(report.summary, "capability_registry", "revision")
	registrySHA := reportString(report.summary, "capability_registry", "sha256")
	for name, value := range map[string]string{"registry ID": registryID, "registry format": registryFormat, "registry revision": registryRevision, "registry digest": registrySHA} {
		if value == absentFact || value == "Invalid in run artifacts" {
			return fmt.Errorf("publication lockup requires %s", name)
		}
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(registrySHA) {
		return fmt.Errorf("publication lockup requires a valid registry digest")
	}
	coverage := map[string][]string{
		"transports":   reportStringList(report.summary, "exercised", "transports"),
		"categories":   reportStringList(report.summary, "exercised", "categories"),
		"capabilities": reportStringList(report.summary, "exercised", "capability_tags"),
	}
	for name, values := range coverage {
		invalid := len(values) == 0
		for _, value := range values {
			if value == absentFact || value == "Invalid in run artifacts" || value == "None declared" {
				invalid = true
				break
			}
		}
		if invalid {
			return fmt.Errorf("publication lockup requires exercised %s", name)
		}
	}
	naReasons, reasonsOK := reportCountMap(report.summary, "case_count", "not_applicable_reasons")
	if !reasonsOK {
		return fmt.Errorf("publication lockup requires not-applicable reasons")
	}
	assuranceText := make([]string, len(assurances))
	for i, assurance := range assurances {
		assuranceText[i] = strings.ReplaceAll(assurance, "-", " ")
	}
	var out bytes.Buffer
	line := func(format string, args ...interface{}) { _, _ = fmt.Fprintf(&out, format+"\n", args...) }
	line("**%s %s — Agent Egress Bench result**", markdownInline(required["tool"]), markdownInline(required["tool version"]))
	line("")
	line("Publisher-declared assurance: **%s** · evidence: %s", markdownInline(strings.Join(assuranceText, ", ")), markdownInline(evidenceURL))
	line("")
	line("Agent Egress Bench `%s@%s` · corpus `%s` · scoring `%s` · manifest `sha256:%s`", markdownInline(required["method repository"]), markdownInline(required["method commit"]), markdownInline(required["corpus version"]), markdownInline(required["scoring version"]), markdownInline(required["benchmark manifest digest"]))
	line("")
	if len(report.failures) > 0 {
		caseURLs, linkErr := report.stableCaseURLs()
		if linkErr != nil {
			return fmt.Errorf("publication lockup requires stable failed-case links: %w", linkErr)
		}
		line("Failed cases:")
		for _, failure := range report.failures {
			caseURL, ok := caseURLs[failure.caseID]
			if !ok {
				return fmt.Errorf("publication lockup requires a stable link for failed case %q: case ID is absent from the retained corpus manifest", failure.caseID)
			}
			line("- [%s](%s): expected `%s`, observed `%s`.", markdownInline(failure.caseID), caseURL, failure.expected, failure.actual)
		}
		line("")
	}
	line("%s total · %s applicable · %s unreachable · %s not applicable · %s errors · containment %s (%d/%d malicious cases; case-equal weighting from corpus composition) · false-positive rate %s (%d/%d benign cases; case-equal weighting from corpus composition)", required["total"], required["applicable"], required["unreachable"], required["not applicable"], required["errors"], required["containment"], report.rowCounts.maliciousBlocked, report.rowCounts.maliciousTotal, required["false-positive rate"], report.rowCounts.benignFalsePositives, report.rowCounts.benignTotal)
	if len(naReasons) > 0 {
		line("Not-applicable reasons: %s", markdownInline(strings.Join(naReasons, ", ")))
	}
	line("")
	line("Registry `%s` format %s revision %s (`sha256:%s`) · profile `sha256:%s`", markdownInline(registryID), registryFormat, registryRevision, markdownInline(registrySHA), markdownInline(required["profile digest"]))
	if corpusStatus, ok := required["corpus Git observation"]; ok {
		line("Corpus Git observation: `%s` · tool version observation: `%s`", markdownInline(corpusStatus), markdownInline(required["tool version observation"]))
	}
	line("")
	line("Exercised transports: %s", markdownInline(strings.Join(coverage["transports"], ", ")))
	line("Exercised categories: %s", markdownInline(strings.Join(coverage["categories"], ", ")))
	line("Exercised capabilities: %s", markdownInline(strings.Join(coverage["capabilities"], ", ")))
	line("")
	line("Adapter `%s` owned by %s · target configuration `%s` (`sha256:%s`) · measured %s · run `%s`", markdownInline(required["adapter"]), markdownInline(required["adapter owner"]), markdownInline(required["target configuration"]), markdownInline(required["target configuration digest"]), markdownInline(required["date"]), markdownInline(required["run id"]))
	line("")
	line("Reproduce and verify with the published command, raw evidence, normalized decisions, profile, and registry snapshot. The artifact-directory checks establish internal consistency only; they do not authenticate who produced the directory or when. This result is not a certification, accreditation, audit, endorsement, pass mark, compliance determination, insurance determination, or claim about unexercised behavior or the absence of bypasses.")

	if outputPath == "-" {
		_, err = os.Stdout.Write(out.Bytes())
		return err
	}
	if err := os.WriteFile(outputPath, out.Bytes(), 0o600); err != nil {
		return fmt.Errorf("writing publication lockup to %s: %w", outputPath, err)
	}
	return nil
}

func (r *buyerReport) stableCaseURLs() (map[string]string, error) {
	repository := reportString(r.summary, "method_repository")
	commit := reportString(r.summary, "method_commit")
	repositoryParts := strings.Split(repository, "/")
	if !regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`).MatchString(repository) ||
		len(repositoryParts) != 2 || repositoryParts[0] == "." || repositoryParts[0] == ".." ||
		repositoryParts[1] == "." || repositoryParts[1] == ".." {
		return nil, fmt.Errorf("method repository is not an owner/name pair")
	}
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(commit) {
		return nil, fmt.Errorf("method commit is not a full lowercase Git commit")
	}
	manifest, err := readRegularArtifact(r.dir, "corpus-manifest.txt")
	if err != nil {
		return nil, fmt.Errorf("reading corpus manifest: %w", err)
	}
	text := strings.ReplaceAll(string(manifest), "\r\n", "\n")
	lines := strings.Split(text, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	if len(lines) == 0 {
		return nil, fmt.Errorf("corpus manifest is empty")
	}
	urls := make(map[string]string, len(lines))
	for index, caseID := range lines {
		if caseID == "" || strings.TrimSpace(caseID) != caseID {
			return nil, fmt.Errorf("corpus manifest must contain one case ID per physical line")
		}
		if _, duplicate := urls[caseID]; duplicate {
			return nil, fmt.Errorf("corpus manifest contains duplicate case ID %q", caseID)
		}
		urls[caseID] = fmt.Sprintf("https://github.com/%s/blob/%s/cases/MANIFEST.txt#L%d", repository, commit, index+1)
	}
	return urls, nil
}

func (r *buyerReport) retainedPublicationRefusal() string {
	if r.decision.status != absentFact {
		if blocked, ok := r.decision.data["blocked"].(bool); !ok || blocked {
			return "execution decision is blocked or invalid"
		}
		if eligible, ok := r.decision.data["publication_eligible"].(bool); !ok || !eligible {
			return "execution decision is ineligible or invalid"
		}
	}
	if r.bundle.status != absentFact {
		if eligible, ok := r.bundle.data["publication_eligible"].(bool); !ok || !eligible {
			return "run bundle is ineligible or invalid"
		}
	}
	return ""
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
	resultMode := reportResultsUnbound
	switch reportNumber(r.summary, "schema_version") {
	case "4":
		resultMode = reportResultsFrozen
	case "5":
		resultMode = reportResultsActive
	}
	expectedScoringVersion := reportString(r.summary, "scoring_version")
	if expectedScoringVersion == absentFact || expectedScoringVersion == "Invalid in run artifacts" || expectedScoringVersion == "Artifact value withheld by claim-language gate" {
		expectedScoringVersion = ""
	}
	r.results, r.failures, r.rowCounts, r.resultErr = loadReportResults(filepath.Join(dir, "results.jsonl"), resultMode, expectedScoringVersion)
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
	// A zero-byte artifact is refused here rather than in each reader, because
	// each reader answered it differently and one answered it wrong: the results
	// scanner read no rows, reported no error, and returned "Readable", so an
	// empty file was described to the operator as a readable artifact. The digest
	// path would equally have hashed an empty slice. Refusing once, where the
	// descriptor is open and its size already known, is the only place all of
	// them share.
	if info.Size() == 0 {
		_ = handle.Close()
		return nil, errEmptyArtifact
	}
	return handle, nil
}

// readRegularArtifact reads a report input, refusing anything that is not a
// regular file. The report states facts about a run, and a file outside the run
// directory is not one.
// maxReportArtifactBytes bounds every run-artifact read. Run artifacts are
// untrusted input, so an unbounded read lets one oversized file exhaust memory
// and take report generation down with it. The largest artifact this repository
// has ever retained is well under a megabyte, so this ceiling is generous by
// several orders of magnitude and exists to fail closed, not to be tight.
const maxReportArtifactBytes = 64 << 20

func readRegularArtifact(dir, name string) ([]byte, error) {
	handle, err := openRegularArtifact(dir, name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = handle.Close() }()
	// Read one byte past the ceiling so an artifact sitting exactly at the
	// limit is still accepted and anything larger is detected rather than
	// silently truncated, which would be worse than refusing it outright.
	data, err := io.ReadAll(io.LimitReader(handle, maxReportArtifactBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxReportArtifactBytes {
		return nil, errArtifactTooLarge
	}
	return data, nil
}

// Compiled once at package scope. These ran per case entry and per result row,
// so a full corpus recompiled the same expressions thousands of times per
// report. The file already keeps reportRestrictedClaims this way.
var (
	reportProfileCaseIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,127}$`)
	reportProfileDigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

var (
	errNotRegularArtifact = errors.New("run artifact is not a regular file")
	errEmptyArtifact      = errors.New("run artifact is empty")
	errArtifactTooLarge   = errors.New("run artifact exceeds the maximum readable size")
)

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
	if errors.Is(err, errEmptyArtifact) {
		doc.status = "Invalid in run artifacts: empty file"
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
	doc.raw = data
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
	if errors.Is(err, errEmptyArtifact) {
		return "Invalid in run artifacts: empty file"
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

// categoryProfile reconstructs the applicable-only category profiles from the
// two retained inputs that bind case identity to observed outcomes. The
// summary's per_category.applicable count cannot supply either denominator:
// it includes malicious and benign rows, so using it would overstate both
// category-specific scopes.
func (r *buyerReport) categoryProfile() reportCategoryProfile {
	if reportNumber(r.summary, "schema_version") != "5" {
		return reportCategoryProfile{unavailable: "requires a v5 summary and bound active evidence"}
	}
	indexData, unavailable := r.categoryProfileArtifact("case_index", "case-index.json")
	if unavailable != "" {
		return reportCategoryProfile{unavailable: unavailable}
	}
	resultsData, unavailable := r.categoryProfileArtifact("results", "results.jsonl")
	if unavailable != "" {
		return reportCategoryProfile{unavailable: unavailable}
	}
	if failures := r.summaryScopeFailures(); len(failures) > 0 {
		return reportCategoryProfile{unavailable: "the summary scope does not match the retained result rows"}
	}
	cases, parseFailure := parseReportProfileCaseIndex(indexData)
	if parseFailure != "" {
		return reportCategoryProfile{unavailable: parseFailure}
	}
	results, parseFailure := parseReportProfileResults(resultsData)
	if parseFailure != "" {
		return reportCategoryProfile{unavailable: parseFailure}
	}
	if len(cases) != len(results) {
		return reportCategoryProfile{unavailable: "the case index and result rows have different case IDs"}
	}

	byCategory := make(map[string]reportCategoryProfileRow)
	for caseID, c := range cases {
		result, present := results[caseID]
		if !present || result.expected != c.expected {
			return reportCategoryProfile{unavailable: "the case index and result rows have different case IDs or expected verdicts"}
		}
		row := byCategory[c.category]
		row.category = c.category
		if result.observed {
			switch c.expected {
			case "block":
				row.malicious++
				if result.actual == "block" {
					row.blocked++
				}
			case "allow":
				row.benign++
				if result.actual == "block" {
					row.falseBlocked++
				}
			}
		}
		byCategory[c.category] = row
	}

	profile := reportCategoryProfile{rows: make([]reportCategoryProfileRow, 0, len(byCategory))}
	for _, row := range byCategory {
		profile.rows = append(profile.rows, row)
		profile.maliciousTotal += row.malicious
		profile.benignTotal += row.benign
	}
	sort.Slice(profile.rows, func(i, j int) bool { return profile.rows[i].category < profile.rows[j].category })
	if !r.matchesApplicableContainment(profile) {
		return reportCategoryProfile{unavailable: "the applicable containment does not match the bound result rows"}
	}
	if !r.matchesApplicableFalsePositiveRate(profile) {
		return reportCategoryProfile{unavailable: "the applicable false-positive rate does not match the bound result rows"}
	}
	return profile
}

// categoryProfileArtifact returns a retained input only when the run bundle
// binds its exact bytes. A buyer report remains useful without this optional
// profile, but a profile without this check could turn a replaced input into a
// reassuring composition display.
func (r *buyerReport) categoryProfileArtifact(key, name string) ([]byte, string) {
	if r.bundle.data == nil {
		return nil, "the run bundle does not bind " + name
	}
	value, present := nestedValue(r.bundle.data, "evidence_sha256", key)
	expected, digestOK := value.(string)
	if !present || !digestOK || !reportProfileDigestPattern.MatchString(expected) {
		return nil, "the run bundle does not carry a valid " + name + " digest"
	}
	data, err := readRegularArtifact(r.dir, name)
	if err != nil {
		return nil, name + " is absent or unreadable"
	}
	actual := sha256.Sum256(data)
	if hex.EncodeToString(actual[:]) != expected {
		return nil, name + " does not match its retained digest"
	}
	return data, ""
}

func parseReportProfileCaseIndex(data []byte) (map[string]reportProfileCase, string) {
	index, err := decodeReportJSONObject(data)
	if err != nil {
		return nil, "case-index.json is malformed"
	}
	version, versionOK := reportJSONInteger(index["schema_version"])
	if !versionOK || (version != 2 && version != 3) || !reportExactKeys(index, "schema_version", "cases") {
		return nil, "case-index.json has an unsupported schema"
	}
	rawCases, casesOK := index["cases"].(map[string]interface{})
	if !casesOK || len(rawCases) == 0 {
		return nil, "case-index.json has no usable cases"
	}
	cases := make(map[string]reportProfileCase, len(rawCases))
	for caseID, raw := range rawCases {
		if !reportProfileCaseIDPattern.MatchString(caseID) {
			return nil, "case-index.json has an invalid case ID"
		}
		entry, entryOK := raw.(map[string]interface{})
		if !entryOK || !reportExactKeys(entry, reportCaseIndexKeys(version)...) {
			return nil, "case-index.json has an invalid case entry"
		}
		category, categoryOK := entry["category"].(string)
		expected, expectedOK := entry["expected_verdict"].(string)
		if !categoryOK || strings.TrimSpace(category) == "" || !expectedOK || (expected != "block" && expected != "allow") {
			return nil, "case-index.json has an invalid case entry"
		}
		if version == 3 && !reportProfileCaseIndexV3EntryValid(entry) {
			return nil, "case-index.json has an invalid case entry"
		}
		cases[caseID] = reportProfileCase{category: category, expected: expected}
	}
	return cases, ""
}

func reportCaseIndexKeys(version int) []string {
	if version == 3 {
		return []string{"category", "expected_verdict", "transport", "capability_tags"}
	}
	return []string{"category", "expected_verdict"}
}

func reportProfileCaseIndexV3EntryValid(entry map[string]interface{}) bool {
	transport, transportOK := entry["transport"].(string)
	tags, tagsOK := entry["capability_tags"].([]interface{})
	if !transportOK || strings.TrimSpace(transport) == "" || !tagsOK || len(tags) == 0 {
		return false
	}
	seen := make(map[string]struct{}, len(tags))
	for _, raw := range tags {
		tag, tagOK := raw.(string)
		if !tagOK || strings.TrimSpace(tag) == "" {
			return false
		}
		if _, duplicate := seen[tag]; duplicate {
			return false
		}
		seen[tag] = struct{}{}
	}
	return true
}

func parseReportProfileResults(data []byte) (map[string]reportProfileResult, string) {
	results := make(map[string]reportProfileResult)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for line := 1; scanner.Scan(); line++ {
		row, err := decodeReportJSONObject([]byte(scanner.Text()))
		if err != nil {
			return nil, "results.jsonl is malformed"
		}
		caseID, caseIDOK := row["case_id"].(string)
		expected, expectedOK := row["expected_verdict"].(string)
		actual, actualOK := row["actual_verdict"].(string)
		score, scoreOK := row["score"].(string)
		evidence, evidenceOK := row["evidence"].(map[string]interface{})
		state, stateOK := evidence["result_state"].(string)
		if !caseIDOK || !reportProfileCaseIDPattern.MatchString(caseID) || !expectedOK ||
			(expected != "block" && expected != "allow") || !actualOK || !scoreOK || !evidenceOK || !stateOK {
			return nil, "results.jsonl has an invalid row"
		}
		if _, duplicate := results[caseID]; duplicate {
			return nil, "results.jsonl has duplicate case IDs"
		}
		observed := actual == "block" || actual == "allow"
		if observed && ((score != "pass" && score != "fail") || state != "observed") {
			return nil, "results.jsonl has an invalid observed row"
		}
		if actual == "unreachable" && (score != "error" || state != "unreachable") {
			return nil, "results.jsonl has an invalid unreachable row"
		}
		if actual == "error" && (score != "error" || !reportErrorResultState(state)) {
			return nil, "results.jsonl has an invalid error row"
		}
		if !observed && actual != "unreachable" && actual != "error" {
			return nil, "results.jsonl has an invalid row"
		}
		results[caseID] = reportProfileResult{caseID: caseID, expected: expected, actual: actual, observed: observed}
	}
	if err := scanner.Err(); err != nil || len(results) == 0 {
		return nil, "results.jsonl is malformed"
	}
	return results, ""
}

func reportErrorResultState(state string) bool {
	switch state {
	case "adapter_error", "delivery_unavailable", "verdict_unobservable", "invalid_verdict":
		return true
	default:
		return false
	}
}

func decodeReportJSONObject(data []byte) (map[string]interface{}, error) {
	var object map[string]interface{}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&object); err != nil {
		return nil, err
	}
	if object == nil {
		return nil, errors.New("expected JSON object")
	}
	if err := ensureJSONEOF(dec); err != nil {
		return nil, err
	}
	return object, nil
}

func reportExactKeys(object map[string]interface{}, allowed ...string) bool {
	if len(object) != len(allowed) {
		return false
	}
	for _, key := range allowed {
		if _, present := object[key]; !present {
			return false
		}
	}
	return true
}

func reportJSONInteger(value interface{}) (int, bool) {
	number, numberOK := value.(json.Number)
	if !numberOK {
		return 0, false
	}
	parsed, err := strconv.Atoi(number.String())
	return parsed, err == nil
}

func (r *buyerReport) matchesApplicableContainment(profile reportCategoryProfile) bool {
	scores, scoresOK := r.summary.data["scores"].(map[string]interface{})
	applicable, applicableOK := scores["applicable"].(map[string]interface{})
	value, present := applicable["containment"]
	if !scoresOK || !applicableOK || !present {
		return false
	}
	if profile.maliciousTotal == 0 {
		return value == nil
	}
	observed, numberOK := value.(json.Number)
	if !numberOK {
		return false
	}
	blocked := 0
	for _, row := range profile.rows {
		blocked += row.blocked
	}
	ratio, err := observed.Float64()
	expected := float64(blocked) / float64(profile.maliciousTotal)
	return err == nil && !math.IsNaN(ratio) && !math.IsInf(ratio, 0) && math.Abs(ratio-expected) <= 1e-12
}

func (r *buyerReport) matchesApplicableFalsePositiveRate(profile reportCategoryProfile) bool {
	scores, scoresOK := r.summary.data["scores"].(map[string]interface{})
	applicable, applicableOK := scores["applicable"].(map[string]interface{})
	value, present := applicable["false_positive_rate"]
	if !scoresOK || !applicableOK || !present {
		return false
	}
	if profile.benignTotal == 0 {
		return value == nil
	}
	observed, numberOK := value.(json.Number)
	if !numberOK {
		return false
	}
	falseBlocked := 0
	for _, row := range profile.rows {
		falseBlocked += row.falseBlocked
	}
	ratio, err := observed.Float64()
	expected := float64(falseBlocked) / float64(profile.benignTotal)
	return err == nil && !math.IsNaN(ratio) && !math.IsInf(ratio, 0) && math.Abs(ratio-expected) <= 1e-12
}

// reportRowCounts is what results.jsonl actually contains, as opposed to what
// the summary declares about it. Comparing the two is the only way the report
// can tell a reader the scope arithmetic holds.
type reportRowCounts struct {
	total                int
	scored               int
	applicable           int
	unreachable          int
	notApplicable        int
	errors               int
	maliciousTotal       int
	maliciousBlocked     int
	benignTotal          int
	benignFalsePositives int
}

type reportResultMode uint8

const (
	reportResultsUnbound reportResultMode = iota
	reportResultsFrozen
	reportResultsActive
	reportFrozenResultSchemaVersion   = 4
	reportRetainedResultSchemaVersion = 5
)

func loadReportResults(path string, mode reportResultMode, expectedScoringVersion string) ([]reportNA, []reportFailure, reportRowCounts, string) {
	var counts reportRowCounts
	// Streams rather than reading whole, so it opens the descriptor itself, and
	// it uses the same no-follow open as the other readers: the type is checked
	// on the descriptor that will actually be read, never on the path.
	f, err := openRegularArtifact(filepath.Dir(path), filepath.Base(path))
	if os.IsNotExist(err) {
		return nil, nil, counts, absentFact
	}
	if errors.Is(err, errNotRegularArtifact) {
		return nil, nil, counts, "Invalid in run artifacts: not a regular file"
	}
	if errors.Is(err, errEmptyArtifact) {
		return nil, nil, counts, "Invalid in run artifacts: empty file"
	}
	if err != nil {
		return nil, nil, counts, "Unreadable run artifact"
	}
	defer func() { _ = f.Close() }()

	var notApplicable []reportNA
	var failures []reportFailure
	var sawActiveRow, sawFrozenRow bool
	seenCaseIDs := make(map[string]bool)
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	line := 0
	for scanner.Scan() {
		line++
		var row map[string]interface{}
		dec := json.NewDecoder(strings.NewReader(scanner.Text()))
		dec.UseNumber()
		if err := dec.Decode(&row); err != nil {
			return notApplicable, failures, counts, fmt.Sprintf("Malformed JSONL at line %d", line)
		}
		// One object per line, and nothing after it. Trailing JSON on a row is
		// malformed input, not a row with extra decoration to ignore.
		if err := ensureJSONEOF(dec); err != nil {
			return notApplicable, failures, counts, fmt.Sprintf("Malformed JSONL at line %d", line)
		}
		rawSchemaVersion, present := row["schema_version"]
		if !present {
			return notApplicable, failures, counts, fmt.Sprintf("Malformed JSONL at line %d", line)
		}
		number, numberOK := rawSchemaVersion.(json.Number)
		schemaVersion, parseErr := strconv.Atoi(fmt.Sprint(number))
		if !numberOK || parseErr != nil || schemaVersion < 4 || schemaVersion > activeResultSchemaVersion {
			return notApplicable, failures, counts, fmt.Sprintf("Malformed JSONL at line %d", line)
		}
		switch mode {
		case reportResultsActive:
			// Summary v5 spans both frozen v5 rows and scorer-bound v6 rows, so
			// the row version selects the provenance rule.
			if schemaVersion == reportFrozenResultSchemaVersion {
				return notApplicable, failures, counts, fmt.Sprintf("Malformed JSONL at line %d", line)
			}
			if schemaVersion == activeResultSchemaVersion {
				if expectedScoringVersion == "" {
					return notApplicable, failures, counts, fmt.Sprintf("Malformed JSONL at line %d", line)
				}
			} else if _, declared := row["scoring_version"]; schemaVersion == reportRetainedResultSchemaVersion && declared {
				return notApplicable, failures, counts, fmt.Sprintf("Malformed JSONL at line %d", line)
			}
		case reportResultsFrozen:
			if schemaVersion != reportFrozenResultSchemaVersion {
				return notApplicable, failures, counts, fmt.Sprintf("Malformed JSONL at line %d", line)
			}
			if _, declared := row["scoring_version"]; declared {
				return notApplicable, failures, counts, fmt.Sprintf("Malformed JSONL at line %d", line)
			}
		default:
			return notApplicable, failures, counts, fmt.Sprintf("Unbound result identity at line %d", line)
		}
		// A runner emits one row schema per file. Mixing active and frozen rows
		// would let the frozen rows carry scores without a scorer identity.
		if schemaVersion == activeResultSchemaVersion {
			sawActiveRow = true
		} else {
			sawFrozenRow = true
		}
		if sawActiveRow && sawFrozenRow {
			return notApplicable, failures, counts, fmt.Sprintf("Malformed JSONL at line %d", line)
		}
		if schemaVersion == activeResultSchemaVersion {
			scorer, scorerOK := row["scoring_version"].(string)
			if !scorerOK || strings.TrimSpace(scorer) == "" || scorer != expectedScoringVersion {
				return notApplicable, failures, counts, fmt.Sprintf("Malformed JSONL at line %d", line)
			}
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
			return notApplicable, failures, counts, fmt.Sprintf("Malformed JSONL at line %d", line)
		}
		score, scoreOK := row["score"].(string)
		if scoreOK && score != "pass" && score != "fail" && score != "error" && score != "not_applicable" {
			return notApplicable, failures, counts, fmt.Sprintf("Malformed JSONL at line %d", line)
		}
		if scoreOK {
			counts.scored++
		}
		caseID, caseIDOK := row["case_id"].(string)
		if !caseIDOK || strings.TrimSpace(caseID) == "" || seenCaseIDs[caseID] {
			return notApplicable, failures, counts, fmt.Sprintf("Malformed JSONL at line %d", line)
		}
		seenCaseIDs[caseID] = true
		expected, expectedOK := row["expected_verdict"].(string)
		if scoreOK {
			if !expectedOK || (expected != "allow" && expected != "block") {
				return notApplicable, failures, counts, fmt.Sprintf("Malformed JSONL at line %d", line)
			}
			switch score {
			case "pass":
				if actual != expected {
					return notApplicable, failures, counts, fmt.Sprintf("Malformed JSONL at line %d", line)
				}
			case "fail":
				// Some scoring rules use evidence beyond the verdict. A budget
				// block at the wrong call is a legitimate fail even though both
				// expected and observed verdicts are "block".
				if actual != "allow" && actual != "block" {
					return notApplicable, failures, counts, fmt.Sprintf("Malformed JSONL at line %d", line)
				}
			case "error":
				if actual != "error" && actual != "unreachable" {
					return notApplicable, failures, counts, fmt.Sprintf("Malformed JSONL at line %d", line)
				}
			case "not_applicable":
				if actual != "not_applicable" {
					return notApplicable, failures, counts, fmt.Sprintf("Malformed JSONL at line %d", line)
				}
			}
		}
		if scoreOK && score != "error" {
			// These counts reconstruct scores.full. Historical not-applicable
			// rows remain in that denominator as misses, matching
			// computeFullCorpusScores. scores.applicable intentionally uses a
			// different denominator and is not reconciled here.
			//
			// Containment counts the observed VERDICT, not the row's score,
			// because the verdict is what the producer counts:
			// computeFullCorpusScores takes every malicious result whose
			// ActualVerdict is "block", and build_gauntlet_provenance derives
			// metric_counts from the same predicate. A row can legitimately
			// score "fail" while still blocking -- a budget block at the wrong
			// call is the live example, and this file already allows that shape
			// a few lines above -- so counting "pass" here made the reconciler
			// demand a LOWER containment than the runner published and refuse a
			// valid run.
			if expected == "block" {
				counts.maliciousTotal++
				if actual == "block" {
					counts.maliciousBlocked++
				}
			} else {
				counts.benignTotal++
				if actual == "block" {
					counts.benignFalsePositives++
				}
			}
		}
		if scoreOK && score == "fail" {
			failures = append(failures, reportFailure{
				caseID: safeReportText(caseID), expected: expected, actual: actual,
			})
		}
		if actual != "not_applicable" {
			continue
		}
		reason := absentFact
		if notes, ok := row["notes"].(string); ok {
			const prefix = "not applicable: "
			if strings.HasPrefix(notes, prefix) && strings.TrimSpace(strings.TrimPrefix(notes, prefix)) != "" {
				reason = strings.TrimSpace(strings.TrimPrefix(notes, prefix))
			}
		}
		notApplicable = append(notApplicable, reportNA{safeReportText(caseID), safeReportText(reason)})
	}
	if err := scanner.Err(); err != nil {
		return notApplicable, failures, counts, "Unreadable run artifact"
	}
	sort.Slice(notApplicable, func(i, j int) bool { return notApplicable[i].caseID < notApplicable[j].caseID })
	sort.Slice(failures, func(i, j int) bool { return failures[i].caseID < failures[j].caseID })
	return notApplicable, failures, counts, "Readable"
}

func (r *buyerReport) publicationScoreFailures() []string {
	checks := []struct {
		label                  string
		path                   []string
		numerator, denominator int
	}{
		{"full containment", []string{"scores", "full", "containment"}, r.rowCounts.maliciousBlocked, r.rowCounts.maliciousTotal},
		{"full false-positive rate", []string{"scores", "full", "false_positive_rate"}, r.rowCounts.benignFalsePositives, r.rowCounts.benignTotal},
	}
	var failures []string
	for _, check := range checks {
		value, ok := nestedValue(r.summary.data, check.path...)
		number, numberOK := value.(json.Number)
		if !ok || !numberOK || check.denominator == 0 {
			failures = append(failures, check.label+" cannot be derived from result rows")
			continue
		}
		observed, err := number.Float64()
		expected := float64(check.numerator) / float64(check.denominator)
		if err != nil || math.IsNaN(observed) || math.IsInf(observed, 0) || math.Abs(observed-expected) > 1e-12 {
			failures = append(failures, fmt.Sprintf("%s disagrees with result rows", check.label))
		}
	}
	return failures
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

func reportCountMap(doc reportDocument, path ...string) ([]string, bool) {
	value, ok := nestedValue(doc.data, path...)
	items, object := value.(map[string]interface{})
	if !ok || !object {
		return nil, false
	}
	out := make([]string, 0, len(items))
	for key, raw := range items {
		number, numberOK := raw.(json.Number)
		if strings.TrimSpace(key) == "" || !numberOK {
			return nil, false
		}
		count, err := strconv.Atoi(number.String())
		if err != nil || count < 0 {
			return nil, false
		}
		out = append(out, fmt.Sprintf("%s=%d", safeReportText(key), count))
	}
	sort.Strings(out)
	return out, true
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
	if receipt, ok := r.receiptProfile(); ok && receipt.SchemaVersion == activeReceiptProfileSchemaVersion {
		bullet("Corpus Git observation", receipt.CorpusGitStatus)
		bullet("Observed tool version status", receipt.ObservedToolVersion.Status)
	}
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
	line("### Applicable-only malicious category profile")
	line("")
	line("This profile is evidence of category coverage and concentration, not a score or ranking. It uses observed malicious rows only. Containment gives every observed malicious case equal influence, and the share column shows how corpus composition sets the category weighting. Do not compare this profile with full-corpus containment when their scopes differ.")
	line("")
	profile := r.categoryProfile()
	if profile.unavailable != "" {
		line("Unavailable: %s.", markdownInline(profile.unavailable))
	} else {
		line("| Category | Blocked / observed malicious | Containment | Share of observed malicious denominator |")
		line("| --- | ---: | ---: | ---: |")
		for _, row := range profile.rows {
			line("| %s | %d / %d | %s | %s |", markdownInline(safeReportText(row.category)), row.blocked, row.malicious,
				reportCategoryProfilePercent(row.blocked, row.malicious), reportCategoryProfilePercent(row.malicious, profile.maliciousTotal))
		}
	}
	line("")
	line("### Applicable-only benign category profile")
	line("")
	line("This profile is evidence of category coverage and concentration, not a score or ranking. It uses observed benign rows only. False-positive rate gives every observed benign case equal influence, and the share column shows how corpus composition sets the category weighting. Do not compare this profile with full-corpus false-positive rate when their scopes differ.")
	line("")
	if profile.unavailable != "" {
		line("Unavailable: %s.", markdownInline(profile.unavailable))
	} else {
		line("| Category | Falsely blocked / observed benign | False-positive rate | Share of observed benign denominator |")
		line("| --- | ---: | ---: | ---: |")
		for _, row := range profile.rows {
			line("| %s | %d / %d | %s | %s |", markdownInline(safeReportText(row.category)), row.falseBlocked, row.benign,
				reportCategoryProfilePercent(row.falseBlocked, row.benign), reportCategoryProfilePercent(row.benign, profile.benignTotal))
		}
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

func reportCategoryProfilePercent(numerator, denominator int) string {
	if denominator == 0 {
		return "N/A"
	}
	return fmt.Sprintf("%.2f%%", 100*float64(numerator)/float64(denominator))
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
	if decision && r.publicationEligible() {
		return "Recorded eligible by both retained decisions"
	}
	if decision {
		return "Not established because retained validation checks are not valid"
	}
	return "Recorded not eligible by both retained decisions"
}

func (r *buyerReport) publicationEligible() bool {
	decisionValue, decisionPresent := nestedValue(r.decision.data, "publication_eligible")
	bundleValue, bundlePresent := nestedValue(r.bundle.data, "publication_eligible")
	decision, decisionBool := decisionValue.(bool)
	bundle, bundleBool := bundleValue.(bool)
	return decisionPresent && bundlePresent && decisionBool && bundleBool && decision && bundle &&
		strings.HasPrefix(r.bundleValidation(), reportSelfConsistentPrefix) &&
		strings.HasPrefix(r.decisionValidation(), reportSelfConsistentPrefix)
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
	return r.receiptProfileBindingError(reference)
}

// receiptProfileBindingError confirms that the retained receipt profile is
// attached to this exact active run. A matching bundle digest only says the
// profile was retained intact; it cannot establish that the retained profile
// describes the summary, tool profile, and registry snapshot beside it.
func (r *buyerReport) receiptProfileBindingError(reference capabilityregistry.Reference) string {
	data, err := readRegularArtifact(r.dir, "receipt-profile.json")
	if err != nil {
		return "receipt profile is absent or unreadable"
	}
	var receipt ReceiptProfile
	if err := decodeStrictJSON(data, &receipt); err != nil {
		return "receipt profile is malformed"
	}
	if issues := ValidateReceiptProfile(receipt); len(issues) != 0 {
		return "receipt profile is invalid"
	}
	if receipt.SchemaVersion != v4SchemaVersion && receipt.SchemaVersion != activeReceiptProfileSchemaVersion {
		return "receipt profile schema version does not match the result"
	}
	if reportNumber(r.summary, "schema_version") == "5" && receipt.SchemaVersion != activeReceiptProfileSchemaVersion && !isFrozenV5SummaryV4Receipt(r.summary.raw, data) {
		return "v5 result requires a v5 receipt profile"
	}
	if receipt.Tool != reportString(r.summary, "tool") || receipt.ToolVersion != reportString(r.summary, "tool_version") {
		return "receipt profile tool identity does not match the result"
	}
	if receipt.CorpusVersion != reportString(r.summary, "corpus_version") || receipt.CorpusSHA256 != reportString(r.summary, "corpus_sha256") {
		return "receipt profile corpus identity does not match the result"
	}
	if receipt.SchemaVersion == activeReceiptProfileSchemaVersion && receipt.BenchmarkManifestSHA256 != reportString(r.summary, "benchmark_manifest_sha256") {
		return "receipt profile benchmark manifest digest does not match the result"
	}
	if receipt.SchemaVersion == activeReceiptProfileSchemaVersion {
		if receipt.CorpusGitStatus != corpusGitStatusClean {
			return "v5 receipt profile requires clean corpus Git provenance for publication"
		}
		if receipt.CorpusGitSHA != reportString(r.summary, "method_commit") {
			return "receipt profile corpus Git commit does not match the result method commit"
		}
	}
	if receipt.ToolProfileSHA256 != reportString(r.summary, "tool_profile_sha256") {
		return "receipt profile tool profile digest does not match the result"
	}
	if receipt.CapabilityRegistry != reference {
		return "receipt profile registry reference does not match the result"
	}
	return ""
}

func (r *buyerReport) receiptProfile() (ReceiptProfile, bool) {
	data, err := readRegularArtifact(r.dir, "receipt-profile.json")
	if err != nil {
		return ReceiptProfile{}, false
	}
	var receipt ReceiptProfile
	if decodeStrictJSON(data, &receipt) != nil {
		return ReceiptProfile{}, false
	}
	return receipt, true
}

func isFrozenV5SummaryV4Receipt(summary, receipt []byte) bool {
	summaryDigest := sha256.Sum256(summary)
	receiptDigest := sha256.Sum256(receipt)
	return hex.EncodeToString(summaryDigest[:]) == frozenV5SummaryV4ReceiptSummarySHA256 &&
		hex.EncodeToString(receiptDigest[:]) == frozenV5SummaryV4ReceiptSHA256
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
