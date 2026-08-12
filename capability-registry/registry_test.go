package capabilityregistry

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeSnapshot(t *testing.T, root, id string, format, revision int, contents string) Reference {
	t.Helper()
	path := SnapshotPath(root, id, format, revision)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return Reference{ID: id, Format: format, Revision: revision, SHA256: SHA256([]byte(contents))}
}

func TestResolveBindsRawSnapshotBytes(t *testing.T) {
	root := t.TempDir()
	ref := writeSnapshot(t, root, "aeb.core-capabilities", 1, 1, `{"id":"aeb.core-capabilities","format":1,"revision":1,"entries":[{"id":"url_dlp","status":"active","introduced_revision":1,"title":"URL DLP","description":"Reporting label only"}]}`)
	resolved, err := (Resolver{Root: root}).Resolve(ref)
	if err != nil {
		t.Fatal(err)
	}
	if string(resolved.RawBytes()) == "" || resolved.Snapshot.Entries[0].ID != "url_dlp" {
		t.Fatalf("resolved snapshot = %#v", resolved)
	}
	if err := resolved.ValidateActiveIDs("claim", []string{"url_dlp"}); err != nil {
		t.Fatal(err)
	}
}

func TestResolveRejectsDigestMismatch(t *testing.T) {
	root := t.TempDir()
	ref := writeSnapshot(t, root, "aeb.core-capabilities", 1, 1, `{"id":"aeb.core-capabilities","format":1,"revision":1,"entries":[{"id":"url_dlp","status":"active","introduced_revision":1,"title":"URL DLP","description":"Reporting label only"}]}`)
	ref.SHA256 = strings.Repeat("0", 64)
	if _, err := (Resolver{Root: root}).Resolve(ref); err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("Resolve() error = %v, want digest mismatch", err)
	}
}

func TestResolveRejectsUnknownAndDeprecatedIDs(t *testing.T) {
	root := t.TempDir()
	ref := writeSnapshot(t, root, "aeb.core-capabilities", 1, 1, `{"id":"aeb.core-capabilities","format":1,"revision":1,"entries":[{"id":"old","status":"deprecated","introduced_revision":1,"title":"Old","description":"Reporting label only","replaced_by":"new"},{"id":"new","status":"active","introduced_revision":1,"title":"New","description":"Reporting label only"}]}`)
	resolved, err := (Resolver{Root: root}).Resolve(ref)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"unknown", "old"} {
		if err := resolved.ValidateActiveIDs("tag", []string{id}); err == nil {
			t.Fatalf("ValidateActiveIDs(%q) unexpectedly succeeded", id)
		}
	}
}

func TestRejectsMutatedPriorSnapshot(t *testing.T) {
	root := t.TempDir()
	first := `{"id":"aeb.core-capabilities","format":1,"revision":1,"entries":[{"id":"url_dlp","status":"active","introduced_revision":1,"title":"URL DLP","description":"Reporting label only"}]}`
	ref := writeSnapshot(t, root, "aeb.core-capabilities", 1, 1, first)
	second := `{"id":"aeb.core-capabilities","format":1,"revision":2,"previous_sha256":"` + ref.SHA256 + `","entries":[{"id":"url_dlp","status":"active","introduced_revision":1,"title":"URL data loss prevention","description":"Reporting label only"},{"id":"header_dlp","status":"active","introduced_revision":2,"title":"Header DLP","description":"Reporting label only"}]}`
	writeSnapshot(t, root, "aeb.core-capabilities", 1, 2, second)
	if err := ValidateHistory(root); err == nil || !strings.Contains(err.Error(), "changed meaning") {
		t.Fatalf("ValidateHistory() error = %v, want mutated-prior failure", err)
	}
}

func TestValidateHistoryAllowsDeprecationOnly(t *testing.T) {
	root := t.TempDir()
	first := `{"id":"aeb.core-capabilities","format":1,"revision":1,"entries":[{"id":"old","status":"active","introduced_revision":1,"title":"Old","description":"Reporting label only"},{"id":"new","status":"active","introduced_revision":1,"title":"New","description":"Reporting label only"}]}`
	ref := writeSnapshot(t, root, "aeb.core-capabilities", 1, 1, first)
	second := `{"id":"aeb.core-capabilities","format":1,"revision":2,"previous_sha256":"` + ref.SHA256 + `","entries":[{"id":"old","status":"deprecated","introduced_revision":1,"title":"Old","description":"Reporting label only","replaced_by":"new"},{"id":"new","status":"active","introduced_revision":1,"title":"New","description":"Reporting label only"}]}`
	writeSnapshot(t, root, "aeb.core-capabilities", 1, 2, second)
	if err := ValidateHistory(root); err != nil {
		t.Fatalf("ValidateHistory() error = %v", err)
	}
}

func TestValidateHistoryCommittedRegistryLayout(t *testing.T) {
	// The registry root is also this Go module, so it contains Go sources,
	// go.mod, and tests beside the permanent registry directory. Exercise that
	// real layout rather than a synthetic directory containing only snapshots.
	if err := ValidateHistory("."); err != nil {
		t.Fatalf("ValidateHistory on committed registry layout: %v", err)
	}
}

func TestCommittedRevisionTwoIntroducesPlannedMCPCapabilities(t *testing.T) {
	ref := Reference{
		ID:       "aeb.core-capabilities",
		Format:   1,
		Revision: 2,
		SHA256:   "ff93a655f609a8040d7904bc86a84d467713afadc886e885f383aa3a91fef99c",
	}
	resolved, err := (Resolver{Root: "."}).Resolve(ref)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"mcp_session_binding", "mcp_tool_result_dlp_scanning"} {
		entry, ok := resolved.Entry(id)
		if !ok || entry.Status != "active" || entry.IntroducedRevision != 2 {
			t.Fatalf("%s entry = %#v, present=%v", id, entry, ok)
		}
	}
}

// A registry whose timeline can be forged is not an immutable registry, and
// every one of these was accepted before the corresponding guard landed.

func TestValidateHistoryRejectsBackdatedNewEntry(t *testing.T) {
	// Revision 2 introduces a label claiming it existed at revision 1. A
	// consumer resolving revision 1 would not find it, while a report generated
	// against revision 2 presents it as having existed then.
	root := t.TempDir()
	first := `{"id":"aeb.core-capabilities","format":1,"revision":1,"entries":[{"id":"url_dlp","status":"active","introduced_revision":1,"title":"URL DLP","description":"Reporting label only"}]}`
	ref := writeSnapshot(t, root, "aeb.core-capabilities", 1, 1, first)
	second := `{"id":"aeb.core-capabilities","format":1,"revision":2,"previous_sha256":"` + ref.SHA256 + `","entries":[{"id":"url_dlp","status":"active","introduced_revision":1,"title":"URL DLP","description":"Reporting label only"},{"id":"backdated","status":"active","introduced_revision":1,"title":"Backdated","description":"Reporting label only"}]}`
	writeSnapshot(t, root, "aeb.core-capabilities", 1, 2, second)

	err := ValidateHistory(root)
	if err == nil {
		t.Fatal("a label backdated into a snapshot that never contained it was accepted")
	}
	if !strings.Contains(err.Error(), "backdated") {
		t.Fatalf("error should name the offending entry, got %v", err)
	}
}

func TestValidateHistoryRejectsNewEntryBornDeprecated(t *testing.T) {
	// After revision 1, deprecation is a transition from active. An entry that
	// arrives already deprecated claims an active life it never had.
	root := t.TempDir()
	first := `{"id":"aeb.core-capabilities","format":1,"revision":1,"entries":[{"id":"url_dlp","status":"active","introduced_revision":1,"title":"URL DLP","description":"Reporting label only"}]}`
	ref := writeSnapshot(t, root, "aeb.core-capabilities", 1, 1, first)
	second := `{"id":"aeb.core-capabilities","format":1,"revision":2,"previous_sha256":"` + ref.SHA256 + `","entries":[{"id":"url_dlp","status":"active","introduced_revision":1,"title":"URL DLP","description":"Reporting label only"},{"id":"stillborn","status":"deprecated","introduced_revision":2,"title":"Stillborn","description":"Reporting label only","replaced_by":"url_dlp"}]}`
	writeSnapshot(t, root, "aeb.core-capabilities", 1, 2, second)

	if err := ValidateHistory(root); err == nil {
		t.Fatal("a new entry introduced as deprecated was accepted")
	}
}

func TestResolveRejectsForkedLineage(t *testing.T) {
	// The forged revision 2 is internally valid and its own digest matches, so
	// integrity alone accepts it. Only the lineage check catches that its
	// previous_sha256 does not descend from the real revision 1.
	root := t.TempDir()
	first := `{"id":"aeb.core-capabilities","format":1,"revision":1,"entries":[{"id":"url_dlp","status":"active","introduced_revision":1,"title":"URL DLP","description":"Reporting label only"}]}`
	writeSnapshot(t, root, "aeb.core-capabilities", 1, 1, first)
	forged := `{"id":"aeb.core-capabilities","format":1,"revision":2,"previous_sha256":"` + strings.Repeat("a", 64) + `","entries":[{"id":"url_dlp","status":"active","introduced_revision":1,"title":"URL DLP","description":"Reporting label only"},{"id":"forged","status":"active","introduced_revision":2,"title":"Forged","description":"Reporting label only"}]}`
	ref := writeSnapshot(t, root, "aeb.core-capabilities", 1, 2, forged)

	// Integrity alone accepts the forgery, which is precisely why Resolve must
	// do more than verify a digest.
	if _, err := ResolveRaw(ref, []byte(forged)); err != nil {
		t.Fatalf("ResolveRaw should accept an intact blob: %v", err)
	}
	if _, err := (Resolver{Root: root}).Resolve(ref); err == nil {
		t.Fatal("Resolve accepted a snapshot that does not descend from the canonical history")
	}
}

func TestResolvedSnapshotRawBytesCannotBeMutated(t *testing.T) {
	// The retained evidence must keep matching the digest that verified it,
	// whatever the caller does with its own buffer or with what it is handed.
	root := t.TempDir()
	contents := `{"id":"aeb.core-capabilities","format":1,"revision":1,"entries":[{"id":"url_dlp","status":"active","introduced_revision":1,"title":"URL DLP","description":"Reporting label only"}]}`
	ref := writeSnapshot(t, root, "aeb.core-capabilities", 1, 1, contents)

	caller := []byte(contents)
	resolved, err := ResolveRaw(ref, caller)
	if err != nil {
		t.Fatal(err)
	}
	caller[0] = 'X' // the caller mutates the buffer it passed in
	handed := resolved.RawBytes()
	handed[0] = 'Y' // and mutates what it was handed back

	if got := SHA256(resolved.RawBytes()); got != ref.SHA256 {
		t.Fatalf("retained evidence no longer matches its reference digest: got %s want %s", got, ref.SHA256)
	}
}
