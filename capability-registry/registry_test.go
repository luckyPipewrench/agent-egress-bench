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
	if string(resolved.Raw) == "" || resolved.Snapshot.Entries[0].ID != "url_dlp" {
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
