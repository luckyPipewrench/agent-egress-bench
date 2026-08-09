// Package capabilityregistry resolves immutable capability-vocabulary
// snapshots. Capability IDs are reporting labels only; this package does not
// expose any scope or scoring semantics.
package capabilityregistry

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const SupportedFormat = 1

// Reference pins the exact raw bytes of a capability-registry snapshot.
// Revision locates a permanent path; SHA256 is the actual immutable binding.
type Reference struct {
	ID       string `json:"id"`
	Format   int    `json:"format"`
	Revision int    `json:"revision"`
	SHA256   string `json:"sha256"`
}

// Snapshot is one immutable registry revision.
type Snapshot struct {
	ID             string  `json:"id"`
	Format         int     `json:"format"`
	Revision       int     `json:"revision"`
	PreviousSHA256 string  `json:"previous_sha256,omitempty"`
	Entries        []Entry `json:"entries"`
}

// Entry defines a reporting label. Its fields intentionally carry no
// applicability, delivery, scoring, sufficiency, or publication behavior.
type Entry struct {
	ID                 string `json:"id"`
	Status             string `json:"status"`
	IntroducedRevision int    `json:"introduced_revision"`
	Title              string `json:"title"`
	Description        string `json:"description"`
	ReplacedBy         string `json:"replaced_by,omitempty"`
}

// ResolvedSnapshot retains the exact bytes that the reference hashes.
//
// The bytes are private and handed out only as copies. An exported slice would
// let a caller mutate the evidence after it was verified, or mutate the buffer
// it passed in, so the "exact bytes this reference hashes" claim could stop
// being true while the resolved snapshot still looked valid. Sharing the
// backing array with a caller also races the hashing and decoding done here.
type ResolvedSnapshot struct {
	Reference Reference
	Snapshot  Snapshot
	raw       []byte
	entries   map[string]Entry
}

// RawBytes returns a copy of the exact bytes the reference hashes. It is a copy
// on every call so a consumer cannot alter retained evidence.
func (s ResolvedSnapshot) RawBytes() []byte { return bytes.Clone(s.raw) }

// Resolver resolves snapshots below Root. Root is normally
// capability-registry, never a mutable “current registry” alias.
type Resolver struct{ Root string }

// Resolve reads the permanent revision path, verifies its raw-byte digest,
// validates the snapshot, and proves the revision belongs to the canonical
// append-only history before a producer emits any result.
//
// The history check is not optional here. A digest proves a snapshot is intact;
// it says nothing about whether that snapshot is the real revision 2 or a fork
// with a plausible previous_sha256. Without the lineage check, a substituted
// registry directory resolves cleanly and every downstream artifact then binds
// a non-canonical vocabulary while looking fully verified. Requiring each
// caller to remember a second call is the kind of guard that silently stops
// being applied, so it is done here.
func (r Resolver) Resolve(ref Reference) (ResolvedSnapshot, error) {
	if err := validateReference(ref); err != nil {
		return ResolvedSnapshot{}, err
	}
	raw, err := os.ReadFile(SnapshotPath(r.Root, ref.ID, ref.Format, ref.Revision))
	if err != nil {
		return ResolvedSnapshot{}, fmt.Errorf("reading capability registry snapshot: %w", err)
	}
	resolved, err := ResolveRaw(ref, raw)
	if err != nil {
		return ResolvedSnapshot{}, err
	}
	if err := ValidateHistory(r.Root); err != nil {
		return ResolvedSnapshot{}, fmt.Errorf("capability registry history is not canonical: %w", err)
	}
	return resolved, nil
}

// ResolveRaw validates a snapshot retained as evidence inside a package. It
// hashes precisely the supplied bytes; callers must not decode and re-marshal
// a snapshot before this check.
//
// One blob cannot prove its own lineage, so this function establishes integrity
// and identity only. It does NOT establish that the snapshot belongs to the
// canonical append-only history: a forged revision whose self-reference digest
// matches will pass here. A consumer accepting a registry from an untrusted
// source must additionally run ValidateHistory over the registry root, which is
// what Resolver.Resolve does.
func ResolveRaw(ref Reference, raw []byte) (ResolvedSnapshot, error) {
	if err := validateReference(ref); err != nil {
		return ResolvedSnapshot{}, err
	}
	// Copy before hashing so the bytes that were verified are the bytes that
	// are retained, whatever the caller does with its buffer afterwards.
	raw = bytes.Clone(raw)
	if digest := SHA256(raw); digest != ref.SHA256 {
		return ResolvedSnapshot{}, fmt.Errorf("capability registry sha256 mismatch: got %s, want %s", digest, ref.SHA256)
	}
	snapshot, entries, err := decodeSnapshot(raw)
	if err != nil {
		return ResolvedSnapshot{}, err
	}
	if snapshot.ID != ref.ID || snapshot.Format != ref.Format || snapshot.Revision != ref.Revision {
		return ResolvedSnapshot{}, fmt.Errorf("capability registry reference does not match snapshot identity")
	}
	return ResolvedSnapshot{Reference: ref, Snapshot: snapshot, raw: raw, entries: entries}, nil
}

// ValidateActiveIDs confirms every reporting label is known by this exact
// snapshot and may be introduced in new active content. Deprecated labels
// remain readable only through their pinned historical snapshot.
func (s ResolvedSnapshot) ValidateActiveIDs(kind string, ids []string) error {
	for _, id := range ids {
		entry, ok := s.entries[id]
		if !ok {
			return fmt.Errorf("unknown %s capability ID: %q", kind, id)
		}
		if entry.Status == "deprecated" {
			return fmt.Errorf("deprecated %s capability ID: %q", kind, id)
		}
	}
	return nil
}

// Entry returns a label definition for generic rendering. It is deliberately
// not a scope or scoring API.
func (s ResolvedSnapshot) Entry(id string) (Entry, bool) {
	entry, ok := s.entries[id]
	return entry, ok
}

// SnapshotPath is the permanent revision path; callers must not replace it
// with a moving “latest” filename.
func SnapshotPath(root, id string, format, revision int) string {
	return filepath.Join(root, id, "format-"+strconv.Itoa(format), "revision-"+strconv.Itoa(revision)+".json")
}

// SHA256 returns lower-case hex of supplied raw bytes.
func SHA256(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }

func validateReference(ref Reference) error {
	if ref.ID == "" {
		return fmt.Errorf("missing capability registry id")
	}
	if filepath.Base(ref.ID) != ref.ID || strings.Contains(ref.ID, "..") {
		return fmt.Errorf("invalid capability registry id: %q", ref.ID)
	}
	if ref.Format != SupportedFormat {
		return fmt.Errorf("unsupported capability registry format: %d", ref.Format)
	}
	if ref.Revision < 1 {
		return fmt.Errorf("invalid capability registry revision: %d", ref.Revision)
	}
	if !validDigest(ref.SHA256) {
		return fmt.Errorf("invalid capability registry sha256")
	}
	return nil
}

func decodeSnapshot(raw []byte) (Snapshot, map[string]Entry, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var snapshot Snapshot
	if err := dec.Decode(&snapshot); err != nil {
		return Snapshot{}, nil, fmt.Errorf("parsing capability registry snapshot: %w", err)
	}
	var extra struct{}
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return Snapshot{}, nil, fmt.Errorf("parsing capability registry snapshot: multiple JSON values")
		}
		return Snapshot{}, nil, fmt.Errorf("parsing capability registry snapshot: %w", err)
	}
	entries, err := validateSnapshot(snapshot)
	if err != nil {
		return Snapshot{}, nil, err
	}
	return snapshot, entries, nil
}

func validateSnapshot(snapshot Snapshot) (map[string]Entry, error) {
	if snapshot.ID == "" || filepath.Base(snapshot.ID) != snapshot.ID || strings.Contains(snapshot.ID, "..") {
		return nil, fmt.Errorf("invalid capability registry snapshot id: %q", snapshot.ID)
	}
	if snapshot.Format != SupportedFormat {
		return nil, fmt.Errorf("unsupported capability registry format: %d", snapshot.Format)
	}
	if snapshot.Revision < 1 {
		return nil, fmt.Errorf("invalid capability registry snapshot revision: %d", snapshot.Revision)
	}
	if snapshot.Revision == 1 && snapshot.PreviousSHA256 != "" {
		return nil, fmt.Errorf("first capability registry revision must not declare previous_sha256")
	}
	if snapshot.Revision > 1 && !validDigest(snapshot.PreviousSHA256) {
		return nil, fmt.Errorf("capability registry revision %d has invalid previous_sha256", snapshot.Revision)
	}
	if len(snapshot.Entries) == 0 {
		return nil, fmt.Errorf("capability registry snapshot has no entries")
	}
	entries := make(map[string]Entry, len(snapshot.Entries))
	for _, entry := range snapshot.Entries {
		if entry.ID == "" || strings.TrimSpace(entry.ID) != entry.ID {
			return nil, fmt.Errorf("invalid capability registry entry id: %q", entry.ID)
		}
		if _, duplicate := entries[entry.ID]; duplicate {
			return nil, fmt.Errorf("duplicate capability registry entry id: %q", entry.ID)
		}
		if entry.Status != "active" && entry.Status != "deprecated" {
			return nil, fmt.Errorf("invalid status for capability registry entry %q: %q", entry.ID, entry.Status)
		}
		if entry.IntroducedRevision < 1 || entry.IntroducedRevision > snapshot.Revision {
			return nil, fmt.Errorf("invalid introduced_revision for capability registry entry %q", entry.ID)
		}
		if entry.Title == "" || entry.Description == "" {
			return nil, fmt.Errorf("capability registry entry %q requires title and description", entry.ID)
		}
		entries[entry.ID] = entry
	}
	for _, entry := range entries {
		if entry.Status == "deprecated" {
			if entry.ReplacedBy == "" {
				return nil, fmt.Errorf("deprecated capability registry entry %q requires replaced_by", entry.ID)
			}
			if _, ok := entries[entry.ReplacedBy]; !ok {
				return nil, fmt.Errorf("deprecated capability registry entry %q names unknown replacement %q", entry.ID, entry.ReplacedBy)
			}
		} else if entry.ReplacedBy != "" {
			return nil, fmt.Errorf("active capability registry entry %q cannot name replaced_by", entry.ID)
		}
	}
	return entries, nil
}

func validDigest(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

// ValidateHistory validates every permanent snapshot below root and proves
// every later revision append-only relative to its predecessor.
func ValidateHistory(root string) error {
	registryDirs, err := os.ReadDir(root)
	if err != nil {
		return fmt.Errorf("reading capability registry root: %w", err)
	}
	if len(registryDirs) == 0 {
		return fmt.Errorf("capability registry root has no registries")
	}
	// Non-directory entries are skipped rather than rejected. The registry root
	// is also a Go package, so it legitimately holds go.mod and source files,
	// and rejecting them made this function unusable against the real registry:
	// it had no production caller and was only ever exercised against synthetic
	// temp directories, so nothing noticed. Skipping costs no security, since a
	// stray file is not a forged revision and every registry directory found is
	// still validated in full.
	registries := 0
	for _, registryDir := range registryDirs {
		if !registryDir.IsDir() {
			continue
		}
		registries++
		if err := validateRegistryHistory(filepath.Join(root, registryDir.Name()), registryDir.Name()); err != nil {
			return err
		}
	}
	if registries == 0 {
		return fmt.Errorf("capability registry root has no registries")
	}
	return nil
}

type historicalSnapshot struct {
	raw     []byte
	entries map[string]Entry
}

func validateRegistryHistory(registryRoot, id string) error {
	formatDirs, err := os.ReadDir(registryRoot)
	if err != nil {
		return err
	}
	if len(formatDirs) == 0 {
		return fmt.Errorf("capability registry %q has no formats", id)
	}
	for _, formatDir := range formatDirs {
		if !formatDir.IsDir() || !strings.HasPrefix(formatDir.Name(), "format-") {
			return fmt.Errorf("capability registry %q has invalid format path %q", id, formatDir.Name())
		}
		format, err := strconv.Atoi(strings.TrimPrefix(formatDir.Name(), "format-"))
		if err != nil || format != SupportedFormat {
			return fmt.Errorf("capability registry %q has unsupported format path %q", id, formatDir.Name())
		}
		if err := validateFormatHistory(filepath.Join(registryRoot, formatDir.Name()), id, format); err != nil {
			return err
		}
	}
	return nil
}

func validateFormatHistory(dir, id string, format int) error {
	paths, err := filepath.Glob(filepath.Join(dir, "revision-*.json"))
	if err != nil {
		return err
	}
	if len(paths) == 0 {
		return fmt.Errorf("capability registry %q format %d has no revisions", id, format)
	}
	sort.Slice(paths, func(i, j int) bool { return revisionFromPath(paths[i]) < revisionFromPath(paths[j]) })
	var previous historicalSnapshot
	for index, path := range paths {
		revision := revisionFromPath(path)
		if revision != index+1 {
			return fmt.Errorf("capability registry %q format %d revisions must start at 1 without gaps", id, format)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		snapshot, entries, err := decodeSnapshot(raw)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if snapshot.ID != id || snapshot.Format != format || snapshot.Revision != revision {
			return fmt.Errorf("%s: snapshot identity does not match permanent path", path)
		}
		current := historicalSnapshot{raw: raw, entries: entries}
		if index > 0 {
			if snapshot.PreviousSHA256 != SHA256(previous.raw) {
				return fmt.Errorf("%s: previous_sha256 does not match raw prior snapshot", path)
			}
			if err := validateAppendOnly(previous.entries, current.entries, revision); err != nil {
				return fmt.Errorf("%s: %w", path, err)
			}
		} else {
			// Revision 1 has no predecessor, so every entry is new here and the
			// same truthfulness rule applies against an empty prior set.
			if err := validateAppendOnly(nil, current.entries, revision); err != nil {
				return fmt.Errorf("%s: %w", path, err)
			}
		}
		previous = current
	}
	return nil
}

func revisionFromPath(path string) int {
	revision, _ := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(filepath.Base(path), "revision-"), ".json"))
	return revision
}

func validateAppendOnly(previous, current map[string]Entry, currentRevision int) error {
	// An entry absent from the previous snapshot is new in THIS revision and
	// must say so. Without this, revision 2 could introduce a label claiming
	// introduced_revision 1, which backdates it into a snapshot that never
	// contained it. That is not a cosmetic lie: a consumer resolving an
	// earlier pinned revision would find the label absent while a report
	// generated against this one presents it as having existed then, and the
	// immutable timeline the registry exists to provide would be false.
	//
	// After revision 1 a new entry also cannot arrive already deprecated:
	// deprecation is a transition from active, so recording one that never had
	// an active life invents history in the other direction. Revision 1 is
	// exempt because there is no prior state to contradict. A genesis snapshot
	// seeded from an existing vocabulary may legitimately record a label that
	// was already retired before this registry existed.
	isGenesis := currentRevision == 1
	for id, entry := range current {
		if _, existed := previous[id]; existed {
			continue
		}
		if entry.IntroducedRevision != currentRevision {
			return fmt.Errorf(
				"new capability registry entry %q claims introduced_revision %d but first appears in revision %d",
				id, entry.IntroducedRevision, currentRevision)
		}
		if !isGenesis && entry.Status != "active" {
			return fmt.Errorf("new capability registry entry %q must be introduced as active, got %q", id, entry.Status)
		}
	}
	for id, before := range previous {
		after, ok := current[id]
		if !ok {
			return fmt.Errorf("prior capability registry entry %q was removed", id)
		}
		if before.ID != after.ID || before.IntroducedRevision != after.IntroducedRevision || before.Title != after.Title || before.Description != after.Description {
			return fmt.Errorf("prior capability registry entry %q changed meaning", id)
		}
		switch {
		case before.Status == "active" && after.Status == "active":
			if after.ReplacedBy != "" {
				return fmt.Errorf("active capability registry entry %q unexpectedly gained replaced_by", id)
			}
		case before.Status == "active" && after.Status == "deprecated":
			// Deprecation is the only allowed mutation.
		case before.Status == "deprecated" && after.Status == "deprecated" && before.ReplacedBy == after.ReplacedBy:
			// Historical deprecation remains immutable.
		default:
			return fmt.Errorf("prior capability registry entry %q has invalid status transition", id)
		}
	}
	return nil
}
