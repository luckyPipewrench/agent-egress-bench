package verifier

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const (
	replayProfile    = "control-evidence-replay-entry/v0"
	maxReplayEntries = 10000
	maxReplaySize    = 4096
)

type replayEntry struct {
	ChallengeNonce         string `json:"challenge_nonce"`
	EnvelopePayloadSHA256  string `json:"envelope_payload_sha256"`
	Profile                string `json:"profile"`
	RequirementID          string `json:"requirement_id"`
	RequirementSignerKeyID string `json:"requirement_signer_key_id"`
}

type replayAttempt struct {
	store      *replayStore
	entry      replayEntry
	seedStatus string
}

type replayStore struct {
	dir string
}

func (s *verificationState) prepareReplay(dir string) (*replayAttempt, *Result) {
	seedStatus, result := s.seedReplayStatus()
	if result != nil {
		return nil, result
	}
	entry := replayEntry{
		Profile:                replayProfile,
		RequirementSignerKeyID: s.req.SignerKeyID,
		RequirementID:          s.req.Payload.RequirementID,
		ChallengeNonce:         s.req.Payload.ChallengeNonce,
		EnvelopePayloadSHA256:  digestBytes(s.env.PayloadBytes),
	}
	attempt := &replayAttempt{entry: entry, seedStatus: seedStatus}
	if dir == "" {
		return attempt, nil
	}
	store, reason, err := openReplayStore(dir)
	if err != nil {
		return nil, failure(outcomeUnverifiable, reason)
	}
	status, reason, err := store.probe(entry)
	if err != nil {
		return nil, failure(outcomeUnverifiable, reason)
	}
	if status == "different_envelope_replay" {
		result := failure(outcomeInvalid, "different_envelope_replay")
		result.NonceStatus = status
		return nil, result
	}
	if status == "reverified_same_envelope" {
		attempt.seedStatus = status
	}
	attempt.store = store
	return attempt, nil
}

func (a *replayAttempt) commit() (string, *Result) {
	if a.store == nil {
		return "", failure(outcomeUnverifiable, "replay_ledger_required")
	}
	status, reason, err := a.store.checkAndRecord(a.entry)
	if err != nil {
		return "", failure(outcomeUnverifiable, reason)
	}
	if status == "different_envelope_replay" {
		result := failure(outcomeInvalid, "different_envelope_replay")
		result.NonceStatus = status
		return "", result
	}
	if a.seedStatus == "reverified_same_envelope" {
		status = a.seedStatus
	}
	return status, nil
}

func openReplayStore(dir string) (*replayStore, string, error) {
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, "replay_ledger_unavailable", err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return nil, "replay_ledger_permissions_invalid", errors.New("replay ledger must be a private directory")
	}
	store := &replayStore{dir: dir}
	if reason, err := store.validateAll(); err != nil {
		return nil, reason, err
	}
	return store, "", nil
}

func (s *replayStore) validateAll() (string, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return "replay_ledger_unavailable", err
	}
	if len(entries) > maxReplayEntries {
		return "replay_ledger_full", errors.New("replay ledger entry limit exceeded")
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".replay-") {
			continue
		}
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !strings.HasSuffix(entry.Name(), ".json") {
			return "replay_ledger_invalid", fmt.Errorf("invalid replay ledger member %q", entry.Name())
		}
		record, err := s.readRecord(filepath.Join(s.dir, entry.Name()))
		if err != nil || replayFilename(record) != entry.Name() {
			return "replay_ledger_invalid", fmt.Errorf("invalid replay ledger record %q", entry.Name())
		}
	}
	return "", nil
}

func (s *replayStore) probe(wanted replayEntry) (string, string, error) {
	path := filepath.Join(s.dir, replayFilename(wanted))
	record, err := s.readRecord(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "first_verification", "", nil
	}
	if err != nil {
		return "", "replay_ledger_invalid", err
	}
	if record.EnvelopePayloadSHA256 == wanted.EnvelopePayloadSHA256 {
		return "reverified_same_envelope", "", nil
	}
	return "different_envelope_replay", "", nil
}

func (s *replayStore) checkAndRecord(wanted replayEntry) (string, string, error) {
	if _, reason, err := openReplayStore(s.dir); err != nil {
		return "", reason, err
	}
	if status, reason, err := s.probe(wanted); err != nil || status != "first_verification" {
		if err == nil && status == "reverified_same_envelope" {
			if syncErr := syncDirectory(s.dir); syncErr != nil {
				return "", "replay_ledger_durability_unknown", syncErr
			}
		}
		return status, reason, err
	}
	data, err := json.Marshal(wanted)
	if err != nil {
		return "", "replay_ledger_write_failed", err
	}
	temporary, err := os.CreateTemp(s.dir, ".replay-")
	if err != nil {
		return "", "replay_ledger_write_failed", err
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return "", "replay_ledger_write_failed", err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return "", "replay_ledger_write_failed", err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return "", "replay_ledger_write_failed", err
	}
	if err := temporary.Close(); err != nil {
		return "", "replay_ledger_write_failed", err
	}
	finalPath := filepath.Join(s.dir, replayFilename(wanted))
	if err := os.Link(temporaryPath, finalPath); err != nil {
		if errors.Is(err, fs.ErrExist) {
			status, reason, probeErr := s.probe(wanted)
			if probeErr == nil && status == "reverified_same_envelope" {
				if syncErr := syncDirectory(s.dir); syncErr != nil {
					return "", "replay_ledger_durability_unknown", syncErr
				}
			}
			return status, reason, probeErr
		}
		return "", "replay_ledger_write_failed", err
	}
	if err := syncDirectory(s.dir); err != nil {
		return "", "replay_ledger_durability_unknown", err
	}
	return "first_verification", "", nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	return errors.Join(syncErr, closeErr)
}

func (s *replayStore) readRecord(path string) (replayEntry, error) {
	var record replayEntry
	info, err := os.Lstat(path)
	if err != nil {
		return record, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return record, errors.New("replay record permissions invalid")
	}
	data, err := readBounded(path, maxReplaySize)
	if err != nil {
		return record, err
	}
	if err := canonicalJSON(data); err != nil {
		return record, err
	}
	if _, err := strictJSON(data, &record); err != nil {
		return record, err
	}
	if record.Profile != replayProfile || !lowerHex(record.RequirementSignerKeyID, 32) ||
		!lowerHex(record.RequirementID, 16) || !lowerHex(record.ChallengeNonce, 32) || !lowerHex(record.EnvelopePayloadSHA256, 32) {
		return record, errors.New("replay record fields invalid")
	}
	return record, nil
}

func replayFilename(entry replayEntry) string {
	return lengthPrefixedDigest(entry.RequirementSignerKeyID, entry.RequirementID, entry.ChallengeNonce) + ".json"
}

func lowerHex(value string, byteLength int) bool {
	if len(value) != byteLength*2 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == byteLength
}
