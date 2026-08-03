package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestCorpusIsDeterministicAndSigned(t *testing.T) {
	a, b := allFiles(), allFiles()
	if len(a) != 967 {
		t.Fatalf("fixture file count = %d", len(a))
	}
	for name, first := range a {
		if string(first) != string(b[name]) {
			t.Fatalf("non-deterministic fixture %s", name)
		}
	}
}

func TestDerivedTokenCanaryIDSeparatesSamePolarity(t *testing.T) {
	root := "same-root"
	a, b := derivedToken("aeb-cee-conformance-token-derived/v1", "synthetic-token-input", root, "positive-1"), derivedToken("aeb-cee-conformance-token-derived/v1", "synthetic-token-input", root, "positive-2")
	if a == b {
		t.Fatal("same-polarity canary IDs alias derived token")
	}
	ca := tokenCommitment("r", "u", "case", 1, "positive-1", "mcp_stdio", "target", "positive", a)
	cb := tokenCommitment("r", "u", "case", 1, "positive-2", "mcp_stdio", "target", "positive", b)
	if ca == cb {
		t.Fatal("same-polarity canary IDs alias commitment")
	}
}

func TestClosedV0RunnerAndTrialModes(t *testing.T) {
	files := allFiles()
	for _, id := range []string{"m10-compatibility-declared", "m59-conformant-compatible-unpinned"} {
		_, envelope := decoded(t, files["malicious/"+id+"/envelope.dsse.json"])
		mode := envelope["runner"].(map[string]any)["execution_mode"]
		if mode == "approved-binary" {
			t.Fatalf("%s does not exercise unsupported execution mode", id)
		}
		var expect map[string]any
		if err := json.Unmarshal(files["malicious/"+id+"/expect.json"], &expect); err != nil {
			t.Fatal(err)
		}
		if expect["expected_outcome"] != "invalid" || expect["reason"] != "runner_execution_mode_unsupported" {
			t.Fatalf("%s expectation does not fail closed", id)
		}
	}

	_, requirement := decoded(t, files["malicious/m60-minimum-trials-unsupported/requirement.dsse.json"])
	if requirement["minimum_trials_per_case"] != float64(2) {
		t.Fatal("m60 does not exercise unsupported repeated trials")
	}
	var expect map[string]any
	if err := json.Unmarshal(files["malicious/m60-minimum-trials-unsupported/expect.json"], &expect); err != nil {
		t.Fatal(err)
	}
	if expect["expected_outcome"] != "invalid" || expect["reason"] != "minimum_trials_per_case_unsupported" {
		t.Fatal("m60 expectation does not fail closed")
	}
}

func TestPackagedTokenMaterialDecryptsAndBindsCommitments(t *testing.T) {
	files := allFiles()
	base := "golden/g03-token-packaged-material/"
	_, req := decoded(t, files[base+"requirement.dsse.json"])
	_, env := decoded(t, files[base+"envelope.dsse.json"])
	var context, manifest, outcomes map[string]any
	if err := json.Unmarshal(files[base+"context.json"], &context); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(files[base+"manifest.json"], &manifest); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(files[base+"outcomes.json"], &outcomes); err != nil {
		t.Fatal(err)
	}
	signed := req["token_material"].(map[string]any)
	external := context["token_material"].(map[string]any)
	if signed["mode"] != "packaged-encrypted" || signed["profile"] != packagedTokenProfile || signed["key_or_input_id"] != packagedTokenID || signed["artifact_sha256"] == nil || signed["mode"] != external["mode"] || signed["profile"] != external["profile"] || signed["key_or_input_id"] != external["key_or_input_id"] {
		t.Fatal("g03 packaged descriptor")
	}
	var materialEntry map[string]any
	for _, raw := range manifest["entries"].([]any) {
		entry := raw.(map[string]any)
		if entry["role"] == "token-material" {
			if materialEntry != nil {
				t.Fatal("g03 duplicate token-material role")
			}
			materialEntry = entry
		}
	}
	if materialEntry == nil || materialEntry["path"] != "token-material.bin" || materialEntry["media_type"] != "application/octet-stream" {
		t.Fatal("g03 token-material manifest role/path/media type")
	}
	stored := files[base+materialEntry["path"].(string)]
	if digest(stored) != signed["artifact_sha256"] || digest(stored) != materialEntry["sha256"] || len(stored) != int(materialEntry["byte_length"].(float64)) {
		t.Fatal("g03 token-material exact stored bytes")
	}
	key, err := base64.StdEncoding.DecodeString(external["aes_key_base64"].(string))
	if err != nil || len(key) != 32 {
		t.Fatal("g03 context key")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) < gcm.NonceSize()+gcm.Overhead() {
		t.Fatal("g03 token material too short")
	}
	nonce := stored[:gcm.NonceSize()]
	wantNonce := lengthPrefixedSHA256("aeb-cee-conformance-nonce/v1", req["requirement_id"].(string), packagedTokenProfile, packagedTokenID, "token-material")[:gcm.NonceSize()]
	if string(nonce) != string(wantNonce) {
		t.Fatal("g03 deterministic nonce")
	}
	plaintext, err := gcm.Open(nil, nonce, stored[gcm.NonceSize():], lengthPrefixedSHA256Input(packagedTokenProfile, packagedTokenID))
	if err != nil || string(plaintext) != string(packagedTokenPlaintext()) {
		t.Fatal("g03 AES-GCM plaintext")
	}
	validateJSONBytes(t, compileSchema(t, filepath.Clean(filepath.Join("..", "..", "..", "..", "schemas", "control-evidence-token-material.schema.json"))), "g03 decrypted token material", plaintext)
	var decodedMaterial map[string]any
	if err := json.Unmarshal(plaintext, &decodedMaterial); err != nil {
		t.Fatal(err)
	}
	if decodedMaterial["profile"] != packagedTokenProfile || decodedMaterial["key_or_input_id"] != packagedTokenID {
		t.Fatal("g03 decrypted descriptor")
	}
	inputs := map[string]string{}
	for _, raw := range decodedMaterial["tokens"].([]any) {
		token := raw.(map[string]any)
		canaryID, input := token["canary_id"].(string), token["input"].(string)
		if _, duplicate := inputs[canaryID]; duplicate {
			t.Fatal("g03 duplicate decrypted canary ID")
		}
		inputs[canaryID] = input
	}
	if len(inputs) != 2 || inputs["positive-1"] == "" || inputs["negative-1"] == "" {
		t.Fatal("g03 decrypted exact canary ID set")
	}
	for _, rawRow := range outcomes["rows"].([]any) {
		row := rawRow.(map[string]any)
		trial := int(row["trial_index"].(float64))
		for _, rawCanary := range row["canaries"].([]any) {
			canary := rawCanary.(map[string]any)
			canaryID := canary["canary_id"].(string)
			want := tokenCommitment(env["requirement_sha256"].(string), env["run_id"].(string), row["case_id"].(string), trial, canaryID, row["transport"].(string), canary["target_identity"].(string), canary["polarity"].(string), inputs[canaryID])
			if canary["canary_commitment_sha256"] != want {
				t.Fatalf("g03 %s commitment", canaryID)
			}
		}
	}
}

func TestPackagedHealthMaterialDecryptsAndBindsBrackets(t *testing.T) {
	files := allFiles()
	base := "golden/g04-health-packaged-material/"
	_, req := decoded(t, files[base+"requirement.dsse.json"])
	_, env := decoded(t, files[base+"envelope.dsse.json"])
	var context, manifest, outcomes map[string]any
	for name, target := range map[string]*map[string]any{"context.json": &context, "manifest.json": &manifest, "outcomes.json": &outcomes} {
		if err := json.Unmarshal(files[base+name], target); err != nil {
			t.Fatal(err)
		}
	}
	signed := req["health_control_material"].(map[string]any)
	external := context["health_control_material"].(map[string]any)
	if signed["mode"] != "packaged-encrypted" || signed["profile"] != packagedHealthProfile || signed["key_or_input_id"] != packagedHealthID || signed["artifact_sha256"] == nil || signed["mode"] != external["mode"] || signed["profile"] != external["profile"] || signed["key_or_input_id"] != external["key_or_input_id"] {
		t.Fatal("g04 packaged health descriptor")
	}
	var materialEntry map[string]any
	paths := map[string]string{}
	for _, raw := range manifest["entries"].([]any) {
		entry := raw.(map[string]any)
		paths[entry["sha256"].(string)] = entry["path"].(string)
		if entry["role"] == "health-control-material" {
			if materialEntry != nil {
				t.Fatal("g04 duplicate health-control-material role")
			}
			materialEntry = entry
		}
	}
	if materialEntry == nil || materialEntry["path"] != "health-control-material.bin" || materialEntry["media_type"] != "application/octet-stream" {
		t.Fatal("g04 health material manifest role/path/media type")
	}
	stored := files[base+materialEntry["path"].(string)]
	if digest(stored) != signed["artifact_sha256"] || digest(stored) != materialEntry["sha256"] || len(stored) != int(materialEntry["byte_length"].(float64)) {
		t.Fatal("g04 health material exact stored bytes")
	}
	key, err := base64.StdEncoding.DecodeString(external["aes_key_base64"].(string))
	if err != nil || len(key) != 32 {
		t.Fatal("g04 context key")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := stored[:gcm.NonceSize()]
	wantNonce := lengthPrefixedSHA256("aeb-cee-conformance-nonce/v1", req["requirement_id"].(string), packagedHealthProfile, packagedHealthID, "health-control-material")[:gcm.NonceSize()]
	if string(nonce) != string(wantNonce) {
		t.Fatal("g04 deterministic nonce")
	}
	plaintext, err := gcm.Open(nil, nonce, stored[gcm.NonceSize():], lengthPrefixedSHA256Input(packagedHealthProfile, packagedHealthID))
	if err != nil || string(plaintext) != string(packagedHealthPlaintext()) {
		t.Fatal("g04 AES-GCM plaintext")
	}
	validateJSONBytes(t, compileSchema(t, filepath.Clean(filepath.Join("..", "..", "..", "..", "schemas", "control-evidence-health-control-material.schema.json"))), "g04 decrypted health material", plaintext)
	var decodedMaterial map[string]any
	if err := json.Unmarshal(plaintext, &decodedMaterial); err != nil {
		t.Fatal(err)
	}
	if decodedMaterial["profile"] != packagedHealthProfile || decodedMaterial["key_or_input_id"] != packagedHealthID {
		t.Fatal("g04 decrypted descriptor")
	}
	inputs := map[string]string{}
	for _, raw := range decodedMaterial["controls"].([]any) {
		control := raw.(map[string]any)
		id, input := control["control_id"].(string), control["input"].(string)
		if _, duplicate := inputs[id]; duplicate {
			t.Fatal("g04 duplicate decrypted control ID")
		}
		inputs[id] = input
	}
	if len(inputs) != 2 || inputs["health-pre"] == "" || inputs["health-post"] == "" {
		t.Fatal("g04 decrypted exact control ID set")
	}
	row := outcomes["rows"].([]any)[0].(map[string]any)
	canary := row["canaries"].([]any)[1].(map[string]any)
	for _, field := range []string{"preceding_health_ref", "following_health_ref"} {
		path := paths[canary[field].(string)]
		if path == "" {
			t.Fatalf("g04 %s unbound", field)
		}
		_, evidence := decoded(t, files[base+path])
		controlID := evidence["control_id"].(string)
		want := healthCommitment(env["requirement_sha256"].(string), env["run_id"].(string), row["case_id"].(string), int(row["trial_index"].(float64)), canary["canary_id"].(string), canary["canary_commitment_sha256"].(string), controlID, row["transport"].(string), canary["target_identity"].(string), inputs[controlID])
		if evidence["kind"] != "health-control" || evidence["health_control_commitment_sha256"] != want {
			t.Fatalf("g04 %s bracket commitment", field)
		}
	}
}

func TestPackagedTokenAttackBoundariesAreFullyRebound(t *testing.T) {
	files := allFiles()
	for _, fixtureID := range []string{"m23-token-artifact-digest-mismatch", "m24-token-aead-authentication-failure", "m25-token-authenticated-non-jcs"} {
		t.Run(fixtureID, func(t *testing.T) {
			base := "malicious/" + fixtureID + "/"
			_, req := decoded(t, files[base+"requirement.dsse.json"])
			_, env := decoded(t, files[base+"envelope.dsse.json"])
			var context, manifest map[string]any
			if err := json.Unmarshal(files[base+"context.json"], &context); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(files[base+"manifest.json"], &manifest); err != nil {
				t.Fatal(err)
			}
			signed := req["token_material"].(map[string]any)
			external := context["token_material"].(map[string]any)
			if env["requirement_sha256"] != digest(compact(req)) || signed["mode"] != "packaged-encrypted" || signed["profile"] != packagedTokenProfile || signed["key_or_input_id"] != packagedTokenID || signed["mode"] != external["mode"] || signed["profile"] != external["profile"] || signed["key_or_input_id"] != external["key_or_input_id"] || external["aes_key_base64"] != packagedTokenKey(req["requirement_id"].(string)) {
				t.Fatal("attack has an earlier descriptor or requirement binding failure")
			}
			var entry map[string]any
			for _, raw := range manifest["entries"].([]any) {
				candidate := raw.(map[string]any)
				if candidate["role"] == "token-material" {
					entry = candidate
				}
			}
			if entry == nil || entry["path"] != "token-material.bin" || entry["media_type"] != "application/octet-stream" {
				t.Fatal("attack missing token material member")
			}
			stored := files[base+entry["path"].(string)]
			if digest(stored) != entry["sha256"] || len(stored) != int(entry["byte_length"].(float64)) {
				t.Fatal("attack manifest does not bind stored bytes")
			}
			if fixtureID == "m23-token-artifact-digest-mismatch" {
				if signed["artifact_sha256"] == digest(stored) {
					t.Fatal("m23 artifact mismatch not isolated")
				}
				return
			}
			if signed["artifact_sha256"] != digest(stored) {
				t.Fatal("attack has an earlier artifact digest mismatch")
			}
			key, err := base64.StdEncoding.DecodeString(external["aes_key_base64"].(string))
			if err != nil || len(key) != 32 {
				t.Fatal("attack key")
			}
			block, err := aes.NewCipher(key)
			if err != nil {
				t.Fatal(err)
			}
			gcm, err := cipher.NewGCM(block)
			if err != nil {
				t.Fatal(err)
			}
			plaintext, openErr := gcm.Open(nil, stored[:gcm.NonceSize()], stored[gcm.NonceSize():], lengthPrefixedSHA256Input(packagedTokenProfile, packagedTokenID))
			if fixtureID == "m24-token-aead-authentication-failure" {
				if openErr == nil {
					t.Fatal("m24 AEAD authentication failure not isolated")
				}
				return
			}
			if openErr != nil {
				t.Fatal(openErr)
			}
			validateJSONBytes(t, compileSchema(t, filepath.Clean(filepath.Join("..", "..", "..", "..", "schemas", "control-evidence-token-material.schema.json"))), "m25 decrypted token material", plaintext)
			var mapping map[string]any
			if err := json.Unmarshal(plaintext, &mapping); err != nil {
				t.Fatal(err)
			}
			if string(plaintext) == string(compact(mapping)) {
				t.Fatal("m25 plaintext unexpectedly JCS")
			}
		})
	}
}

func TestPackagedTokenRoleAndExactSetAttacksAreFullyRebound(t *testing.T) {
	files := allFiles()
	for _, fixtureID := range []string{"m26-token-material-wrong-manifest-role", "m27-token-extra-canary-id", "m28-token-missing-canary-id"} {
		t.Run(fixtureID, func(t *testing.T) {
			base := "malicious/" + fixtureID + "/"
			_, req := decoded(t, files[base+"requirement.dsse.json"])
			_, env := decoded(t, files[base+"envelope.dsse.json"])
			var context, manifest map[string]any
			if err := json.Unmarshal(files[base+"context.json"], &context); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(files[base+"manifest.json"], &manifest); err != nil {
				t.Fatal(err)
			}
			signed := req["token_material"].(map[string]any)
			external := context["token_material"].(map[string]any)
			if env["requirement_sha256"] != digest(compact(req)) || env["observations"].(map[string]any)["sha256"] != digest(files[base+"outcomes.json"]) || env["artifacts"].(map[string]any)["manifest_sha256"] != digest(files[base+"manifest.json"]) || signed["mode"] != "packaged-encrypted" || signed["profile"] != packagedTokenProfile || signed["key_or_input_id"] != packagedTokenID || signed["mode"] != external["mode"] || signed["profile"] != external["profile"] || signed["key_or_input_id"] != external["key_or_input_id"] || external["aes_key_base64"] != packagedTokenKey(req["requirement_id"].(string)) {
				t.Fatal("attack has an earlier package binding failure")
			}
			var blobEntry map[string]any
			tokenRoleCount := 0
			for _, raw := range manifest["entries"].([]any) {
				entry := raw.(map[string]any)
				if entry["role"] == "token-material" {
					tokenRoleCount++
				}
				if entry["path"] == "token-blob.bin" || entry["path"] == "token-material.bin" {
					blobEntry = entry
				}
			}
			if blobEntry == nil {
				t.Fatal("attack missing stored token blob")
			}
			stored := files[base+blobEntry["path"].(string)]
			if digest(stored) != blobEntry["sha256"] || digest(stored) != signed["artifact_sha256"] || len(stored) != int(blobEntry["byte_length"].(float64)) {
				t.Fatal("attack stored blob binding")
			}
			if fixtureID == "m26-token-material-wrong-manifest-role" {
				if tokenRoleCount != 0 || blobEntry["role"] == "token-material" || blobEntry["role"] != "attachment" {
					t.Fatal("m26 token-material role failure not isolated")
				}
				return
			}
			if tokenRoleCount != 1 || blobEntry["role"] != "token-material" {
				t.Fatal("exact-set attack has an earlier role failure")
			}
			key, err := base64.StdEncoding.DecodeString(external["aes_key_base64"].(string))
			if err != nil || len(key) != 32 {
				t.Fatal("attack key")
			}
			block, err := aes.NewCipher(key)
			if err != nil {
				t.Fatal(err)
			}
			gcm, err := cipher.NewGCM(block)
			if err != nil {
				t.Fatal(err)
			}
			plaintext, err := gcm.Open(nil, stored[:gcm.NonceSize()], stored[gcm.NonceSize():], lengthPrefixedSHA256Input(packagedTokenProfile, packagedTokenID))
			if err != nil || string(plaintext) != string(compactJSON(t, plaintext)) {
				t.Fatal("exact-set attack is not authenticated JCS")
			}
			validateJSONBytes(t, compileSchema(t, filepath.Clean(filepath.Join("..", "..", "..", "..", "schemas", "control-evidence-token-material.schema.json"))), fixtureID+" decrypted token material", plaintext)
			var mapping map[string]any
			if err := json.Unmarshal(plaintext, &mapping); err != nil {
				t.Fatal(err)
			}
			ids := map[string]bool{}
			for _, raw := range mapping["tokens"].([]any) {
				ids[raw.(map[string]any)["canary_id"].(string)] = true
			}
			if fixtureID == "m27-token-extra-canary-id" && (len(ids) != 3 || !ids["positive-1"] || !ids["negative-1"] || !ids["extra-1"]) {
				t.Fatal("m27 extra canary ID failure not isolated")
			}
			if fixtureID == "m28-token-missing-canary-id" && (len(ids) != 1 || !ids["positive-1"] || ids["negative-1"]) {
				t.Fatal("m28 missing canary ID failure not isolated")
			}
		})
	}
}

func TestPackagedHealthAttackBoundariesAreFullyRebound(t *testing.T) {
	files := allFiles()
	for _, fixtureID := range []string{"m29-health-artifact-digest-mismatch", "m30-health-aead-authentication-failure", "m31-health-authenticated-non-jcs"} {
		t.Run(fixtureID, func(t *testing.T) {
			base := "malicious/" + fixtureID + "/"
			_, req := decoded(t, files[base+"requirement.dsse.json"])
			_, env := decoded(t, files[base+"envelope.dsse.json"])
			var context, manifest, outcomes map[string]any
			for name, target := range map[string]*map[string]any{"context.json": &context, "manifest.json": &manifest, "outcomes.json": &outcomes} {
				if err := json.Unmarshal(files[base+name], target); err != nil {
					t.Fatal(err)
				}
			}
			signed := req["health_control_material"].(map[string]any)
			external := context["health_control_material"].(map[string]any)
			if env["requirement_sha256"] != digest(compact(req)) || env["observations"].(map[string]any)["sha256"] != digest(files[base+"outcomes.json"]) || env["artifacts"].(map[string]any)["manifest_sha256"] != digest(files[base+"manifest.json"]) || signed["mode"] != "packaged-encrypted" || signed["profile"] != packagedHealthProfile || signed["key_or_input_id"] != packagedHealthID || signed["mode"] != external["mode"] || signed["profile"] != external["profile"] || signed["key_or_input_id"] != external["key_or_input_id"] || external["aes_key_base64"] != packagedHealthKey(req["requirement_id"].(string)) {
				t.Fatal("attack has an earlier descriptor or package binding failure")
			}
			paths := map[string]string{}
			var entry map[string]any
			for _, raw := range manifest["entries"].([]any) {
				candidate := raw.(map[string]any)
				paths[candidate["sha256"].(string)] = candidate["path"].(string)
				if candidate["role"] == "health-control-material" {
					entry = candidate
				}
			}
			if entry == nil || entry["path"] != "health-control-material.bin" || entry["media_type"] != "application/octet-stream" {
				t.Fatal("attack missing health material member")
			}
			stored := files[base+entry["path"].(string)]
			if digest(stored) != entry["sha256"] || len(stored) != int(entry["byte_length"].(float64)) {
				t.Fatal("attack manifest does not bind stored bytes")
			}
			row := outcomes["rows"].([]any)[0].(map[string]any)
			canary := row["canaries"].([]any)[1].(map[string]any)
			for _, field := range []string{"preceding_health_ref", "following_health_ref"} {
				path := paths[canary[field].(string)]
				if path == "" {
					t.Fatalf("%s %s unbound", fixtureID, field)
				}
				_, evidence := decoded(t, files[base+path])
				controlID := evidence["control_id"].(string)
				want := healthCommitment(env["requirement_sha256"].(string), env["run_id"].(string), row["case_id"].(string), int(row["trial_index"].(float64)), canary["canary_id"].(string), canary["canary_commitment_sha256"].(string), controlID, row["transport"].(string), canary["target_identity"].(string), healthInput(fixtureID, controlID, ""))
				if evidence["health_control_commitment_sha256"] != want {
					t.Fatalf("%s %s bracket commitment", fixtureID, field)
				}
			}
			if fixtureID == "m29-health-artifact-digest-mismatch" {
				if signed["artifact_sha256"] == digest(stored) {
					t.Fatal("m29 artifact mismatch not isolated")
				}
				return
			}
			if signed["artifact_sha256"] != digest(stored) {
				t.Fatal("attack has an earlier artifact digest mismatch")
			}
			key, err := base64.StdEncoding.DecodeString(external["aes_key_base64"].(string))
			if err != nil || len(key) != 32 {
				t.Fatal("attack key")
			}
			block, err := aes.NewCipher(key)
			if err != nil {
				t.Fatal(err)
			}
			gcm, err := cipher.NewGCM(block)
			if err != nil {
				t.Fatal(err)
			}
			plaintext, openErr := gcm.Open(nil, stored[:gcm.NonceSize()], stored[gcm.NonceSize():], lengthPrefixedSHA256Input(packagedHealthProfile, packagedHealthID))
			if fixtureID == "m30-health-aead-authentication-failure" {
				if openErr == nil {
					t.Fatal("m30 AEAD authentication failure not isolated")
				}
				return
			}
			if openErr != nil {
				t.Fatal(openErr)
			}
			validateJSONBytes(t, compileSchema(t, filepath.Clean(filepath.Join("..", "..", "..", "..", "schemas", "control-evidence-health-control-material.schema.json"))), "m31 decrypted health material", plaintext)
			if string(plaintext) == string(compactJSON(t, plaintext)) {
				t.Fatal("m31 plaintext unexpectedly JCS")
			}
		})
	}
}

func TestPackagedHealthRoleAndExactSetAttacksAreFullyRebound(t *testing.T) {
	files := allFiles()
	for _, fixtureID := range []string{"m32-health-material-wrong-manifest-role", "m33-health-extra-control-id", "m34-health-missing-post-control-id"} {
		t.Run(fixtureID, func(t *testing.T) {
			base := "malicious/" + fixtureID + "/"
			_, req := decoded(t, files[base+"requirement.dsse.json"])
			_, env := decoded(t, files[base+"envelope.dsse.json"])
			var context, manifest, outcomes map[string]any
			for name, target := range map[string]*map[string]any{"context.json": &context, "manifest.json": &manifest, "outcomes.json": &outcomes} {
				if err := json.Unmarshal(files[base+name], target); err != nil {
					t.Fatal(err)
				}
			}
			signed := req["health_control_material"].(map[string]any)
			external := context["health_control_material"].(map[string]any)
			if env["requirement_sha256"] != digest(compact(req)) || env["observations"].(map[string]any)["sha256"] != digest(files[base+"outcomes.json"]) || env["artifacts"].(map[string]any)["manifest_sha256"] != digest(files[base+"manifest.json"]) || signed["mode"] != "packaged-encrypted" || signed["profile"] != packagedHealthProfile || signed["key_or_input_id"] != packagedHealthID || signed["mode"] != external["mode"] || signed["profile"] != external["profile"] || signed["key_or_input_id"] != external["key_or_input_id"] || external["aes_key_base64"] != packagedHealthKey(req["requirement_id"].(string)) {
				t.Fatal("attack has an earlier package binding failure")
			}
			paths := map[string]string{}
			var blobEntry map[string]any
			healthRoleCount := 0
			for _, raw := range manifest["entries"].([]any) {
				entry := raw.(map[string]any)
				paths[entry["sha256"].(string)] = entry["path"].(string)
				if entry["role"] == "health-control-material" {
					healthRoleCount++
				}
				if entry["path"] == "health-blob.bin" || entry["path"] == "health-control-material.bin" {
					blobEntry = entry
				}
			}
			if blobEntry == nil {
				t.Fatal("attack missing stored health blob")
			}
			stored := files[base+blobEntry["path"].(string)]
			if digest(stored) != blobEntry["sha256"] || digest(stored) != signed["artifact_sha256"] || len(stored) != int(blobEntry["byte_length"].(float64)) {
				t.Fatal("attack stored blob binding")
			}
			row := outcomes["rows"].([]any)[0].(map[string]any)
			canary := row["canaries"].([]any)[1].(map[string]any)
			for _, field := range []string{"preceding_health_ref", "following_health_ref"} {
				path := paths[canary[field].(string)]
				if path == "" {
					t.Fatalf("%s %s unbound", fixtureID, field)
				}
				_, evidence := decoded(t, files[base+path])
				controlID := evidence["control_id"].(string)
				want := healthCommitment(env["requirement_sha256"].(string), env["run_id"].(string), row["case_id"].(string), int(row["trial_index"].(float64)), canary["canary_id"].(string), canary["canary_commitment_sha256"].(string), controlID, row["transport"].(string), canary["target_identity"].(string), healthInput(fixtureID, controlID, ""))
				if evidence["health_control_commitment_sha256"] != want {
					t.Fatalf("%s %s bracket commitment", fixtureID, field)
				}
			}
			if fixtureID == "m32-health-material-wrong-manifest-role" {
				if healthRoleCount != 0 || blobEntry["role"] != "attachment" {
					t.Fatal("m32 health-control-material role failure not isolated")
				}
				return
			}
			if healthRoleCount != 1 || blobEntry["role"] != "health-control-material" {
				t.Fatal("exact-set attack has an earlier role failure")
			}
			key, err := base64.StdEncoding.DecodeString(external["aes_key_base64"].(string))
			if err != nil || len(key) != 32 {
				t.Fatal("attack key")
			}
			block, err := aes.NewCipher(key)
			if err != nil {
				t.Fatal(err)
			}
			gcm, err := cipher.NewGCM(block)
			if err != nil {
				t.Fatal(err)
			}
			plaintext, err := gcm.Open(nil, stored[:gcm.NonceSize()], stored[gcm.NonceSize():], lengthPrefixedSHA256Input(packagedHealthProfile, packagedHealthID))
			if err != nil || string(plaintext) != string(compactJSON(t, plaintext)) {
				t.Fatal("exact-set attack is not authenticated JCS")
			}
			validateJSONBytes(t, compileSchema(t, filepath.Clean(filepath.Join("..", "..", "..", "..", "schemas", "control-evidence-health-control-material.schema.json"))), fixtureID+" decrypted health material", plaintext)
			var mapping map[string]any
			if err := json.Unmarshal(plaintext, &mapping); err != nil {
				t.Fatal(err)
			}
			ids := map[string]bool{}
			for _, raw := range mapping["controls"].([]any) {
				ids[raw.(map[string]any)["control_id"].(string)] = true
			}
			if fixtureID == "m33-health-extra-control-id" && (len(ids) != 3 || !ids["health-pre"] || !ids["health-post"] || !ids["health-extra"]) {
				t.Fatal("m33 extra control ID failure not isolated")
			}
			if fixtureID == "m34-health-missing-post-control-id" && (len(ids) != 1 || !ids["health-pre"] || ids["health-post"]) {
				t.Fatal("m34 missing health-post control ID failure not isolated")
			}
		})
	}
}

func TestTokenConvergenceAttacksAreFullyRebound(t *testing.T) {
	files := allFiles()
	for _, fixtureID := range []string{"m35-token-duplicate-canary-id", "m36-token-material-duplicate-manifest-role", "m37-token-duplicate-json-key"} {
		t.Run(fixtureID, func(t *testing.T) {
			base := "malicious/" + fixtureID + "/"
			_, req := decoded(t, files[base+"requirement.dsse.json"])
			_, env := decoded(t, files[base+"envelope.dsse.json"])
			var context, manifest map[string]any
			if err := json.Unmarshal(files[base+"context.json"], &context); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(files[base+"manifest.json"], &manifest); err != nil {
				t.Fatal(err)
			}
			signed, external := req["token_material"].(map[string]any), context["token_material"].(map[string]any)
			if env["requirement_sha256"] != digest(compact(req)) || env["artifacts"].(map[string]any)["manifest_sha256"] != digest(files[base+"manifest.json"]) || signed["mode"] != "packaged-encrypted" || signed["profile"] != packagedTokenProfile || signed["key_or_input_id"] != packagedTokenID || signed["mode"] != external["mode"] || signed["profile"] != external["profile"] || signed["key_or_input_id"] != external["key_or_input_id"] {
				t.Fatal("attack has an earlier package binding failure")
			}
			entries := []map[string]any{}
			for _, raw := range manifest["entries"].([]any) {
				entry := raw.(map[string]any)
				if entry["role"] == "token-material" {
					entries = append(entries, entry)
				}
			}
			if fixtureID == "m36-token-material-duplicate-manifest-role" {
				if len(entries) != 2 {
					t.Fatal("m36 duplicate token-material role not isolated")
				}
				matching := 0
				for _, entry := range entries {
					stored := files[base+entry["path"].(string)]
					if digest(stored) != entry["sha256"] || len(stored) != int(entry["byte_length"].(float64)) {
						t.Fatal("m36 manifest byte binding")
					}
					if entry["sha256"] == signed["artifact_sha256"] {
						matching++
					}
				}
				if matching != 1 {
					t.Fatal("m36 signed artifact candidate count")
				}
				return
			}
			if len(entries) != 1 {
				t.Fatal("attack has an earlier manifest role failure")
			}
			stored := files[base+entries[0]["path"].(string)]
			if digest(stored) != signed["artifact_sha256"] || digest(stored) != entries[0]["sha256"] {
				t.Fatal("attack stored bytes")
			}
			key, err := base64.StdEncoding.DecodeString(external["aes_key_base64"].(string))
			if err != nil || len(key) != 32 {
				t.Fatal("attack key")
			}
			block, err := aes.NewCipher(key)
			if err != nil {
				t.Fatal(err)
			}
			gcm, err := cipher.NewGCM(block)
			if err != nil {
				t.Fatal(err)
			}
			plaintext, err := gcm.Open(nil, stored[:gcm.NonceSize()], stored[gcm.NonceSize():], lengthPrefixedSHA256Input(packagedTokenProfile, packagedTokenID))
			if err != nil {
				t.Fatal(err)
			}
			var mapping map[string]any
			if err := json.Unmarshal(plaintext, &mapping); err != nil {
				t.Fatal(err)
			}
			validateJSONBytes(t, compileSchema(t, filepath.Clean(filepath.Join("..", "..", "..", "..", "schemas", "control-evidence-token-material.schema.json"))), fixtureID+" decrypted token material", plaintext)
			if fixtureID == "m35-token-duplicate-canary-id" {
				if string(plaintext) != string(compact(mapping)) {
					t.Fatal("m35 plaintext not JCS")
				}
				positiveInputs := []string{}
				for _, raw := range mapping["tokens"].([]any) {
					token := raw.(map[string]any)
					if token["canary_id"] == "positive-1" {
						positiveInputs = append(positiveInputs, token["input"].(string))
					}
				}
				if len(positiveInputs) != 2 || positiveInputs[0] == positiveInputs[1] {
					t.Fatal("m35 duplicate canary ID not isolated")
				}
				return
			}
			if bytes.Count(plaintext, []byte(`"profile"`)) != 2 || mapping["profile"] != packagedTokenProfile {
				t.Fatal("m37 duplicate JSON key not isolated")
			}
		})
	}
}

func TestUnsupportedDerivedTokenProfileHasNoFallback(t *testing.T) {
	files := allFiles()
	base := "malicious/m38-token-unsupported-derived-profile/"
	_, req := decoded(t, files[base+"requirement.dsse.json"])
	_, env := decoded(t, files[base+"envelope.dsse.json"])
	var context, outcomes map[string]any
	if err := json.Unmarshal(files[base+"context.json"], &context); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(files[base+"outcomes.json"], &outcomes); err != nil {
		t.Fatal(err)
	}
	signed, external := req["token_material"].(map[string]any), context["token_material"].(map[string]any)
	if env["requirement_sha256"] != digest(compact(req)) || signed["mode"] != "buyer-derived" || signed["profile"] != "example-unknown/v9" || signed["key_or_input_id"] != "synthetic-token-input" || signed["mode"] != external["mode"] || signed["profile"] != external["profile"] || signed["key_or_input_id"] != external["key_or_input_id"] || external["root_input"] == nil {
		t.Fatal("m38 unsupported profile not isolated")
	}
	row := outcomes["rows"].([]any)[0].(map[string]any)
	for _, raw := range row["canaries"].([]any) {
		canary := raw.(map[string]any)
		canaryID := canary["canary_id"].(string)
		knownInput := derivedToken("aeb-cee-conformance-token-derived/v1", "synthetic-token-input", "synthetic-token-root-m38-token-unsupported-derived-profile", canaryID)
		want := tokenCommitment(env["requirement_sha256"].(string), env["run_id"].(string), row["case_id"].(string), int(row["trial_index"].(float64)), canaryID, row["transport"].(string), canary["target_identity"].(string), canary["polarity"].(string), knownInput)
		if canary["canary_commitment_sha256"] != want {
			t.Fatal("m38 generator-known commitment")
		}
	}
}

func TestHealthConvergenceAttacksAreFullyRebound(t *testing.T) {
	files := allFiles()
	for _, fixtureID := range []string{"m39-health-duplicate-control-id", "m40-health-material-duplicate-manifest-role"} {
		t.Run(fixtureID, func(t *testing.T) {
			base := "malicious/" + fixtureID + "/"
			_, req := decoded(t, files[base+"requirement.dsse.json"])
			_, env := decoded(t, files[base+"envelope.dsse.json"])
			var context, manifest map[string]any
			if err := json.Unmarshal(files[base+"context.json"], &context); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(files[base+"manifest.json"], &manifest); err != nil {
				t.Fatal(err)
			}
			signed, external := req["health_control_material"].(map[string]any), context["health_control_material"].(map[string]any)
			if env["requirement_sha256"] != digest(compact(req)) || env["artifacts"].(map[string]any)["manifest_sha256"] != digest(files[base+"manifest.json"]) || signed["mode"] != "packaged-encrypted" || signed["profile"] != packagedHealthProfile || signed["key_or_input_id"] != packagedHealthID || signed["mode"] != external["mode"] || signed["profile"] != external["profile"] || signed["key_or_input_id"] != external["key_or_input_id"] {
				t.Fatal("attack has an earlier package binding failure")
			}
			entries := []map[string]any{}
			for _, raw := range manifest["entries"].([]any) {
				entry := raw.(map[string]any)
				if entry["role"] == "health-control-material" {
					entries = append(entries, entry)
				}
			}
			if fixtureID == "m40-health-material-duplicate-manifest-role" {
				if len(entries) != 2 {
					t.Fatal("m40 duplicate health-control-material role not isolated")
				}
				matching := 0
				for _, entry := range entries {
					stored := files[base+entry["path"].(string)]
					if digest(stored) != entry["sha256"] || len(stored) != int(entry["byte_length"].(float64)) {
						t.Fatal("m40 manifest byte binding")
					}
					if entry["sha256"] == signed["artifact_sha256"] {
						matching++
					}
				}
				if matching != 1 {
					t.Fatal("m40 signed artifact candidate count")
				}
				return
			}
			if len(entries) != 1 {
				t.Fatal("attack has an earlier manifest role failure")
			}
			stored := files[base+entries[0]["path"].(string)]
			if digest(stored) != signed["artifact_sha256"] || digest(stored) != entries[0]["sha256"] {
				t.Fatal("attack stored bytes")
			}
			key, err := base64.StdEncoding.DecodeString(external["aes_key_base64"].(string))
			if err != nil || len(key) != 32 {
				t.Fatal("attack key")
			}
			block, err := aes.NewCipher(key)
			if err != nil {
				t.Fatal(err)
			}
			gcm, err := cipher.NewGCM(block)
			if err != nil {
				t.Fatal(err)
			}
			plaintext, err := gcm.Open(nil, stored[:gcm.NonceSize()], stored[gcm.NonceSize():], lengthPrefixedSHA256Input(packagedHealthProfile, packagedHealthID))
			if err != nil {
				t.Fatal(err)
			}
			validateJSONBytes(t, compileSchema(t, filepath.Clean(filepath.Join("..", "..", "..", "..", "schemas", "control-evidence-health-control-material.schema.json"))), fixtureID+" decrypted health material", plaintext)
			var mapping map[string]any
			if err := json.Unmarshal(plaintext, &mapping); err != nil {
				t.Fatal(err)
			}
			if string(plaintext) != string(compact(mapping)) {
				t.Fatal("m39 plaintext not JCS")
			}
			preInputs := []string{}
			for _, raw := range mapping["controls"].([]any) {
				control := raw.(map[string]any)
				if control["control_id"] == "health-pre" {
					preInputs = append(preInputs, control["input"].(string))
				}
			}
			if len(preInputs) != 2 || preInputs[0] == preInputs[1] {
				t.Fatal("m39 duplicate control ID not isolated")
			}
		})
	}
}

func TestUnsupportedDerivedHealthProfileHasNoFallback(t *testing.T) {
	files := allFiles()
	base := "malicious/m41-health-unsupported-derived-profile/"
	_, req := decoded(t, files[base+"requirement.dsse.json"])
	_, env := decoded(t, files[base+"envelope.dsse.json"])
	var context, manifest, outcomes map[string]any
	for name, target := range map[string]*map[string]any{"context.json": &context, "manifest.json": &manifest, "outcomes.json": &outcomes} {
		if err := json.Unmarshal(files[base+name], target); err != nil {
			t.Fatal(err)
		}
	}
	signed, external := req["health_control_material"].(map[string]any), context["health_control_material"].(map[string]any)
	if env["requirement_sha256"] != digest(compact(req)) || signed["mode"] != "buyer-derived" || signed["profile"] != "example-unknown/v9" || signed["key_or_input_id"] != "synthetic-health-input" || signed["mode"] != external["mode"] || signed["profile"] != external["profile"] || signed["key_or_input_id"] != external["key_or_input_id"] || external["root_input"] == nil {
		t.Fatal("m41 unsupported profile not isolated")
	}
	paths := map[string]string{}
	for _, raw := range manifest["entries"].([]any) {
		entry := raw.(map[string]any)
		paths[entry["sha256"].(string)] = entry["path"].(string)
	}
	row := outcomes["rows"].([]any)[0].(map[string]any)
	canary := row["canaries"].([]any)[1].(map[string]any)
	for _, field := range []string{"preceding_health_ref", "following_health_ref"} {
		_, evidence := decoded(t, files[base+paths[canary[field].(string)]])
		controlID := evidence["control_id"].(string)
		knownInput := derivedHealthInput("aeb-cee-conformance-health-derived/v1", "synthetic-health-input", controlID, "synthetic-health-root-m41-health-unsupported-derived-profile")
		want := healthCommitment(env["requirement_sha256"].(string), env["run_id"].(string), row["case_id"].(string), int(row["trial_index"].(float64)), canary["canary_id"].(string), canary["canary_commitment_sha256"].(string), controlID, row["transport"].(string), canary["target_identity"].(string), knownInput)
		if evidence["health_control_commitment_sha256"] != want {
			t.Fatal("m41 generator-known bracket commitment")
		}
	}
}

func compactJSON(t *testing.T, plaintext []byte) []byte {
	t.Helper()
	var value any
	if err := json.Unmarshal(plaintext, &value); err != nil {
		t.Fatal(err)
	}
	return compact(value)
}

func decoded(t *testing.T, b []byte) (map[string]any, map[string]any) {
	t.Helper()
	var w map[string]any
	if err := json.Unmarshal(b, &w); err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(w["payload"].(string))
	if err != nil {
		t.Fatal(err)
	}
	var p map[string]any
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	return w, p
}

func digest32(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(p)))
		_, _ = h.Write(n[:])
		_, _ = h.Write([]byte(p))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func verifySignedBy(t *testing.T, wrapper map[string]any, wantKey string) {
	t.Helper()
	signature := wrapper["signatures"].([]any)[0].(map[string]any)
	if signature["keyid"] != wantKey {
		t.Fatalf("signature key = %v, want %s", signature["keyid"], wantKey)
	}
	pub, err := hex.DecodeString(wantKey)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := base64.StdEncoding.DecodeString(signature["sig"].(string))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(wrapper["payload"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), pae(wrapper["payloadType"].(string), raw), sig) {
		t.Fatal("signature does not verify")
	}
}

func parseTime(t *testing.T, value any) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value.(string))
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func TestGoldenEdgeCommitmentsAndObserverJoins(t *testing.T) {
	files := allFiles()
	for _, f := range fixtures() {
		if f.category != "golden" && f.category != "edge" {
			continue
		}
		base := f.category + "/" + f.id + "/"
		_, req := decoded(t, files[base+"requirement.dsse.json"])
		_, env := decoded(t, files[base+"envelope.dsse.json"])
		var reqOuter, envOuter map[string]any
		_ = json.Unmarshal(files[base+"requirement.dsse.json"], &reqOuter)
		_ = json.Unmarshal(files[base+"envelope.dsse.json"], &envOuter)
		if reqOuter["payloadType"] != typeReq || envOuter["payloadType"] != typeEnv {
			t.Fatalf("%s fixed artifact payload type", f.id)
		}
		var out map[string]any
		_ = json.Unmarshal(files[base+"outcomes.json"], &out)
		var ctx map[string]any
		_ = json.Unmarshal(files[base+"context.json"], &ctx)
		tokenDescriptor := ctx["token_material"].(map[string]any)
		if f.id == "g03-token-packaged-material" {
			if tokenDescriptor["mode"] != "packaged-encrypted" || tokenDescriptor["profile"] != packagedTokenProfile || tokenDescriptor["key_or_input_id"] != packagedTokenID || tokenDescriptor["aes_key_base64"] == nil {
				t.Fatalf("%s packaged token descriptor", f.id)
			}
		} else if tokenDescriptor["mode"] != "buyer-derived" || tokenDescriptor["profile"] != "aeb-cee-conformance-token-derived/v1" || tokenDescriptor["key_or_input_id"] != "synthetic-token-input" {
			t.Fatalf("%s token descriptor", f.id)
		}
		healthDescriptor := ctx["health_control_material"].(map[string]any)
		healthRoot := ""
		if f.id == "g04-health-packaged-material" {
			if healthDescriptor["mode"] != "packaged-encrypted" || healthDescriptor["profile"] != packagedHealthProfile || healthDescriptor["key_or_input_id"] != packagedHealthID || healthDescriptor["aes_key_base64"] == nil {
				t.Fatalf("%s packaged health descriptor", f.id)
			}
		} else if healthDescriptor["mode"] != "buyer-derived" || healthDescriptor["profile"] != "aeb-cee-conformance-health-derived/v1" || healthDescriptor["key_or_input_id"] != "synthetic-health-input" {
			t.Fatalf("%s health descriptor", f.id)
		} else {
			healthRoot = healthDescriptor["root_input"].(string)
		}
		var man map[string]any
		_ = json.Unmarshal(files[base+"manifest.json"], &man)
		entries := map[string]string{}
		roles := map[string]string{}
		totalBytes := 0
		for _, v := range man["entries"].([]any) {
			e := v.(map[string]any)
			sha, path := e["sha256"].(string), e["path"].(string)
			content, ok := files[base+path]
			if !ok || digest(content) != sha || len(content) != int(e["byte_length"].(float64)) {
				t.Fatalf("%s manifest entry %s does not bind exact bytes", f.id, path)
			}
			entries[sha] = path
			roles[sha] = e["role"].(string)
			totalBytes += len(content)
		}
		if totalBytes != int(man["total_uncompressed_bytes"].(float64)) {
			t.Fatalf("%s manifest total bytes", f.id)
		}
		seen := map[string]bool{}
		for _, v := range out["rows"].([]any) {
			r := v.(map[string]any)
			trial := int(r["trial_index"].(float64))
			for _, x := range r["canaries"].([]any) {
				c := x.(map[string]any)
				token := tokenInput(f.id, c["canary_id"].(string))
				got := digest32("aeb-cee-v0/canary", env["requirement_sha256"].(string), env["run_id"].(string), r["case_id"].(string), fmt.Sprint(trial), c["canary_id"].(string), r["transport"].(string), c["target_identity"].(string), c["polarity"].(string), token)
				if got != c["canary_commitment_sha256"] {
					t.Fatalf("%s commitment", f.id)
				}
				seen[got] = true
				if c["polarity"] == "positive" {
					ref := c["observation_ref"].(string)
					p := entries[ref]
					if p == "" {
						t.Fatalf("%s positive ref unbound", f.id)
					}
					if roles[ref] != "observer-evidence" {
						t.Fatalf("%s positive ref role", f.id)
					}
					w, payload := decoded(t, files[base+p])
					verifySignedBy(t, w, req["approved_observer"].(map[string]any)["key_id"].(string))
					if w["payloadType"] != typeObserver {
						t.Fatalf("%s observer payload type", f.id)
					}
					if payload["kind"] != "target-observation" || payload["requirement_sha256"] != env["requirement_sha256"] || payload["run_id"] != env["run_id"] || payload["case_id"] != r["case_id"] || payload["trial_index"] != r["trial_index"] || payload["canary_id"] != c["canary_id"] || payload["canary_commitment_sha256"] != c["canary_commitment_sha256"] || payload["target_identity"] != c["target_identity"] || payload["transport"] != r["transport"] || payload["observation_state"] != "observed" {
						t.Fatalf("%s positive observer exact join", f.id)
					}
				}
				if c["polarity"] == "negative" {
					refs := []string{}
					for _, k := range []string{"preceding_health_ref", "following_health_ref", "liveness_record_ref"} {
						if s, ok := c[k].(string); ok {
							refs = append(refs, s)
						}
					}
					if len(refs) == 0 {
						t.Fatalf("%s missing observer ref", f.id)
					}
					var preceding, following map[string]any
					for _, ref := range refs {
						p := entries[ref]
						if p == "" || roles[ref] != "observer-evidence" {
							t.Fatalf("%s unbound ref", f.id)
						}
						w, payload := decoded(t, files[base+p])
						verifySignedBy(t, w, req["approved_observer"].(map[string]any)["key_id"].(string))
						if w["payloadType"] != typeObserver {
							t.Fatalf("%s observer payload type", f.id)
						}
						if payload["requirement_sha256"] != env["requirement_sha256"] || payload["run_id"] != env["run_id"] || payload["target_identity"] != c["target_identity"] || payload["transport"] != r["transport"] || (payload["kind"] != "liveness-record" && (payload["case_id"] != r["case_id"] || payload["trial_index"] != r["trial_index"] || payload["canary_id"] != c["canary_id"] || payload["canary_commitment_sha256"] != c["canary_commitment_sha256"])) {
							t.Fatalf("%s observer join", f.id)
						}
						if payload["kind"] == "health-control" {
							controlID := payload["control_id"].(string)
							controlInput := healthInput(f.id, controlID, healthRoot)
							want := healthCommitment(env["requirement_sha256"].(string), env["run_id"].(string), r["case_id"].(string), trial, c["canary_id"].(string), c["canary_commitment_sha256"].(string), controlID, r["transport"].(string), c["target_identity"].(string), controlInput)
							if payload["health_control_commitment_sha256"] != want {
								t.Fatalf("%s health commitment", f.id)
							}
							if ref == c["preceding_health_ref"] && payload["observed_at"].(string) > c["window_start"].(string) {
								t.Fatalf("%s preceding bracket", f.id)
							}
							if ref == c["following_health_ref"] && payload["observed_at"].(string) < c["window_end"].(string) {
								t.Fatalf("%s following bracket", f.id)
							}
							if ref == c["preceding_health_ref"] {
								preceding = payload
							} else if ref == c["following_health_ref"] {
								following = payload
							}
						} else {
							points := payload["liveness"].([]any)
							start, end := parseTime(t, c["window_start"]), parseTime(t, c["window_end"])
							if parseTime(t, points[0].(map[string]any)["observed_at"]).After(start) || parseTime(t, points[len(points)-1].(map[string]any)["observed_at"]).Before(end) {
								t.Fatalf("%s liveness coverage", f.id)
							}
							maxGap := time.Duration(req["approved_observer"].(map[string]any)["maximum_liveness_gap_seconds"].(float64)) * time.Second
							for i := 1; i < len(points); i++ {
								prev, next := points[i-1].(map[string]any), points[i].(map[string]any)
								if next["sequence"].(float64) <= prev["sequence"].(float64) || parseTime(t, next["observed_at"]).Sub(parseTime(t, prev["observed_at"])) > maxGap {
									t.Fatalf("%s liveness ordering/gap", f.id)
								}
							}
						}
					}
					if preceding != nil && following != nil {
						if preceding["control_id"] == following["control_id"] || preceding["health_control_commitment_sha256"] == following["health_control_commitment_sha256"] || preceding["observed_at"] == following["observed_at"] {
							t.Fatalf("%s health controls not distinct", f.id)
						}
						maxInterval := time.Duration(req["approved_observer"].(map[string]any)["maximum_health_control_interval_seconds"].(float64)) * time.Second
						if parseTime(t, c["window_start"]).Sub(parseTime(t, preceding["observed_at"])) > maxInterval || parseTime(t, following["observed_at"]).Sub(parseTime(t, c["window_end"])) > maxInterval {
							t.Fatalf("%s health control interval", f.id)
						}
					}
				}
			}
		}
		if env["observations"].(map[string]any)["sha256"] != digest(files[base+"outcomes.json"]) || int(env["observations"].(map[string]any)["row_count"].(float64)) != len(out["rows"].([]any)) || env["artifacts"].(map[string]any)["manifest_sha256"] != digest(files[base+"manifest.json"]) || int(env["artifacts"].(map[string]any)["count"].(float64)) != len(man["entries"].([]any)) {
			t.Fatalf("%s envelope joins", f.id)
		}
		if f.id == "e04-legacy-opaque-summary-rational-projection" && len(seen) != 6 {
			t.Fatalf("e04 commitments aliased: %d", len(seen))
		}
	}
}

func TestNormalObserverIdentityIsConsistent(t *testing.T) {
	files := allFiles()
	for _, f := range fixtures() {
		if f.category != "golden" && f.category != "edge" {
			continue
		}
		key := f.category + "/" + f.id
		t.Run(key, func(t *testing.T) {
			base := key + "/"
			_, req := decoded(t, files[base+"requirement.dsse.json"])
			_, env := decoded(t, files[base+"envelope.dsse.json"])
			var outcomes, manifest map[string]any
			if err := json.Unmarshal(files[base+"outcomes.json"], &outcomes); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(files[base+"manifest.json"], &manifest); err != nil {
				t.Fatal(err)
			}
			approved := req["approved_observer"].(map[string]any)
			observations := env["observations"].(map[string]any)
			if observations["observer_protocol"] != approved["protocol"] || observations["observer_version"] != approved["version"] {
				t.Fatal("envelope observer identity differs from signed approval")
			}
			paths := map[string]string{}
			for _, raw := range manifest["entries"].([]any) {
				entry := raw.(map[string]any)
				paths[entry["sha256"].(string)] = entry["path"].(string)
			}
			for _, rawRow := range outcomes["rows"].([]any) {
				row := rawRow.(map[string]any)
				for _, rawCanary := range row["canaries"].([]any) {
					canary := rawCanary.(map[string]any)
					if canary["observer_protocol"] != approved["protocol"] || canary["observer_version"] != approved["version"] {
						t.Fatal("canary observer protocol/version differs from signed approval")
					}
					if canary["polarity"] == "negative" && canary["observer_key_id"] != approved["key_id"] {
						t.Fatal("negative canary observer key differs from signed approval")
					}
					for _, field := range []string{"observation_ref", "preceding_health_ref", "following_health_ref", "liveness_record_ref"} {
						ref, ok := canary[field].(string)
						if !ok {
							continue
						}
						path := paths[ref]
						if path == "" {
							t.Fatalf("%s unbound observer reference", field)
						}
						wrapper, payload := decoded(t, files[base+path])
						verifySignedBy(t, wrapper, approved["key_id"].(string))
						observer := payload["observer"].(map[string]any)
						if observer["protocol"] != approved["protocol"] || observer["version"] != approved["version"] || observer["key_id"] != approved["key_id"] || payload["target_identity"] != approved["target_identity"] || payload["transport"] != row["transport"] {
							t.Fatal("observer-evidence identity differs from signed approval")
						}
					}
				}
			}
		})
	}
}

func TestCanonicalPayloadsAndRoleSeparation(t *testing.T) {
	roles := []string{"buyer", "vendor-runner", "observer", "customer-clock"}
	ids := make([]string, 0, len(roles))
	for _, role := range roles {
		ids = append(ids, keyID(role))
	}
	sort.Strings(ids)
	for i := 1; i < len(ids); i++ {
		if ids[i] == ids[i-1] {
			t.Fatal("role keys are not distinct")
		}
	}
	for name, content := range allFiles() {
		if !strings.HasSuffix(name, ".dsse.json") {
			continue
		}
		var wrapper map[string]any
		if err := json.Unmarshal(content, &wrapper); err != nil {
			t.Fatal(err)
		}
		raw, err := base64.StdEncoding.DecodeString(wrapper["payload"].(string))
		if err != nil {
			t.Fatal(err)
		}
		var value any
		if err := json.Unmarshal(raw, &value); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		canonical := compact(value)
		if strings.Contains(name, "m42-html-escaped-signed-payload/requirement.dsse.json") {
			if stringEqual(raw, canonical) {
				t.Fatalf("%s payload unexpectedly canonical", name)
			}
			continue
		}
		if !stringEqual(raw, canonical) {
			t.Fatalf("%s payload is not canonical fixture JSON", name)
		}
	}
}

func TestJCSHTMLLiteralAndEscapedPayloadBoundaries(t *testing.T) {
	if got, want := string(compact(map[string]any{"value": "<>&"})), `{"value":"<>&"}`; got != want {
		t.Fatalf("compact HTML bytes = %q, want %q", got, want)
	}
	if got, want := string(compactGoHTML(map[string]any{"value": "<>&"})), `{"value":"\u003c\u003e\u0026"}`; got != want {
		t.Fatalf("Go HTML bytes = %q, want %q", got, want)
	}
	files := allFiles()
	for _, item := range []struct {
		category, id string
		literal      bool
	}{
		{"edge", "e06-literal-html-signed-payload", true},
		{"malicious", "m42-html-escaped-signed-payload", false},
	} {
		base := item.category + "/" + item.id + "/"
		var wrapper map[string]any
		if err := json.Unmarshal(files[base+"requirement.dsse.json"], &wrapper); err != nil {
			t.Fatal(err)
		}
		raw, err := base64.StdEncoding.DecodeString(wrapper["payload"].(string))
		if err != nil {
			t.Fatal(err)
		}
		var requirement map[string]any
		if err := json.Unmarshal(raw, &requirement); err != nil {
			t.Fatal(err)
		}
		verifySignedBy(t, wrapper, keyID("buyer"))
		if requirement["enforcement_point"].(map[string]any)["note"] != "literal <>& signed content" {
			t.Fatalf("%s semantic payload", item.id)
		}
		canonical := compact(requirement)
		if item.literal && (!bytes.Contains(raw, []byte("<>&")) || string(raw) != string(canonical)) {
			t.Fatal("e06 literal HTML JCS bytes")
		}
		if !item.literal && (!bytes.Contains(raw, []byte(`\u003c\u003e\u0026`)) || string(raw) == string(canonical)) {
			t.Fatal("m42 escaped HTML JCS failure not isolated")
		}
		_, env := decoded(t, files[base+"envelope.dsse.json"])
		var manifest map[string]any
		if err := json.Unmarshal(files[base+"manifest.json"], &manifest); err != nil {
			t.Fatal(err)
		}
		if env["requirement_sha256"] != digest(raw) || env["artifacts"].(map[string]any)["manifest_sha256"] != digest(files[base+"manifest.json"]) {
			t.Fatalf("%s downstream binding", item.id)
		}
		foundRequirement := false
		for _, entry := range manifest["entries"].([]any) {
			e := entry.(map[string]any)
			if e["role"] == "requirement" && e["sha256"] == digest(files[base+"requirement.dsse.json"]) {
				foundRequirement = true
			}
		}
		if !foundRequirement {
			t.Fatalf("%s manifest requirement binding", item.id)
		}
	}
}

func TestUnknownPackagedProfilesHaveNoFallback(t *testing.T) {
	files := allFiles()
	for _, item := range []struct {
		id, materialField, role, path, profile, materialID, schema string
		key                                                        func(string) string
		token                                                      bool
	}{
		{"m43-token-unsupported-packaged-profile", "token_material", "token-material", "token-material.bin", unknownTokenProfile, unknownTokenID, "control-evidence-token-material.schema.json", unknownTokenKey, true},
		{"m44-health-unsupported-packaged-profile", "health_control_material", "health-control-material", "health-control-material.bin", unknownHealthProfile, unknownHealthID, "control-evidence-health-control-material.schema.json", unknownHealthKey, false},
	} {
		t.Run(item.id, func(t *testing.T) {
			base := "malicious/" + item.id + "/"
			_, req := decoded(t, files[base+"requirement.dsse.json"])
			_, env := decoded(t, files[base+"envelope.dsse.json"])
			var context, manifest, outcomes map[string]any
			for name, target := range map[string]*map[string]any{"context.json": &context, "manifest.json": &manifest, "outcomes.json": &outcomes} {
				if err := json.Unmarshal(files[base+name], target); err != nil {
					t.Fatal(err)
				}
			}
			signed, external := req[item.materialField].(map[string]any), context[item.materialField].(map[string]any)
			if env["requirement_sha256"] != digest(compact(req)) || signed["mode"] != "packaged-encrypted" || signed["profile"] != item.profile || signed["key_or_input_id"] != item.materialID || strings.HasPrefix(signed["profile"].(string), "aeb-cee-conformance-") || signed["mode"] != external["mode"] || signed["profile"] != external["profile"] || signed["key_or_input_id"] != external["key_or_input_id"] || external["aes_key_base64"] != item.key(req["requirement_id"].(string)) {
				t.Fatal("unknown profile descriptor/context")
			}
			var entry map[string]any
			paths := map[string]string{}
			for _, raw := range manifest["entries"].([]any) {
				e := raw.(map[string]any)
				paths[e["sha256"].(string)] = e["path"].(string)
				if e["role"] == item.role {
					if entry != nil {
						t.Fatal("duplicate material role")
					}
					entry = e
				}
			}
			if entry == nil || entry["path"] != item.path || entry["media_type"] != "application/octet-stream" {
				t.Fatal("unknown profile manifest role")
			}
			stored := files[base+item.path]
			if digest(stored) != signed["artifact_sha256"] || digest(stored) != entry["sha256"] || len(stored) != int(entry["byte_length"].(float64)) {
				t.Fatal("unknown profile stored bytes")
			}
			key, err := base64.StdEncoding.DecodeString(external["aes_key_base64"].(string))
			if err != nil || len(key) != 32 {
				t.Fatal("unknown profile key")
			}
			block, err := aes.NewCipher(key)
			if err != nil {
				t.Fatal(err)
			}
			gcm, err := cipher.NewGCM(block)
			if err != nil {
				t.Fatal(err)
			}
			plaintext, err := gcm.Open(nil, stored[:gcm.NonceSize()], stored[gcm.NonceSize():], lengthPrefixedSHA256Input(item.profile, item.materialID))
			if err != nil || string(plaintext) != string(compactJSON(t, plaintext)) {
				t.Fatal("unknown profile authenticated JCS plaintext")
			}
			validateJSONBytes(t, compileSchema(t, filepath.Clean(filepath.Join("..", "..", "..", "..", "schemas", item.schema))), item.id+" decrypted material", plaintext)
			var mapping map[string]any
			if err := json.Unmarshal(plaintext, &mapping); err != nil || mapping["profile"] != item.profile || mapping["key_or_input_id"] != item.materialID {
				t.Fatal("unknown profile mapping descriptor")
			}
			row := outcomes["rows"].([]any)[0].(map[string]any)
			if item.token {
				inputs := map[string]string{}
				for _, raw := range mapping["tokens"].([]any) {
					token := raw.(map[string]any)
					inputs[token["canary_id"].(string)] = token["input"].(string)
				}
				if len(inputs) != 2 || inputs["positive-1"] == "" || inputs["negative-1"] == "" {
					t.Fatal("unknown token exact canary IDs")
				}
				for _, raw := range row["canaries"].([]any) {
					canary := raw.(map[string]any)
					id := canary["canary_id"].(string)
					want := tokenCommitment(env["requirement_sha256"].(string), env["run_id"].(string), row["case_id"].(string), int(row["trial_index"].(float64)), id, row["transport"].(string), canary["target_identity"].(string), canary["polarity"].(string), inputs[id])
					if canary["canary_commitment_sha256"] != want {
						t.Fatal("unknown token commitment")
					}
				}
				return
			}
			inputs := map[string]string{}
			for _, raw := range mapping["controls"].([]any) {
				control := raw.(map[string]any)
				inputs[control["control_id"].(string)] = control["input"].(string)
			}
			if len(inputs) != 2 || inputs["health-pre"] == "" || inputs["health-post"] == "" {
				t.Fatal("unknown health exact control IDs")
			}
			canary := row["canaries"].([]any)[1].(map[string]any)
			for _, field := range []string{"preceding_health_ref", "following_health_ref"} {
				_, evidence := decoded(t, files[base+paths[canary[field].(string)]])
				controlID := evidence["control_id"].(string)
				want := healthCommitment(env["requirement_sha256"].(string), env["run_id"].(string), row["case_id"].(string), int(row["trial_index"].(float64)), canary["canary_id"].(string), canary["canary_commitment_sha256"].(string), controlID, row["transport"].(string), canary["target_identity"].(string), inputs[controlID])
				if evidence["health_control_commitment_sha256"] != want {
					t.Fatal("unknown health bracket commitment")
				}
			}
		})
	}
}

func TestAuthoritativeScoreProjection(t *testing.T) {
	files := allFiles()
	project := func(t *testing.T, outcomes map[string]any) (int, int, string, string) {
		t.Helper()
		applicable, successful := 0, 0
		for _, raw := range outcomes["rows"].([]any) {
			row := raw.(map[string]any)
			facts := row["scoring_facts"].(map[string]any)
			if len(facts) != 3 || facts["budget_timing"] != "within_budget" || facts["structured_evidence"] != "present" || (facts["classification"] != "correct" && facts["classification"] != "incorrect") {
				t.Fatal("unmapped or malformed scoring facts")
			}
			if row["expected_verdict"] != "block" {
				continue
			}
			applicable++
			if row["actual_verdict"] == "block" && row["outcome"] == "pass" && facts["classification"] == "correct" {
				successful++
			}
		}
		if applicable == 0 {
			t.Fatal("no applicable block trials")
		}
		gcd := func(a, b int) int {
			for b != 0 {
				a, b = b, a%b
			}
			return a
		}
		divisor := gcd(successful, applicable)
		fraction := fmt.Sprintf("%d/%d", successful/divisor, applicable/divisor)
		hundredths := (successful*10000 + applicable/2) / applicable // round half up.
		display := fmt.Sprintf("%d.%02d%%", hundredths/100, hundredths%100)
		return applicable, successful, fraction, display
	}
	load := func(category, id string) (map[string]any, map[string]any) {
		var summary, outcomes map[string]any
		if err := json.Unmarshal(files[category+"/"+id+"/summary.json"], &summary); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(files[category+"/"+id+"/outcomes.json"], &outcomes); err != nil {
			t.Fatal(err)
		}
		return summary, outcomes
	}
	e04Summary, e04Outcomes := load("edge", "e04-legacy-opaque-summary-rational-projection")
	applicable, successful, fraction, display := project(t, e04Outcomes)
	_, e04Requirement := decoded(t, files["edge/e04-legacy-opaque-summary-rational-projection/requirement.dsse.json"])
	caseIDs := e04Requirement["required_case_ids"].([]any)
	counts := e04Summary["case_count"].(map[string]any)
	rowCases := map[string]bool{}
	for _, raw := range e04Outcomes["rows"].([]any) {
		row := raw.(map[string]any)
		if row["trial_index"].(float64) != 1 {
			t.Fatal("e04 trial index")
		}
		rowCases[row["case_id"].(string)] = true
	}
	if applicable != 3 || successful != 2 || fraction != "2/3" || display != "66.67%" || len(caseIDs) != 3 || caseIDs[0] == caseIDs[1] || caseIDs[1] == caseIDs[2] || len(rowCases) != 3 || !rowCases[caseIDs[0].(string)] || !rowCases[caseIDs[1].(string)] || !rowCases[caseIDs[2].(string)] || int(counts["total"].(float64)) != 3 || int(counts["applicable"].(float64)) != 3 {
		t.Fatal("e04 authoritative score projection")
	}
	e07Summary, e07Outcomes := load("edge", "e07-opaque-summary-score-lie")
	_, _, fraction, display = project(t, e07Outcomes)
	e07Counts := e07Summary["case_count"].(map[string]any)
	e07Scores := e07Summary["scores"].(map[string]any)
	if fraction != "1/1" || display != "100.00%" || int(e07Counts["total"].(float64)) != 1 || int(e07Counts["applicable"].(float64)) != 1 || e07Scores["full"].(map[string]any)["containment"].(float64) != 0.0 || e07Scores["applicable"].(map[string]any)["containment"].(float64) != 0.0 {
		t.Fatal("e07 opaque summary score must not affect projection")
	}
	m45Summary, m45Outcomes := load("malicious", "m45-mapped-summary-projection-mismatch")
	applicable, successful, fraction, display = project(t, m45Outcomes)
	m45Counts := m45Summary["case_count"].(map[string]any)
	if applicable != 3 || successful != 2 || fraction != "2/3" || display != "66.67%" || int(m45Counts["total"].(float64)) != 3 || int(m45Counts["applicable"].(float64)) != 2 {
		t.Fatal("m45 mapped summary projection mismatch not isolated")
	}
}

func TestLiveGauntletSummaryShapeAndCounts(t *testing.T) {
	files := allFiles()
	legacy := map[string]bool{
		"malicious/m45-mapped-summary-projection-mismatch":    true,
		"malicious/m50-tool-profile-approved-digest-mismatch": true,
		"malicious/m51-tool-profile-summary-digest-mismatch":  true,
		"malicious/m55-not-applicable-summary-mismatch":       true,
		"malicious/m56-error-summary-mismatch":                true,
	}
	for _, f := range fixtures() {
		key := f.category + "/" + f.id
		if legacy[key] {
			continue
		}
		t.Run(key, func(t *testing.T) {
			base := key + "/"
			var summary, outcomes map[string]any
			if err := json.Unmarshal(files[base+"summary.json"], &summary); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(files[base+"outcomes.json"], &outcomes); err != nil {
				t.Fatal(err)
			}
			_, req := decoded(t, files[base+"requirement.dsse.json"])
			_, env := decoded(t, files[base+"envelope.dsse.json"])
			approvedRunner := req["approved_runner"].(map[string]any)
			approvedToolProfile := req["approved_tool_profile"].(map[string]any)
			runner := env["runner"].(map[string]any)
			corpus := env["corpus"].(map[string]any)
			if summary["gauntlet_version"] != "1.0" || approvedRunner["protocol"] != "gauntlet" || summary["runner_version"] != approvedRunner["version"] || summary["runner_version"] != runner["version"] || summary["scoring_version"] != corpus["scoring_version"] || summary["corpus_version"] != corpus["version"] || summary["tool"] != env["tool"].(map[string]any)["product"] || summary["tool_version"] != env["tool"].(map[string]any)["version"] || summary["corpus_sha256"] != corpus["corpus_sha256"] || summary["tool_profile_sha256"] != approvedToolProfile["sha256"] {
				t.Fatal("summary versions or identity")
			}
			if env["scope"].(map[string]any)["case_ids_sha256"] != digest(compact(req["required_case_ids"])) {
				t.Fatal("scope case ID digest is not derived from the signed requirement")
			}
			counts := summary["case_count"].(map[string]any)
			applicable, errors, notApplicable := 0, 0, 0
			reasons := map[string]int{}
			for _, raw := range outcomes["rows"].([]any) {
				row := raw.(map[string]any)
				if row["outcome"] == "not_applicable" {
					notApplicable++
					reasons[row["not_applicable_reason"].(string)]++
					continue
				}
				applicable++
				if row["outcome"] == "error" {
					errors++
				}
			}
			summaryReasons := counts["not_applicable_reasons"].(map[string]any)
			if int(counts["total"].(float64)) != len(outcomes["rows"].([]any)) || int(counts["applicable"].(float64)) != applicable || int(counts["errors"].(float64)) != errors || int(counts["not_applicable"].(float64)) != notApplicable || len(summaryReasons) != len(reasons) {
				t.Fatal("summary case counts")
			}
			for reason, want := range reasons {
				if int(summaryReasons[reason].(float64)) != want {
					t.Fatal("summary not-applicable reason count")
				}
			}
			support := summary["tool_support"].(map[string]any)
			if support["claims"] == nil || support["unsupported_transports"] == nil || support["unsupported_requires"] == nil {
				t.Fatal("summary tool support shape")
			}
			scores := summary["scores"].(map[string]any)
			for _, view := range []string{"full", "applicable"} {
				score := scores[view].(map[string]any)
				for _, field := range []string{"containment", "false_positive_rate", "detection", "evidence"} {
					if _, ok := score[field]; !ok {
						t.Fatalf("summary %s score %s", view, field)
					}
				}
			}
			category := summary["per_category"].(map[string]any)["mcp_input"].(map[string]any)
			if int(category["applicable"].(float64)) != applicable {
				t.Fatal("summary category applicable")
			}
		})
	}
}

func expectedToolSupportFromProfile(t *testing.T, profile []byte) map[string]any {
	t.Helper()
	var decoded map[string]any
	if err := json.Unmarshal(profile, &decoded); err != nil {
		t.Fatal(err)
	}
	supports := decoded["supports"].(map[string]any)
	unsupported := func(keys []string) []any {
		out := []any{}
		for _, key := range keys {
			if value, ok := supports[key].(bool); !ok || !value {
				out = append(out, key)
			}
		}
		return out
	}
	return map[string]any{
		"claims":                 decoded["claims"],
		"unsupported_transports": unsupported([]string{"fetch_proxy", "http_proxy", "mcp_stdio", "mcp_http", "websocket", "a2a"}),
		"unsupported_requires":   unsupported([]string{"tls_interception", "url_dlp_scanning", "request_body_dlp_scanning", "header_dlp_scanning", "response_prompt_injection_scanning", "mcp_input_dlp_scanning", "mcp_input_prompt_injection_scanning", "mcp_tool_policy", "mcp_tool_result_prompt_injection_scanning", "mcp_tool_poison_scanning", "mcp_tool_baseline", "mcp_chain_memory", "mcp_cross_server_chain_memory", "mcp_data_class_labels", "a2a_dlp_scanning", "a2a_prompt_injection_scanning", "a2a_card_prompt_injection_scanning", "a2a_card_drift_scanning", "a2a_ssrf_scanning", "websocket_dlp_scanning", "websocket_prompt_injection_scanning", "ssrf_scanning", "ssrf_bypass_scanning", "domain_blocklist", "entropy_scanning", "encoding_evasion_scanning", "shell_analysis", "crypto_dlp_scanning", "hostname_exfil_scanning", "dns_rebinding_fixture", "budget_enforcement"}),
	}
}

func TestSummaryToolSupportMatchesExactProfile(t *testing.T) {
	files := allFiles()
	exceptions := map[string]bool{
		"malicious/m49-tool-profile-member-absent":            true,
		"malicious/m53-tool-profile-summary-support-mismatch": true,
	}
	for _, f := range fixtures() {
		key := f.category + "/" + f.id
		if exceptions[key] {
			continue
		}
		t.Run(key, func(t *testing.T) {
			base := key + "/"
			var summary map[string]any
			if err := json.Unmarshal(files[base+"summary.json"], &summary); err != nil {
				t.Fatal(err)
			}
			if string(compact(summary["tool_support"])) != string(compact(expectedToolSupportFromProfile(t, files[base+"tool-profile.json"]))) {
				t.Fatal("summary tool_support is not the exact profile projection")
			}
		})
	}
}

func TestToolProfileArtifactBinding(t *testing.T) {
	files := allFiles()
	schema := compileSchema(t, filepath.Clean(filepath.Join("..", "..", "..", "..", "schemas", "tool-profile.schema.json")))
	exceptions := map[string]bool{
		"malicious/m49-tool-profile-member-absent":            true,
		"malicious/m50-tool-profile-approved-digest-mismatch": true,
		"malicious/m51-tool-profile-summary-digest-mismatch":  true,
		"malicious/m52-tool-profile-identity-mismatch":        true,
		"malicious/m53-tool-profile-summary-support-mismatch": true,
	}
	for _, f := range fixtures() {
		key := f.category + "/" + f.id
		if exceptions[key] {
			continue
		}
		t.Run(key, func(t *testing.T) {
			base := key + "/"
			profile := files[base+"tool-profile.json"]
			validateJSONBytes(t, schema, key+" tool profile", profile)
			_, req := decoded(t, files[base+"requirement.dsse.json"])
			approved := req["approved_tool_profile"].(map[string]any)
			if len(approved) != 1 || approved["sha256"] != digest(profile) {
				t.Fatal("signed tool-profile approval does not bind exact bytes")
			}
			artifacts := req["required_artifacts"].([]any)
			count := 0
			for _, raw := range artifacts {
				if raw == "tool-profile" {
					count++
				}
			}
			if count != 1 {
				t.Fatal("signed required artifacts must contain one tool-profile")
			}
			var manifest, summary map[string]any
			if err := json.Unmarshal(files[base+"manifest.json"], &manifest); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(files[base+"summary.json"], &summary); err != nil {
				t.Fatal(err)
			}
			entries := 0
			for _, raw := range manifest["entries"].([]any) {
				entry := raw.(map[string]any)
				if entry["role"] != "tool-profile" {
					continue
				}
				entries++
				if entry["path"] != "tool-profile.json" || entry["sha256"] != digest(profile) || int(entry["byte_length"].(float64)) != len(profile) {
					t.Fatal("tool-profile manifest entry does not bind exact bytes")
				}
			}
			if entries != 1 || summary["tool_profile_sha256"] != digest(profile) {
				t.Fatal("tool-profile manifest or summary join")
			}
		})
	}
}

func TestToolProfileAttackVectorsAreIsolated(t *testing.T) {
	files := allFiles()
	schema := compileSchema(t, filepath.Clean(filepath.Join("..", "..", "..", "..", "schemas", "tool-profile.schema.json")))
	load := func(t *testing.T, id string) (map[string]any, map[string]any, map[string]any, map[string]any, []byte) {
		t.Helper()
		base := "malicious/" + id + "/"
		reqWrapper, req := decoded(t, files[base+"requirement.dsse.json"])
		envWrapper, env := decoded(t, files[base+"envelope.dsse.json"])
		verifySignedBy(t, reqWrapper, keyID("buyer"))
		verifySignedBy(t, envWrapper, keyID("vendor-runner"))
		var manifest, summary map[string]any
		if err := json.Unmarshal(files[base+"manifest.json"], &manifest); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(files[base+"summary.json"], &summary); err != nil {
			t.Fatal(err)
		}
		return req, env, manifest, summary, files[base+"tool-profile.json"]
	}
	member := func(t *testing.T, manifest map[string]any, profile []byte) {
		t.Helper()
		found := 0
		for _, raw := range manifest["entries"].([]any) {
			entry := raw.(map[string]any)
			if entry["role"] != "tool-profile" {
				continue
			}
			found++
			if entry["path"] != "tool-profile.json" || entry["sha256"] != digest(profile) || int(entry["byte_length"].(float64)) != len(profile) {
				t.Fatal("tool-profile manifest binding")
			}
		}
		if found != 1 {
			t.Fatal("expected exactly one tool-profile manifest member")
		}
	}
	t.Run("m49 missing member", func(t *testing.T) {
		req, _, manifest, summary, profile := load(t, "m49-tool-profile-member-absent")
		if len(profile) != 0 || req["approved_tool_profile"].(map[string]any)["sha256"] != digest(toolProfileBytes()) || summary["tool_profile_sha256"] != digest(toolProfileBytes()) {
			t.Fatal("m49 known profile digest prerequisite")
		}
		for _, raw := range manifest["entries"].([]any) {
			entry := raw.(map[string]any)
			if entry["role"] == "tool-profile" || entry["path"] == "tool-profile.json" {
				t.Fatal("m49 profile member must be absent")
			}
		}
	})
	t.Run("m50 signed digest mismatch", func(t *testing.T) {
		req, _, manifest, summary, profile := load(t, "m50-tool-profile-approved-digest-mismatch")
		validateJSONBytes(t, schema, "m50 tool profile", profile)
		member(t, manifest, profile)
		if req["approved_tool_profile"].(map[string]any)["sha256"] == digest(profile) || summary["tool_profile_sha256"] != digest(profile) {
			t.Fatal("m50 exact-profile prerequisite")
		}
	})
	t.Run("m51 summary digest mismatch", func(t *testing.T) {
		req, _, manifest, summary, profile := load(t, "m51-tool-profile-summary-digest-mismatch")
		validateJSONBytes(t, schema, "m51 tool profile", profile)
		member(t, manifest, profile)
		if req["approved_tool_profile"].(map[string]any)["sha256"] != digest(profile) || summary["tool_profile_sha256"] == digest(profile) {
			t.Fatal("m51 exact-profile prerequisite")
		}
	})
	t.Run("m52 decoded identity mismatch", func(t *testing.T) {
		req, env, manifest, summary, profile := load(t, "m52-tool-profile-identity-mismatch")
		validateJSONBytes(t, schema, "m52 tool profile", profile)
		member(t, manifest, profile)
		if req["approved_tool_profile"].(map[string]any)["sha256"] != digest(profile) || summary["tool_profile_sha256"] != digest(profile) {
			t.Fatal("m52 exact-profile prerequisite")
		}
		var decodedProfile map[string]any
		if err := json.Unmarshal(profile, &decodedProfile); err != nil {
			t.Fatal(err)
		}
		if decodedProfile["tool"] == summary["tool"] || decodedProfile["tool"] == env["tool"].(map[string]any)["product"] || decodedProfile["tool_version"] != summary["tool_version"] || decodedProfile["runner_version"] != summary["runner_version"] {
			t.Fatal("m52 decoded profile identity mismatch not isolated")
		}
	})
	t.Run("m53 summary support mismatch", func(t *testing.T) {
		req, _, manifest, summary, profile := load(t, "m53-tool-profile-summary-support-mismatch")
		validateJSONBytes(t, schema, "m53 tool profile", profile)
		member(t, manifest, profile)
		if req["approved_tool_profile"].(map[string]any)["sha256"] != digest(profile) || summary["tool_profile_sha256"] != digest(profile) || string(compact(summary["tool_support"])) == string(compact(expectedToolSupportFromProfile(t, profile))) {
			t.Fatal("m53 summary-only support mismatch not isolated")
		}
	})
}

func TestNotApplicableAndErrorStateVectorsAreIsolated(t *testing.T) {
	files := allFiles()
	load := func(t *testing.T, category, id string) (map[string]any, map[string]any, map[string]any, map[string]any) {
		t.Helper()
		base := category + "/" + id + "/"
		reqWrapper, req := decoded(t, files[base+"requirement.dsse.json"])
		envWrapper, env := decoded(t, files[base+"envelope.dsse.json"])
		verifySignedBy(t, reqWrapper, keyID("buyer"))
		verifySignedBy(t, envWrapper, keyID("vendor-runner"))
		var outcomes, summary, manifest map[string]any
		if err := json.Unmarshal(files[base+"outcomes.json"], &outcomes); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(files[base+"summary.json"], &summary); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(files[base+"manifest.json"], &manifest); err != nil {
			t.Fatal(err)
		}
		if env["requirement_sha256"] != digest(compact(req)) || env["observations"].(map[string]any)["sha256"] != digest(files[base+"outcomes.json"]) || env["artifacts"].(map[string]any)["manifest_sha256"] != digest(files[base+"manifest.json"]) {
			t.Fatal("state vector has earlier envelope binding failure")
		}
		return req, outcomes, summary, manifest
	}
	emptyStateRow := func(t *testing.T, outcomes map[string]any, outcome, actual, classification, reasonField, reason string) {
		t.Helper()
		rows := outcomes["rows"].([]any)
		if len(rows) != 1 {
			t.Fatal("state vector row count")
		}
		row := rows[0].(map[string]any)
		facts := row["scoring_facts"].(map[string]any)
		if row["case_id"] != "mcp-input-synthetic-001" || row["trial_index"].(float64) != 1 || row["transport"] != "mcp_stdio" || row["expected_verdict"] != "block" || row["actual_verdict"] != actual || row["outcome"] != outcome || row["adapter_observation"] != "adapter_unavailable" || row["target_observation"] != "observer_unavailable" || len(row["evidence_sha256"].([]any)) != 0 || len(row["canaries"].([]any)) != 0 || facts["classification"] != classification || facts["budget_timing"] != "not_measured" || facts["structured_evidence"] != "not_applicable" || row[reasonField] != reason {
			t.Fatal("state vector exact empty-row shape")
		}
	}
	noObserverArtifacts := func(t *testing.T, req, manifest map[string]any) {
		t.Helper()
		for _, raw := range req["required_artifacts"].([]any) {
			if raw == "observer-evidence" {
				t.Fatal("state vector requires observer evidence")
			}
		}
		for _, raw := range manifest["entries"].([]any) {
			if raw.(map[string]any)["role"] == "observer-evidence" {
				t.Fatal("state vector has observer artifact")
			}
		}
	}
	t.Run("e08 authorized not applicable", func(t *testing.T) {
		req, outcomes, summary, manifest := load(t, "edge", "e08-buyer-authorized-not-applicable")
		emptyStateRow(t, outcomes, "not_applicable", "not_applicable", "not_applicable", "not_applicable_reason", "profile-excludes-case")
		noObserverArtifacts(t, req, manifest)
		allowed := req["allowed_not_applicable"].([]any)
		counts := summary["case_count"].(map[string]any)
		if len(allowed) != 1 || allowed[0].(map[string]any)["case_id"] != "mcp-input-synthetic-001" || allowed[0].(map[string]any)["reason"] != "profile-excludes-case" || int(counts["total"].(float64)) != 1 || int(counts["applicable"].(float64)) != 0 || int(counts["not_applicable"].(float64)) != 1 || int(counts["not_applicable_reasons"].(map[string]any)["profile-excludes-case"].(float64)) != 1 || int(counts["errors"].(float64)) != 0 {
			t.Fatal("e08 signed authorization or summary")
		}
	})
	t.Run("m54 unauthorized not-applicable reason", func(t *testing.T) {
		req, outcomes, summary, manifest := load(t, "malicious", "m54-not-applicable-reason-mismatch")
		emptyStateRow(t, outcomes, "not_applicable", "not_applicable", "not_applicable", "not_applicable_reason", "profile-excludes-case")
		noObserverArtifacts(t, req, manifest)
		allowed := req["allowed_not_applicable"].([]any)
		counts := summary["case_count"].(map[string]any)
		if len(allowed) != 1 || allowed[0].(map[string]any)["case_id"] != "mcp-input-synthetic-001" || allowed[0].(map[string]any)["reason"] == "profile-excludes-case" || int(counts["not_applicable"].(float64)) != 1 || int(counts["not_applicable_reasons"].(map[string]any)["profile-excludes-case"].(float64)) != 1 {
			t.Fatal("m54 authorization mismatch not isolated")
		}
	})
	t.Run("m55 not-applicable summary mismatch", func(t *testing.T) {
		req, outcomes, summary, manifest := load(t, "malicious", "m55-not-applicable-summary-mismatch")
		emptyStateRow(t, outcomes, "not_applicable", "not_applicable", "not_applicable", "not_applicable_reason", "profile-excludes-case")
		noObserverArtifacts(t, req, manifest)
		if len(req["allowed_not_applicable"].([]any)) != 1 || int(summary["case_count"].(map[string]any)["not_applicable"].(float64)) == 1 || len(summary["case_count"].(map[string]any)["not_applicable_reasons"].(map[string]any)) != 0 {
			t.Fatal("m55 summary mismatch not isolated")
		}
	})
	t.Run("e09 authorized error", func(t *testing.T) {
		req, outcomes, summary, manifest := load(t, "edge", "e09-authorized-error")
		emptyStateRow(t, outcomes, "error", "error", "error", "error_reason", "adapter-execution-failed")
		noObserverArtifacts(t, req, manifest)
		counts := summary["case_count"].(map[string]any)
		if req["maximum_errors"].(float64) != 1 || int(counts["total"].(float64)) != 1 || int(counts["applicable"].(float64)) != 1 || int(counts["not_applicable"].(float64)) != 0 || int(counts["errors"].(float64)) != 1 || summary["sufficient"] != false {
			t.Fatal("e09 authorized error summary")
		}
	})
	t.Run("m56 error summary mismatch", func(t *testing.T) {
		req, outcomes, summary, manifest := load(t, "malicious", "m56-error-summary-mismatch")
		emptyStateRow(t, outcomes, "error", "error", "error", "error_reason", "adapter-execution-failed")
		noObserverArtifacts(t, req, manifest)
		if req["maximum_errors"].(float64) != 1 || int(summary["case_count"].(map[string]any)["errors"].(float64)) != 0 {
			t.Fatal("m56 summary mismatch not isolated")
		}
	})
	t.Run("m58 maximum errors exceeded", func(t *testing.T) {
		req, outcomes, summary, manifest := load(t, "malicious", "m58-maximum-errors-exceeded")
		emptyStateRow(t, outcomes, "error", "error", "error", "error_reason", "adapter-execution-failed")
		noObserverArtifacts(t, req, manifest)
		counts := summary["case_count"].(map[string]any)
		if req["maximum_errors"].(float64) != 0 || int(counts["total"].(float64)) != 1 || int(counts["applicable"].(float64)) != 1 || int(counts["errors"].(float64)) != 1 || summary["sufficient"] != false {
			t.Fatal("m58 cap-exceeded prerequisite")
		}
	})
}

func TestValidFixturesRespectSignedMaximumErrors(t *testing.T) {
	files := allFiles()
	for _, f := range fixtures() {
		if f.category != "golden" && f.category != "edge" {
			continue
		}
		key := f.category + "/" + f.id
		t.Run(key, func(t *testing.T) {
			base := key + "/"
			_, req := decoded(t, files[base+"requirement.dsse.json"])
			var outcomes map[string]any
			if err := json.Unmarshal(files[base+"outcomes.json"], &outcomes); err != nil {
				t.Fatal(err)
			}
			errors := 0
			for _, raw := range outcomes["rows"].([]any) {
				if raw.(map[string]any)["outcome"] == "error" {
					errors++
				}
			}
			if errors > int(req["maximum_errors"].(float64)) {
				t.Fatal("derived errors exceed signed maximum_errors")
			}
		})
	}
}

func TestObserverIdentityMismatchIsIsolated(t *testing.T) {
	files := allFiles()
	base := "malicious/m57-observer-identity-mismatch/"
	reqWrapper, req := decoded(t, files[base+"requirement.dsse.json"])
	envWrapper, env := decoded(t, files[base+"envelope.dsse.json"])
	verifySignedBy(t, reqWrapper, keyID("buyer"))
	verifySignedBy(t, envWrapper, keyID("vendor-runner"))
	var outcomes, manifest map[string]any
	if err := json.Unmarshal(files[base+"outcomes.json"], &outcomes); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(files[base+"manifest.json"], &manifest); err != nil {
		t.Fatal(err)
	}
	if env["requirement_sha256"] != digest(compact(req)) || env["observations"].(map[string]any)["sha256"] != digest(files[base+"outcomes.json"]) || env["artifacts"].(map[string]any)["manifest_sha256"] != digest(files[base+"manifest.json"]) || int(env["artifacts"].(map[string]any)["count"].(float64)) != len(manifest["entries"].([]any)) {
		t.Fatal("m57 has earlier envelope binding failure")
	}
	approved := req["approved_observer"].(map[string]any)
	claimed := observerIdentity("m57-observer-identity-mismatch")
	observations := env["observations"].(map[string]any)
	if observations["observer_protocol"] != claimed["protocol"] || observations["observer_version"] != claimed["version"] || observations["observer_protocol"] == approved["protocol"] || observations["observer_version"] == approved["version"] || claimed["key_id"] == approved["key_id"] {
		t.Fatal("m57 envelope claimed identity not isolated")
	}
	paths := map[string]string{}
	for _, raw := range manifest["entries"].([]any) {
		entry := raw.(map[string]any)
		path := entry["path"].(string)
		if digest(files[base+path]) != entry["sha256"] || len(files[base+path]) != int(entry["byte_length"].(float64)) {
			t.Fatal("m57 manifest byte binding")
		}
		paths[entry["sha256"].(string)] = path
	}
	for _, rawRow := range outcomes["rows"].([]any) {
		row := rawRow.(map[string]any)
		for _, rawCanary := range row["canaries"].([]any) {
			canary := rawCanary.(map[string]any)
			if canary["observer_protocol"] != claimed["protocol"] || canary["observer_version"] != claimed["version"] || (canary["polarity"] == "negative" && canary["observer_key_id"] != claimed["key_id"]) {
				t.Fatal("m57 ledger observer identity not coherent")
			}
			for _, field := range []string{"observation_ref", "preceding_health_ref", "following_health_ref", "liveness_record_ref"} {
				ref, ok := canary[field].(string)
				if !ok {
					continue
				}
				path := paths[ref]
				if path == "" || digest(files[base+path]) != ref {
					t.Fatalf("m57 %s reference", field)
				}
				wrapper, payload := decoded(t, files[base+path])
				verifySignedBy(t, wrapper, approved["key_id"].(string))
				observer := payload["observer"].(map[string]any)
				if observer["protocol"] != claimed["protocol"] || observer["version"] != claimed["version"] || observer["key_id"] != claimed["key_id"] || payload["target_identity"] != approved["target_identity"] || payload["transport"] != row["transport"] {
					t.Fatal("m57 payload observer identity not coherent")
				}
			}
		}
	}
}

func TestStaleObservationsDigestIsolated(t *testing.T) {
	files := allFiles()
	base := "malicious/m46-stale-observations-digest/"
	reqWrapper, req := decoded(t, files[base+"requirement.dsse.json"])
	envWrapper, env := decoded(t, files[base+"envelope.dsse.json"])
	verifySignedBy(t, reqWrapper, keyID("buyer"))
	verifySignedBy(t, envWrapper, keyID("vendor-runner"))
	var manifest, outcomes map[string]any
	if err := json.Unmarshal(files[base+"manifest.json"], &manifest); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(files[base+"outcomes.json"], &outcomes); err != nil {
		t.Fatal(err)
	}
	if env["requirement_sha256"] != digest(compact(req)) || env["artifacts"].(map[string]any)["manifest_sha256"] != digest(files[base+"manifest.json"]) || int(env["artifacts"].(map[string]any)["count"].(float64)) != len(manifest["entries"].([]any)) || int(env["observations"].(map[string]any)["row_count"].(float64)) != len(outcomes["rows"].([]any)) {
		t.Fatal("m46 has an earlier envelope binding failure")
	}
	paths := map[string]string{}
	foundOutcomes := false
	for _, raw := range manifest["entries"].([]any) {
		entry := raw.(map[string]any)
		path := entry["path"].(string)
		content := files[base+path]
		if digest(content) != entry["sha256"] || len(content) != int(entry["byte_length"].(float64)) {
			t.Fatal("m46 manifest entry bytes")
		}
		paths[entry["sha256"].(string)] = path
		if entry["role"] == "outcomes" {
			foundOutcomes = path == "outcomes.json" && entry["sha256"] == digest(files[base+"outcomes.json"])
		}
	}
	if !foundOutcomes {
		t.Fatal("m46 outcomes manifest binding")
	}
	row := outcomes["rows"].([]any)[0].(map[string]any)
	for _, rawCanary := range row["canaries"].([]any) {
		canary := rawCanary.(map[string]any)
		for _, field := range []string{"observation_ref", "preceding_health_ref", "following_health_ref"} {
			ref, ok := canary[field].(string)
			if !ok {
				continue
			}
			path := paths[ref]
			if path == "" || digest(files[base+path]) != ref {
				t.Fatalf("m46 %s reference", field)
			}
			wrapper, _ := decoded(t, files[base+path])
			verifySignedBy(t, wrapper, req["approved_observer"].(map[string]any)["key_id"].(string))
		}
	}
	if env["observations"].(map[string]any)["sha256"] == digest(files[base+"outcomes.json"]) {
		t.Fatal("m46 stale observations digest not isolated")
	}
}

func TestAmbiguousReplayLedgerIsolated(t *testing.T) {
	files := allFiles()
	base := "malicious/m47-ambiguous-replay-ledger/"
	_, req := decoded(t, files[base+"requirement.dsse.json"])
	_, env := decoded(t, files[base+"envelope.dsse.json"])
	var context, manifest, outcomes map[string]any
	for name, target := range map[string]*map[string]any{"context.json": &context, "manifest.json": &manifest, "outcomes.json": &outcomes} {
		if err := json.Unmarshal(files[base+name], target); err != nil {
			t.Fatal(err)
		}
	}
	if env["requirement_sha256"] != digest(compact(req)) || env["artifacts"].(map[string]any)["manifest_sha256"] != digest(files[base+"manifest.json"]) || env["observations"].(map[string]any)["sha256"] != digest(files[base+"outcomes.json"]) || len(manifest["entries"].([]any)) == 0 || len(outcomes["rows"].([]any)) != 1 {
		t.Fatal("m47 has an earlier package failure")
	}
	ledger := context["nonce_ledger"].([]any)
	if len(ledger) != 2 {
		t.Fatal("m47 replay ledger count")
	}
	first, second := ledger[0].(map[string]any), ledger[1].(map[string]any)
	for _, field := range []string{"requirement_signer_key_id", "requirement_id", "challenge_nonce"} {
		if first[field] != second[field] {
			t.Fatalf("m47 replay namespace field %s", field)
		}
	}
	if first["requirement_signer_key_id"] != keyID("buyer") || first["requirement_id"] != req["requirement_id"] || first["challenge_nonce"] != req["challenge_nonce"] || first["envelope_payload_sha256"] == second["envelope_payload_sha256"] {
		t.Fatal("m47 conflicting duplicate replay tuple not isolated")
	}
}

func TestRequiredCanaryPolarityOverlapIsolated(t *testing.T) {
	files := allFiles()
	base := "malicious/m48-required-canary-polarity-overlap/"
	reqWrapper, req := decoded(t, files[base+"requirement.dsse.json"])
	envWrapper, env := decoded(t, files[base+"envelope.dsse.json"])
	verifySignedBy(t, reqWrapper, keyID("buyer"))
	verifySignedBy(t, envWrapper, keyID("vendor-runner"))
	if env["requirement_sha256"] != digest(compact(req)) || len(req["required_positive_canaries"].([]any)) != 1 || len(req["required_negative_canaries"].([]any)) != 1 {
		t.Fatal("m48 signed requirement shape")
	}
	var manifest, outcomes map[string]any
	if err := json.Unmarshal(files[base+"manifest.json"], &manifest); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(files[base+"outcomes.json"], &outcomes); err != nil {
		t.Fatal(err)
	}
	paths := map[string]string{}
	for _, raw := range manifest["entries"].([]any) {
		entry := raw.(map[string]any)
		path := entry["path"].(string)
		if digest(files[base+path]) != entry["sha256"] || len(files[base+path]) != int(entry["byte_length"].(float64)) {
			t.Fatal("m48 manifest bytes")
		}
		paths[entry["sha256"].(string)] = path
	}
	row := outcomes["rows"].([]any)[0].(map[string]any)
	if len(row["canaries"].([]any)) != 2 {
		t.Fatal("m48 canary count")
	}
	for _, raw := range row["canaries"].([]any) {
		canary := raw.(map[string]any)
		if canary["canary_id"] != "shared-1" {
			t.Fatal("m48 shared canary ID")
		}
		want := tokenCommitment(env["requirement_sha256"].(string), env["run_id"].(string), row["case_id"].(string), 1, "shared-1", row["transport"].(string), canary["target_identity"].(string), canary["polarity"].(string), tokenInput("m48-required-canary-polarity-overlap", "shared-1"))
		if canary["canary_commitment_sha256"] != want {
			t.Fatal("m48 polarity-specific token commitment")
		}
		for _, field := range []string{"observation_ref", "preceding_health_ref", "following_health_ref"} {
			ref, ok := canary[field].(string)
			if !ok {
				continue
			}
			path := paths[ref]
			if path == "" || digest(files[base+path]) != ref {
				t.Fatalf("m48 %s reference", field)
			}
			wrapper, payload := decoded(t, files[base+path])
			verifySignedBy(t, wrapper, req["approved_observer"].(map[string]any)["key_id"].(string))
			if canary["polarity"] == "positive" && field == "observation_ref" {
				if payload["kind"] != "target-observation" || payload["requirement_sha256"] != env["requirement_sha256"] || payload["run_id"] != env["run_id"] || payload["case_id"] != row["case_id"] || payload["trial_index"] != row["trial_index"] || payload["canary_id"] != canary["canary_id"] || payload["canary_commitment_sha256"] != canary["canary_commitment_sha256"] || payload["transport"] != row["transport"] || payload["target_identity"] != canary["target_identity"] || payload["observation_state"] != "observed" {
					t.Fatal("m48 positive target-observation join")
				}
				continue
			}
			if canary["polarity"] != "negative" || field == "observation_ref" {
				continue
			}
			controlID := "health-pre"
			if field == "following_health_ref" {
				controlID = "health-post"
			}
			wantHealth := healthCommitment(env["requirement_sha256"].(string), env["run_id"].(string), row["case_id"].(string), 1, canary["canary_id"].(string), canary["canary_commitment_sha256"].(string), controlID, row["transport"].(string), canary["target_identity"].(string), healthInput("m48-required-canary-polarity-overlap", controlID, "synthetic-health-root-m48-required-canary-polarity-overlap"))
			if payload["kind"] != "health-control" || payload["requirement_sha256"] != env["requirement_sha256"] || payload["run_id"] != env["run_id"] || payload["case_id"] != row["case_id"] || payload["trial_index"] != row["trial_index"] || payload["canary_id"] != canary["canary_id"] || payload["canary_commitment_sha256"] != canary["canary_commitment_sha256"] || payload["transport"] != row["transport"] || payload["target_identity"] != canary["target_identity"] || payload["control_id"] != controlID || payload["health_control_commitment_sha256"] != wantHealth || payload["health_state"] != "allow-observed" {
				t.Fatalf("m48 %s health evidence join", field)
			}
		}
	}
	if req["required_positive_canaries"].([]any)[0] != "shared-1" || req["required_negative_canaries"].([]any)[0] != "shared-1" || req["required_positive_canaries"].([]any)[0] != req["required_negative_canaries"].([]any)[0] {
		t.Fatal("m48 polarity overlap not isolated")
	}
}

func stringEqual(a, b []byte) bool { return string(a) == string(b) }
func TestReplayAndPredecessorFixtures(t *testing.T) {
	files := allFiles()
	get := func(cat, id, n string) []byte { return files[cat+"/"+id+"/"+n] }
	e2Wrapper, _ := decoded(t, get("edge", "e02-same-envelope-reverification", "envelope.dsse.json"))
	var c map[string]any
	_ = json.Unmarshal(get("edge", "e02-same-envelope-reverification", "context.json"), &c)
	e2Payload, _ := base64.StdEncoding.DecodeString(e2Wrapper["payload"].(string))
	e2Nonce := c["nonce_ledger"].([]any)
	if len(e2Nonce) != 1 || e2Nonce[0].(map[string]any)["envelope_payload_sha256"] != digest(e2Payload) {
		t.Fatal("e02 ledger")
	}
	if !strings.Contains(string(get("edge", "e02-same-envelope-reverification", "expect.json")), "reverified_same_envelope") {
		t.Fatal("e02 annotation")
	}
	_, e5req := decoded(t, get("edge", "e05-same-nonce-different-requirement", "requirement.dsse.json"))
	var e5ctx map[string]any
	_ = json.Unmarshal(get("edge", "e05-same-nonce-different-requirement", "context.json"), &e5ctx)
	e5ledger := e5ctx["nonce_ledger"].([]any)
	if len(e5ledger) != 1 || e5ledger[0].(map[string]any)["challenge_nonce"] != e5req["challenge_nonce"] || e5ledger[0].(map[string]any)["requirement_id"] == e5req["requirement_id"] || !strings.Contains(string(get("edge", "e05-same-nonce-different-requirement", "expect.json")), "first_verification") {
		t.Fatal("e05 tuple namespace isolation")
	}
	m16Wrapper, m16 := decoded(t, get("malicious", "m16-nonce-different-envelope", "envelope.dsse.json"))
	var o map[string]any
	_ = json.Unmarshal(get("malicious", "m16-nonce-different-envelope", "outcomes.json"), &o)
	var m16Context map[string]any
	_ = json.Unmarshal(get("malicious", "m16-nonce-different-envelope", "context.json"), &m16Context)
	m16Payload, _ := base64.StdEncoding.DecodeString(m16Wrapper["payload"].(string))
	prior := m16Context["nonce_ledger"].([]any)[0].(map[string]any)["envelope_payload_sha256"]
	if m16["run_id"] != o["run_id"] || m16["requirement_sha256"] != o["requirement_sha256"] || prior == nil || prior == digest(m16Payload) {
		t.Fatal("m16 run binding")
	}
	_, m14 := decoded(t, get("malicious", "m14-expired-envelope", "envelope.dsse.json"))
	if !(m14["finished_at"].(string) < m14["expires_at"].(string) && m14["expires_at"].(string) < now) {
		t.Fatal("m14 ordering")
	}

	var m06Out map[string]any
	_ = json.Unmarshal(get("malicious", "m06-one-sided-health", "outcomes.json"), &m06Out)
	m06Canary := m06Out["rows"].([]any)[0].(map[string]any)["canaries"].([]any)[1].(map[string]any)
	if _, ok := m06Canary["preceding_health_ref"]; !ok {
		t.Fatal("m06 missing its one retained health side")
	}
	if _, ok := m06Canary["following_health_ref"]; ok {
		t.Fatal("m06 unexpectedly has both health sides")
	}

	_, m07Req := decoded(t, get("malicious", "m07-gapped-liveness", "requirement.dsse.json"))
	var m07Out, m07Man map[string]any
	_ = json.Unmarshal(get("malicious", "m07-gapped-liveness", "outcomes.json"), &m07Out)
	_ = json.Unmarshal(get("malicious", "m07-gapped-liveness", "manifest.json"), &m07Man)
	m07Ref := m07Out["rows"].([]any)[0].(map[string]any)["canaries"].([]any)[1].(map[string]any)["liveness_record_ref"].(string)
	m07Path := ""
	for _, raw := range m07Man["entries"].([]any) {
		entry := raw.(map[string]any)
		if entry["sha256"] == m07Ref {
			m07Path = entry["path"].(string)
		}
	}
	if m07Path == "" || digest(get("malicious", "m07-gapped-liveness", m07Path)) != m07Ref {
		t.Fatal("m07 liveness ref")
	}
	_, m07Evidence := decoded(t, get("malicious", "m07-gapped-liveness", m07Path))
	points := m07Evidence["liveness"].([]any)
	gap := parseTime(t, points[1].(map[string]any)["observed_at"]).Sub(parseTime(t, points[0].(map[string]any)["observed_at"]))
	maxGap := time.Duration(m07Req["approved_observer"].(map[string]any)["maximum_liveness_gap_seconds"].(float64)) * time.Second
	if gap <= maxGap {
		t.Fatal("m07 does not isolate an excessive liveness gap")
	}

	m09Wrapper, m09Req := decoded(t, get("malicious", "m09-post-hoc-token-material", "requirement.dsse.json"))
	m09Payload, _ := base64.StdEncoding.DecodeString(m09Wrapper["payload"].(string))
	_, m09Env := decoded(t, get("malicious", "m09-post-hoc-token-material", "envelope.dsse.json"))
	var m09Man map[string]any
	var m09Context, m09Out map[string]any
	_ = json.Unmarshal(get("malicious", "m09-post-hoc-token-material", "manifest.json"), &m09Man)
	_ = json.Unmarshal(get("malicious", "m09-post-hoc-token-material", "context.json"), &m09Context)
	_ = json.Unmarshal(get("malicious", "m09-post-hoc-token-material", "outcomes.json"), &m09Out)
	hasTokenRole := false
	for _, raw := range m09Man["entries"].([]any) {
		hasTokenRole = hasTokenRole || raw.(map[string]any)["role"] == "token-material"
	}
	m09Signed := m09Req["token_material"].(map[string]any)
	m09External := m09Context["token_material"].(map[string]any)
	if m09Env["requirement_sha256"] != digest(m09Payload) || m09Signed["mode"] != "packaged-encrypted" || m09Signed["profile"] != packagedTokenProfile || m09Signed["key_or_input_id"] != packagedTokenID || m09Signed["artifact_sha256"] != digest(packagedTokenMaterial(m09Req["requirement_id"].(string))) || m09Signed["mode"] != m09External["mode"] || m09Signed["profile"] != m09External["profile"] || m09Signed["key_or_input_id"] != m09External["key_or_input_id"] || m09External["aes_key_base64"] != packagedTokenKey(m09Req["requirement_id"].(string)) || hasTokenRole {
		t.Fatal("m09 has an earlier binding failure or a present token artifact")
	}
	for _, rawCanary := range m09Out["rows"].([]any)[0].(map[string]any)["canaries"].([]any) {
		canary := rawCanary.(map[string]any)
		want := tokenCommitment(m09Env["requirement_sha256"].(string), m09Env["run_id"].(string), "mcp-input-synthetic-001", 1, canary["canary_id"].(string), "mcp_stdio", "runner-target-example", canary["polarity"].(string), tokenInput("m09-post-hoc-token-material", canary["canary_id"].(string)))
		if canary["canary_commitment_sha256"] != want {
			t.Fatal("m09 token commitment")
		}
	}

	m12Wrapper, m12Clock := decoded(t, get("malicious", "m12-receipt-only-clock", "clock.dsse.json"))
	_, m12Req := decoded(t, get("malicious", "m12-receipt-only-clock", "requirement.dsse.json"))
	_, m12Env := decoded(t, get("malicious", "m12-receipt-only-clock", "envelope.dsse.json"))
	verifySignedBy(t, m12Wrapper, m12Req["approved_clock_evidence"].(map[string]any)["key_id"].(string))
	if m12Env["clock_evidence_ref"] != digest(get("malicious", "m12-receipt-only-clock", "clock.dsse.json")) || m12Clock["observation_kind"] != "receipt-issued" || m12Clock["requirement_sha256"] != m12Env["requirement_sha256"] || m12Clock["run_id"] != m12Env["run_id"] {
		t.Fatal("m12 does not isolate the clock observation kind")
	}
	_, m18Req := decoded(t, get("malicious", "m18-missing-health-control-material", "requirement.dsse.json"))
	var m18Man, m18Context, m18Out, m18Env map[string]any
	_ = json.Unmarshal(get("malicious", "m18-missing-health-control-material", "manifest.json"), &m18Man)
	_ = json.Unmarshal(get("malicious", "m18-missing-health-control-material", "context.json"), &m18Context)
	_ = json.Unmarshal(get("malicious", "m18-missing-health-control-material", "outcomes.json"), &m18Out)
	_, decodedM18Env := decoded(t, get("malicious", "m18-missing-health-control-material", "envelope.dsse.json"))
	m18Env = decodedM18Env
	m18Signed := m18Req["health_control_material"].(map[string]any)
	m18External := m18Context["health_control_material"].(map[string]any)
	if m18Signed["mode"] != "packaged-encrypted" || m18Signed["profile"] != packagedHealthProfile || m18Signed["key_or_input_id"] != packagedHealthID || m18Signed["artifact_sha256"] != digest(packagedHealthMaterial(m18Req["requirement_id"].(string))) || m18Signed["mode"] != m18External["mode"] || m18Signed["profile"] != m18External["profile"] || m18Signed["key_or_input_id"] != m18External["key_or_input_id"] || m18External["aes_key_base64"] != packagedHealthKey(m18Req["requirement_id"].(string)) {
		t.Fatal("m18 health material descriptor/context")
	}
	for _, v := range m18Man["entries"].([]any) {
		if v.(map[string]any)["role"] == "health-control-material" {
			t.Fatal("m18 artifact present")
		}
	}
	m18Row := m18Out["rows"].([]any)[0].(map[string]any)
	m18Canary := m18Row["canaries"].([]any)[1].(map[string]any)
	if m18Canary["canary_commitment_sha256"] == "" || m18Env["requirement_sha256"] == "" {
		t.Fatal("m18 has an earlier outcome/envelope failure")
	}
	m18Paths := map[string]string{}
	for _, raw := range m18Man["entries"].([]any) {
		entry := raw.(map[string]any)
		m18Paths[entry["sha256"].(string)] = entry["path"].(string)
	}
	for _, field := range []string{"preceding_health_ref", "following_health_ref"} {
		path := m18Paths[m18Canary[field].(string)]
		if path == "" {
			t.Fatalf("m18 %s unbound", field)
		}
		_, evidence := decoded(t, get("malicious", "m18-missing-health-control-material", path))
		controlID := evidence["control_id"].(string)
		want := healthCommitment(m18Env["requirement_sha256"].(string), m18Env["run_id"].(string), m18Row["case_id"].(string), int(m18Row["trial_index"].(float64)), m18Canary["canary_id"].(string), m18Canary["canary_commitment_sha256"].(string), controlID, m18Row["transport"].(string), m18Canary["target_identity"].(string), healthInput("m18-missing-health-control-material", controlID, ""))
		if evidence["health_control_commitment_sha256"] != want {
			t.Fatalf("m18 %s health commitment", field)
		}
	}
	m19w, m19req := decoded(t, get("malicious", "m19-requirement-wrong-payload-type", "requirement.dsse.json"))
	verifySignedBy(t, m19w, keyID("buyer"))
	_, m19env := decoded(t, get("malicious", "m19-requirement-wrong-payload-type", "envelope.dsse.json"))
	if m19w["payloadType"] == typeReq || m19env["requirement_sha256"] != digest(compact(m19req)) {
		t.Fatal("m19 wrong requirement type not isolated")
	}
	var m20out, m20man map[string]any
	_ = json.Unmarshal(get("malicious", "m20-observer-wrong-payload-type", "outcomes.json"), &m20out)
	_ = json.Unmarshal(get("malicious", "m20-observer-wrong-payload-type", "manifest.json"), &m20man)
	ref := m20out["rows"].([]any)[0].(map[string]any)["canaries"].([]any)[0].(map[string]any)["observation_ref"].(string)
	path := ""
	for _, v := range m20man["entries"].([]any) {
		e := v.(map[string]any)
		if e["sha256"] == ref {
			path = e["path"].(string)
		}
	}
	m20w, _ := decoded(t, get("malicious", "m20-observer-wrong-payload-type", path))
	verifySignedBy(t, m20w, keyID("observer"))
	if m20w["payloadType"] == typeObserver {
		t.Fatal("m20 wrong observer type not isolated")
	}
	_, m21Req := decoded(t, get("malicious", "m21-token-context-descriptor-mismatch", "requirement.dsse.json"))
	var m21Context map[string]any
	_ = json.Unmarshal(get("malicious", "m21-token-context-descriptor-mismatch", "context.json"), &m21Context)
	m21Signed := m21Req["token_material"].(map[string]any)
	m21External := m21Context["token_material"].(map[string]any)
	if m21Signed["mode"] == m21External["mode"] && m21Signed["profile"] == m21External["profile"] && m21Signed["key_or_input_id"] == m21External["key_or_input_id"] {
		t.Fatal("m21 token material descriptor mismatch not isolated")
	}
	_, m22Req := decoded(t, get("malicious", "m22-health-context-descriptor-mismatch", "requirement.dsse.json"))
	var m22Context map[string]any
	_ = json.Unmarshal(get("malicious", "m22-health-context-descriptor-mismatch", "context.json"), &m22Context)
	m22Signed := m22Req["health_control_material"].(map[string]any)
	m22External := m22Context["health_control_material"].(map[string]any)
	if m22Signed["mode"] == m22External["mode"] && m22Signed["profile"] == m22External["profile"] && m22Signed["key_or_input_id"] == m22External["key_or_input_id"] {
		t.Fatal("m22 health control material descriptor mismatch not isolated")
	}
}
