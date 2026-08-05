'use strict';

const assert = require('node:assert/strict');
const nodeCrypto = require('node:crypto');
const crypto = nodeCrypto.webcrypto;

global.window = {};
require('./latest-result.js');

const artifact = {
  schema_version: 2,
  artifact_id: 'github-actions:luckyPipewrench/agent-egress-bench:123',
  canonical_url: 'https://github.com/luckyPipewrench/agent-egress-bench/actions/runs/123',
  tool: 'pipelock',
  tool_version: '3.3.0',
  generated_at: '2026-08-05T00:10:08Z',
};
const artifactText = JSON.stringify(artifact) + '\n';
const digest = nodeCrypto.createHash('sha256').update(artifactText).digest('hex');
const manifest = {
  schema_version: 1,
  tool: artifact.tool,
  tool_version: artifact.tool_version,
  artifact_id: artifact.artifact_id,
  canonical_url: artifact.canonical_url,
  generated_at: artifact.generated_at,
  candidate_sha256: digest,
  previous_candidate_sha256: null,
  previous_record_manifest_sha256: null,
  files: { 'continuous-gauntlet-pipelock.json': digest },
};
const manifestText = JSON.stringify(manifest) + '\n';
const manifestDigest = nodeCrypto.createHash('sha256').update(manifestText).digest('hex');
const pointer = {
  schema_version: 1,
  status: 'verified',
  tool: artifact.tool,
  tool_version: artifact.tool_version,
  generated_at: artifact.generated_at,
  artifact_id: artifact.artifact_id,
  canonical_url: artifact.canonical_url,
  candidate_sha256: digest,
  record_manifest_sha256: manifestDigest,
  record_path: './results/pipelock/' + digest + '/continuous-gauntlet-pipelock.json',
  record_manifest_path: './results/pipelock/' + digest + '/record-manifest.json',
};

function response(body, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    arrayBuffer: async () => {
      const bytes = Buffer.from(body);
      return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
    },
  };
}

function fetcher(pointerValue = pointer, recordText = artifactText, recordManifestText = manifestText) {
  return async (url) => {
    if (url === './latest-verified.json') return response(JSON.stringify(pointerValue));
    if (url === pointerValue.record_manifest_path) return response(recordManifestText);
    if (url === pointerValue.record_path) return response(recordText);
    return response('', 404);
  };
}

(async () => {
  const loaded = await window.loadLatestVerifiedResult(
    './latest-verified.json', fetcher(), crypto
  );
  assert.deepEqual(loaded, artifact);

  const unsafe = { ...pointer, record_path: 'https://attacker.example/result.json' };
  await assert.rejects(
    window.loadLatestVerifiedResult('./latest-verified.json', fetcher(unsafe), crypto),
    /record_path is not canonical/
  );

  await assert.rejects(
    window.loadLatestVerifiedResult(
      './latest-verified.json', fetcher(pointer, artifactText + ' '), crypto
    ),
    /digest does not match/
  );

  await assert.rejects(
    window.loadLatestVerifiedResult(
      './latest-verified.json', fetcher(pointer, artifactText, manifestText + ' '), crypto
    ),
    /record manifest digest does not match/
  );

  const mismatch = { ...artifact, artifact_id: artifact.artifact_id + ':other' };
  const mismatchText = JSON.stringify(mismatch) + '\n';
  const mismatchDigest = nodeCrypto.createHash('sha256').update(mismatchText).digest('hex');
  const mismatchManifest = {
    ...manifest,
    candidate_sha256: mismatchDigest,
    files: { 'continuous-gauntlet-pipelock.json': mismatchDigest },
  };
  const mismatchManifestText = JSON.stringify(mismatchManifest) + '\n';
  const mismatchManifestDigest = nodeCrypto.createHash('sha256')
    .update(mismatchManifestText).digest('hex');
  const mismatchPointer = {
    ...pointer,
    candidate_sha256: mismatchDigest,
    record_manifest_sha256: mismatchManifestDigest,
    record_path: './results/pipelock/' + mismatchDigest + '/continuous-gauntlet-pipelock.json',
    record_manifest_path: './results/pipelock/' + mismatchDigest + '/record-manifest.json',
  };
  await assert.rejects(
    window.loadLatestVerifiedResult(
      './latest-verified.json',
      fetcher(mismatchPointer, mismatchText, mismatchManifestText),
      crypto
    ),
    /disagree on artifact_id/
  );

  const manifestIdentityMismatch = { ...manifest, tool_version: '9.9.9' };
  const manifestIdentityMismatchText = JSON.stringify(manifestIdentityMismatch) + '\n';
  const manifestIdentityMismatchPointer = {
    ...pointer,
    record_manifest_sha256: nodeCrypto.createHash('sha256')
      .update(manifestIdentityMismatchText).digest('hex'),
  };
  await assert.rejects(
    window.loadLatestVerifiedResult(
      './latest-verified.json',
      fetcher(manifestIdentityMismatchPointer, artifactText, manifestIdentityMismatchText),
      crypto
    ),
    /record manifest and result record disagree on tool_version/
  );

  const missing = async () => response('', 404);
  const missingError = await window.loadLatestVerifiedResult(
    './latest-verified.json', missing, crypto
  ).then(() => null, (error) => error);
  assert.equal(missingError.status, 404);
  assert.equal(missingError.resource, 'pointer');

  const missingRecord = async (url) => {
    if (url === './latest-verified.json') return response(JSON.stringify(pointer));
    if (url === pointer.record_manifest_path) return response(manifestText);
    return response('', 404);
  };
  const recordError = await window.loadLatestVerifiedResult(
    './latest-verified.json', missingRecord, crypto
  ).then(() => null, (error) => error);
  assert.equal(recordError.status, 404);
  assert.equal(recordError.resource, 'record');

  console.log('latest verified result loader tests: OK');
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
