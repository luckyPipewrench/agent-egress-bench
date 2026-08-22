'use strict';

const assert = require('node:assert/strict');
const nodeCrypto = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = nodeCrypto.webcrypto;

function element(tagName) {
  return {
    tagName,
    children: [],
    appendChild(child) {
      this.children.push(child);
    },
  };
}

global.document = {
  createElement: element,
  createTextNode(text) {
    return { textContent: text };
  },
};
global.window = {};
require('./latest-result.js');
require('./scope-render.js');

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
  const misleadingAssurance = { ...pointer, assurances: ['independently-executed'] };
  await assert.rejects(
    window.loadLatestVerifiedResult(
      './latest-verified.json', fetcher(misleadingAssurance), crypto
    ),
    /assurances must name self-run and artifact-validated/
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

  const snapshotText = JSON.stringify({
  id: 'aeb.core-capabilities', format: 1, revision: 1,
    entries: [{ id: 'url_dlp', status: 'active', title: 'URL DLP' }],
  }) + '\n';
  const snapshotDigest = nodeCrypto.createHash('sha256').update(snapshotText).digest('hex');
  const profileText = JSON.stringify({
    schema_version: 4,
    capability_registry: { id: 'aeb.core-capabilities', format: 1, revision: 1, sha256: snapshotDigest },
    claims: ['url_dlp'],
  }) + '\n';
  const profileDigest = nodeCrypto.createHash('sha256').update(profileText).digest('hex');
  const v4Artifact = {
    ...artifact,
    schema_version: 4,
    tool_profile_sha256: profileDigest,
    capability_registry: { id: 'aeb.core-capabilities', format: 1, revision: 1, sha256: snapshotDigest },
    reported_claims: ['url_dlp'],
    exercised: { capability_tags: ['url_dlp'] },
  };
  const v4ArtifactText = JSON.stringify(v4Artifact) + '\n';
  const v4Digest = nodeCrypto.createHash('sha256').update(v4ArtifactText).digest('hex');
  const v4Manifest = {
    ...manifest,
    candidate_sha256: v4Digest,
    files: {
      'continuous-gauntlet-pipelock.json': v4Digest,
      'capability-registry.json': snapshotDigest,
      'tool-profile.json': profileDigest,
    },
  };
  const v4ManifestText = JSON.stringify(v4Manifest) + '\n';
  const v4Pointer = {
    ...pointer,
    candidate_sha256: v4Digest,
    record_manifest_sha256: nodeCrypto.createHash('sha256').update(v4ManifestText).digest('hex'),
    record_path: './results/pipelock/' + v4Digest + '/continuous-gauntlet-pipelock.json',
    record_manifest_path: './results/pipelock/' + v4Digest + '/record-manifest.json',
  };
  const v4Fetch = async (url) => {
    const prefix = './results/pipelock/' + v4Digest + '/';
    if (url === './latest-verified.json') return response(JSON.stringify(v4Pointer));
    if (url === v4Pointer.record_manifest_path) return response(v4ManifestText);
    if (url === v4Pointer.record_path) return response(v4ArtifactText);
    if (url === prefix + 'capability-registry.json') return response(snapshotText);
    if (url === prefix + 'tool-profile.json') return response(profileText);
    return response('', 404);
  };
  const v4Loaded = await window.loadLatestVerifiedResult('./latest-verified.json', v4Fetch, crypto);
  assert.equal(v4Loaded._capabilityRegistry.id, 'aeb.core-capabilities');
  assert.equal(window.capabilityLabel(v4Loaded, 'url_dlp'), 'URL DLP');

  const v6Artifact = {
    ...v4Artifact,
    schema_version: 6,
    method_repository: 'example/agent-egress-bench',
    method_commit: 'e'.repeat(40),
    adapter_id: 'proxy',
    adapter_owner: 'Example Maintainers',
    target_config_ref: 'examples/tool/benchmark.yaml',
    target_config_sha256: 'f'.repeat(64),
    case_count: { total: 2 },
  };
  const v6ResultsText = [
    // Evidence-sensitive scoring can fail an observed block, for example when
    // a call-budget block happens too early or too late.
    JSON.stringify({ case_id: 'url-attack-001', expected_verdict: 'block', actual_verdict: 'block', score: 'fail' }),
    JSON.stringify({ case_id: 'url-benign-002', expected_verdict: 'allow', actual_verdict: 'allow', score: 'pass' }),
  ].join('\n') + '\n';
  const v6CaseIndexText = JSON.stringify({
    schema_version: 3,
    cases: {
      'url-attack-001': { category: 'url', expected_verdict: 'block', transport: 'fetch', capability_tags: ['url_dlp'] },
      'url-benign-002': { category: 'url', expected_verdict: 'allow', transport: 'fetch', capability_tags: ['url_dlp'] },
    },
  }) + '\n';
  const v6CorpusManifestText = 'url-attack-001\nurl-benign-002\n';
  const v6ResultsDigest = nodeCrypto.createHash('sha256').update(v6ResultsText).digest('hex');
  const v6CaseIndexDigest = nodeCrypto.createHash('sha256').update(v6CaseIndexText).digest('hex');
  const v6CorpusManifestDigest = nodeCrypto.createHash('sha256').update(v6CorpusManifestText).digest('hex');
  const v6ArtifactText = JSON.stringify(v6Artifact) + '\n';
  const v6Digest = nodeCrypto.createHash('sha256').update(v6ArtifactText).digest('hex');
  const v6Manifest = {
    ...v4Manifest,
    candidate_sha256: v6Digest,
    files: { ...v4Manifest.files, 'continuous-gauntlet-pipelock.json': v6Digest },
  };
  Object.assign(v6Manifest.files, {
    'results.jsonl': v6ResultsDigest,
    'case-index.json': v6CaseIndexDigest,
    'corpus-manifest.txt': v6CorpusManifestDigest,
  });
  const v6ManifestText = JSON.stringify(v6Manifest) + '\n';
  const v6Pointer = {
    ...v4Pointer,
    candidate_sha256: v6Digest,
    record_manifest_sha256: nodeCrypto.createHash('sha256').update(v6ManifestText).digest('hex'),
    record_path: './results/pipelock/' + v6Digest + '/continuous-gauntlet-pipelock.json',
    record_manifest_path: './results/pipelock/' + v6Digest + '/record-manifest.json',
    assurances: ['self-run', 'artifact-validated'],
  };
  const v6Fetch = async (url) => {
    const prefix = './results/pipelock/' + v6Digest + '/';
    if (url === './latest-verified.json') return response(JSON.stringify(v6Pointer));
    if (url === v6Pointer.record_manifest_path) return response(v6ManifestText);
    if (url === v6Pointer.record_path) return response(v6ArtifactText);
    if (url === prefix + 'capability-registry.json') return response(snapshotText);
    if (url === prefix + 'tool-profile.json') return response(profileText);
    if (url === prefix + 'results.jsonl') return response(v6ResultsText);
    if (url === prefix + 'case-index.json') return response(v6CaseIndexText);
    if (url === prefix + 'corpus-manifest.txt') return response(v6CorpusManifestText);
    return response('', 404);
  };
  const v6Loaded = await window.loadLatestVerifiedResult('./latest-verified.json', v6Fetch, crypto);
  assert.equal(v6Loaded.schema_version, 6);
  assert.equal(v6Loaded.method_repository, 'example/agent-egress-bench');
  assert.equal(v6Loaded._failedCases.length, 1);
  assert.equal(v6Loaded._failedCases[0].manifest_line, 1);
  assert.equal(v6Loaded._failedCases[0].actual_verdict, 'block');
  assert.deepEqual(v6Loaded._assurances, ['self-run', 'artifact-validated']);

  const v6BlankManifestText = 'url-attack-001\n\nurl-benign-002\n';
  const v6BlankManifest = {
    ...v6Manifest,
    files: {
      ...v6Manifest.files,
      'corpus-manifest.txt': nodeCrypto.createHash('sha256').update(v6BlankManifestText).digest('hex'),
    },
  };
  const v6BlankManifestRecordText = JSON.stringify(v6BlankManifest) + '\n';
  const v6BlankPointer = {
    ...v6Pointer,
    record_manifest_sha256: nodeCrypto.createHash('sha256')
      .update(v6BlankManifestRecordText).digest('hex'),
  };
  await assert.rejects(
    window.loadLatestVerifiedResult('./latest-verified.json', async (url) => {
      const prefix = './results/pipelock/' + v6Digest + '/';
      if (url === './latest-verified.json') return response(JSON.stringify(v6BlankPointer));
      if (url === v6BlankPointer.record_manifest_path) return response(v6BlankManifestRecordText);
      if (url === v6BlankPointer.record_path) return response(v6ArtifactText);
      if (url === prefix + 'capability-registry.json') return response(snapshotText);
      if (url === prefix + 'tool-profile.json') return response(profileText);
      if (url === prefix + 'results.jsonl') return response(v6ResultsText);
      if (url === prefix + 'case-index.json') return response(v6CaseIndexText);
      if (url === prefix + 'corpus-manifest.txt') return response(v6BlankManifestText);
      return response('', 404);
    }, crypto),
    /one case ID per physical line/
  );

  // A v6 record with a not-applicable row must still load. The runner emits
  // score "not_applicable" for cases that did not apply to the target, and the
  // failed-case list excludes them rather than the loader refusing the record.
  const v6NaArtifact = { ...v6Artifact, case_count: { total: 3 } };
  const v6NaResultsText = [
    JSON.stringify({ case_id: 'url-attack-001', expected_verdict: 'block', actual_verdict: 'allow', score: 'fail' }),
    JSON.stringify({ case_id: 'url-benign-002', expected_verdict: 'allow', actual_verdict: 'allow', score: 'pass' }),
    JSON.stringify({ case_id: 'url-na-003', expected_verdict: 'block', actual_verdict: 'not_applicable', score: 'not_applicable' }),
  ].join('\n') + '\n';
  const v6NaCaseIndexText = JSON.stringify({
    schema_version: 3,
    cases: {
      'url-attack-001': { category: 'url', expected_verdict: 'block', transport: 'fetch', capability_tags: ['url_dlp'] },
      'url-benign-002': { category: 'url', expected_verdict: 'allow', transport: 'fetch', capability_tags: ['url_dlp'] },
      'url-na-003': { category: 'url', expected_verdict: 'block', transport: 'fetch', capability_tags: ['url_dlp'] },
    },
  }) + '\n';
  const v6NaCorpusManifestText = 'url-attack-001\nurl-benign-002\nurl-na-003\n';
  const v6NaResultsDigest = nodeCrypto.createHash('sha256').update(v6NaResultsText).digest('hex');
  const v6NaCaseIndexDigest = nodeCrypto.createHash('sha256').update(v6NaCaseIndexText).digest('hex');
  const v6NaCorpusManifestDigest = nodeCrypto.createHash('sha256').update(v6NaCorpusManifestText).digest('hex');
  const v6NaArtifactText = JSON.stringify(v6NaArtifact) + '\n';
  const v6NaDigest = nodeCrypto.createHash('sha256').update(v6NaArtifactText).digest('hex');
  const v6NaManifest = {
    ...v4Manifest,
    candidate_sha256: v6NaDigest,
    files: {
      ...v4Manifest.files,
      'continuous-gauntlet-pipelock.json': v6NaDigest,
      'results.jsonl': v6NaResultsDigest,
      'case-index.json': v6NaCaseIndexDigest,
      'corpus-manifest.txt': v6NaCorpusManifestDigest,
    },
  };
  const v6NaManifestText = JSON.stringify(v6NaManifest) + '\n';
  const v6NaPointer = {
    ...v4Pointer,
    candidate_sha256: v6NaDigest,
    record_manifest_sha256: nodeCrypto.createHash('sha256').update(v6NaManifestText).digest('hex'),
    record_path: './results/pipelock/' + v6NaDigest + '/continuous-gauntlet-pipelock.json',
    record_manifest_path: './results/pipelock/' + v6NaDigest + '/record-manifest.json',
    assurances: ['self-run', 'artifact-validated'],
  };
  const v6NaFetch = async (url) => {
    const prefix = './results/pipelock/' + v6NaDigest + '/';
    if (url === './latest-verified.json') return response(JSON.stringify(v6NaPointer));
    if (url === v6NaPointer.record_manifest_path) return response(v6NaManifestText);
    if (url === v6NaPointer.record_path) return response(v6NaArtifactText);
    if (url === prefix + 'capability-registry.json') return response(snapshotText);
    if (url === prefix + 'tool-profile.json') return response(profileText);
    if (url === prefix + 'results.jsonl') return response(v6NaResultsText);
    if (url === prefix + 'case-index.json') return response(v6NaCaseIndexText);
    if (url === prefix + 'corpus-manifest.txt') return response(v6NaCorpusManifestText);
    return response('', 404);
  };
  const v6NaLoaded = await window.loadLatestVerifiedResult('./latest-verified.json', v6NaFetch, crypto);
  assert.equal(v6NaLoaded._failedCases.length, 1);
  assert.equal(v6NaLoaded._failedCases[0].case_id, 'url-attack-001');

  // A not-applicable score with any other verdict is still refused: the guard
  // broadens acceptance for the honest shape only, not for arbitrary rows.
  const v6NaBadVerdictResultsText = [
    JSON.stringify({ case_id: 'url-attack-001', expected_verdict: 'block', actual_verdict: 'allow', score: 'fail' }),
    JSON.stringify({ case_id: 'url-benign-002', expected_verdict: 'allow', actual_verdict: 'allow', score: 'pass' }),
    JSON.stringify({ case_id: 'url-na-003', expected_verdict: 'block', actual_verdict: 'allow', score: 'not_applicable' }),
  ].join('\n') + '\n';
  const v6NaBadVerdictResultsDigest = nodeCrypto.createHash('sha256').update(v6NaBadVerdictResultsText).digest('hex');
  const v6NaBadVerdictManifest = {
    ...v6NaManifest,
    files: { ...v6NaManifest.files, 'results.jsonl': v6NaBadVerdictResultsDigest },
  };
  const v6NaBadVerdictManifestText = JSON.stringify(v6NaBadVerdictManifest) + '\n';
  const v6NaBadVerdictPointer = {
    ...v6NaPointer,
    record_manifest_sha256: nodeCrypto.createHash('sha256').update(v6NaBadVerdictManifestText).digest('hex'),
  };
  const v6NaBadVerdictFetch = async (url) => {
    const prefix = './results/pipelock/' + v6NaDigest + '/';
    if (url === './latest-verified.json') return response(JSON.stringify(v6NaBadVerdictPointer));
    if (url === v6NaBadVerdictPointer.record_manifest_path) return response(v6NaBadVerdictManifestText);
    if (url === prefix + 'results.jsonl') return response(v6NaBadVerdictResultsText);
    return v6NaFetch(url);
  };
  await assert.rejects(
    window.loadLatestVerifiedResult('./latest-verified.json', v6NaBadVerdictFetch, crypto),
    /not-applicable row disagrees with its verdict/
  );

  await assert.rejects(
    window.loadLatestVerifiedResult('./latest-verified.json', async (url) => {
      if (url.endsWith('capability-registry.json')) return response('', 404);
      return v4Fetch(url);
    }, crypto),
    /capability registry snapshot returned HTTP 404/
  );
  await assert.rejects(
    window.loadLatestVerifiedResult('./latest-verified.json', async (url) => {
      if (url.endsWith('capability-registry.json')) return response(snapshotText + ' ');
      return v4Fetch(url);
    }, crypto),
    /capability registry snapshot digest does not match/
  );

  const siteRoot = path.resolve(__dirname);
  const liveFetch = async (url) => {
    const resolved = path.resolve(siteRoot, url);
    if (!resolved.startsWith(siteRoot + path.sep)) return response('', 404);
    try {
      return response(await fs.readFile(resolved));
    } catch (error) {
      return response('', error && error.code === 'ENOENT' ? 404 : 500);
    }
  };
  const live = await window.loadLatestVerifiedResult('./latest-verified.json', liveFetch, crypto);
  assert.deepEqual(live._assurances, ['self-run', 'artifact-validated']);
  const liveFailures = window.renderGauntletFailures(live);
  if (live._failedCases.length > 0) {
    const renderedList = liveFailures.children[liveFailures.children.length - 1];
    assert.equal(renderedList.tagName, 'ul');
    assert.equal(renderedList.children.length, live._failedCases.length);
    live._failedCases.forEach((failure, index) => {
      assert.equal(renderedList.children[index].children[0].textContent, failure.case_id);
    });
  } else {
    assert.match(liveFailures.children[1].textContent, /None|No applicable failed cases/);
  }

  console.log('latest verified result loader tests: OK');
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
