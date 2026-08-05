/* Load and hash-check the append-only record selected by latest-verified. */
(function(root) {
  'use strict';

  var SHA256 = /^[0-9a-f]{64}$/;

  function nonEmptyString(value, label) {
    if (typeof value !== 'string' || !value.trim()) {
      throw new Error(label + ' must be a non-empty string');
    }
    return value;
  }

  function validatePointer(pointer) {
    if (!pointer || typeof pointer !== 'object' || Array.isArray(pointer)) {
      throw new Error('latest-verified pointer must be an object');
    }
    if (pointer.schema_version !== 1 || pointer.status !== 'verified') {
      throw new Error('latest-verified pointer must be schema v1 with verified status');
    }
    var digest = nonEmptyString(pointer.candidate_sha256, 'candidate_sha256');
    if (!SHA256.test(digest)) throw new Error('candidate_sha256 must be lower-case SHA-256');
    var manifestDigest = nonEmptyString(pointer.record_manifest_sha256, 'record_manifest_sha256');
    if (!SHA256.test(manifestDigest)) {
      throw new Error('record_manifest_sha256 must be lower-case SHA-256');
    }
    var expectedRecord = './results/pipelock/' + digest + '/continuous-gauntlet-pipelock.json';
    var expectedManifest = './results/pipelock/' + digest + '/record-manifest.json';
    if (pointer.record_path !== expectedRecord) {
      throw new Error('latest-verified record_path is not canonical');
    }
    if (pointer.record_manifest_path !== expectedManifest) {
      throw new Error('latest-verified record_manifest_path is not canonical');
    }
    nonEmptyString(pointer.artifact_id, 'artifact_id');
    nonEmptyString(pointer.canonical_url, 'canonical_url');
    nonEmptyString(pointer.tool, 'tool');
    nonEmptyString(pointer.tool_version, 'tool_version');
    nonEmptyString(pointer.generated_at, 'generated_at');
    return pointer;
  }

  async function responseBytes(response, label, resource) {
    if (!response.ok) {
      var error = new Error(label + ' returned HTTP ' + response.status);
      error.status = response.status;
      error.resource = resource;
      throw error;
    }
    return new Uint8Array(await response.arrayBuffer());
  }

  function decodeUTF8(bytes, label) {
    try {
      return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    } catch (error) {
      throw new Error(label + ' is not valid UTF-8');
    }
  }

  async function sha256Hex(bytes, cryptoImpl) {
    if (!cryptoImpl || !cryptoImpl.subtle) throw new Error('Web Crypto is unavailable');
    var digest = await cryptoImpl.subtle.digest('SHA-256', bytes);
    return Array.from(new Uint8Array(digest)).map(function(value) {
      return value.toString(16).padStart(2, '0');
    }).join('');
  }

  async function loadLatestVerifiedResult(pointerURL, fetchImpl, cryptoImpl) {
    var pointerBytes = await responseBytes(
      await fetchImpl(pointerURL), 'latest-verified pointer', 'pointer'
    );
    var pointerText = decodeUTF8(pointerBytes, 'latest-verified pointer');
    var pointer;
    try {
      pointer = validatePointer(JSON.parse(pointerText));
    } catch (error) {
      if (error instanceof SyntaxError) throw new Error('latest-verified pointer is not valid JSON');
      throw error;
    }
    var manifestBytes = await responseBytes(
      await fetchImpl(pointer.record_manifest_path),
      'append-only record manifest',
      'manifest'
    );
    var manifestDigest = await sha256Hex(manifestBytes, cryptoImpl);
    if (manifestDigest !== pointer.record_manifest_sha256) {
      throw new Error('append-only record manifest digest does not match latest-verified');
    }
    var manifest;
    try {
      manifest = JSON.parse(decodeUTF8(manifestBytes, 'append-only record manifest'));
    } catch (error) {
      if (error instanceof SyntaxError) {
        throw new Error('append-only record manifest is not valid JSON');
      }
      throw error;
    }
    if (!manifest || manifest.schema_version !== 1 ||
        manifest.candidate_sha256 !== pointer.candidate_sha256 ||
        !manifest.files ||
        manifest.files['continuous-gauntlet-pipelock.json'] !== pointer.candidate_sha256) {
      throw new Error('append-only record manifest does not bind the selected candidate');
    }

    var artifactBytes = await responseBytes(
      await fetchImpl(pointer.record_path),
      'append-only result record',
      'record'
    );
    var actualDigest = await sha256Hex(artifactBytes, cryptoImpl);
    if (actualDigest !== pointer.candidate_sha256) {
      throw new Error('append-only result digest does not match latest-verified');
    }
    var artifact;
    try {
      artifact = JSON.parse(decodeUTF8(artifactBytes, 'append-only result record'));
    } catch (error) {
      throw new Error('append-only result record is not valid JSON');
    }
    ['artifact_id', 'canonical_url', 'tool', 'tool_version', 'generated_at'].forEach(function(key) {
      if (artifact[key] !== pointer[key]) {
        throw new Error('latest-verified and result record disagree on ' + key);
      }
    });
    return artifact;
  }

  root.validateLatestVerifiedPointer = validatePointer;
  root.loadLatestVerifiedResult = loadLatestVerifiedResult;
})(window);
