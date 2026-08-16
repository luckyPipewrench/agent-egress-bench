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

  function registryReference(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value) ||
        Object.keys(value).sort().join(',') !== 'format,id,revision,sha256') {
      throw new Error('capability_registry must be an exact registry reference');
    }
    if (typeof value.id !== 'string' || !value.id || value.format !== 1 ||
        !Number.isInteger(value.revision) || value.revision < 1 ||
        !SHA256.test(value.sha256)) {
        throw new Error('capability_registry is invalid');
    }
    return value;
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

  function registryEntries(snapshot) {
    if (!snapshot || typeof snapshot !== 'object' || !Array.isArray(snapshot.entries)) {
      throw new Error('capability registry snapshot entries are invalid');
    }
    var entries = {};
    snapshot.entries.forEach(function(entry) {
      if (!entry || typeof entry !== 'object' || typeof entry.id !== 'string' ||
          !entry.id || (entry.status !== 'active' && entry.status !== 'deprecated') ||
          Object.prototype.hasOwnProperty.call(entries, entry.id)) {
        throw new Error('capability registry snapshot has invalid or duplicate IDs');
      }
      entries[entry.id] = entry;
    });
    return entries;
  }

  function activeLabels(value, label, entries) {
    if (!Array.isArray(value)) {
      throw new Error(label + ' must be an array');
    }
    var seen = {};
    value.forEach(function(id) {
      if (typeof id !== 'string' || !id || seen[id] || !entries[id] || entries[id].status !== 'active') {
        throw new Error(label + ' contains an unknown, duplicate, or inactive capability ID');
      }
      seen[id] = true;
    });
    return value;
  }

  function capabilityLabel(artifact, id) {
    if (!artifact || !artifact._capabilityLabels || !artifact._capabilityLabels[id]) {
      throw new Error('capability label is not present in the verified registry snapshot');
    }
    var entry = artifact._capabilityLabels[id];
    return typeof entry.title === 'string' && entry.title ? entry.title : entry.id;
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
      if (artifact[key] !== manifest[key]) {
        throw new Error('record manifest and result record disagree on ' + key);
      }
    });
    // V2 records predate registry bytes and remain readable as frozen history.
    // A supported v4/v5/v6 result is not rendered until its pinned raw profile and raw
    // registry snapshot have both been fetched and bound to the candidate.
    if (artifact.schema_version === 4 || artifact.schema_version === 5 || artifact.schema_version === 6) {
      var reference = registryReference(artifact.capability_registry);
      if (!artifact.tool_profile_sha256 || !SHA256.test(artifact.tool_profile_sha256)) {
        throw new Error('active result has no valid tool_profile_sha256');
      }
      var prefix = './results/pipelock/' + pointer.candidate_sha256 + '/';
      var snapshotName = 'capability-registry.json';
      var profileName = 'tool-profile.json';
      if (!manifest.files || manifest.files[snapshotName] !== reference.sha256) {
        throw new Error('record manifest does not bind the active capability registry snapshot');
      }
      var snapshotBytes = await responseBytes(await fetchImpl(prefix + snapshotName), 'capability registry snapshot', 'capability registry snapshot');
      if (await sha256Hex(snapshotBytes, cryptoImpl) !== reference.sha256) {
        throw new Error('capability registry snapshot digest does not match active result');
      }
      var profileBytes = await responseBytes(await fetchImpl(prefix + profileName), 'tool profile', 'tool profile');
      if (await sha256Hex(profileBytes, cryptoImpl) !== artifact.tool_profile_sha256) {
        throw new Error('tool profile digest does not match active result');
      }
      var profile;
      var snapshot;
      try {
        profile = JSON.parse(decodeUTF8(profileBytes, 'tool profile'));
        snapshot = JSON.parse(decodeUTF8(snapshotBytes, 'capability registry snapshot'));
      } catch (error) {
        throw new Error('active registry evidence is not valid JSON');
      }
      if (JSON.stringify(registryReference(profile.capability_registry)) !== JSON.stringify(reference) ||
          snapshot.id !== reference.id || snapshot.format !== reference.format || snapshot.revision !== reference.revision) {
        throw new Error('active registry evidence does not match result capability_registry');
      }
      var entries = registryEntries(snapshot);
      var profileClaims = activeLabels(profile.claims, 'active profile claims', entries);
      var reportedClaims = activeLabels(artifact.reported_claims, 'active reported_claims', entries);
      var exercisedTags = activeLabels(
        artifact.exercised && artifact.exercised.capability_tags,
        'active exercised capability_tags',
        entries
      );
      if (JSON.stringify(profileClaims) !== JSON.stringify(reportedClaims)) {
        throw new Error('active profile claims do not match result reported_claims');
      }
      Object.defineProperty(artifact, '_capabilityRegistry', { value: snapshot, enumerable: false });
      Object.defineProperty(artifact, '_capabilityLabels', { value: entries, enumerable: false });
      Object.defineProperty(artifact, '_exercisedCapabilityTags', { value: exercisedTags, enumerable: false });
    } else if (artifact.schema_version !== 2) {
      throw new Error('result record must be frozen schema v2 or supported schema v4/v5/v6');
    }
    return artifact;
  }

  root.validateLatestVerifiedPointer = validatePointer;
  root.loadLatestVerifiedResult = loadLatestVerifiedResult;
  root.capabilityLabel = capabilityLabel;
})(window);
