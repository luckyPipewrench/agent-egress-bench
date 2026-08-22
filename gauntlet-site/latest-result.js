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
    if (pointer.assurances !== undefined &&
        JSON.stringify(pointer.assurances) !== JSON.stringify(['self-run', 'artifact-validated'])) {
      throw new Error('latest-verified assurances must name self-run and artifact-validated');
    }
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

  function sameRegistryReference(left, right) {
    return left && right && left.id === right.id && left.format === right.format &&
      left.revision === right.revision && left.sha256 === right.sha256;
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

  async function boundRecordFile(prefix, name, manifest, fetchImpl, cryptoImpl) {
    if (!manifest.files || !SHA256.test(manifest.files[name])) {
      throw new Error('record manifest does not bind ' + name);
    }
    var bytes = await responseBytes(await fetchImpl(prefix + name), name, name);
    if (await sha256Hex(bytes, cryptoImpl) !== manifest.files[name]) {
      throw new Error(name + ' digest does not match the record manifest');
    }
    return bytes;
  }

  function loadFailedCases(artifact, resultsBytes, caseIndexBytes, corpusManifestBytes) {
    var caseIndex;
    try {
      caseIndex = JSON.parse(decodeUTF8(caseIndexBytes, 'case-index.json'));
    } catch (error) {
      throw new Error('case-index.json is not valid JSON');
    }
    if (!caseIndex || caseIndex.schema_version !== 3 || !caseIndex.cases ||
        typeof caseIndex.cases !== 'object' || Array.isArray(caseIndex.cases)) {
      throw new Error('case-index.json is not a v3 case index');
    }

    var manifestLines = decodeUTF8(corpusManifestBytes, 'corpus-manifest.txt').split(/\r?\n/);
    if (manifestLines.length && manifestLines[manifestLines.length - 1] === '') manifestLines.pop();
    if (!manifestLines.length || manifestLines.some(function(line) {
      return line === '' || line.trim() !== line;
    })) {
      throw new Error('corpus-manifest.txt must contain one case ID per physical line');
    }
    var manifestLine = {};
    manifestLines.forEach(function(caseID, index) {
      if (manifestLine[caseID]) throw new Error('corpus-manifest.txt contains duplicate case IDs');
      manifestLine[caseID] = index + 1;
    });

    var text = decodeUTF8(resultsBytes, 'results.jsonl');
    var lines = text.split(/\r?\n/);
    if (lines.length && lines[lines.length - 1] === '') lines.pop();
    if (!lines.length || lines.some(function(line) { return line === ''; })) {
      throw new Error('results.jsonl must contain one non-empty JSON object per line');
    }
    var seen = {};
    var failed = [];
    lines.forEach(function(line, index) {
      var row;
      try {
        row = JSON.parse(line);
      } catch (error) {
        throw new Error('results.jsonl line ' + (index + 1) + ' is not valid JSON');
      }
      if (!row || typeof row !== 'object' || Array.isArray(row) ||
          typeof row.case_id !== 'string' || !row.case_id || seen[row.case_id]) {
        throw new Error('results.jsonl contains an invalid or duplicate case ID');
      }
      if (row.schema_version !== undefined && [4, 5, 6].indexOf(row.schema_version) === -1) {
        throw new Error('results.jsonl contains an unsupported result schema version');
      }
      if (row.schema_version === 6 &&
          (typeof row.scoring_version !== 'string' || !row.scoring_version.trim() ||
           row.scoring_version !== artifact.scoring_version)) {
        throw new Error('results.jsonl scoring version does not match the published artifact');
      }
      var indexed = caseIndex.cases[row.case_id];
      if (!indexed || row.expected_verdict !== indexed.expected_verdict ||
          (row.expected_verdict !== 'allow' && row.expected_verdict !== 'block')) {
        throw new Error('results.jsonl case does not match case-index.json');
      }
      if (row.score !== 'pass' && row.score !== 'fail' && row.score !== 'error' &&
          row.score !== 'not_applicable') {
        throw new Error('results.jsonl contains an invalid score');
      }
      if (row.score === 'pass' && row.actual_verdict !== row.expected_verdict) {
        throw new Error('results.jsonl pass row disagrees with its verdicts');
      }
      if (row.score === 'fail' &&
          row.actual_verdict !== 'allow' && row.actual_verdict !== 'block') {
        throw new Error('results.jsonl fail row disagrees with its verdicts');
      }
      if (row.score === 'error' && row.actual_verdict !== 'error' && row.actual_verdict !== 'unreachable') {
        throw new Error('results.jsonl error row disagrees with its verdict');
      }
      // A not-applicable row is an honestly measured outcome: the runner emits
      // score "not_applicable" with the matching verdict when a case did not
      // apply to this target. It is not a loss, so it is validated for shape and
      // then excluded from the failed-case list. Refusing the whole record over
      // one such row would blank the public card for an ordinary run and is the
      // over-strict failure direction; the current retained run happens to carry
      // none, so nothing but this guard exercised the path.
      if (row.score === 'not_applicable' && row.actual_verdict !== 'not_applicable') {
        throw new Error('results.jsonl not-applicable row disagrees with its verdict');
      }
      seen[row.case_id] = true;
      if (row.score !== 'fail') return;
      if (!Array.isArray(indexed.capability_tags) || typeof indexed.category !== 'string' ||
          !indexed.category || !manifestLine[row.case_id]) {
        throw new Error('failed case has no category, capability tags, or stable manifest line');
      }
      failed.push({
        case_id: row.case_id,
        expected_verdict: row.expected_verdict,
        actual_verdict: row.actual_verdict,
        category: indexed.category,
        capability_tags: indexed.capability_tags.slice(),
        manifest_line: manifestLine[row.case_id],
      });
    });
    var indexedIDs = Object.keys(caseIndex.cases);
    if (indexedIDs.length !== lines.length ||
        !artifact.case_count || artifact.case_count.total !== lines.length ||
        indexedIDs.some(function(caseID) { return !seen[caseID]; })) {
      throw new Error('result rows, case index, and published total do not cover the same cases');
    }
    failed.sort(function(left, right) { return left.case_id.localeCompare(right.case_id); });
    return failed;
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
    if (!manifest || [1, 2, 3].indexOf(manifest.schema_version) === -1 ||
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
    Object.defineProperty(artifact, '_assurances', {
      value: pointer.assurances ? pointer.assurances.slice() : [], enumerable: false,
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
      if (!sameRegistryReference(registryReference(profile.capability_registry), reference) ||
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
      if (artifact.schema_version === 6) {
        var resultsBytes = await boundRecordFile(prefix, 'results.jsonl', manifest, fetchImpl, cryptoImpl);
        var caseIndexBytes = await boundRecordFile(prefix, 'case-index.json', manifest, fetchImpl, cryptoImpl);
        var corpusManifestBytes = await boundRecordFile(prefix, 'corpus-manifest.txt', manifest, fetchImpl, cryptoImpl);
        Object.defineProperty(artifact, '_failedCases', {
          value: loadFailedCases(artifact, resultsBytes, caseIndexBytes, corpusManifestBytes),
          enumerable: false,
        });
      }
    } else if (artifact.schema_version !== 2) {
      throw new Error('result record must be frozen schema v2 or supported schema v4/v5/v6');
    }
    return artifact;
  }

  root.validateLatestVerifiedPointer = validatePointer;
  root.loadLatestVerifiedResult = loadLatestVerifiedResult;
  root.capabilityLabel = capabilityLabel;
})(window);
