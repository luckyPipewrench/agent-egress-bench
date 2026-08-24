/*
 * Future publish consumers call renderGauntletScope with a provenance artifact.
 * It creates the score headline and every required scope qualifier together.
 */
(function(root) {
  'use strict';

  function scopeValue(artifact, path) {
    var value = artifact;
    for (var i = 0; i < path.length; i++) {
      if (!value || typeof value !== 'object' ||
          !Object.prototype.hasOwnProperty.call(value, path[i])) {
        throw new Error('missing required scope field: ' + path.join('.'));
      }
      value = value[path[i]];
    }
    return value;
  }

  function formatPercent(value) {
    return value === null ? 'N/A' : (value * 100).toFixed(1) + '%';
  }

  // validateMetricFraction already required this equality. Publishing the
  // percent without the denominator still hides the count that was checked.
  function formatReconstructedPercent(score, numerator, denominator, caseKind) {
    var percent = formatPercent(score);
    if (typeof score !== 'number' || !Number.isFinite(score)) return percent;
    if (!Number.isInteger(numerator) || !Number.isInteger(denominator) ||
        denominator <= 0 || numerator < 0 || numerator > denominator) {
      return percent;
    }
    if (Math.abs(score - (numerator / denominator)) > 1e-12) return percent;
    return percent + ' (' + numerator + '/' + denominator + ' ' + caseKind + ')';
  }

  function formatReasons(reasons) {
    var names = Object.keys(reasons).sort();
    if (names.length === 0) return 'none';
    return names.map(function(name) { return name + ': ' + reasons[name]; }).join(', ');
  }

  function nonNegativeInteger(value, path) {
    if (!Number.isInteger(value) || value < 0) {
      throw new Error('scope field must be a non-negative integer: ' + path);
    }
    return value;
  }

  function finiteFraction(value, path, allowNull) {
    if (value === null && allowNull) return value;
    if (typeof value !== 'number' || !Number.isFinite(value)) {
      throw new Error('scope field must be a finite number' + (allowNull ? ' or null' : '') + ': ' + path);
    }
    if (value < 0 || value > 1) {
      throw new Error('scope field must be between 0 and 1: ' + path);
    }
    return value;
  }

  function nonEmptyString(value, path) {
    if (typeof value !== 'string' || !value.trim()) {
      throw new Error('scope field must be a non-empty string: ' + path);
    }
    return value;
  }

  function validateManifestDigest(value, path) {
    nonEmptyString(value, path);
    if (!/^[0-9a-f]{64}$/.test(value)) {
      throw new Error(path + ' must be 64 lower-case hex characters');
    }
    return value;
  }

  function sortedStringSet(value, path) {
    if (!Array.isArray(value) || value.some(function(item) {
      return typeof item !== 'string' || !item.trim();
    })) {
      throw new Error(path + ' must be an array of non-empty strings');
    }
    var sorted = value.slice().sort();
    if (sorted.some(function(item, index) {
      return index > 0 && item === sorted[index - 1];
    })) {
      throw new Error(path + ' must contain unique strings');
    }
    return sorted;
  }

  // scope is 'applicable' or 'full'. The full-corpus block gets the same
  // numerator/denominator agreement check as the applicable block, because it
  // is the figure the card now leads with and an unvalidated headline is not
  // evidence.
  function validateMetricFraction(artifact, metric, scope) {
    var scorePath = 'scores.' + scope + '.' + metric;
    var countPath = 'metric_counts.' + scope + '.' + metric;
    var numerator = nonNegativeInteger(scopeValue(artifact,
      ['metric_counts', scope, metric, 'numerator']), countPath + '.numerator');
    var denominator = nonNegativeInteger(scopeValue(artifact,
      ['metric_counts', scope, metric, 'denominator']), countPath + '.denominator');
    if (numerator > denominator) {
      throw new Error('metric numerator cannot exceed denominator: ' + countPath);
    }

    var score = finiteFraction(scopeValue(artifact, ['scores', scope, metric]), scorePath, true);
    if (denominator === 0) {
      if (score !== null) {
        throw new Error('score must be null when metric denominator is zero: ' + scorePath);
      }
    } else if (score === null) {
      throw new Error('score must be a number when metric denominator is non-zero: ' + scorePath);
    } else if (score !== numerator / denominator) {
      throw new Error('score must equal metric numerator/denominator: ' + scorePath);
    }
    return { numerator: numerator, denominator: denominator };
  }

  function validateCanonicalURL(canonicalURL) {
    if (typeof canonicalURL !== 'string' || !/^https:\/\//i.test(canonicalURL)) {
      throw new Error('canonical_url must be an absolute https URL');
    }
    try {
      var parsed = new URL(canonicalURL);
      if (parsed.protocol !== 'https:' || !parsed.hostname) {
        throw new Error('invalid canonical URL');
      }
    } catch (error) {
      throw new Error('canonical_url must be an absolute https URL');
    }
    return canonicalURL;
  }

  function validateScope(artifact) {
    if (!artifact || typeof artifact !== 'object' || Array.isArray(artifact)) {
      throw new Error('artifact must be an object');
    }
    if ((artifact.schema_version === 4 || artifact.schema_version === 5 || artifact.schema_version === 6) && (!artifact._capabilityRegistry ||
        artifact._capabilityRegistry.id !== scopeValue(artifact, ['capability_registry', 'id']))) {
      throw new Error('active artifact is uninterpretable without its verified capability registry snapshot');
    }

    nonEmptyString(scopeValue(artifact, ['artifact_id']), 'artifact_id');
    validateManifestDigest(scopeValue(artifact, ['corpus_manifest_sha256']), 'corpus_manifest_sha256');
    if (artifact.schema_version === 5 || artifact.schema_version === 6) {
      validateManifestDigest(
        scopeValue(artifact, ['benchmark_manifest_sha256']),
        'benchmark_manifest_sha256'
      );
    }
    if (artifact.schema_version === 6) {
      nonEmptyString(scopeValue(artifact, ['method_repository']), 'method_repository');
      var repositoryParts = artifact.method_repository.split('/');
      if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(artifact.method_repository) ||
          repositoryParts.length !== 2 || repositoryParts[0] === '.' || repositoryParts[0] === '..' ||
          repositoryParts[1] === '.' || repositoryParts[1] === '..') {
        throw new Error('method_repository must name one owner and repository');
      }
      nonEmptyString(scopeValue(artifact, ['method_commit']), 'method_commit');
      if (!/^[0-9a-f]{40}$/.test(artifact.method_commit)) {
        throw new Error('method_commit must be a 40-character lower-case commit');
      }
      nonEmptyString(scopeValue(artifact, ['adapter_id']), 'adapter_id');
      nonEmptyString(scopeValue(artifact, ['adapter_owner']), 'adapter_owner');
      nonEmptyString(scopeValue(artifact, ['target_config_ref']), 'target_config_ref');
      validateManifestDigest(
        scopeValue(artifact, ['target_config_sha256']),
        'target_config_sha256'
      );
    }
    var logicalCaseCount = nonNegativeInteger(scopeValue(artifact, ['logical_case_count']), 'logical_case_count');
    if (logicalCaseCount === 0) throw new Error('logical_case_count must be greater than zero');
    nonEmptyString(scopeValue(artifact, ['runner_version']), 'runner_version');
    nonEmptyString(scopeValue(artifact, ['scoring_version']), 'scoring_version');

    var applicable = nonNegativeInteger(scopeValue(artifact, ['case_count', 'applicable']), 'case_count.applicable');
    var total = nonNegativeInteger(scopeValue(artifact, ['case_count', 'total']), 'case_count.total');
    var hasUnreachable = Object.prototype.hasOwnProperty.call(artifact.case_count || {}, 'unreachable');
    var unreachable = hasUnreachable
      ? nonNegativeInteger(scopeValue(artifact, ['case_count', 'unreachable']), 'case_count.unreachable')
      : 0;
    var notApplicable = nonNegativeInteger(scopeValue(artifact, ['case_count', 'not_applicable']), 'case_count.not_applicable');
    var errors = nonNegativeInteger(scopeValue(artifact, ['case_count', 'errors']), 'case_count.errors');
    if (total === 0) throw new Error('case_count.total must be greater than zero');
    if (total !== logicalCaseCount) {
      throw new Error('case_count.total must equal logical_case_count');
    }
    if (applicable > total) throw new Error('case_count.applicable cannot exceed case_count.total');
    if (applicable + unreachable + notApplicable !== total) {
      throw new Error('case_count.applicable, unreachable, and not_applicable must equal case_count.total');
    }
    var measurementStatus;
    if (artifact.schema_version === 4 || artifact.schema_version === 5 || artifact.schema_version === 6) {
      measurementStatus = scopeValue(artifact, ['measurement_status']);
      if (measurementStatus !== 'measured' && measurementStatus !== 'incomplete') {
        throw new Error('measurement_status must be measured or incomplete');
      }
    } else {
      var sufficient = scopeValue(artifact, ['sufficient']);
      if (typeof sufficient !== 'boolean') {
        throw new Error('legacy sufficient must be a boolean');
      }
      measurementStatus = sufficient ? 'measured' : 'incomplete';
    }
    if ((unreachable !== 0 || errors !== 0) && measurementStatus === 'measured') {
      throw new Error('unmeasured cases require measurement_status=incomplete');
    }
    if (measurementStatus !== 'measured') {
      throw new Error('incomplete measurements cannot render as verified');
    }

    var reasons = scopeValue(artifact, ['case_count', 'not_applicable_reasons']);
    if (!reasons || typeof reasons !== 'object' || Array.isArray(reasons)) {
      throw new Error('scope field must be an object: case_count.not_applicable_reasons');
    }
    var reasonTotal = 0;
    Object.keys(reasons).forEach(function(reason) {
      if (!reason) throw new Error('not_applicable_reasons keys must be non-empty strings');
      reasonTotal += nonNegativeInteger(reasons[reason], 'case_count.not_applicable_reasons.' + reason);
    });
    if (reasonTotal !== notApplicable) {
      throw new Error('not_applicable_reasons must sum to case_count.not_applicable');
    }

    var containment = scopeValue(artifact, ['scores', 'applicable', 'containment']);
    var containmentCounts = validateMetricFraction(artifact, 'containment', 'applicable');
    var falsePositiveCounts = validateMetricFraction(artifact, 'false_positive_rate', 'applicable');

    // Full corpus is the published view, so it is validated rather than merely
    // read. Its containment denominator is the MALICIOUS cases in the corpus,
    // not every case: benign controls are counted by the false-positive rate
    // instead. So it is bounded by total but is normally well below it, and the
    // rendered text must state that denominator rather than implying the score
    // covers all cases.
    var fullContainment = scopeValue(artifact, ['scores', 'full', 'containment']);
    var fullContainmentCounts = validateMetricFraction(artifact, 'containment', 'full');
    var fullFalsePositiveCounts = validateMetricFraction(artifact, 'false_positive_rate', 'full');
    if (fullContainmentCounts.denominator > total - unreachable) {
      throw new Error('metric denominator cannot exceed scoreable cases: metric_counts.full.containment');
    }
    if (fullFalsePositiveCounts.denominator > total - unreachable) {
      throw new Error('metric denominator cannot exceed scoreable cases: metric_counts.full.false_positive_rate');
    }
    if (fullFalsePositiveCounts.denominator < falsePositiveCounts.denominator) {
      throw new Error('full false-positive denominator cannot be smaller than the applicable denominator');
    }
    if (fullFalsePositiveCounts.numerator < falsePositiveCounts.numerator) {
      throw new Error('full false-positive numerator cannot be smaller than the applicable numerator');
    }
    if (fullContainmentCounts.denominator < containmentCounts.denominator) {
      throw new Error('full containment denominator cannot be smaller than the applicable denominator');
    }
    var retainedNotApplicableMalicious =
      fullContainmentCounts.denominator - containmentCounts.denominator;
    if (artifact.schema_version === 6 && retainedNotApplicableMalicious > notApplicable) {
      throw new Error('full containment denominator gap exceeds retained not-applicable cases');
    }
    // Schema 6 is rebuilt from retained rows. The producer uses the same
    // observed blocked-malicious count for both scopes and changes only the
    // denominator by retaining historical N/A rows in the full view. Without
    // this binding, a digest-valid artifact could claim a perfect full-corpus
    // headline directly above applicable failures that contradict it.
    if (artifact.schema_version === 6 &&
        fullContainmentCounts.numerator !== containmentCounts.numerator) {
      throw new Error('full containment numerator must equal the applicable numerator');
    }
    if (artifact.schema_version === 6 &&
        fullFalsePositiveCounts.numerator !== falsePositiveCounts.numerator) {
      throw new Error('full false-positive numerator must equal the applicable numerator');
    }
    if (containmentCounts.denominator > applicable || falsePositiveCounts.denominator > applicable) {
      throw new Error('metric denominator cannot exceed case_count.applicable');
    }
    if (applicable === 0) {
      if (containment !== null || containmentCounts.denominator !== 0) {
        throw new Error('scores.applicable.containment must be null when case_count.applicable is zero');
      }
    } else {
      if (containmentCounts.denominator === 0) {
        throw new Error('containment must have a denominator when case_count.applicable is non-zero');
      }
    }
    if (applicable === 0 && falsePositiveCounts.denominator !== 0) {
      throw new Error('false_positive_rate must have a zero denominator when case_count.applicable is zero');
    }

    return {
      applicable: applicable,
      total: total,
      unreachable: unreachable,
      hasUnreachable: hasUnreachable,
      notApplicable: notApplicable,
      errors: errors,
      measurementStatus: measurementStatus,
      reasons: reasons,
      containment: containment,
      containmentNumerator: containmentCounts.numerator,
      containmentDenominator: containmentCounts.denominator,
      fullContainment: fullContainment,
      fullContainmentDenominator: fullContainmentCounts.denominator,
      retainedNotApplicableMalicious: retainedNotApplicableMalicious,
      falsePositiveRate: scopeValue(artifact, ['scores', 'full', 'false_positive_rate']),
      falsePositiveNumerator: falsePositiveCounts.numerator,
      fullFalsePositiveNumerator: fullFalsePositiveCounts.numerator,
      fullFalsePositiveDenominator: fullFalsePositiveCounts.denominator,
      canonicalURL: validateCanonicalURL(scopeValue(artifact, ['canonical_url'])),
    };
  }

  // Returns a .denominator block. Its score text is never built separately
  // from the denominator, N/A reasons, FP rate, and canonical artifact link.
  function renderGauntletScope(artifact) {
    var scope = validateScope(artifact);
    var applicable = scope.applicable;
    var total = scope.total;
    var unreachable = scope.unreachable;
    var notApplicable = scope.notApplicable;
    var reasons = scope.reasons;
    var containment = scope.containment;
    var falsePositiveRate = scope.falsePositiveRate;
    var canonicalURL = scope.canonicalURL;

    var block = document.createElement('div');
    block.className = 'denominator';
    // Lead with full-corpus containment, the primary published view, and name
    // the applicable figure as diagnostic behind it. Both denominators stay
    // visible: applicable-only results are a delivery-and-observation diagnostic,
    // not a substitute for coverage of the complete corpus.
    block.appendChild(document.createTextNode(
      'Containment ' + formatPercent(scope.fullContainment) + ' of ' + scope.fullContainmentDenominator +
      ' malicious cases in the full ' + total + '-case corpus; ' +
      formatPercent(containment) + ' of ' + scope.containmentDenominator +
      ' applicable malicious (diagnostic, ' + (scope.hasUnreachable ? unreachable + ' unreachable, ' : '') + notApplicable + ' N/A: ' + formatReasons(reasons) +
      '), full-corpus false positives ' + formatReconstructedPercent(
        falsePositiveRate,
        scope.fullFalsePositiveNumerator,
        scope.fullFalsePositiveDenominator,
        'benign cases'
      ) + ', '
    ));

    var assurances = artifact._assurances || [];
    if (assurances.length &&
        JSON.stringify(assurances) !== JSON.stringify(['self-run', 'artifact-validated'])) {
      throw new Error('publisher assurance labels are invalid');
    }
    assurances.forEach(function(assurance) {
      var badge = document.createElement('span');
      badge.className = 'badge badge-assurance';
      badge.textContent = assurance;
      block.appendChild(badge);
    });
    if (assurances.length) block.appendChild(document.createTextNode(' '));

    var link = document.createElement('a');
    link.href = canonicalURL;
    link.textContent = 'canonical artifact';
    block.appendChild(link);
    block.appendChild(document.createTextNode(' · '));

    var evidenceLink = document.createElement('a');
    evidenceLink.href = 'https://github.com/luckyPipewrench/agent-egress-bench/blob/main/docs/RESULTS-USE.md#verify-a-public-result';
    evidenceLink.textContent = 'evidence and verify';
    block.appendChild(evidenceLink);
    return block;
  }

  function renderGauntletFailures(artifact) {
    var scope = validateScope(artifact);
    var block = document.createElement('div');
    block.className = 'failure-summary';
    var title = document.createElement('div');
    title.className = 'section-label failure-title';
    title.textContent = 'Failed cases';
    block.appendChild(title);
    if (artifact.schema_version !== 6) {
      var unavailable = document.createElement('div');
      unavailable.className = 'failure-context';
      unavailable.textContent = 'Per-case loss details were not retained in this frozen result format.';
      block.appendChild(unavailable);
      return block;
    }
    var failures = artifact._failedCases;
    if (!Array.isArray(failures)) {
      throw new Error('verified result has no digest-bound failed-case list');
    }
    var seen = {};
    // A failed case is not always a containment miss. Containment counts the
    // observed VERDICT: the producer takes every malicious row whose
    // actual_verdict is "block", regardless of its score. A malicious row can
    // block and still score "fail" -- a budget block at the wrong call is the
    // live example -- so it belongs in the loss list while leaving containment
    // untouched. Comparing ALL malicious failures against the score gap threw
    // on that run and blanked the entire card, score included.
    var maliciousMisses = 0;
    var benignBlocked = 0;
    failures.forEach(function(failure) {
      if (!failure || typeof failure !== 'object' || Array.isArray(failure) ||
          typeof failure.case_id !== 'string' || !failure.case_id || seen[failure.case_id] ||
          (failure.expected_verdict !== 'allow' && failure.expected_verdict !== 'block') ||
          (failure.actual_verdict !== 'allow' && failure.actual_verdict !== 'block') ||
          typeof failure.category !== 'string' || !failure.category ||
          !Number.isInteger(failure.manifest_line) || failure.manifest_line < 1) {
        throw new Error('failed-case list contains an invalid row');
      }
      sortedStringSet(failure.capability_tags, 'failed case capability_tags');
      seen[failure.case_id] = true;
      if (failure.expected_verdict === 'block') {
        if (failure.actual_verdict !== 'block') maliciousMisses++;
      } else if (failure.actual_verdict === 'block') {
        benignBlocked++;
      }
    });
    if (maliciousMisses !== scope.containmentDenominator - scope.containmentNumerator ||
        benignBlocked !== scope.falsePositiveNumerator) {
      throw new Error('failed-case list does not explain the applicable score losses');
    }

    var retainedNotApplicableMalicious = scope.retainedNotApplicableMalicious;
    if (failures.length === 0) {
      if (retainedNotApplicableMalicious > 0) {
        var retainedOnly = document.createElement('div');
        retainedOnly.className = 'failure-context';
        retainedOnly.textContent = 'No applicable failed cases. Full-corpus containment retains ' +
          retainedNotApplicableMalicious + ' not-applicable malicious ' +
          (retainedNotApplicableMalicious === 1 ? 'case' : 'cases') + ' as misses.';
        block.appendChild(retainedOnly);
      } else {
        block.appendChild(document.createTextNode('None.'));
      }
      return block;
    }

    var categories = {};
    var sharedTags = null;
    failures.forEach(function(failure) {
      categories[failure.category] = true;
      var tags = sortedStringSet(failure.capability_tags, 'failed case capability_tags');
      sharedTags = sharedTags === null ? tags : sharedTags.filter(function(tag) {
        return tags.indexOf(tag) !== -1;
      });
    });
    var context = document.createElement('div');
    context.className = 'failure-context';
    var contextParts = [failures.length + (failures.length === 1 ? ' failed case in ' : ' failed cases in ') +
      Object.keys(categories).sort().join(', ').replaceAll('_', ' ')];
    if (retainedNotApplicableMalicious > 0) {
      contextParts.push('Full-corpus containment retains ' + retainedNotApplicableMalicious +
        ' not-applicable malicious ' + (retainedNotApplicableMalicious === 1 ? 'case' : 'cases') + ' as misses');
    }
    if (sharedTags.length) {
      contextParts.push('Shared capabilities: ' + sharedTags.map(function(tag) {
        return root.capabilityLabel(artifact, tag);
      }).join(', '));
    }
    context.textContent = contextParts.join('. ') + '.';
    block.appendChild(context);

    var list = document.createElement('ul');
    failures.forEach(function(failure) {
      var item = document.createElement('li');
      var link = document.createElement('a');
      link.href = 'https://github.com/' + artifact.method_repository + '/blob/' +
        artifact.method_commit + '/cases/MANIFEST.txt#L' + failure.manifest_line;
      link.textContent = failure.case_id;
      item.appendChild(link);
      item.appendChild(document.createTextNode(': expected ' + failure.expected_verdict +
        ', observed ' + failure.actual_verdict + '.'));
      list.appendChild(item);
    });
    block.appendChild(list);
    return block;
  }

  function renderGauntletControlCoverage(artifact) {
    validateScope(artifact);
    var block = document.createElement('div');
    block.className = 'exercised-coverage';
    if (artifact.schema_version !== 4 && artifact.schema_version !== 5 && artifact.schema_version !== 6) {
      block.textContent = 'Exercised-control coverage: not recorded in this frozen result.';
      return block;
    }
    var transports = sortedStringSet(scopeValue(artifact, ['exercised', 'transports']), 'exercised.transports');
    var categories = sortedStringSet(scopeValue(artifact, ['exercised', 'categories']), 'exercised.categories');
    var tags = sortedStringSet(scopeValue(artifact, ['exercised', 'capability_tags']), 'exercised.capability_tags');
    // Only a v6 artifact has had this object re-derived from the raw rows and
    // the pinned case index, by the builder and again by the promotion gate. An
    // earlier artifact carries whatever its runner recorded, and saying "from
    // observed rows" there would claim a derivation nothing performed.
    var origin = artifact.schema_version === 6
      ? 'Exercised-control coverage from observed rows: transports '
      : 'Exercised-control coverage as recorded by the runner: transports ';
    block.textContent = origin +
      (transports.join(', ') || 'none') + '; categories ' +
      (categories.join(', ') || 'none') + '; capability tags ' +
      (tags.join(', ') || 'none') + '. These labels describe tested surfaces, not successful outcomes or framework conformance.';
    return block;
  }

  root.renderGauntletScope = renderGauntletScope;
  root.renderGauntletFailures = renderGauntletFailures;
  root.renderGauntletControlCoverage = renderGauntletControlCoverage;
})(window);
