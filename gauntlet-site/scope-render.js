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

  function validateManifestDigest(value) {
    nonEmptyString(value, 'corpus_manifest_sha256');
    if (!/^[0-9a-f]{64}$/.test(value)) {
      throw new Error('corpus_manifest_sha256 must be 64 lower-case hex characters');
    }
    return value;
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
    if (artifact.schema_version === 4 && (!artifact._capabilityRegistry ||
        artifact._capabilityRegistry.id !== scopeValue(artifact, ['capability_registry', 'id']))) {
      throw new Error('v4 artifact is uninterpretable without its verified capability registry snapshot');
    }

    nonEmptyString(scopeValue(artifact, ['artifact_id']), 'artifact_id');
    validateManifestDigest(scopeValue(artifact, ['corpus_manifest_sha256']));
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
    if (total === 0) throw new Error('case_count.total must be greater than zero');
    if (total !== logicalCaseCount) {
      throw new Error('case_count.total must equal logical_case_count');
    }
    if (applicable > total) throw new Error('case_count.applicable cannot exceed case_count.total');
    if (applicable + unreachable + notApplicable !== total) {
      throw new Error('case_count.applicable, unreachable, and not_applicable must equal case_count.total');
    }
    var sufficient = scopeValue(artifact, ['sufficient']);
    if (typeof sufficient !== 'boolean') {
      throw new Error('sufficient must be a boolean');
    }
    if (unreachable !== 0 && sufficient) {
      throw new Error('an unreachable case requires sufficient=false');
    }
    if (!sufficient) {
      throw new Error('insufficient runs cannot render as verified');
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
    if (fullContainmentCounts.denominator > total - unreachable) {
      throw new Error('metric denominator cannot exceed scoreable cases: metric_counts.full.containment');
    }
    if (fullContainmentCounts.denominator < containmentCounts.denominator) {
      throw new Error('full containment denominator cannot be smaller than the applicable denominator');
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
      reasons: reasons,
      containment: containment,
      containmentDenominator: containmentCounts.denominator,
      fullContainment: fullContainment,
      fullContainmentDenominator: fullContainmentCounts.denominator,
      falsePositiveRate: scopeValue(artifact, ['scores', 'applicable', 'false_positive_rate']),
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
      '), false positives ' + formatPercent(falsePositiveRate) + ', '
    ));

    var badge = document.createElement('span');
    badge.className = 'badge badge-verified';
    badge.textContent = 'verified';
    block.appendChild(badge);
    block.appendChild(document.createTextNode(' '));

    var link = document.createElement('a');
    link.href = canonicalURL;
    link.textContent = 'canonical artifact';
    block.appendChild(link);
    return block;
  }

  root.renderGauntletScope = renderGauntletScope;
})(window);
