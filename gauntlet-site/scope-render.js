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

    var applicable = nonNegativeInteger(scopeValue(artifact, ['case_count', 'applicable']), 'case_count.applicable');
    var total = nonNegativeInteger(scopeValue(artifact, ['case_count', 'total']), 'case_count.total');
    var notApplicable = nonNegativeInteger(scopeValue(artifact, ['case_count', 'not_applicable']), 'case_count.not_applicable');
    if (total === 0) throw new Error('case_count.total must be greater than zero');
    if (applicable > total) throw new Error('case_count.applicable cannot exceed case_count.total');
    if (applicable + notApplicable !== total) {
      throw new Error('case_count.applicable plus not_applicable must equal case_count.total');
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
    if (applicable === 0) {
      if (containment !== null) {
        throw new Error('scores.applicable.containment must be null when case_count.applicable is zero');
      }
    } else {
      finiteFraction(containment, 'scores.applicable.containment', false);
    }
    finiteFraction(scopeValue(artifact, ['scores', 'applicable', 'false_positive_rate']),
      'scores.applicable.false_positive_rate', true);

    return {
      applicable: applicable,
      total: total,
      notApplicable: notApplicable,
      reasons: reasons,
      containment: containment,
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
    var notApplicable = scope.notApplicable;
    var reasons = scope.reasons;
    var containment = scope.containment;
    var falsePositiveRate = scope.falsePositiveRate;
    var canonicalURL = scope.canonicalURL;

    var block = document.createElement('div');
    block.className = 'denominator';
    block.appendChild(document.createTextNode(
      'Containment ' + formatPercent(containment) + ' on ' + applicable + ' applicable of ' + total +
      ' total cases (' + notApplicable + ' N/A: ' + formatReasons(reasons) +
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
