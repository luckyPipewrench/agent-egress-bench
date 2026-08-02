/*
 * Future publish consumers call renderGauntletScope with a provenance artifact.
 * It creates the score headline and every required scope qualifier together.
 */
(function(root) {
  'use strict';

  function scopeValue(artifact, path) {
    var value = artifact;
    for (var i = 0; i < path.length; i++) {
      if (!value || typeof value !== 'object' || !(path[i] in value)) {
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

  // Returns a .denominator block. Its score text is never built separately
  // from the denominator, N/A reasons, FP rate, and canonical artifact link.
  function renderGauntletScope(artifact) {
    var applicable = scopeValue(artifact, ['case_count', 'applicable']);
    var total = scopeValue(artifact, ['case_count', 'total']);
    var notApplicable = scopeValue(artifact, ['case_count', 'not_applicable']);
    var reasons = scopeValue(artifact, ['case_count', 'not_applicable_reasons']);
    var containment = scopeValue(artifact, ['scores', 'applicable', 'containment']);
    var falsePositiveRate = scopeValue(artifact, ['scores', 'applicable', 'false_positive_rate']);
    var canonicalURL = scopeValue(artifact, ['canonical_url']);

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
