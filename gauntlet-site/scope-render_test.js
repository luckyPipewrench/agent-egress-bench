'use strict';

const assert = require('node:assert/strict');

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

require('./scope-render.js');

function completeArtifact() {
  return {
    canonical_url: 'https://github.com/luckyPipewrench/agent-egress-bench/actions/runs/123',
    artifact_id: 'github-actions:luckyPipewrench/agent-egress-bench:123',
    corpus_manifest_sha256: 'ce4e2cc1cc62b8e3aebfdbea08c1b4ef2450020accf5db694bfc7927fe3e249d',
    logical_case_count: 213,
    runner_version: '0.4.0',
    scoring_version: '2.2',
    case_count: {
      total: 213,
      applicable: 212,
      not_applicable: 1,
      not_applicable_reasons: { missing_requires: 1 },
    },
    scores: {
      applicable: { containment: 1, false_positive_rate: 0 },
      // The card leads with full-corpus containment, so the artifact must carry
      // it. 212 of 213 contained: the one non-applicable case counts against the
      // full corpus, which is exactly why the two figures differ.
      full: { containment: 212 / 213, false_positive_rate: 0 },
    },
    metric_counts: {
      applicable: {
        containment: { numerator: 1, denominator: 1 },
        false_positive_rate: { numerator: 0, denominator: 1 },
      },
      full: {
        containment: { numerator: 212, denominator: 213 },
        false_positive_rate: { numerator: 0, denominator: 1 },
      },
    },
  };
}

function expectReject(mutator, message) {
  const artifact = completeArtifact();
  mutator(artifact);
  assert.throws(() => window.renderGauntletScope(artifact), message);
}

const rendered = window.renderGauntletScope(completeArtifact());
assert.equal(rendered.className, 'denominator');
// Full corpus leads; the applicable figure follows, named as diagnostic. The
// two numbers differ here precisely because a non-applicable case still counts
// against the full corpus, which is the property that makes it non-gameable.
assert.match(rendered.children[0].textContent, /Containment 99\.5% on all 213 cases; 100\.0% on the 212 applicable \(diagnostic/);
assert.equal(rendered.children[3].href, completeArtifact().canonical_url);

expectReject((artifact) => { artifact.scores.applicable.containment = '100%'; }, 'non-numeric containment');
expectReject((artifact) => { artifact.scores.applicable.false_positive_rate = 1.1; }, 'out-of-range FP rate');
expectReject((artifact) => { artifact.case_count.total = 0; }, 'zero total');
expectReject((artifact) => { artifact.case_count.total = -1; }, 'negative total');
expectReject((artifact) => { artifact.case_count.applicable = 198; }, 'applicable exceeds total');
expectReject((artifact) => { artifact.case_count.not_applicable = 0; }, 'counts do not sum to total');
expectReject((artifact) => { artifact.case_count.not_applicable_reasons = { missing_requires: 0 }; }, 'N/A reasons do not sum');
expectReject((artifact) => { artifact.canonical_url = 'javascript:alert(1)'; }, 'unsafe canonical URL');
expectReject((artifact) => { delete artifact.corpus_manifest_sha256; }, 'missing corpus digest');
expectReject((artifact) => { artifact.scores.applicable.containment = 0.5; }, 'score must equal numerator/denominator');
expectReject((artifact) => { artifact.scores.applicable.false_positive_rate = 0.5; }, 'FP score must equal numerator/denominator');
expectReject((artifact) => {
  artifact.case_count.applicable = 0;
  artifact.case_count.not_applicable = 213;
  artifact.case_count.not_applicable_reasons = { missing_requires: 213 };
}, 'all-N/A runs cannot have a numeric containment score');

const allNA = completeArtifact();
allNA.case_count.applicable = 0;
allNA.case_count.not_applicable = 213;
allNA.case_count.not_applicable_reasons = { missing_requires: 213 };
allNA.scores.applicable.containment = null;
allNA.scores.applicable.false_positive_rate = null;
allNA.metric_counts.applicable.containment = { numerator: 0, denominator: 0 };
allNA.metric_counts.applicable.false_positive_rate = { numerator: 0, denominator: 0 };
// A tool declaring no capabilities contains nothing, so full-corpus containment
// is 0 of 213 rather than the 212/213 the base fixture carries.
allNA.scores.full.containment = 0;
allNA.metric_counts.full.containment = { numerator: 0, denominator: 213 };
// This is the whole point of leading with full corpus. Declaring nothing makes
// the applicable score vanish into N/A, which under the old presentation left
// no headline number at all. Full corpus reports it as 0.0%: the cases were
// still attacks, and none of them were contained.
assert.match(window.renderGauntletScope(allNA).children[0].textContent,
  /Containment 0\.0% on all 213 cases; N\/A on the 0 applicable \(diagnostic/);

console.log('scope renderer tests: OK');
