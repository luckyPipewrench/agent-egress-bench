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
    sufficient: true,
    case_count: {
      total: 213,
      applicable: 212,
      not_applicable: 1,
      errors: 0,
      not_applicable_reasons: { missing_requires: 1 },
    },
    scores: {
      applicable: { containment: 1, false_positive_rate: 0 },
      // The card leads with full-corpus containment, so the artifact must carry
      // it. Containment is scored over MALICIOUS cases only, so its denominator
      // is 158 rather than the 213 total: the benign controls are counted by the
      // false-positive rate instead. 157 of 158 contained, the miss being the
      // retained historical N/A case, which is why the full and applicable
      // figures differ.
      full: { containment: 157 / 158, false_positive_rate: 0 },
    },
    metric_counts: {
      applicable: {
        containment: { numerator: 1, denominator: 1 },
        false_positive_rate: { numerator: 0, denominator: 1 },
      },
      full: {
        containment: { numerator: 157, denominator: 158 },
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
// Every denominator is stated. The headline covers 158 malicious cases, not all
// 213: saying "on all 213 cases" beside a score computed over the malicious
// subset would be false, which is the same class of error as leading with the
// applicable score in the first place.
assert.match(rendered.children[0].textContent,
  /Containment 99\.4% of 158 malicious cases in the full 213-case corpus; 100\.0% of 1 applicable malicious \(diagnostic/);
assert.equal(rendered.children[3].href, completeArtifact().canonical_url);
assert.equal(rendered.children[5].textContent, 'evidence and verify');
assert.match(rendered.children[5].href, /docs\/RESULTS-USE\.md#verify-a-public-result$/);

const unboundV4 = completeArtifact();
unboundV4.schema_version = 4;
unboundV4.capability_registry = { id: 'aeb.core-capabilities', format: 1, revision: 1, sha256: '0'.repeat(64) };
assert.throws(
  () => window.renderGauntletScope(unboundV4),
  /uninterpretable without its verified capability registry snapshot/
);

const withUnreachable = completeArtifact();
withUnreachable.case_count.applicable = 211;
withUnreachable.case_count.unreachable = 1;
withUnreachable.metric_counts.applicable.false_positive_rate.denominator = 0;
withUnreachable.metric_counts.full.false_positive_rate.denominator = 0;
withUnreachable.scores.applicable.false_positive_rate = null;
withUnreachable.scores.full.false_positive_rate = null;
assert.throws(
  () => window.renderGauntletScope(withUnreachable),
  /unmeasured cases require measurement_status=incomplete/
);

const insufficient = completeArtifact();
insufficient.sufficient = false;
assert.throws(
  () => window.renderGauntletScope(insufficient),
  /incomplete measurements cannot render as verified/
);

const activeMeasured = completeArtifact();
activeMeasured.schema_version = 4;
activeMeasured.capability_registry = { id: 'aeb.core-capabilities' };
activeMeasured._capabilityRegistry = { id: 'aeb.core-capabilities' };
delete activeMeasured.sufficient;
activeMeasured.measurement_status = 'measured';
activeMeasured.metric_counts.applicable.containment = { numerator: 1, denominator: 2 };
activeMeasured.scores.applicable.containment = 0.5;
activeMeasured.metric_counts.full.containment = { numerator: 79, denominator: 158 };
activeMeasured.scores.full.containment = 0.5;
assert.match(window.renderGauntletScope(activeMeasured).children[0].textContent,
  /Containment 50\.0% of 158 malicious cases/);

const activeV5 = JSON.parse(JSON.stringify(activeMeasured));
activeV5.schema_version = 5;
activeV5._capabilityRegistry = { id: 'aeb.core-capabilities' };
activeV5.benchmark_manifest_sha256 = 'f'.repeat(64);
assert.match(window.renderGauntletScope(activeV5).children[0].textContent,
  /Containment 50\.0% of 158 malicious cases/);

const v5WithoutBenchmarkManifest = JSON.parse(JSON.stringify(activeV5));
delete v5WithoutBenchmarkManifest.benchmark_manifest_sha256;
assert.throws(
  () => window.renderGauntletScope(v5WithoutBenchmarkManifest),
  /benchmark_manifest_sha256/
);

const activeV6 = JSON.parse(JSON.stringify(activeV5));
activeV6.schema_version = 6;
activeV6.method_repository = 'example/security/agent-egress-bench';
activeV6.method_commit = 'c'.repeat(40);
activeV6.adapter_id = 'proxy';
activeV6.adapter_owner = 'Example Maintainers';
activeV6.target_config_ref = 'examples/tool/benchmark.yaml';
activeV6.target_config_sha256 = 'd'.repeat(64);
assert.match(window.renderGauntletScope(activeV6).children[0].textContent,
  /Containment 50\.0% of 158 malicious cases/);

[
  'method_repository',
  'method_commit',
  'adapter_id',
  'adapter_owner',
  'target_config_ref',
  'target_config_sha256',
].forEach((field) => {
  const incompleteV6 = JSON.parse(JSON.stringify(activeV6));
  delete incompleteV6[field];
  assert.throws(
    () => window.renderGauntletScope(incompleteV6),
    new RegExp(field)
  );
});

['incomplete', 'complete', undefined].forEach((status) => {
  const artifact = JSON.parse(JSON.stringify(activeMeasured));
  artifact._capabilityRegistry = { id: 'aeb.core-capabilities' };
  if (status === undefined) delete artifact.measurement_status;
  else artifact.measurement_status = status;
  assert.throws(
    () => window.renderGauntletScope(artifact),
    /measurement_status|incomplete measurements/
  );
});

const activeWithError = JSON.parse(JSON.stringify(activeMeasured));
activeWithError._capabilityRegistry = { id: 'aeb.core-capabilities' };
activeWithError.case_count.errors = 1;
assert.throws(
  () => window.renderGauntletScope(activeWithError),
  /unmeasured cases require measurement_status=incomplete/
);

expectReject((artifact) => { artifact.scores.applicable.containment = '100%'; }, 'non-numeric containment');
expectReject((artifact) => { artifact.scores.applicable.false_positive_rate = 1.1; }, 'out-of-range FP rate');
expectReject((artifact) => { artifact.case_count.total = 0; }, 'zero total');
expectReject((artifact) => { artifact.case_count.total = -1; }, 'negative total');
expectReject((artifact) => { artifact.case_count.applicable = 198; }, 'applicable exceeds total');
expectReject((artifact) => { artifact.case_count.not_applicable = 0; }, 'counts do not sum to total');
expectReject((artifact) => { artifact.case_count.not_applicable_reasons = { missing_requires: 0 }; }, 'N/A reasons do not sum');
expectReject((artifact) => { artifact.canonical_url = 'javascript:alert(1)'; }, 'unsafe canonical URL');
// The full-corpus denominator is bounded by the corpus, and cannot be narrower
// than the applicable view it is meant to contain. It is NOT required to equal
// case_count.total: containment is scored over malicious cases, so a real
// artifact carries 158 of 213 here and a total-equality rule would reject every
// genuine record.
expectReject((artifact) => {
  artifact.metric_counts.full.containment = { numerator: 214, denominator: 214 };
  artifact.scores.full.containment = 1;
}, 'full containment denominator exceeds total');
expectReject((artifact) => {
  artifact.metric_counts.applicable.containment = { numerator: 200, denominator: 200 };
  artifact.metric_counts.full.containment = { numerator: 150, denominator: 150 };
  artifact.scores.full.containment = 1;
}, 'full containment denominator narrower than applicable');
expectReject((artifact) => { delete artifact.metric_counts.full; }, 'missing full-corpus metric counts');
expectReject((artifact) => { delete artifact.scores.full; }, 'missing full-corpus scores');
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
// This retained historical all-N/A fixture contains nothing, so full-corpus
// containment is 0 of the 158 malicious cases rather than the 157/158 the base
// fixture carries. The denominator stays 158 because it counts attacks present
// in the corpus.
allNA.scores.full.containment = 0;
allNA.metric_counts.full.containment = { numerator: 0, denominator: 158 };
// This is the point of leading with full corpus. Historical all-N/A data makes
// the applicable score vanish into N/A, but full corpus reports 0.0%: the cases
// were still attacks, and none of them were contained.
assert.match(window.renderGauntletScope(allNA).children[0].textContent,
  /Containment 0\.0% of 158 malicious cases in the full 213-case corpus; N\/A of 0 applicable malicious \(diagnostic/);

console.log('scope renderer tests: OK');
