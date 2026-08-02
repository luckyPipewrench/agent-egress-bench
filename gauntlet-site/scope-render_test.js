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
    case_count: {
      total: 197,
      applicable: 196,
      not_applicable: 1,
      not_applicable_reasons: { missing_requires: 1 },
    },
    scores: {
      applicable: { containment: 1, false_positive_rate: 0 },
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
assert.match(rendered.children[0].textContent, /Containment 100\.0% on 196 applicable of 197 total cases/);
assert.equal(rendered.children[3].href, completeArtifact().canonical_url);

expectReject((artifact) => { artifact.scores.applicable.containment = '100%'; }, 'non-numeric containment');
expectReject((artifact) => { artifact.scores.applicable.false_positive_rate = 1.1; }, 'out-of-range FP rate');
expectReject((artifact) => { artifact.case_count.total = 0; }, 'zero total');
expectReject((artifact) => { artifact.case_count.total = -1; }, 'negative total');
expectReject((artifact) => { artifact.case_count.applicable = 198; }, 'applicable exceeds total');
expectReject((artifact) => { artifact.case_count.not_applicable = 0; }, 'counts do not sum to total');
expectReject((artifact) => { artifact.case_count.not_applicable_reasons = { missing_requires: 0 }; }, 'N/A reasons do not sum');
expectReject((artifact) => { artifact.canonical_url = 'javascript:alert(1)'; }, 'unsafe canonical URL');
expectReject((artifact) => {
  artifact.case_count.applicable = 0;
  artifact.case_count.not_applicable = 197;
  artifact.case_count.not_applicable_reasons = { missing_requires: 197 };
}, 'all-N/A runs cannot have a numeric containment score');

const allNA = completeArtifact();
allNA.case_count.applicable = 0;
allNA.case_count.not_applicable = 197;
allNA.case_count.not_applicable_reasons = { missing_requires: 197 };
allNA.scores.applicable.containment = null;
assert.match(window.renderGauntletScope(allNA).children[0].textContent, /Containment N\/A on 0 applicable/);

console.log('scope renderer tests: OK');
