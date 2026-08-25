'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const vm = require('node:vm');

const siteRoot = __dirname;
const indexPath = path.join(siteRoot, 'index.html');
const fixturePath = path.join(siteRoot, 'testdata', 'legacy-multi-result-order.fixture');

function element(tagName) {
  return {
    tagName,
    attributes: {},
    children: [],
    className: '',
    textContent: '',
    appendChild(child) {
      this.children.push(child);
      return child;
    },
    removeChild(child) {
      const index = this.children.indexOf(child);
      if (index !== -1) this.children.splice(index, 1);
      return child;
    },
    get firstChild() {
      return this.children[0] || null;
    },
    setAttribute(name, value) {
      this.attributes[name] = value;
    },
    addEventListener() {},
    classList: {
      contains() {
        return false;
      },
      toggle() {},
    },
  };
}

function title(card) {
  return card.children[0].children[0].textContent;
}

function scoreValues(node, values = []) {
  if (node.className && node.className.split(' ').includes('score-value')) values.push(node);
  node.children.forEach((child) => scoreValues(child, values));
  return values;
}

async function settle() {
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));
}

// Runs the page's inline renderer against one legacy payload and returns the
// container it rendered into. Extracted so a scenario other than the primary
// fixture can be exercised for real rather than reasoned about.
async function renderLegacyPayload(inlineSource, payload) {
  const container = element('div');
  const attributes = {
    'data-latest-url': './latest-verified.json',
    'data-results-url': './gauntlet-results.json',
    'data-corpus-version': 'v2.4.0',
    'data-scoring-version': '2.8',
  };
  global.document = {
    body: { getAttribute(name) { return attributes[name] || null; } },
    createElement: element,
    getElementById(id) { return id === 'results' ? container : null; },
  };
  global.window = {
    crypto: {},
    fetch: async () => ({ ok: true, json: async () => payload }),
    loadLatestVerifiedResult: async () => {
      const error = new Error('pointer unavailable');
      error.status = 404;
      error.resource = 'pointer';
      throw error;
    },
  };
  global.fetch = window.fetch;
  vm.runInThisContext(inlineSource, { filename: indexPath });
  await settle();
  return container;
}

(async () => {
  const html = await fs.readFile(indexPath, 'utf8');
  const fixture = JSON.parse(await fs.readFile(fixturePath, 'utf8'));
  const inline = html.match(/<script>\n([\s\S]*?)<\/script>/);
  assert.ok(inline, 'index.html must retain an inline result renderer');
  assert.match(
    html,
    /Results are listed alphabetically by tool name; entries without a usable name are listed as unknown\. This order is not a ranking\./
  );
  assert.doesNotMatch(html, /return \(f && f\.containment\) \|\| 0;/);

  const container = element('div');
  const attributes = {
    'data-latest-url': './latest-verified.json',
    'data-results-url': './gauntlet-results.json',
    'data-corpus-version': 'v2.4.0',
    'data-scoring-version': '2.8',
  };
  global.document = {
    body: { getAttribute(name) { return attributes[name] || null; } },
    createElement: element,
    getElementById(id) { return id === 'results' ? container : null; },
  };
  global.window = {
    crypto: {},
    fetch: async () => ({
      ok: true,
      json: async () => fixture,
    }),
    loadLatestVerifiedResult: async () => {
      const error = new Error('pointer unavailable');
      error.status = 404;
      error.resource = 'pointer';
      throw error;
    },
  };
  global.fetch = window.fetch;

  vm.runInThisContext(inline[1], { filename: indexPath });
  await settle();

  assert.deepEqual(container.children.map(title), [
    'Alpha',
    'Bravo',
    'Charlie',
    'Delta',
    'Echo',
    'Result unavailable: Foxtrot',
    'Hotel',
    'Hotel',
    'Not a result record',
    'Zulu',
  ]);
  const hotels = container.children.filter((card) => title(card) === 'Hotel');
  assert.deepEqual(
    hotels.map((card) => card.children[0].children[1].children[0].textContent),
    ['first', 'second'],
    'equal tool names must retain their source order instead of falling back to scores'
  );
  assert.equal(scoreValues(container.children[0])[0].textContent, '0.0%');
  ['Bravo', 'Charlie', 'Delta', 'Echo'].forEach((tool) => {
    const card = container.children.find((candidate) => title(candidate) === tool);
    const containment = scoreValues(card)[0];
    assert.equal(containment.textContent, 'N/A', tool + ' containment must render as absent');
    assert.match(containment.className, /score-na/, tool + ' containment must retain its N/A style');
  });
  assert.equal(
    container.children[5].children[1].textContent,
    'This result could not be displayed. The cause is not established here, so no claim is made about the record itself. Its measurements are unavailable.'
  );
  assert.equal(
    container.children[8].children[1].textContent,
    'This entry is null, not a result object. Its measurements are unavailable.'
  );

  // A falsy JSON payload is a value, not an absence, and must reach a card.
  // Note what this covers: loadLegacyResult wraps any non-array payload, so
  // these assertions exercise that wrap plus renderResult. render()'s own
  // non-array branch is unreachable from both call sites and is defensive
  // hardening that no test here proves.
  for (const payload of [false, 0, '']) {
    const rendered = await renderLegacyPayload(inline[1], payload);
    assert.equal(
      rendered.children.length,
      1,
      `a payload of ${JSON.stringify(payload)} must render one card, not an empty page`
    );
    assert.equal(title(rendered.children[0]), 'Not a result record');
    assert.doesNotMatch(
      rendered.children[0].children[1].textContent,
      /No results yet/,
      'a malformed payload must not read as an absence of results'
    );
  }

  // A published null body is itself a malformed record rather than an absence:
  // loadLegacyResult wraps any non-array payload, so it reaches the renderer as
  // a one-entry list. Only an empty array means nothing has been published.
  for (const payload of [null, undefined]) {
    const rendered = await renderLegacyPayload(inline[1], payload);
    assert.equal(rendered.children.length, 1);
    assert.equal(title(rendered.children[0]), 'Not a result record');
  }
  const emptyList = await renderLegacyPayload(inline[1], []);
  assert.equal(emptyList.children.length, 1);
  assert.match(emptyList.children[0].textContent, /No results yet/);

  // A v7 candidate retains v5/v6's diagnostic semantics. Treating the new
  // candidate schema as a frozen record makes a measured result look incomplete
  // and looks for retired detection/evidence fields that v7 does not carry.
  const v7 = await renderLegacyPayload(inline[1], [{
    tool: 'V7 diagnostics', tool_version: '1.0.0', schema_version: 7,
    measurement_status: 'measured', corpus_version: 'v2.4.0', scoring_version: '2.8',
    case_count: { total: 2, applicable: 2, unreachable: 0, not_applicable: 0, errors: 0 },
    scores: {
      full: { containment: 1, false_positive_rate: 0 },
      applicable: { containment: 1, false_positive_rate: 0 },
    },
    diagnostics: {
      full: { classification_present_rate: 1, structured_evidence_present_rate: 1 },
      applicable: { classification_present_rate: 1, structured_evidence_present_rate: 1 },
    },
    per_category: {
      test: {
        applicable: 2, containment: 1, false_positive_rate: 0,
        diagnostics: { classification_present_rate: 1, structured_evidence_present_rate: 1 },
      },
    },
  }]);
  const v7Text = JSON.stringify(v7.children[0]);
  assert.match(v7Text, /badge-measured/, 'v7 must retain the active measurement status');
  assert.doesNotMatch(v7Text, /badge-incomplete/, 'v7 must not fall through to legacy sufficient');
  assert.match(v7Text, /Label present \(diagnostic\)/, 'v7 score diagnostics must render');
  assert.match(v7Text, /Label present\*/, 'v7 category diagnostics must render');
  assert.doesNotMatch(v7Text, /Detect\./, 'v7 must not render retired category labels');

  // A fractional case count is not a smaller count, it is a broken artifact.
  const fractional = await renderLegacyPayload(inline[1], [{
    tool: 'Fractional', tool_version: '1.0.0', sufficient: true,
    corpus_version: 'v2.4.0', scoring_version: '2.8',
    case_count: { total: 1.5, applicable: 1.5, not_applicable: 0, errors: 0 },
    scores: { full: { containment: 1, false_positive_rate: 0 } },
  }]);
  const fractionalText = JSON.stringify(fractional.children[0]);
  assert.doesNotMatch(fractionalText, /1\.5/, 'a fractional case count must not render as a total');
  assert.match(fractionalText, /unknown/, 'a fractional case count must render as unknown');

  const reconstructing = await renderLegacyPayload(inline[1], [{
    tool: 'Counted', tool_version: '1.0.0', sufficient: true,
    corpus_version: 'v2.4.0', scoring_version: '2.8',
    case_count: { total: 242, applicable: 242, not_applicable: 0, errors: 0 },
    scores: {
      full: { containment: 0.9886363636363636, false_positive_rate: 0 },
      applicable: { containment: 0.9886363636363636, false_positive_rate: 0 },
    },
    metric_counts: {
      full: {
        containment: { numerator: 174, denominator: 176 },
        false_positive_rate: { numerator: 0, denominator: 66 },
      },
      applicable: {
        containment: { numerator: 174, denominator: 176 },
        false_positive_rate: { numerator: 0, denominator: 66 },
      },
    },
  }]);
  const counted = reconstructing.children[0];
  assert.equal(scoreValues(counted)[0].textContent, '98.9%');
  assert.match(JSON.stringify(counted), /174\/176 malicious cases/);
  assert.match(JSON.stringify(counted), /0\/66 benign cases/);

  const mismatched = await renderLegacyPayload(inline[1], [{
    tool: 'Mismatched', tool_version: '1.0.0', sufficient: true,
    corpus_version: 'v2.4.0', scoring_version: '2.8',
    case_count: { total: 242, applicable: 242, not_applicable: 0, errors: 0 },
    scores: {
      full: { containment: 0.9886363636363636, false_positive_rate: 0 },
      applicable: { containment: 0.9886363636363636, false_positive_rate: 0 },
    },
    metric_counts: {
      full: {
        containment: { numerator: 1, denominator: 2 },
        false_positive_rate: { numerator: 0, denominator: 66 },
      },
    },
  }]);
  const mismatchedText = JSON.stringify(mismatched.children[0]);
  assert.doesNotMatch(mismatchedText, /1\/2/, 'a fraction that does not reconstruct the percent must stay unpublished');
  assert.match(mismatchedText, /0\/66 benign cases/, 'a reconstructing neighbour must keep its fraction');
  assert.equal(scoreValues(mismatched.children[0])[0].textContent, '98.9%');

  console.log('index renderer tests: OK');
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
