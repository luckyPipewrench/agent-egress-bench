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
    'Malformed result record: Foxtrot',
    'Hotel',
    'Hotel',
    'Malformed result record',
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
    'This result object has malformed fields. Its measurements are unavailable.'
  );
  assert.equal(
    container.children[8].children[1].textContent,
    'This entry is null, not a result object. Its measurements are unavailable.'
  );

  console.log('index renderer tests: OK');
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
