// The first frame must use this window's preferences, including after a reload or a fresh launch.
// Run with: node tests/test_appearance.js (no browser or user's vault involved).
'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const source = fs.readFileSync(path.join(__dirname, '../secretbroker/web/appearance.js'), 'utf8');
const appSource = fs.readFileSync(path.join(__dirname, '../secretbroker/web/app.js'), 'utf8');

function storage(values = {}) {
  return {
    getItem(key) { return values[key] || null; },
    setItem(key, value) { values[key] = value; },
  };
}

function start(hash, session = storage(), local = storage()) {
  const root = { dataset: {}, style: { setProperty() {}, removeProperty() {} } };
  const context = vm.createContext({
    window: { location: { hash }, addEventListener() {}, matchMedia() { return { matches: false, addEventListener() {} }; } },
    document: { documentElement: root }, sessionStorage: session, localStorage: local, URLSearchParams,
  });
  vm.runInContext(source, context);
  return { context, look: root.dataset };
}

test('a fresh launch uses saved preferences even when an older window left a stale persistent mirror', () => {
  const stale = storage({ appearance: JSON.stringify({ theme: 'light', palette: 'cobalto' }) });
  const { look } = start('#theme=dark&palette=custom&accent=%23ffc53d&text_size=xlarge&density=compact&reduce_motion=1', storage(), stale);
  assert.deepEqual(look, { theme: 'dark', scheme: 'dark', palette: 'custom', textSize: 'xlarge', density: 'compact', motion: 'reduce' });
});

test('a page reload keeps choices made since launch even though its original fragment is older', () => {
  const session = storage();
  const persistent = storage();
  const first = start('#theme=light&palette=cobalto', session, persistent);
  vm.runInContext("applyAppearance({ theme: 'dark', palette: 'oliva', text_size: 'large' })", first.context);
  const { look } = start('#theme=light&palette=cobalto', session, persistent);
  assert.equal(look.scheme, 'dark');
  assert.equal(look.palette, 'oliva');
  assert.equal(look.textSize, 'large');
});

test('a new window follows newly saved preferences rather than the previous window\'s preview', () => {
  const persistent = storage();
  const first = start('#theme=light', storage(), persistent);
  vm.runInContext("applyAppearance({ theme: 'dark' })", first.context);
  const { look } = start('#theme=light&palette=salvia', storage(), persistent);
  assert.equal(look.scheme, 'light');
  assert.equal(look.palette, 'salvia');
});

function settings(bridge) {
  const page = start('');
  Object.assign(page.context, { Element: function () {}, localized() { return {}; } });
  vm.runInContext(appSource, page.context);
  page.context.window.pywebview = { api: { set_pref: bridge } };
  page.context.messages = [];
  vm.runInContext("state.info = { prefs: {} }; toast = (message, kind) => messages.push([message, kind]);", page.context);
  return page;
}

test('a slow earlier save cannot overwrite a later choice, which is previewed immediately', async () => {
  let release;
  const delayed = new Promise((resolve) => { release = resolve; });
  const saved = {};
  let calls = 0;
  const page = settings(async (key, value) => {
    if (++calls === 1) await delayed;
    saved[key] = value;
    return true;
  });
  const first = vm.runInContext("setAppearance('theme', 'light')", page.context);
  const last = vm.runInContext("setAppearance('theme', 'dark')", page.context);
  assert.equal(page.look.scheme, 'dark');
  await new Promise(setImmediate);
  release();
  await Promise.all([first, last]);
  assert.equal(saved.theme, 'dark');
});

test('a failed save is shown as an error and does not stop later choices being saved', async () => {
  let calls = 0;
  const saved = {};
  const page = settings(async (key, value) => {
    if (++calls === 1) throw new Error('Disk unavailable');
    saved[key] = value;
    return true;
  });
  const first = vm.runInContext("setAppearance('theme', 'light')", page.context);
  const last = vm.runInContext("setAppearance('theme', 'dark')", page.context);
  assert.equal(await first, false);
  assert.equal(await last, true);
  assert.equal(saved.theme, 'dark');
  assert.equal(page.context.messages.length, 1);
  assert.equal(page.context.messages[0][0], 'Disk unavailable');
  assert.equal(page.context.messages[0][1], 'error');
});
