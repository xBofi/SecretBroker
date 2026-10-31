// SecretBroker extension: background (service worker in Chromium, event page in Firefox).
//
// The only part that talks to SecretBroker, through native messaging (no network port): the browser starts the
// native host (secretbroker/native_host.py), which relays to the SecretBroker service. The service decides which
// logins belong to a page (registrable domain, never a lookalike) and only answers a browser the user connected.
// Values are asked for one at a time, after a click or the keyboard shortcut, and go only to the frame that asked.

const ext = globalThis.browser || globalThis.chrome;
// chrome.i18n with named values, in the order the message declares them (_locales/*/messages.json).
const msg = (key, values = {}) => ext.i18n.getMessage(key, Object.values(values).map(String)) || key;
const HOST = 'com.secretbroker.autofill';
const REPLY_TIMEOUT = 35000;
const OFFER_MINUTES = 5;
const USERNAME_MINUTES = 5;

// ----------------------------------------------------------------------------------------- native messaging

let port = null;
let nextId = 1;
const waiting = new Map();

function connect() {
  port = ext.runtime.connectNative(HOST);
  port.onMessage.addListener((message) => {
    const pending = waiting.get(message.id);
    if (!pending) return;
    waiting.delete(message.id);
    clearTimeout(pending.timer);
    pending.resolve(message);
  });
  port.onDisconnect.addListener((p) => {
    const error = (p && p.error && p.error.message) || (ext.runtime.lastError && ext.runtime.lastError.message) || '';
    port = null;
    for (const [id, pending] of waiting) {
      clearTimeout(pending.timer);
      pending.resolve({ id, ok: false, code: 'no_host', error: hostError(error) });
    }
    waiting.clear();
  });
}

function hostError(error) {
  return /not found|no such native|specified native messaging host/i.test(error)
    ? msg('secretbroker_isn_installed_on_this')
    : msg('can_talk_secretbroker_open_it');
}

async function pairing() {
  const stored = await ext.storage.local.get('pair');
  if (stored.pair && stored.pair.id && stored.pair.key) return stored.pair;
  const random = (n) => {
    const bytes = crypto.getRandomValues(new Uint8Array(n));
    return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  };
  const pair = { id: random(18), key: random(32) };
  await ext.storage.local.set({ pair });
  return pair;
}

function browserName() {
  const brands = (navigator.userAgentData && navigator.userAgentData.brands || []).map((b) => b.brand);
  if (navigator.brave) return 'Brave';
  if (brands.some((b) => /Edge/i.test(b)) || /Edg\//.test(navigator.userAgent)) return 'Edge';
  if (/Firefox\//.test(navigator.userAgent)) return 'Firefox';
  if (brands.some((b) => /Opera/i.test(b))) return 'Opera';
  if (brands.some((b) => /Chrome/i.test(b))) return 'Chrome';
  return msg('browser');
}

async function native(op, params = {}) {
  const pair = await pairing();
  try {
    if (!port) connect();
  } catch (error) {
    return { ok: false, code: 'no_host', error: hostError(String(error)) };
  }
  const id = nextId++;
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      waiting.delete(id);
      resolve({ id, ok: false, code: 'timeout', error: msg('secretbroker_didn_answer_in_time') });
    }, REPLY_TIMEOUT);
    waiting.set(id, { resolve, timer });
    try {
      port.postMessage({ id, op, params, pair, browser: browserName() });
    } catch (error) {
      waiting.delete(id);
      clearTimeout(timer);
      port = null;
      resolve({ id, ok: false, code: 'no_host', error: hostError(String(error)) });
    }
  });
}

// ----------------------------------------------------------------------------------------- per tab state
// Kept in session storage (memory only, gone when the browser closes), so it survives the worker restarting.

async function tabState(tabId) {
  const key = `tab:${tabId}`;
  return (await ext.storage.session.get(key))[key] || { frames: {} };
}

async function setTabState(tabId, data) {
  await ext.storage.session.set({ [`tab:${tabId}`]: data });
}

ext.tabs.onRemoved.addListener((tabId) => ext.storage.session.remove(`tab:${tabId}`));

async function offerFor(tabId) {
  const data = await tabState(tabId);
  const offer = data.offer;
  if (!offer || offer.expires < Date.now()) return null;
  return offer;
}

function publicOffer(offer) {
  return offer && { id: offer.id, action: offer.plan.action, name: offer.plan.name, username: offer.username, host: offer.host };
}

// ----------------------------------------------------------------------------------------- pages and frames

async function activeTab() {
  const [tab] = await ext.tabs.query({ active: true, currentWindow: true });
  return tab;
}

function isWebPage(url) {
  return /^https?:\/\//i.test(url || '');
}

// The frame of a tab where the login form is: the page itself if it has one, else a frame that reported fields.
async function loginFrame(tab) {
  const frames = (await tabState(tab.id)).frames || {};
  const withFields = Object.entries(frames).filter(([, f]) => f.fields).map(([id, f]) => ({ frameId: Number(id), url: f.url }));
  return withFields.find((f) => f.frameId === 0) || withFields[0] || { frameId: 0, url: tab.url };
}

async function logins(tab, frame) {
  const params = { url: tab.url };
  if (frame && frame.frameId !== 0) params.frame_url = frame.url;
  return native('logins', params);
}

// Ask for one login's values and hand them to the frame that will be filled. Only after a user gesture:
// a click in the popup or in our menu (checked as a trusted event in the page), or the keyboard shortcut.
async function fill(tab, frame, id, what) {
  if (frame.frameId !== 0) {
    const visible = await ext.tabs.sendMessage(tab.id, { type: 'frame_visible', url: frame.url }, { frameId: 0 }).catch(() => false);
    if (!visible) return { ok: false, code: 'hidden', error: msg('form_is_in_hidden_or') };
  }
  const params = { url: tab.url, id, what };
  if (frame.frameId !== 0) params.frame_url = frame.url;
  const answer = await native('fill', params);
  if (!answer.ok) return answer;
  // The service checked the address it was given; the frame gets the values only if it still shows that origin
  // (it may have navigated elsewhere since it reported its form, or while the service answered).
  const origin = new URL(frame.frameId !== 0 ? frame.url : tab.url).origin;
  const applied = await ext.tabs.sendMessage(tab.id, { type: 'apply', what, values: answer.result, origin }, { frameId: frame.frameId })
    .catch(() => ({ ok: false, error: msg('page_has_changed_try_again') }));
  return applied && applied.ok ? { ok: true } : { ok: false, code: 'not_filled', error: (applied && applied.error) || msg('couldn_find_where_fill_it') };
}

async function fillFromShortcut() {
  const tab = await activeTab();
  if (!tab || !isWebPage(tab.url)) return;
  const frame = await loginFrame(tab);
  const answer = await logins(tab, frame);
  const say = (text) => ext.tabs.sendMessage(tab.id, { type: 'toast', text }, { frameId: 0 }).catch(() => {});
  if (!answer.ok) { say(answer.code === 'locked' ? msg('secretbroker_is_locked_unlock_it') : answer.error); return; }
  const usable = answer.result.logins.filter((l) => l.can_fill);
  if (!usable.length) {
    say(answer.result.logins.length ? msg('this_team_credential_is_use')
      : msg('there_are_no_saved_logins', { domain: answer.result.domain }));
    return;
  }
  const result = await fill(tab, frame, usable[0].id, 'login');
  if (!result.ok) say(result.error);
}

ext.commands.onCommand.addListener((command) => {
  if (command === 'fill-login') fillFromShortcut();
});

// ----------------------------------------------------------------------------------------- saving logins

async function submitted(tab, sender, data) {
  const state = await tabState(tab.id);
  let username = String(data.username || '').trim();
  const host = new URL(sender.url).host;
  if (!data.password) {
    // The first step of a two-step login (only the user name): remember it for the password step.
    if (username) { state.username = { value: username, host, at: Date.now() }; await setTabState(tab.id, state); }
    return;
  }
  if (!username && state.username && state.username.at > Date.now() - USERNAME_MINUTES * 60000) username = state.username.value;
  const params = { url: tab.url, username, password: data.password };
  if (sender.frameId !== 0) params.frame_url = sender.url;
  const answer = await native('save_check', params);
  if (!answer.ok || answer.result.action === 'none') return;
  state.offer = { id: crypto.randomUUID(), plan: answer.result, username, password: data.password, url: tab.url,
    frame_url: params.frame_url || null, host: answer.result.host, expires: Date.now() + OFFER_MINUTES * 60000 };
  await setTabState(tab.id, state);
  ext.tabs.sendMessage(tab.id, { type: 'offer', offer: publicOffer(state.offer) }, { frameId: 0 }).catch(() => {});
}

async function answerOffer(tabId, id, save, name) {
  const state = await tabState(tabId);
  const offer = state.offer;
  if (!offer || offer.id !== id || offer.expires < Date.now()) return { ok: false, error: msg('it_no_longer_pending') };
  delete state.offer;
  await setTabState(tabId, state);
  if (!save) return { ok: true, result: { saved: false } };
  const params = { url: offer.url, username: offer.username, password: offer.password };
  if (offer.frame_url) params.frame_url = offer.frame_url;
  if (name) params.name = name;
  return native('save', params);
}

// ----------------------------------------------------------------------------------------- messages

async function onMessage(message, sender) {
  const fromPage = !!sender.tab && isWebPage(sender.url);  // a content script; else the popup
  if (fromPage) {
    const tab = sender.tab;
    const frame = { frameId: sender.frameId || 0, url: sender.url };
    if (!isWebPage(tab.url)) return { ok: false };
    switch (message.type) {
      case 'fields': {
        const state = await tabState(tab.id);
        state.frames = state.frames || {};
        if (message.has) state.frames[frame.frameId] = { url: sender.url, fields: true };
        else delete state.frames[frame.frameId];
        await setTabState(tab.id, state);
        return { ok: true };
      }
      case 'logins': {
        const [hello, list] = await Promise.all([native('hello'), logins(tab, frame)]);
        return { hello, list };
      }
      case 'fill':
        if (!message.trusted) return { ok: false };
        return fill(tab, frame, message.id, message.what === 'totp' ? 'totp' : 'login');
      case 'submitted':
        submitted(tab, sender, message);
        return { ok: true };
      case 'offer?':
        return { offer: frame.frameId === 0 ? publicOffer(await offerFor(tab.id)) : null };
      case 'offer_answer':
        return answerOffer(tab.id, message.id, !!message.save);
      case 'open_app':
        return native('open_app');
      case 'toast_top':  // a message for the user from a frame: shown by the page itself
        ext.tabs.sendMessage(tab.id, { type: 'toast', text: String(message.text || '').slice(0, 200) }, { frameId: 0 }).catch(() => {});
        return { ok: true };
      default:
        return { ok: false };
    }
  }
  // The popup (an extension page).
  const tab = await activeTab();
  switch (message.type) {
    case 'state': {
      const hello = await native('hello');
      if (!hello.ok || !hello.result.paired || hello.result.state !== 'unlocked' || !tab || !isWebPage(tab.url)) {
        return { hello, page: tab && isWebPage(tab.url) ? { host: new URL(tab.url).host } : null };
      }
      const frame = await loginFrame(tab);
      const list = await logins(tab, frame);
      return { hello, list, offer: publicOffer(await offerFor(tab.id)) };
    }
    case 'pair':
      return native('pair', { name: browserName() });
    case 'open_app':
      return native('open_app');
    case 'fill':
      if (!tab || !isWebPage(tab.url)) return { ok: false, error: msg('open_website_you_want_sign') };
      return fill(tab, await loginFrame(tab), message.id, message.what === 'totp' ? 'totp' : 'login');
    case 'copy': {
      if (!tab || !isWebPage(tab.url)) return { ok: false };
      const frame = await loginFrame(tab);
      const params = { url: tab.url, id: message.id, what: message.what, copy: true };
      if (frame.frameId !== 0) params.frame_url = frame.url;
      return native('fill', params);
    }
    case 'search':
      return native('search', { query: message.query, url: tab && isWebPage(tab.url) ? tab.url : '' });
    case 'open_site':
      if (/^https?:\/\//i.test(message.url || '')) await ext.tabs.create({ url: message.url });
      return { ok: true };
    case 'offer_answer':
      return tab ? answerOffer(tab.id, message.id, !!message.save, message.name) : { ok: false };
    default:
      return { ok: false };
  }
}

ext.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (sender.id !== ext.runtime.id) return false;
  onMessage(message || {}, sender).then(sendResponse, (error) => sendResponse({ ok: false, error: String(error) }));
  return true;
});
