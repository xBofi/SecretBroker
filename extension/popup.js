// SecretBroker extension: popup. The logins saved for the current site (matched by SecretBroker, by registrable
// domain), to fill or copy; a search over the rest to open their site; connecting the browser; saving a login.

const ext = globalThis.browser || globalThis.chrome;
// chrome.i18n with named values, in the order the message declares them (_locales/*/messages.json).
const msg = (key, values = {}) => ext.i18n.getMessage(key, Object.values(values).map(String)) || key;
const main = document.getElementById('main');
document.documentElement.lang = ext.i18n.getUILanguage();
for (const node of document.querySelectorAll('[data-i18n-title]')) { node.title = msg(node.dataset.i18nTitle); node.setAttribute('aria-label', node.title); }
for (const node of document.querySelectorAll('[data-i18n-label]')) node.setAttribute('aria-label', msg(node.dataset.i18nLabel));
const ask = (message) => ext.runtime.sendMessage(message).catch((error) => ({ ok: false, error: String(error) }));

const ICONS = {
  globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3c2.5 2.5 3.8 5.5 3.8 9s-1.3 6.5-3.8 9c-2.5-2.5-3.8-5.5-3.8-9S9.5 5.5 12 3z"/>',
  lock: '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
  search: '<circle cx="11" cy="11" r="7"/><path d="m20 20-4-4"/>',
  user: '<circle cx="12" cy="8" r="3.8"/><path d="M4.5 20a7.5 7.5 0 0 1 15 0"/>',
  key: '<circle cx="7.5" cy="15.5" r="4"/><path d="m10.4 12.6 9.1-9.1"/><path d="m16 7 3 3"/><path d="m18.5 4.5 2 2"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  external: '<path d="M14 4h6v6"/><path d="M20 4 10 14"/><path d="M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5"/>',
  plug: '<path d="M9 2v6M15 2v6"/><path d="M6 8h12v3a6 6 0 0 1-12 0z"/><path d="M12 17v5"/>',
  alert: '<path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><path d="M12 9v4M12 17h.01"/>',
  check: '<path d="m5 12.5 4.5 4.5L19 7.5"/>',
};

function icon(name) {
  const node = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  node.setAttribute('viewBox', '0 0 24 24');
  node.setAttribute('aria-hidden', 'true');
  node.innerHTML = ICONS[name];  // static, trusted markup
  return node;
}

function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === 'class') node.className = v;
    else if (k.startsWith('on')) node.addEventListener(k.slice(2), v);
    else if (v !== null && v !== undefined && v !== false) node.setAttribute(k, v === true ? '' : v);
  }
  for (const child of children.flat()) if (child !== null && child !== undefined && child !== false) node.append(child);
  return node;
}

// The fill shortcut as the user has it (they can change it in the browser's shortcuts page).
let fillShortcut = '';
ext.commands.getAll().then((commands) => {
  const command = commands.find((c) => c.name === 'fill-login');
  fillShortcut = (command && command.shortcut) || '';
  const kbd = document.querySelector('.hint kbd');
  if (kbd) kbd.textContent = fillShortcut;
}).catch(() => {});

function shortcut() {
  return fillShortcut;
}

document.getElementById('open-app').addEventListener('click', () => { ask({ type: 'open_app' }); window.close(); });

function stateScreen(badge, title, text, ...actions) {
  main.replaceChildren(el('div', { class: 'state' }, el('div', { class: 'badge' }, icon(badge)), el('h1', {}, title),
    el('p', {}, text), ...actions));
}

function message(text, error = false) {
  main.querySelectorAll('.message').forEach((m) => m.remove());
  const node = el('div', { class: `message ${error ? 'error' : ''}`, role: 'status' }, text);
  main.append(node);
  setTimeout(() => node.remove(), 4000);
}

let pairTimer = null;

async function render() {
  const answer = await ask({ type: 'state' });
  const hello = answer && answer.hello;
  if (!hello || !hello.ok) {
    if (hello && hello.code === 'no_host') {
      stateScreen('plug', msg('secretbroker_is_missing_on_this'), hello.error,
        el('p', {}, msg('install_secretbroker_and_open_settings')));
    } else {
      stateScreen('alert', msg('can_talk_secretbroker_2'), (hello && hello.error) || msg('open_it_and_try_again'),
        el('button', { class: 'btn primary block', onclick: () => { ask({ type: 'open_app' }); window.close(); } }, msg('open_secretbroker')));
    }
    return;
  }
  const info = hello.result;
  if (info.state === 'no_vault') {
    stateScreen('key', msg('create_your_vault_first'), msg('open_secretbroker_and_create_your'),
      el('button', { class: 'btn primary block', onclick: () => { ask({ type: 'open_app' }); window.close(); } }, msg('open_secretbroker')));
    return;
  }
  if (!info.paired) { renderPairing(info); return; }
  clearTimeout(pairTimer);
  if (info.state !== 'unlocked') {
    stateScreen('lock', msg('secretbroker_is_locked_2'), msg('unlock_it_fill_in_your'),
      el('button', { class: 'btn primary block', onclick: () => { ask({ type: 'open_app' }); window.close(); } }, msg('unlock')));
    return;
  }
  renderLogins(answer);
}

function renderPairing(info) {
  if (info.pending) {
    stateScreen('plug', msg('confirm_it_in_secretbroker'), msg('check_that_secretbroker_shows_this'),
      el('div', { class: 'code', 'aria-label': msg('code') }, `${info.pending.code.slice(0, 3)} ${info.pending.code.slice(3)}`),
      el('button', { class: 'btn block', onclick: () => { ask({ type: 'open_app' }); } }, msg('open_secretbroker')));
    clearTimeout(pairTimer);
    pairTimer = setTimeout(render, 1500);  // until the user answers in the app
    return;
  }
  const connect = el('button', { class: 'btn primary block', onclick: async () => {
    connect.disabled = true;
    const result = await ask({ type: 'pair' });
    if (!result || !result.ok) {
      connect.disabled = false;
      message(result && result.code === 'locked' ? msg('unlock_secretbroker_and_click_connect') : (result && result.error) || msg('couldn_connect'), true);
      return;
    }
    ask({ type: 'open_app' });
    render();
  } }, msg('connect', { browser: info.browser }));
  stateScreen('plug', msg('connect_this_browser'), msg('that_way_it_can_fill'), connect);
}

function siteLine(list, fallbackHost) {
  const result = list && list.ok ? list.result : null;
  const host = result ? result.domain : fallbackHost;
  if (!host) return null;
  return el('div', { class: 'site' }, icon(result && !result.secure ? 'alert' : 'globe'),
    el('span', {}, result && result.frame ? msg('form_from') : msg('you_re_on')), el('span', { class: 'domain', title: result ? result.host : host }, host),
    result && !result.secure ? el('span', { class: 'insecure' }, msg('no_https')) : null);
}

function offerBox(offer) {
  if (!offer) return null;
  const update = offer.action === 'update';
  const name = el('input', { class: 'search', style: 'padding-left:10px;margin-bottom:8px', value: offer.name, 'aria-label': msg('name') });
  const save = el('button', { class: 'btn primary', onclick: async () => {
    save.disabled = true;
    const result = await ask({ type: 'offer_answer', id: offer.id, save: true, name: update ? undefined : name.value.trim() || offer.name });
    if (result && result.ok) { message(update ? msg('password_updated') : msg('saved')); render(); } else { save.disabled = false; message((result && result.error) || msg('couldn_save'), true); }
  } }, update ? msg('update') : msg('save'));
  return el('div', { class: 'offer' },
    el('b', {}, update ? msg('update_password', { name: offer.name }) : msg('save_this_login')),
    el('p', {}, `${offer.username} · ${offer.host}`),
    update ? null : name,
    el('div', { class: 'buttons' }, el('button', { class: 'btn', onclick: async () => { await ask({ type: 'offer_answer', id: offer.id, save: false }); render(); } }, msg('not_now')), save));
}

async function copy(login, what) {
  const result = await ask({ type: 'copy', id: login.id, what });
  if (!result || !result.ok) { message((result && result.error) || msg('couldn_copy'), true); return; }
  const value = what === 'totp' ? result.result.totp : what === 'username' ? result.result.username : result.result.password;
  await navigator.clipboard.writeText(value || '');
  message({ username: msg('username_copied'), password: msg('password_copied'), totp: msg('2fa_code_copied') }[what]);
}

function loginRow(login) {
  const fill = el('button', { class: 'btn primary', disabled: !login.can_fill, onclick: async () => {
    fill.disabled = true;
    const result = await ask({ type: 'fill', id: login.id });
    if (result && result.ok) window.close();
    else { fill.disabled = false; message((result && result.error) || msg('couldn_fill_it_in'), true); }
  } }, msg('fill_in'));
  const actions = login.can_fill ? [
    el('button', { class: 'icon-btn', title: msg('copy_username'), 'aria-label': msg('copy_username'), onclick: () => copy(login, 'username') }, icon('user')),
    el('button', { class: 'icon-btn', title: msg('copy_password'), 'aria-label': msg('copy_password'), onclick: () => copy(login, 'password') }, icon('key')),
    login.totp ? el('button', { class: 'icon-btn', title: msg('copy_2fa_code'), 'aria-label': msg('copy_2fa_code'), onclick: () => copy(login, 'totp') }, icon('clock')) : null,
    fill] : [];
  return el('div', { class: 'row', title: login.can_fill ? msg('saved_for', { site: login.site }) : '' },
    el('div', { class: 'avatar' }, (login.name.trim().charAt(0) || '?').toUpperCase()),
    el('div', { class: 'who' }, el('div', { class: 'name' }, login.name),
      login.can_fill
        ? el('div', { class: 'user' }, login.username || msg('no_username'), login.collection ? ` · ${login.collection}` : '')
        : el('div', { class: 'user locked', title: msg('use_only_team_credentials_can') },
          msg('use_only_on_team_not'))),
    el('div', { class: 'actions' }, actions));
}

function renderLogins(answer) {
  const list = answer.list;
  const page = list && list.ok ? list.result : null;
  const search = el('input', { class: 'search', type: 'search', placeholder: msg('search_secretbroker'), 'aria-label': msg('search') });
  const results = el('div', {});
  const matches = el('div', {});
  if (!page) {
    matches.append(el('div', { class: 'empty' }, list && list.code === 'frame' ? list.error
      : answer.page ? (list && list.error) || msg('this_page_can_be_filled') : msg('open_website_see_its_passwords')));
  } else if (!page.logins.length) {
    matches.append(el('div', { class: 'empty' }, msg('nothing_saved_for_sign_in', { domain: page.domain })));
  } else {
    matches.append(el('div', { class: 'list' }, page.logins.map(loginRow)));
  }
  let timer = null;
  search.addEventListener('input', () => {
    clearTimeout(timer);
    timer = setTimeout(async () => {
      const query = search.value.trim();
      if (!query) { results.replaceChildren(); matches.hidden = false; return; }
      const found = await ask({ type: 'search', query });
      const local = page ? page.logins.filter((l) => `${l.name} ${l.username}`.toLowerCase().includes(query.toLowerCase())) : [];
      const elsewhere = found && found.ok ? found.result.results.filter((r) => !local.some((l) => l.id === r.id)) : [];
      matches.hidden = true;
      results.replaceChildren(...[
        local.length ? el('div', { class: 'section' }, msg('on_this_website')) : null,
        local.length ? el('div', { class: 'list' }, local.map(loginRow)) : null,
        elsewhere.length ? el('div', { class: 'section' }, msg('on_other_websites')) : null,
        elsewhere.length ? el('div', { class: 'list' }, elsewhere.map((r) => el('div', { class: 'row' },
          el('div', { class: 'avatar' }, (r.name.trim().charAt(0) || '?').toUpperCase()),
          el('div', { class: 'who' }, el('div', { class: 'name' }, r.name), el('div', { class: 'user' }, `${r.username || msg('no_username')} · ${r.host}`)),
          el('div', { class: 'actions' }, el('button', { class: 'icon-btn', title: msg('open_it_can_be_filled', { host: r.host }), 'aria-label': msg('open', { host: r.host }),
            onclick: () => { ask({ type: 'open_site', url: r.url }); window.close(); } }, icon('external'))))))
          : null,
        !local.length && !elsewhere.length ? el('div', { class: 'empty' }, msg('nothing_matches')) : null].filter(Boolean));
    }, 150);
  });
  main.replaceChildren(...[
    offerBox(answer.offer),
    siteLine(list, answer.page && answer.page.host),
    el('div', { class: 'search-wrap' }, icon('search'), search),
    matches, results,
    el('div', { class: 'hint' }, el('span', {}, msg('it_only_fills_in_on')),
      el('span', { title: msg('fill_in_without_opening_this') }, el('kbd', {}, shortcut() || 'Ctrl+Shift+L')))].filter(Boolean));
  search.focus();
}

render();
