// SecretBroker extension: content script (every http/https page and frame).
//
// Finds login, and 2FA code fields, shows a small SecretBroker button in them while they have the focus, and a
// menu with the logins saved for this site when it is clicked. Nothing is ever filled on page load: only after a
// trusted click (pages cannot fake one) or the keyboard shortcut, and only into fields the user can see. After a
// login form is sent it offers to save it; nothing is stored until the user clicks «Guardar».
// Everything it draws lives in a closed shadow root, out of reach of the page's scripts and styles.

(() => {
  if (window.__secretBrokerLoaded) return;
  window.__secretBrokerLoaded = true;
  const ext = globalThis.browser || globalThis.chrome;
  // chrome.i18n with named values, in the order the message declares them (_locales/*/messages.json).
  const msg = (key, values = {}) => ext.i18n.getMessage(key, Object.values(values).map(String)) || key;
  const send = (message) => ext.runtime.sendMessage(message).catch(() => null);

  // --------------------------------------------------------------------------------------- field detection

  const TEXTISH = new Set(['text', 'email', 'tel', '']);
  const USER_HINT = /user|e-?mail|login|account|identifier|usuario|correo|cuenta|benutzer|utilisateur|nom.?d.?utilisateur/i;
  const OTP_HINT = /one.?time|otp|totp|2fa|mfa|two.?factor|verification.?code|security.?code|auth.?code|authenticator|c[oó]digo|token/i;
  const SKIP_HINT = /search|buscar|captcha|coupon|promo|zip|postal/i;

  function hints(input) {
    return [input.name, input.id, input.placeholder, input.getAttribute('aria-label'), input.autocomplete,
      input.labels && [...input.labels].map((l) => l.textContent).join(' ')].filter(Boolean).join(' ');
  }

  function visible(element) {
    if (!element || !element.isConnected) return false;
    const rect = element.getBoundingClientRect();
    if (rect.width < 4 || rect.height < 4) return false;
    for (let node = element; node && node.nodeType === 1; node = node.parentElement) {
      const style = getComputedStyle(node);
      if (style.display === 'none' || style.visibility === 'hidden' || style.visibility === 'collapse') return false;
      if (Number(style.opacity) < 0.1) return false;
    }
    return true;
  }

  // A frame too small to see (or a tracking pixel) is never filled.
  function frameUsable() {
    return window.innerWidth >= 60 && window.innerHeight >= 30;
  }

  function fillable(input) {
    return input instanceof HTMLInputElement && !input.disabled && !input.readOnly && visible(input);
  }

  function isPassword(input) {
    return input instanceof HTMLInputElement && (input.type === 'password' || input.dataset.sbWasPassword === '1');
  }

  function isOtp(input) {
    if (!(input instanceof HTMLInputElement) || isPassword(input)) return false;
    if (input.autocomplete === 'one-time-code') return true;
    if (!TEXTISH.has(input.type) && input.type !== 'number') return false;
    const text = hints(input);
    if (!OTP_HINT.test(text) || SKIP_HINT.test(text)) return false;
    const max = Number(input.maxLength);
    return max <= 0 || max <= 10;
  }

  function isUsername(input) {
    if (!(input instanceof HTMLInputElement) || !TEXTISH.has(input.type) || isOtp(input)) return false;
    if (input.autocomplete === 'username' || input.type === 'email') return true;
    const text = hints(input);
    return USER_HINT.test(text) && !SKIP_HINT.test(text);
  }

  function scopeOf(input) {
    return input.form || input.closest('[role=form], form, main, section, div[class*=login i], div[class*=signin i]') || document;
  }

  function inputsIn(scope) {
    return [...scope.querySelectorAll('input')].filter(fillable);
  }

  // The user name field that goes with a password field: the closest text input before it.
  function usernameFor(password) {
    const fields = inputsIn(scopeOf(password));
    const index = fields.indexOf(password);
    for (let i = index - 1; i >= 0; i--) {
      if (isPassword(fields[i])) continue;
      if (TEXTISH.has(fields[i].type) && !isOtp(fields[i])) return fields[i];
    }
    return fields.find(isUsername) || null;
  }

  // What a focused field belongs to: {kind: login | totp, username, password, otp: [inputs]}.
  function groupOf(input) {
    if (isOtp(input)) {
      const scope = scopeOf(input);
      const boxes = inputsIn(scope).filter((i) => isOtp(i) || (Number(i.maxLength) === 1 && TEXTISH.has(i.type)));
      return { kind: 'totp', otp: boxes.length >= 4 && boxes.length <= 8 && boxes.every((b) => Number(b.maxLength) === 1) ? boxes : [input] };
    }
    if (isPassword(input)) {
      const passwords = inputsIn(scopeOf(input)).filter(isPassword);
      // A form to change the password (2-3 password fields): only the current one is filled, if it is marked.
      const current = passwords.length > 1 ? passwords.find((p) => p.autocomplete === 'current-password') || input : input;
      return { kind: 'login', username: usernameFor(current), password: current };
    }
    if (isUsername(input) || TEXTISH.has(input.type)) {
      const password = inputsIn(scopeOf(input)).find(isPassword) || null;
      if (password || isUsername(input)) return { kind: 'login', username: input, password };
    }
    return null;
  }

  function relevant(input) {
    return input instanceof HTMLInputElement && fillable(input) && (isPassword(input) || isOtp(input)
      || (isUsername(input) && (inputsIn(scopeOf(input)).some(isPassword) || input.autocomplete === 'username' || input.type === 'email' || USER_HINT.test(hints(input)))));
  }

  // Tell the background whether this frame has a login form (so the popup and the shortcut know where to fill).
  let reported = null;
  function scan() {
    const has = frameUsable() && [...document.querySelectorAll('input')].some((i) => fillable(i) && (isPassword(i) || isOtp(i) || isUsername(i)));
    if (has !== reported) {
      reported = has;
      send({ type: 'fields', has });
    }
  }
  let scanTimer = null;
  new MutationObserver(() => {
    clearTimeout(scanTimer);
    scanTimer = setTimeout(scan, 400);
  }).observe(document.documentElement, { childList: true, subtree: true, attributes: true, attributeFilter: ['type', 'style', 'class', 'hidden'] });
  scan();

  // --------------------------------------------------------------------------------------- filling

  const valueSetter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;

  function type(input, value) {
    input.focus({ preventScroll: true });
    valueSetter.call(input, value);
    input.dispatchEvent(new Event('input', { bubbles: true, composed: true }));
    input.dispatchEvent(new Event('change', { bubbles: true }));
  }

  function target() {
    const active = document.activeElement;
    if (active instanceof HTMLInputElement && relevant(active)) return active;
    if (lastField && lastField.isConnected && fillable(lastField)) return lastField;
    const all = [...document.querySelectorAll('input')].filter(fillable);
    return all.find(isPassword) || all.find(isOtp) || all.find(isUsername) || null;
  }

  function apply(what, values, origin) {
    // Only the page the service matched: a frame that navigated to another site since keeps nothing.
    if (location.origin !== origin) return { ok: false, error: msg('page_has_changed_try_again') };
    if (!frameUsable()) return { ok: false, error: msg('form_is_in_frame_too') };
    const field = target();
    const group = field && groupOf(field);
    if (what === 'totp') {
      const otp = group && group.kind === 'totp' ? group.otp
        : [...document.querySelectorAll('input')].filter((i) => fillable(i) && isOtp(i)).slice(0, 1);
      if (!otp.length || !values.totp) return { ok: false, error: msg('there_no_visible_2fa_code') };
      if (otp.length > 1) otp.forEach((box, i) => type(box, values.totp[i] || ''));
      else type(otp[0], values.totp);
      return { ok: true };
    }
    if (!group || group.kind !== 'login') return { ok: false, error: msg('there_no_visible_login_form') };
    if (group.username && values.username) type(group.username, values.username);
    if (group.password && values.password) type(group.password, values.password);
    hideMenu();
    return { ok: true };
  }

  // Asked by the background before filling a frame of this page: is a frame of that origin really on screen?
  function frameVisible(url) {
    let origin;
    try { origin = new URL(url).origin; } catch { return false; }
    return [...document.querySelectorAll('iframe, frame')].some((frame) => {
      let src;
      try { src = new URL(frame.src, location.href).origin; } catch { return false; }
      if (src !== origin || !visible(frame)) return false;
      const rect = frame.getBoundingClientRect();
      return rect.width >= 60 && rect.height >= 30;
    });
  }

  // --------------------------------------------------------------------------------------- our UI (shadow DOM)

  const host = document.createElement('secretbroker-ui');
  host.style.cssText = 'all: initial; position: fixed; top: 0; left: 0; width: 0; height: 0; z-index: 2147483647;';
  const root = host.attachShadow({ mode: 'closed' });
  root.innerHTML = `<style>
    :host { all: initial; }
    * { box-sizing: border-box; }
    .sb { --bg: #ffffff; --text: #171717; --muted: #5f5f5f; --faint: #8f8f8f; --line: #e4e4e4; --fill: #ebebeb;
      --hover: #f2f2f2; --accent: #171717; --accent-text: #fff; --interactive: #3a64b0; --danger: #c4321f;
      --shadow: 0 1px 2px rgba(0,0,0,.06), 0 12px 32px rgba(0,0,0,.16);
      --tile: #fff; --logo-tile: #171717; --logo-glyph: #fff;
      font: 400 13px/1.45 "Segoe UI Variable Text", "Segoe UI", system-ui, -apple-system, sans-serif; color: var(--text); }
    @media (prefers-color-scheme: dark) {
      .sb { --bg: #202020; --text: #ececec; --muted: #a3a3a3; --faint: #727272; --line: #3b3b3b; --fill: #2e2e2e;
        --hover: #2a2a2a; --accent: #f2f2f2; --accent-text: #111; --interactive: #8eaee6; --danger: #f2705f;
        --shadow: 0 1px 2px rgba(0,0,0,.4), 0 16px 40px rgba(0,0,0,.5);
        --tile: #2a2a2a; --logo-tile: #f2f2f2; --logo-glyph: #111; }
    }
    .button { position: fixed; width: 22px; height: 22px; padding: 0; border: 0; border-radius: 6px; cursor: pointer;
      background: transparent; display: grid; place-items: center; opacity: .9; }
    .button:hover, .button:focus-visible { background: rgba(127,127,127,.18); opacity: 1; outline: none; }
    .logo { display: block; width: 16px; height: 16px; flex: none; }
    .logo svg { display: block; width: 100%; height: 100%; }
    .bar .title .logo { width: 20px; height: 20px; }
    .menu { position: fixed; width: 300px; max-height: 340px; overflow: auto; background: var(--bg); color: var(--text);
      border: 1px solid var(--line); border-radius: 10px; box-shadow: var(--shadow); padding: 6px; }
    .head { display: flex; align-items: center; gap: 8px; padding: 6px 8px 8px; color: var(--muted); font-size: 12px; }
    .head b { color: var(--text); font-weight: 600; }
    .item { display: flex; align-items: center; gap: 10px; width: 100%; text-align: left; border: 0; background: none;
      color: inherit; font: inherit; padding: 7px 8px; border-radius: 8px; cursor: pointer; }
    .item:hover, .item.active { background: var(--hover); }
    .item[disabled] { cursor: default; opacity: .65; background: none; }
    .avatar { --h: 220; flex: none; width: 28px; height: 28px; border-radius: 6px; display: grid; place-items: center;
      font-weight: 600; overflow: hidden; background: hsl(var(--h) 45% 90%); color: hsl(var(--h) 40% 32%); }
    @media (prefers-color-scheme: dark) { .avatar { background: hsl(var(--h) 25% 24%); color: hsl(var(--h) 55% 80%); } }
    .avatar.has-icon { background: var(--tile); box-shadow: inset 0 0 0 1px var(--line); }
    .avatar img { width: 18px; height: 18px; object-fit: contain; }
    .logo .tile { fill: var(--logo-tile); } .logo .glyph { fill: var(--logo-glyph); } .logo .hole { fill: var(--logo-tile); }
    .hints { display: flex; flex-direction: column; align-items: flex-start; gap: 4px; padding: 4px 8px 2px; color: var(--faint); font-size: 12px; }
    kbd { font: 500 11px/1 "Cascadia Mono", Consolas, ui-monospace, monospace; background: var(--fill); color: var(--muted);
      border-radius: 4px; padding: 3px 5px; }
    .foot { display: flex; flex-direction: column; }
    .foot .link { align-self: flex-start; }
    .text { min-width: 0; flex: 1; }
    .name, .user { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .name { font-weight: 500; }
    .user { color: var(--muted); font-size: 12px; }
    .note { padding: 8px; color: var(--muted); }
    .note b { color: var(--text); font-weight: 600; }
    .foot { border-top: 1px solid var(--line); margin-top: 6px; padding-top: 6px; }
    .link { border: 0; background: none; color: var(--interactive); font: inherit; cursor: pointer; padding: 6px 8px; border-radius: 6px; }
    .link:hover { background: var(--hover); }
    .bar { position: fixed; top: 16px; right: 16px; width: 360px; background: var(--bg); border: 1px solid var(--line);
      border-radius: 10px; box-shadow: var(--shadow); padding: 14px 16px; }
    .bar .title { display: flex; gap: 10px; align-items: center; font-weight: 600; font-size: 14px; }
    .bar p { margin: 6px 0 12px; color: var(--muted); overflow-wrap: anywhere; }
    .bar .actions { display: flex; gap: 8px; justify-content: flex-end; }
    .btn { border: 1px solid var(--line); background: var(--bg); color: var(--text); font-family: inherit; font-size: 13px;
      font-weight: 500; line-height: 1; padding: 8px 14px; border-radius: 6px; cursor: pointer; }
    .btn:hover { background: var(--hover); }
    .btn.primary { background: var(--accent); color: var(--accent-text); border-color: var(--accent); }
    .btn.primary:hover { opacity: .9; }
    .toast { position: fixed; top: 16px; right: 16px; max-width: 360px; background: var(--bg); border: 1px solid var(--line);
      border-radius: 10px; box-shadow: var(--shadow); padding: 10px 14px; display: flex; gap: 10px; align-items: center; }
  </style><div class="sb"></div>`;
  const layer = root.querySelector('.sb');
  // Drawn inline: the page cannot load the extension's files (and must not be able to tell it is installed).
  // The tile follows the theme (dark on light pages, light in dark mode), like the app's own mark.
  const LOGO = '<svg viewBox="0 0 32 32" aria-hidden="true"><rect class="tile" width="32" height="32" rx="7"/>'
    + '<path class="glyph" d="M16 6.5 8.5 9.5v5.6c0 4.7 3.2 8.4 7.5 9.9 4.3-1.5 7.5-5.2 7.5-9.9V9.5z"/>'
    + '<circle class="hole" cx="16" cy="14.2" r="2.3"/><path class="hole" d="M15 15.5h2l.6 4.5h-3.2z"/></svg>';
  const logo = () => { const span = document.createElement('span'); span.className = 'logo'; span.innerHTML = LOGO; return span; };
  let attached = false;
  function attach() {
    if (!attached) { document.documentElement.appendChild(host); attached = true; }
  }

  function make(tag, props = {}, ...children) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(props)) {
      if (k === 'class') node.className = v;
      else if (k.startsWith('on')) node.addEventListener(k.slice(2), v);
      else if (v !== null && v !== undefined && v !== false) node.setAttribute(k, v === true ? '' : v);
    }
    for (const child of children.flat()) if (child !== null && child !== undefined) node.append(child);
    return node;
  }

  // ---- the button in the focused field

  let lastField = null;
  let button = null;

  function placeButton() {
    if (!button || !lastField) return;
    if (!lastField.isConnected || !visible(lastField)) { removeButton(); return; }
    const rect = lastField.getBoundingClientRect();
    button.style.left = `${Math.round(rect.right - 28)}px`;
    button.style.top = `${Math.round(rect.top + (rect.height - 22) / 2)}px`;
  }

  function removeButton() {
    if (button) button.remove();
    button = null;
  }

  function showButton(input) {
    lastField = input;
    const rect = input.getBoundingClientRect();
    if (rect.width < 90 || rect.height < 18) { removeButton(); return; }
    attach();
    if (!button) {
      button = make('button', { class: 'button', title: msg('fill_in_with_secretbroker'), 'aria-label': msg('fill_in_with_secretbroker'),
        onmousedown: (event) => event.preventDefault(),  // keep the focus in the field
        onclick: (event) => { if (event.isTrusted) toggleMenu(); } }, logo());
      layer.append(button);
    }
    placeButton();
  }

  document.addEventListener('focusin', (event) => {
    const input = event.composedPath()[0];
    if (input instanceof HTMLInputElement && relevant(input) && frameUsable()) showButton(input);
  }, true);
  document.addEventListener('focusout', () => {
    setTimeout(() => {
      const active = document.activeElement;
      if (active !== lastField && active !== host && !menu) removeButton();
    }, 150);
  }, true);
  window.addEventListener('scroll', () => { placeButton(); placeMenu(); }, true);
  window.addEventListener('resize', () => { placeButton(); placeMenu(); });

  // ---- the menu of logins

  let menu = null;
  let menuItems = [];
  let activeIndex = -1;

  function hideMenu() {
    if (menu) menu.remove();
    menu = null;
    menuItems = [];
  }

  function placeMenu() {
    if (!menu || !lastField) return;
    const rect = lastField.getBoundingClientRect();
    const width = 300;
    const left = Math.max(8, Math.min(rect.left, window.innerWidth - width - 8));
    const below = window.innerHeight - rect.bottom;
    const above = below < 220 && rect.top > below;
    menu.style.left = `${Math.round(left)}px`;
    if (above) { menu.style.top = ''; menu.style.bottom = `${Math.round(window.innerHeight - rect.top + 4)}px`; }
    else { menu.style.bottom = ''; menu.style.top = `${Math.round(rect.bottom + 4)}px`; }
    // Never taller than the room there is (a small window, or a form in a frame): it scrolls instead of being cut off.
    menu.style.maxHeight = `${Math.round(Math.max(96, Math.min(340, (above ? rect.top : below) - 12)))}px`;
  }

  function initial(name) {
    return (name || '?').trim().charAt(0).toUpperCase() || '?';
  }

  // Each name gets its own colour, so initials tell logins apart until (or unless) the site's icon arrives.
  function tinted(node, name) {
    let hash = 0;
    for (const ch of String(name || '')) hash = (hash * 31 + ch.codePointAt(0)) % 360;
    node.style.setProperty('--h', String(hash));  // CSSOM, not an inline style: pages' CSP can't block it
    return node;
  }

  // The site's icon (the extension fetched and keeps it, see background.js), else the coloured initial stays.
  function showIcon(avatars, data) {
    if (!data || !/^data:image\//.test(data)) return;
    for (const avatar of avatars) {
      const img = make('img', { alt: '' });
      img.addEventListener('load', () => { avatar.replaceChildren(img); avatar.classList.add('has-icon'); });
      img.src = data;
    }
  }

  async function toggleMenu() {
    if (menu) { hideMenu(); return; }
    const group = lastField && groupOf(lastField);
    const wantsTotp = group && group.kind === 'totp';
    menu = make('div', { class: 'menu', role: 'listbox' }, make('div', { class: 'note' }, msg('searching')));
    layer.append(menu);
    placeMenu();
    const answer = await send({ type: 'logins' });
    if (!menu) return;
    const head = (domain) => make('div', { class: 'head' }, logo(),
      make('span', {}, 'SecretBroker', domain ? ' · ' : '', domain ? make('b', {}, domain) : null));
    const openLink = make('button', { class: 'link', onclick: (e) => { if (e.isTrusted) { send({ type: 'open_app' }); hideMenu(); } } }, msg('open_secretbroker'));
    const openApp = make('div', { class: 'foot' }, openLink);
    const note = (...content) => menu.replaceChildren(head(), make('div', { class: 'note' }, ...content), openApp);
    const hello = answer && answer.hello;
    if (!hello || !hello.ok) { note((hello && hello.error) || msg('can_talk_secretbroker')); return; }
    if (!hello.result.paired) { note(msg('connect_this_browser_click_secretbroker')); return; }
    if (hello.result.state !== 'unlocked') { note(make('b', {}, msg('secretbroker_is_locked')), msg('unlock_it_and_click_here')); return; }
    const list = answer.list;
    if (!list || !list.ok) { note((list && list.error) || msg('couldn_look_it_up')); return; }
    const { domain, logins } = list.result;
    const shown = wantsTotp ? logins.filter((l) => l.totp) : logins;
    if (!shown.length) {
      note(wantsTotp ? msg('no_credential_for_has_2fa', { domain }) : msg('nothing_saved_for_sign_in', { domain }));
      return;
    }
    menuItems = shown.map((login) => {
      const choose = async () => {
        if (!login.can_fill) return;
        hideMenu();
        const result = await send({ type: 'fill', id: login.id, what: wantsTotp ? 'totp' : 'login', trusted: true });
        if (result && !result.ok && result.error) toast(result.error);
      };
      const item = make('button', { class: 'item', role: 'option', disabled: !login.can_fill,
        title: login.can_fill ? msg('fill_in_on', { host: list.result.host }) : msg('use_only_team_credential_filling'),
        onclick: (event) => { if (event.isTrusted) choose(); } },
      tinted(make('span', { class: 'avatar', 'aria-hidden': 'true' }, initial(login.name)), login.name),
      make('span', { class: 'text' }, make('div', { class: 'name' }, login.name),
        make('div', { class: 'user' }, login.can_fill ? (wantsTotp ? msg('2fa_code') : login.username || msg('no_username')) : msg('use_only_not_filled_in'))));
      item.choose = choose;
      return item;
    });
    activeIndex = -1;
    // How to fill it from the keyboard: here (↑ ↓ and Enter), and the shortcut that does it without the menu.
    const fillable = menuItems.some((i) => !i.disabled);
    const hints = fillable ? make('div', { class: 'hints' }, make('span', {}, msg('menu_keys_hint')),
      !wantsTotp && answer.shortcut ? make('span', {}, make('kbd', {}, answer.shortcut), ' ', msg('menu_shortcut_hint')) : null) : null;
    menu.replaceChildren(head(domain), ...menuItems, make('div', { class: 'foot' }, hints, openLink));
    placeMenu();
    send({ type: 'icon' }).then((found) => menu && showIcon(menuItems.map((i) => i.querySelector('.avatar')), found && found.icon));
  }

  document.addEventListener('keydown', (event) => {
    if (!menu || !event.isTrusted) return;
    const enabled = menuItems.filter((i) => !i.disabled);
    if (event.key === 'Escape') { hideMenu(); event.stopPropagation(); return; }
    if (!enabled.length) return;
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      event.preventDefault();
      activeIndex = (activeIndex + (event.key === 'ArrowDown' ? 1 : -1) + enabled.length) % enabled.length;
      enabled.forEach((item, i) => item.classList.toggle('active', i === activeIndex));
    } else if (event.key === 'Enter' && activeIndex >= 0) {
      event.preventDefault();
      event.stopPropagation();
      enabled[activeIndex].choose();  // the Enter that chose it is a trusted event
    }
  }, true);
  document.addEventListener('mousedown', (event) => {
    if (menu && event.isTrusted && !event.composedPath().includes(host)) hideMenu();
  }, true);

  // --------------------------------------------------------------------------------------- saving

  let typed = { username: '', password: '', at: 0 };
  let lastSent = 0;

  document.addEventListener('input', (event) => {
    const input = event.composedPath()[0];
    if (!event.isTrusted || !(input instanceof HTMLInputElement)) return;
    if (isPassword(input)) {
      const group = groupOf(input);
      // A form to change the password: the new one (the last field) is what gets saved.
      const passwords = inputsIn(scopeOf(input)).filter(isPassword);
      const fresh = passwords.length > 1 ? passwords.find((p) => p.autocomplete === 'new-password') || passwords[passwords.length - 1] : input;
      typed = { username: (group && group.username && group.username.value) || typed.username, password: fresh.value, at: Date.now() };
    } else if (isUsername(input)) {
      typed = { ...typed, username: input.value, at: Date.now() };
    }
  }, true);

  function sent() {
    if (!typed.at || Date.now() - typed.at > 10 * 60000 || Date.now() - lastSent < 1500) return;
    lastSent = Date.now();
    send({ type: 'submitted', username: typed.username, password: typed.password });
    if (typed.password) typed = { username: '', password: '', at: 0 };
  }

  document.addEventListener('submit', (event) => { if (event.isTrusted) sent(); }, true);
  document.addEventListener('click', (event) => {
    if (!event.isTrusted) return;
    const button = event.composedPath().find((n) => n instanceof HTMLElement && (n.matches('button, input[type=submit], [role=button]')));
    if (!button) return;
    const text = `${button.textContent || ''} ${button.value || ''} ${button.getAttribute('aria-label') || ''} ${button.type || ''}`;
    if (button.type === 'submit' || /log ?in|sign ?in|next|continue|submit|entrar|acceder|iniciar|siguiente|continuar|guardar|save|anmelden|connexion/i.test(text)) sent();
  }, true);
  document.addEventListener('keydown', (event) => {
    if (event.isTrusted && event.key === 'Enter' && event.target instanceof HTMLInputElement && (isPassword(event.target) || isUsername(event.target))) sent();
  }, true);

  let bar = null;
  function showOffer(offer) {
    if (window !== window.top || !offer) return;
    attach();
    if (bar) bar.remove();
    const update = offer.action === 'update';
    const answer = async (save, button) => {
      if (button) button.disabled = true;
      const result = await send({ type: 'offer_answer', id: offer.id, save });
      bar.remove();
      bar = null;
      if (save) toast(result && result.ok ? (update ? msg('password_updated_in_secretbroker') : msg('saved_in_secretbroker')) : (result && result.error) || msg('couldn_save'));
    };
    const primary = make('button', { class: 'btn primary', onclick: (e) => { if (e.isTrusted) answer(true, primary); } }, update ? msg('update') : msg('save'));
    bar = make('div', { class: 'bar', role: 'dialog', 'aria-label': 'SecretBroker' },
      make('div', { class: 'title' }, logo(),
        update ? msg('update_password', { name: offer.name }) : msg('save_this_password_in_secretbroker')),
      make('p', {}, `${offer.username} · ${offer.host}`),
      make('div', { class: 'actions' }, make('button', { class: 'btn', onclick: (e) => { if (e.isTrusted) answer(false); } }, msg('not_now')), primary));
    layer.append(bar);
  }

  let toastTimer = null;
  function toast(text) {
    if (window !== window.top) { send({ type: 'toast_top', text }); return; }
    attach();
    const node = make('div', { class: 'toast', role: 'status' }, logo(), make('span', {}, text));
    layer.querySelectorAll('.toast').forEach((t) => t.remove());
    layer.append(node);
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => node.remove(), 4500);
  }

  // --------------------------------------------------------------------------------------- from the background

  ext.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (sender.id !== ext.runtime.id || !message) return false;
    if (message.type === 'apply') sendResponse(apply(message.what, message.values || {}, message.origin));
    else if (message.type === 'frame_visible') sendResponse(frameVisible(message.url));
    else if (message.type === 'offer') { showOffer(message.offer); sendResponse(true); }
    else if (message.type === 'toast') { if (window === window.top) toast(message.text); sendResponse(true); }
    else return false;
    return false;
  });

  if (window === window.top) send({ type: 'offer?' }).then((answer) => answer && answer.offer && showOffer(answer.offer));
})();
