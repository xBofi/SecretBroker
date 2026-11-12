'use strict';

// ======================================================================= helpers

const api = () => window.pywebview.api;
const $app = () => document.getElementById('app');

// Let replaceChildren take the same optional / nested children as el() (native one prints "null").
const nativeReplaceChildren = Element.prototype.replaceChildren;
Element.prototype.replaceChildren = function replaceChildren(...children) {
  return nativeReplaceChildren.apply(this, children.flat(Infinity).filter((c) => c !== null && c !== undefined && c !== false));
};

function el(tag, props, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (key === 'class') node.className = value;
    else if (key === 'html') node.innerHTML = value;           // only used with trusted icon markup
    else if (key.startsWith('on')) node.addEventListener(key.slice(2), value);
    else if (key === 'value') node.value = value;
    else node.setAttribute(key, value === true ? '' : value);
  }
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(osText(String(child))));
  }
  return node;
}

// The copy names Windows; on Linux and macOS the same sentences name that system (info().os_label, set in boot).
// «Windows Hello» is shown only where there is a biometric proof: on macOS it reads «Touch ID» (info().biometric_label),
// and «your PIN, fingerprint or face» reads «your fingerprint», in whichever language (os.* in the locale files).
function osText(text) {
  const label = window.SB_OS_LABEL;
  if (!label || label === 'Windows') return text;
  const biometric = window.SB_BIOMETRIC_LABEL;
  if (biometric && biometric !== 'Windows Hello') {
    const means = t('os.hello_means'), yourMeans = t('os.your_hello_means');
    if (/Hello/.test(text) || text.includes(means)) {
      text = text.split(`Windows Hello (${means})`).join(biometric).split(yourMeans).join(t('os.your_touch_id_means'))
        .replace(/(Windows )?\bHello\b/g, biometric);
    }
  }
  if (!text.includes('Win')) return text;
  return text.replace(/Windows(?! Hello)/g, label).replace(/ \(Win\+L\)/g, '');
}

function icon(name, size = '') {
  return el('span', { class: `icon ${size}`, html: `<svg viewBox="0 0 24 24" aria-hidden="true">${ICONS[name] || ''}</svg>` });
}

function glyph(templateId, size = '') {
  const t = TEMPLATES[templateId] || TEMPLATES.generic;
  return el('div', { class: `glyph ${t.icon} ${size}` }, icon(t.icon, size === 'lg' ? 'lg' : ''));
}

// Bottom right, at most three; the same message again counts up (×2) instead of stacking.
// kind: '' (done), 'info', 'warning' or 'error'.
const TOAST_ICONS = { '': 'check', info: 'info', warning: 'alert', error: 'alert' };
const MAX_TOASTS = 3;

function toast(message, kind = '') {
  const root = document.getElementById('toasts');
  const text = String(message);
  const life = kind === 'error' ? 6000 : 2800;
  let node = [...root.children].find((t) => t.dataset.kind === kind && t.dataset.text === text);
  if (node) {
    node.count += 1;
    node.querySelector('.times').textContent = `×${node.count}`;
    root.append(node);  // the newest goes last, nearest the corner
  } else {
    node = el('div', { class: `toast ${kind ? `is-${kind}` : ''}`, role: kind === 'error' ? 'alert' : null, 'data-kind': kind, 'data-text': text },
      icon(TOAST_ICONS[kind] || 'info', 'sm'),
      el('div', { class: 'message' }, text, el('span', { class: 'times' })),
      el('button', { class: 'close', type: 'button', title: t('common.close'), 'aria-label': t('common.close'), onclick: () => node.remove() }, icon('x', 'sm')));
    node.count = 1;
    root.append(node);
    while (root.children.length > MAX_TOASTS) root.firstElementChild.remove();
  }
  clearTimeout(node.timer);
  node.timer = setTimeout(() => node.remove(), life);
}

function clearToasts() {
  const root = document.getElementById('toasts');
  if (root) root.replaceChildren();
}

function busy(button, on) {
  if (!button) return;
  if (on) {
    button.dataset.label = button.innerHTML;
    button.disabled = true;
    button.innerHTML = '<div class="spinner"></div>';
  } else if (button.dataset.label !== undefined) {
    button.disabled = false;
    button.innerHTML = button.dataset.label;
  }
}

function passwordInput(props = {}) {
  const input = el('input', { class: 'input', type: 'password', autocomplete: 'new-password', spellcheck: 'false', ...props });
  const toggle = el('button', { class: 'toggle', type: 'button', title: t('common.show') }, icon('eye', 'sm'));
  toggle.addEventListener('click', () => {
    const show = input.type === 'password';
    input.type = show ? 'text' : 'password';
    toggle.title = show ? t('common.hide') : t('common.show');
    toggle.replaceChildren(icon(show ? 'eyeOff' : 'eye', 'sm'));
    input.focus();
  });
  const group = el('div', { class: 'input-group' }, input, toggle);
  group.input = input;
  return group;
}

function strengthOf(password) {
  if (!password) return 0;
  let score = 0;
  if (password.length >= 12) score++;
  if (password.length >= 16) score++;
  const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((r) => r.test(password)).length;
  if (classes >= 3) score++;
  if (password.length >= 20 || (password.length >= 14 && classes === 4)) score++;
  return password.length < 12 ? Math.min(score, 1) : Math.max(score, 1);
}

function strengthMeter(input) {
  const meter = el('div', { class: 'strength', 'data-level': '0' }, el('span'), el('span'), el('span'), el('span'));
  const label = el('div', { class: 'help' }, t('strength_meter.at_least_12_characters_long'));
  input.addEventListener('input', () => {
    const level = strengthOf(input.value);
    meter.dataset.level = String(level);
    label.textContent = input.value.length < 12
      ? tn('password.chars_left', 12 - input.value.length)
      : ['', t('common.weak'), t('common.fair'), t('common.good'), t('common.excellent')][level];
  });
  return [meter, label];
}

function slugify(text) {
  return text.normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase()
    .replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 64);
}

function hostOf(url) {
  if (!url) return '';
  try { return new URL(url.includes('://') ? url : `https://${url}`).hostname; } catch { return url; }
}

function formatTime(iso) {
  if (!iso) return '';
  return fmtDate(iso, { day: '2-digit', month: 'short', hour: 'numeric', minute: '2-digit' });
}

// ======================================================================= state

const state = {
  info: null,
  status: null,
  screen: null,
  view: 'credentials',
  entries: [],
  selected: null,
  search: '',
  setupActive: false,
  afterUnlock: null,
  approvalOpen: null,
  revealed: {},
  exposure: null,
  scan: null,
  team: null,        // team_status: account, sync state, counts
  collection: null,  // filter of the credential list by team collection
  teamOrg: null,     // organization open in the Equipo view
  teamTab: 'collections',  // Colecciones · Personas · Actividad · Tu cuenta
  teamData: null,    // team_overview: what the Equipo view draws (from this PC, then refreshed)
  joinLink: null,    // an invite link the app was opened with, until the team form takes it
  picked: new Set(), // credentials ticked in the list (to share several at once)
};
let TEMPLATES = {};
let DB_ENGINES = {};

const DEFAULT_PALETTE = 'grafito';
const PALETTES = localized(() => ([
  ['grafito', t('palette.graphite'), '#171717'],
  ['salvia', t('palette.sage'), '#0f766e'],
  ['cobalto', t('palette.cobalt'), '#1f5fbf'],
  ['terracota', t('palette.terracotta'), '#b5441b'],
]));
const ACTION_LABELS = localized(() => ({
  http_request: t('activity_action.web_request'),
  ssh_exec: t('activity_action.command_on_server'),
  ssh_upload: t('activity_action.upload_file_server'),
  ssh_download: t('activity_action.download_file_from_server'),
  run_command: t('activity_action.program_on_this_pc'),
  release_env: t('activity_action.handed_local_app'),
  rotate: t('activity_action.rotated_with_provider'),
  draft: t('activity_action.prepared_by_ai'),
  edit: t('activity_action.change_settings'),
  revoke: t('common.approval_withdrawn'),
  request_access: t('activity_action.access_for_task'),
  ai_permissions: t('common.ai_permissions'),
  import_env: t('activity_action.imported_from_env'),
  import_file: t('activity_action.imported_from_another_manager'),
  export: t('activity_action.vault_exported'),
  restore: t('common.backup_restored'),
  check: t('activity_action.checked'),
  pause_ai: t('common.ai_paused'),
  resume_ai: t('activity.ai_resumed'),
  session_unlock: t('activity_action.open_with_windows_session'),
  push_github_secret: t('activity_action.uploaded_github'),
  unlock: t('activity_action.unlocked'), lock: t('activity_action.locked'), save: t('common.saved'), delete: t('common.deleted'),
  reveal: t('activity_action.secret_shown'), create: t('activity_action.vault_created'), enroll_hello: t('common.windows_hello_turned_on'),
  remove_hello: t('common.windows_hello_turned_off'), change_master_password: t('common.master_password_changed'),
  exposure: t('activity_action.found_in_plain_text'), check: t('activity_action.checked_with_provider'),
  team_connect: t('activity_action.team_account_connected'), team_disconnect: t('activity_action.team_account_disconnected'),
  share: t('activity_action.shared_with_team'), unshare: t('common.no_longer_shared'), team_change: t('activity_action.team_change_reviewed'),
  team_conflict: t('activity_action.sync_conflict'), team_join: t('activity_action.invitation_accepted'), team_confirm: t('activity_action.member_confirmed'),
  browser_fill: t('activity_action.filled_in_browser'), browser_copy: t('activity_action.copied_from_browser'), browser_save: t('activity_action.saved_from_browser'),
  browser_pair: t('activity_action.browser_connected'), browser_forget: t('activity_action.browser_disconnected'),
  team_remove: t('activity_action.member_removed'), team_grant: t('activity_action.access_collection'), team_revoke: t('activity_action.access_withdrawn'),
  team_add: t('activity_action.arrived_from_team'), team_update: t('activity_action.changed_by_team'), team_delete: t('activity_action.deleted_by_team'),
  team_review: t('activity_action.team_change_review'), team_held: t('activity_action.team_deletions_on_hold'),
  team_unsigned: t('activity_action.unsigned_change_discarded'), team_recovery: t('activity_action.recovery_access'), team_resolve: t('activity_action.team_deletions_decided'),
  team_verify_email: t('activity.email_verified'), team_admin: t('activity_action.team_server_admin'),
  team_recovery_code: t('activity_action.team_recovery_code'), team_password_reset: t('activity_action.team_password_reset'),
  team_account_recovered: t('activity_action.team_account_recovered'),
}));
const APPROVAL_LABELS = localized(() => ({ session: t('approval_mode.once_per_session'), always: t('approval_mode.always'), never: t('common.never') }));
const AUTH_LABELS = localized(() => ({ none: t('auth.don_add'), header: t('auth.in_header'), query: t('auth.as_url_parameter'), basic: t('auth.http_basic_username_and_password') }));

// ======================================================================= boot & polling

async function boot() {
  state.info = await api().info();
  window.SB_OS_LABEL = state.info.os_label;
  window.SB_BIOMETRIC_LABEL = state.info.biometric_label;
  applyPalette(state.info.prefs.palette);
  I18N.available = state.info.languages || ['en'];
  await applyLanguage(state.info.prefs.language || matchLanguage(navigator.languages || [navigator.language], I18N.available));
  document.addEventListener('keydown', onShortcut);
  await refreshStatus();
  window.onJoinLink();
  setInterval(tick, 1500);
  checkUpdate(false);
  setInterval(() => checkUpdate(false), 3 * 3600 * 1000);
}

// A link or a file dropped on the window would open in it, and that page would get the bridge to the app (app.py,
// page_api). The app takes no drops anywhere: nothing it does is dragged in from outside.
['dragenter', 'dragover', 'drop'].forEach((type) => window.addEventListener(type, (event) => {
  event.preventDefault();
  if (event.dataTransfer) event.dataTransfer.dropEffect = 'none';
}, true));

if (window.pywebview && window.pywebview.api) boot();
else window.addEventListener('pywebviewready', boot);

// The language shown: the one chosen in Ajustes, else the system's, else English (see i18n.js). The app's own
// texts (templates, service errors, the icon next to the clock) follow it; the caller redraws the page.
async function applyLanguage(code) {
  await setLanguage(code, (lang) => api().locale(lang));
  const fresh = await api().set_language(I18N.lang);
  if (fresh) Object.assign(state.info, fresh);
  TEMPLATES = {};
  for (const template of state.info.templates.templates) TEMPLATES[template.id] = template;
  DB_ENGINES = state.info.templates.db_engines;
}

// A select of the languages there are files for, each in its own name («Deutsch», «Русский», «中文»).
function languageSelect(onChanged) {
  const codes = [...I18N.available].sort((a, b) => compareText(languageName(a), languageName(b)));
  const select = el('select', { class: 'input language-select', 'aria-label': t('settings.language') },
    codes.map((code) => el('option', { value: code, selected: code === I18N.lang, lang: code }, languageName(code))));
  select.addEventListener('change', async () => {
    state.info.prefs.language = select.value;
    await api().set_pref('language', select.value);
    await applyLanguage(select.value);
    if (state.screen === 'main') await loadEntries();  // reminders and health reasons are written by the service
    onChanged();
  });
  return select;
}

function applyPalette(name) {
  if (name && name !== DEFAULT_PALETTE) document.documentElement.dataset.palette = name;
  else delete document.documentElement.dataset.palette;
}

function onShortcut(event) {
  const top = openOverlays().pop();
  if (event.key === 'Escape' && top) {
    top.dispatchEvent(new CustomEvent('dismiss'));
    return;
  }
  if (state.screen !== 'main' || top || !event.ctrlKey) return;
  const key = event.key.toLowerCase();
  if (key === 'f') { event.preventDefault(); state.view = 'credentials'; renderMain(); document.querySelector('.search .input')?.focus(); }
  else if (key === 'n') { event.preventDefault(); openEditor(null); }
  else if (key === 'l') { event.preventDefault(); lockNow(); }
  else if (key === 'g') { event.preventDefault(); openGenerator(); }
}

// One tick at a time: an older, slower one answering last would close an approval that just opened.
let ticking = false;
async function tick() {
  if (ticking) return;
  ticking = true;
  try {
    await refreshStatus();
    if (state.status && state.status.state === 'unlocked') {
      await pollDrafts();
      await pollApprovals();
      await pollBrowserPairing();
      await pollScan();
      await pollTeam();
    }
  } finally {
    ticking = false;
  }
}

async function refreshStatus() {
  const response = await api().status();
  if (!response.ok) { renderUnavailable(response.error); return; }
  state.status = response.result;
  const target = state.setupActive ? 'setup' : { no_vault: 'setup', locked: 'lock', unlocked: 'main' }[state.status.state];
  if (target !== state.screen) {
    state.screen = target;
    closeAllModals();
    if (target === 'setup') renderSetup();
    else if (target === 'lock') { clearToasts(); state.info.session_unlock_here = await api().has_session_unlock(); renderLock(); }
    else await enterMain();
  } else if (target === 'main') {
    updateSidebarState();
  }
  if (state.screen === 'main') {
    // Data changed outside this window (or by it): redraw what is shown, in place.
    const known = state.revision;
    state.revision = state.status.revision;
    if (known !== undefined && known !== state.status.revision) await refreshInPlace();
  } else {
    state.revision = undefined;
  }
}

function renderUnavailable(message) {
  state.screen = 'unavailable';
  $app().replaceChildren(el('div', { class: 'center-screen' },
    el('div', { class: 'auth' },
      el('div', { class: 'auth-head' }, brand(), el('h2', {}, t('unavailable.can_connect_service'))),
      el('p', { class: 'lead' }, message || t('unavailable.secretbroker_service_isn_responding')),
      el('p', { class: 'help' }, state.info && state.info.installed
        ? t('unavailable.service_starts_with_windows_if')
        : t('unavailable.retrying')))));
}

function brand(big = false) {
  return el('div', { class: 'brand' },
    el('div', { class: `mark ${big ? 'big' : ''}` }, icon('shield', big ? 'xl' : 'sm')),
    big ? null : el('div', { class: 'brand-name' }, t('common.secretbroker')));
}

// ======================================================================= dialogs & proofs

function closeAllModals() {
  document.getElementById('modal-root').replaceChildren();
  document.getElementById('approval-banner')?.remove();
  state.approvalOpen = null;
}

// The open dialogs, oldest first (without a scrim that is fading out).
function openOverlays() {
  return [...document.getElementById('modal-root').children].filter((n) => n.classList.contains('overlay'));
}

// `confirmClose()`: for dialogs with work in progress (a rotation, an edit), the question to ask before the
// X or Esc closes it (a string, or {title, text}); null closes at once. Those never close with a click outside.
// `closeLabel`: a text button instead of the X; `onDismiss`: what the X and Esc do instead of closing.
function openModal({ title, body, footer, wide = false, onClose, lead, confirmClose, closeLabel, onDismiss, className = '' }) {
  let closed = false;
  let asking = false;
  const close = () => {
    if (closed) return;
    closed = true;
    // The last dialog leaves its scrim for a moment: a next step opening right away takes it over
    // instead of the page flashing between two dialogs.
    if (openOverlays().length === 1 && overlay.isConnected) {
      overlay.className = 'scrim-out';
      overlay.replaceChildren();
      setTimeout(() => overlay.remove(), 300);
    } else {
      overlay.remove();
    }
    if (onClose) onClose();
  };
  const dismiss = () => {
    if (onDismiss && !closed) { onDismiss(); return; }
    const question = confirmClose && !closed && confirmClose();
    if (!question) { close(); return; }
    if (asking) return;
    asking = true;
    const keep = el('button', { class: 'btn' }, t('common.keep_going'));
    const discard = el('button', { class: 'btn primary' }, t('open_modal.discard'));
    const ask = openModal({ title: question.title || t('open_modal.discard_2'), body: el('p', { class: 'muted' }, question.text || question),
      footer: [el('div', { class: 'spacer' }), keep, discard], onClose: () => { asking = false; } });
    keep.addEventListener('click', () => ask.close());
    discard.addEventListener('click', () => { ask.close(); close(); });
  };
  const root = document.getElementById('modal-root');
  const fading = root.querySelector(':scope > .scrim-out');
  if (fading) fading.remove();
  const overlay = el('div', { class: `overlay ${fading ? 'continued' : ''}` },
    el('div', { class: `modal ${wide ? 'wide' : ''} ${className}`, role: 'dialog', 'aria-modal': 'true', 'aria-label': title },
      el('div', { class: 'modal-head' }, lead || null, el('h2', { title }, title),
        closeLabel ? el('button', { class: 'btn ghost close-label', onclick: dismiss, title: t('open_modal.esc') }, closeLabel)
          : el('button', { class: 'btn icon-only', onclick: dismiss, title: t('open_modal.close_esc') }, icon('x'))),
      el('div', { class: 'modal-body' }, body),
      footer ? el('div', { class: 'modal-foot' }, footer) : null));
  // A click outside closes a simple dialog, never one with work in progress (it would be lost by a stray click).
  overlay.addEventListener('mousedown', (event) => { if (event.target === overlay && !confirmClose && !onDismiss) dismiss(); });
  overlay.addEventListener('dismiss', dismiss);
  root.append(overlay);
  return { close, overlay, dismiss };
}

// Ask for a password proof. Resolves {kind, value}, 'hello' (retry with Hello) or null.
function askProof(reason, error, note) {
  return new Promise((resolve) => {
    const status = state.status || {};
    const kinds = [];
    if (status.windows_password) kinds.push(['windows_password', t('common.windows_password')]);
    kinds.push(['master_password', t('common.master_password')]);
    let kind = localStorage.getItem('proofKind') || kinds[0][0];
    if (!kinds.some(([k]) => k === kind)) kind = kinds[0][0];

    const pw = passwordInput({ autocomplete: 'current-password' });
    const errorText = el('div', { class: 'error-text' }, error || '');
    const label = el('label', {});
    const help = el('div', { class: 'help' });
    const tabs = el('div', { class: 'segmented' });
    const renderKind = () => {
      label.textContent = kinds.find(([k]) => k === kind)[1];
      help.textContent = kind === 'windows_password'
        ? t('ask_proof.one_you_use_sign_in')
        : t('ask_proof.one_you_chose_when_you');
      tabs.replaceChildren(kinds.map(([k, text]) => el('button', {
        class: k === kind ? 'active' : '', type: 'button',
        onclick: () => { kind = k; renderKind(); pw.input.focus(); },
      }, text)));
    };
    renderKind();

    let done = false;
    const finish = (value) => { if (!done) { done = true; modal.close(); resolve(value); } };
    const submit = () => {
      if (!pw.input.value) { errorText.textContent = t('ask_proof.type_password'); return; }
      localStorage.setItem('proofKind', kind);
      finish({ kind, value: pw.input.value });
    };
    pw.input.addEventListener('keydown', (event) => { if (event.key === 'Enter') submit(); });

    const helloAvailable = status.hello_enrolled && state.info.hello_supported;
    const modal = openModal({
      title: t('ask_proof.confirm_you'),
      body: [
        el('p', { class: 'muted' }, reason || t('ask_proof.this_action_needs_verify_your')),
        note ? el('div', { class: 'warning' }, icon('info', 'sm'), el('span', {}, note)) : null,
        kinds.length > 1 ? tabs : null,
        el('div', { class: 'field' }, label, pw, help),
        errorText,
      ],
      footer: [
        helloAvailable ? el('button', { class: 'btn ghost', onclick: () => finish('hello') }, icon('fingerprint', 'sm'), t('ask_proof.use_windows_hello')) : null,
        el('div', { class: 'spacer' }),
        el('button', { class: 'btn', onclick: () => finish(null) }, t('common.cancel')),
        el('button', { class: 'btn primary', onclick: submit }, t('common.confirm')),
      ],
      onClose: () => finish(null),
    });
    setTimeout(() => pw.input.focus(), 50);
  });
}

// Run fn(proof). The first attempt uses Windows Hello when set up; otherwise ask for a password.
async function withProof(fn, reason) {
  let result = await fn(null);
  let weak = false;
  while (!result.ok && ['proof_required', 'hello_cancelled', 'hello_failed', 'proof_invalid'].includes(result.code)) {
    weak = weak || !!result.weak;
    const choice = await askProof(reason, result.code === 'proof_required' ? null : result.error, weak
      ? t('with_proof.you_opened_secretbroker_with_your')
      : null);
    if (!choice) return { ok: false, code: 'cancelled', error: t('with_proof.cancelled') };
    result = await fn(choice === 'hello' ? null : choice);
  }
  return result;
}

// ======================================================================= setup

function renderSetup() {
  state.setupActive = true;
  const status = state.status;
  let importLegacy = !!status.legacy_vault;
  let masterPassword = null;

  const box = el('div', { class: 'auth wide' });
  $app().replaceChildren(el('div', { class: 'center-screen' }, box));
  const steps = (n) => el('div', { class: 'steps' }, [1, 2, 3, 4].map((i) => el('span', { class: i <= n ? 'done' : '' })));

  // Importing needs a vault to import into: create it first, then the import opens by itself.
  let thenImport = false;
  const welcome = () => {
    box.classList.add('centered');
    const start = el('button', { class: 'btn primary lg', style: 'min-width:220px', onclick: () => { thenImport = false; passwordStep(); } }, t('common.get_started'));
    box.replaceChildren(
      el('div', { class: 'auth-head center' }, brand(true), el('h1', { style: 'margin-top:12px' }, t('setup.your_keys_used_without_being'))),
      el('p', { class: 'lead' }, t('setup.store_passwords_api_keys_and')),
      el('div', { class: 'points', style: 'margin:8px auto 12px;max-width:400px' },
        el('div', {}, icon('bot'), el('div', {}, el('b', {}, t('setup.ai_uses_never_sees')), el('span', { class: 'muted' }, t('setup.keys_are_inserted_into_each')))),
        el('div', {}, icon('check'), el('div', {}, el('b', {}, t('setup.you_decide')), el('span', { class: 'muted' }, t('setup.approve_with_one_click_once')))),
        el('div', {}, icon('lock'), el('div', {}, el('b', {}, t('setup.encrypted_on_this_pc')), el('span', { class: 'muted' }, t('setup.if_you_share_with_your'))))),
      status.legacy_vault ? el('p', { class: 'help', style: 'text-align:center' }, t('setup.we_found_your_previous_vault')) : null,
      el('div', { class: 'auth-actions' }, start,
        el('div', { class: 'secondary' },
          el('button', { class: 'link muted-link', onclick: () => restoreBackup(() => { state.setupActive = false; state.screen = null; refreshStatus(); }) }, t('common.restore_backup')),
          el('button', { class: 'link muted-link', onclick: () => { thenImport = true; passwordStep(); } }, t('common.import_from_another_manager')))),
      I18N.available.length > 1 ? el('div', { class: 'auth-language' }, icon('globe', 'sm'), languageSelect(() => renderSetup())) : null);
    setTimeout(() => start.focus(), 50);
  };

  const passwordStep = () => {
    const pw = passwordInput();
    const confirm = passwordInput();
    const legacy = passwordInput({ autocomplete: 'current-password' });
    const errorText = el('div', { class: 'error-text' });
    const button = el('button', { class: 'btn primary lg' }, t('setup.create_vault'));

    const sameAsNew = el('input', { type: 'checkbox', checked: true });
    const legacyBox = el('div', { class: 'field hidden' }, el('label', {}, t('setup.previous_vault_password')), legacy);
    sameAsNew.addEventListener('change', () => legacyBox.classList.toggle('hidden', sameAsNew.checked));
    let legacySection = null;
    if (status.legacy_vault) {
      const importToggle = el('input', { type: 'checkbox', checked: true });
      const sameRow = el('label', { class: 'check-row', style: 'padding-left:26px' }, sameAsNew, t('setup.i_used_this_same_password'));
      importToggle.addEventListener('change', () => {
        importLegacy = importToggle.checked;
        sameRow.classList.toggle('hidden', !importLegacy);
        legacyBox.classList.toggle('hidden', !importLegacy || sameAsNew.checked);
      });
      legacySection = [el('label', { class: 'check-row' }, importToggle, t('setup.import_credentials_from_previous_vault')), sameRow, legacyBox];
    }

    const submit = async () => {
      errorText.textContent = '';
      if (pw.input.value.length < 12) { errorText.textContent = t('setup.master_password_needs_at_least'); return; }
      if (pw.input.value !== confirm.input.value) { errorText.textContent = t('common.two_passwords_don_match'); return; }
      busy(button, true);
      const params = { master_password: pw.input.value };
      if (importLegacy) {
        params.import_legacy = true;
        params.legacy_password = sameAsNew.checked ? pw.input.value : legacy.input.value;
      }
      const result = await api().call('create_vault', params);
      busy(button, false);
      if (!result.ok) { errorText.textContent = result.error; return; }
      masterPassword = pw.input.value;
      unlockStep();
    };
    button.addEventListener('click', submit);
    confirm.input.addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });

    box.classList.remove('centered');
    box.replaceChildren(
      el('div', { class: 'auth-head' }, steps(2), el('h2', { style: 'margin-top:12px' }, t('setup.choose_master_password'))),
      el('p', { class: 'lead' }, t('setup.encrypts_vault_day_day_you', { value: state.info.hello_supported ? t('setup.windows_hello_or') : '' })),
      thenImport ? el('p', { class: 'help' }, t('setup.next_you_ll_pick_file')) : null,
      el('div', { class: 'field' }, el('label', {}, t('common.master_password')), pw, strengthMeter(pw.input)),
      el('div', { class: 'field' }, el('label', {}, t('common.repeat')), confirm),
      legacySection,
      errorText,
      el('div', {}, button));
    setTimeout(() => pw.input.focus(), 50);
  };

  // How it opens day to day, so the master password is typed only to restore a backup or on another PC.
  const unlockStep = () => {
    const errorText = el('div', { class: 'error-text' });
    const hello = !!state.info.hello_supported;
    const options = [
      hello && ['hello', 'fingerprint', t('setup.windows_hello_pin_fingerprint_or'),
        t('setup.asked_for_when_you_open')],
      ['session', 'unlock', t('common.open_with_my_windows_session'),
        t('setup.opens_by_itself_when_you')],
      ['master', 'key', t('setup.type_master_password_every_time'), t('setup.strictest_and_most_tedious')],
    ].filter(Boolean);
    let choice = options[0][0];
    const list = el('div', { class: 'choice-list', role: 'radiogroup' });
    const draw = () => list.replaceChildren(options.map(([value, iconName, title, text]) => el('label', { class: `choice ${choice === value ? 'active' : ''}` },
      el('input', { type: 'radio', name: 'unlock-way', value, checked: choice === value, onchange: () => { choice = value; draw(); } }),
      el('span', { class: 'choice-icon' }, icon(iconName)),
      el('span', {}, el('b', {}, title), value === options[0][0] ? el('span', { class: 'badge-soft' }, t('setup.recommended')) : null,
        el('span', { class: 'muted small choice-text' }, text)))));
    draw();
    const button = el('button', { class: 'btn primary lg' }, t('common.continue'));
    button.addEventListener('click', async () => {
      errorText.textContent = '';
      const proof = { kind: 'master_password', value: masterPassword };
      busy(button, true);
      const result = choice === 'hello' ? await api().enroll_hello(proof)
        : choice === 'session' ? await api().enable_session_unlock(proof) : { ok: true };
      busy(button, false);
      if (!result.ok) { if (result.code !== 'hello_cancelled') errorText.textContent = result.error; return; }
      if (choice === 'session') state.info.session_unlock_here = true;
      rememberUnlockMethod(choice === 'hello' ? 'hello' : choice === 'session' ? 'session' : 'master');
      finish();
    });
    box.replaceChildren(
      el('div', { class: 'auth-head' }, steps(3), el('h2', { style: 'margin-top:12px' }, t('setup.how_do_you_want_open'))),
      el('p', { class: 'lead' }, t('setup.you_ll_only_type_master')),
      list,
      el('p', { class: 'help' }, t('setup.ai_requests_are_always_approved')),
      errorText,
      el('div', {}, button));
    setTimeout(() => button.focus(), 50);
  };

  // Every way through the setup ends connecting the user's AI (connect.js), then the app opens.
  const finish = () => {
    masterPassword = null;
    renderConnectAi(box, done, steps(4));
  };
  const done = () => {
    if (thenImport) state.afterUnlock = 'import';
    state.setupActive = false;
    state.screen = null;
    refreshStatus();
  };

  welcome();
}

// ======================================================================= lock screen

// One way to unlock in front (the one used last time, else the quickest), the rest folded away.
const UNLOCK_METHOD_KEY = 'unlockMethod';

function rememberUnlockMethod(method) {
  try { localStorage.setItem(UNLOCK_METHOD_KEY, method); } catch { /* not remembered: the default order stays */ }
}

function renderLock() {
  const status = state.status;
  const canDevice = status.device_unlock;
  const helloAvailable = canDevice && status.hello_enrolled && state.info.hello_supported;
  const sessionAvailable = status.session_unlock && state.info.session_unlock_here;
  const windowsAvailable = canDevice && status.windows_password;
  const errorText = el('div', { class: 'error-text', style: 'text-align:center' });

  const methods = [sessionAvailable && 'session', helloAvailable && 'hello', 'master', windowsAvailable && 'windows'].filter(Boolean);
  let last = null;
  try { last = localStorage.getItem(UNLOCK_METHOD_KEY); } catch { /* use the default order */ }
  const primary = methods.includes(last) ? last : methods[0];
  const done = (method) => { rememberUnlockMethod(method); refreshStatus(); };

  const master = passwordInput({ placeholder: t('common.master_password'), autocomplete: 'current-password' });
  const masterButton = el('button', { class: `btn ${primary === 'master' ? 'primary lg block' : ''}` }, t('lock.unlock'));
  const unlockMaster = async () => {
    if (!master.input.value) { master.input.focus(); return; }
    busy(masterButton, true);
    const result = await api().call('unlock', {}, { kind: 'master_password', value: master.input.value });
    busy(masterButton, false);
    if (!result.ok) { errorText.textContent = result.error; master.input.select(); return; }
    master.input.value = '';
    done('master');
  };
  masterButton.addEventListener('click', unlockMaster);
  master.input.addEventListener('keydown', (e) => { if (e.key === 'Enter') unlockMaster(); });

  const sessionButton = el('button', { class: `btn ${primary === 'session' ? 'primary' : ''} lg block` }, icon('unlock', 'sm'), t('common.open_with_my_windows_session'));
  sessionButton.addEventListener('click', async () => {
    errorText.textContent = '';
    busy(sessionButton, true);
    const ok = await api().session_unlock();
    busy(sessionButton, false);
    if (!ok) { errorText.textContent = osText(t('lock.couldn_open_with_windows_session')); state.info.session_unlock_here = false; return; }
    done('session');
  });

  const helloButton = el('button', { class: `btn ${primary === 'hello' ? 'primary' : ''} lg block` }, icon('fingerprint', 'sm'), t('lock.unlock_with_windows_hello'));
  const unlockHello = async () => {
    errorText.textContent = '';
    busy(helloButton, true);
    const result = await api().call('unlock', {});
    busy(helloButton, false);
    if (!result.ok) { if (result.code !== 'hello_cancelled') errorText.textContent = result.error; return; }
    done('hello');
  };
  helloButton.addEventListener('click', unlockHello);

  const unlockWindows = async () => {
    errorText.textContent = '';
    const proof = await askProof(t('lock.type_password_your_windows_account'));
    if (!proof) return;
    if (proof === 'hello') return unlockHello();
    const result = await api().call('unlock', {}, proof);
    if (!result.ok) { errorText.textContent = result.error; return; }
    done('windows');
  };
  const windowsButton = el('button', { class: `btn ${primary === 'windows' ? 'primary' : ''} lg block`, onclick: unlockWindows },
    icon('key', 'sm'), t('lock.use_windows_password'));

  const forgot = () => {
    if (!canDevice) {
      openModal({ title: t('lock.recover_access'), body: [
        el('p', {}, t('lock.this_pc_doesn_have_windows')),
        el('p', { class: 'muted' }, t('lock.for_security_there_no_other'))] });
      return;
    }
    const modal = openModal({
      title: t('lock.recover_access'),
      body: el('p', {}, t('lock.sign_in_with_windows_hello')),
      footer: [
        status.windows_password ? el('button', { class: 'btn', onclick: () => { modal.close(); state.afterUnlock = 'change_master'; unlockWindows(); } }, t('common.windows_password')) : null,
        helloAvailable ? el('button', { class: 'btn primary', onclick: () => { modal.close(); state.afterUnlock = 'change_master'; unlockHello(); } }, t('common.windows_hello')) : null,
      ],
    });
  };

  const buttons = { session: sessionButton, hello: helloButton, windows: windowsButton };
  const view = (method) => {
    if (method !== 'master') return buttons[method];
    return method === primary
      ? el('div', { style: 'display:flex;flex-direction:column;gap:10px' }, master, masterButton)
      : el('div', { style: 'display:flex;gap:8px' }, el('div', { style: 'flex:1' }, master), masterButton);
  };
  const others = methods.filter((m) => m !== primary);

  // Locked for inactivity with the Windows session unlock on: it opens again by itself as soon as the user comes
  // back to this window (the AI's requests open it too, see client.reopen_with_session). Never after «Bloquear».
  const reopen = sessionAvailable && status.lock_reason === 'idle';
  const thisScreen = state.lockScreen = {};  // a later lock screen (after «Bloquear») must not open by itself
  if (reopen) {
    // The user's own input, or the window coming to the front (not the focus moving inside the page).
    const again = async () => {
      ['pointerdown', 'keydown'].forEach((type) => window.removeEventListener(type, again, true));
      window.removeEventListener('focus', again);
      if (state.screen === 'lock' && state.lockScreen === thisScreen && await api().session_unlock()) done('session');
    };
    ['pointerdown', 'keydown'].forEach((type) => window.addEventListener(type, again, true));
    window.addEventListener('focus', again);
  }

  $app().replaceChildren(el('div', { class: 'center-screen' },
    el('div', { class: 'auth' },
      el('div', { class: 'auth-head center' }, brand(true), el('h2', { style: 'margin-top:10px' }, t('lock.secretbroker_is_locked'))),
      reopen ? el('p', { class: 'help', style: 'text-align:center' }, t('lock.locked_after_period_inactivity_will')) : null,
      view(primary),
      errorText,
      others.length ? el('details', { class: 'other-unlock' },
        el('summary', {}, el('span', { class: 'chev' }, icon('chevronRight', 'sm')), t('lock.other_ways_unlock')),
        el('div', { class: 'inner' }, others.map(view))) : null,
      el('div', { style: 'text-align:center' }, el('button', { class: 'link faint-link small', onclick: forgot }, t('lock.forgot_your_master_password'))),
      el('p', { class: 'footnote', style: 'margin-top:24px' }, t('lock.only_unlock_in_this_window')))));
  setTimeout(() => (primary === 'master' ? master.input : buttons[primary]).focus(), 50);
}

// ======================================================================= main

async function enterMain() {
  await loadEntries();
  renderMain();
  applyJoinLink();
  if (await api().auto_scan()) { state.scan = { running: true }; renderMain(); }
  if (state.afterUnlock === 'import') {
    state.afterUnlock = null;
    openImport();  // personal.js
  }
  if (state.afterUnlock === 'change_master') {
    state.afterUnlock = null;
    state.view = 'settings';
    renderMain();
    changeMasterPassword(true);
  }
}

// `background`: the app reloading by itself (it doesn't count as using the vault, and a failure keeps what is shown).
let loadsStarted = 0;
let newestLoaded = 0;
async function loadEntries(background = false) {
  const extra = background ? { _poll: true } : {};
  const seq = ++loadsStarted;
  const [result, reminders, team] = await Promise.all([api().call('entries', extra), api().call('reminders', extra), api().call('team_status', extra)]);
  // A slower, older reload answering last would bring back what a newer one already replaced.
  if (seq < newestLoaded || (background && !result.ok)) return false;
  newestLoaded = seq;
  state.entries = result.ok ? result.result : [];
  state.team = team.ok ? team.result : null;
  state.reminders = Object.fromEntries((reminders.ok ? reminders.result : []).map((r) => [r.id, r]));
  if (state.selected && !state.entries.some((e) => e.id === state.selected)) state.selected = null;
  await loadExposure(background);
  return true;
}

async function loadExposure(background = false) {
  const result = await api().exposure_report(background);
  state.exposure = result.ok ? result.result : null;
}

function renderMain() {
  const sidebar = el('aside', { class: 'sidebar' },
    brand(),
    el('nav', { class: 'nav' },
      navButton('credentials', 'key', t('common.credentials'), state.entries.length),
      navButton('exposure', 'shield', t('common.health'), exposedCount(), 'danger'),
      navButton('access', 'bot', t('common.ai_access'), state.status.ai_paused ? el('span', { title: t('common.ai_paused') }, icon('pause', 'sm')) : null, 'is-warning'),
      navButton('team', 'users', t('common.team'), teamAttentionCount()),
      navButton('activity', 'activity', t('common.activity')),
      navButton('settings', 'settings', t('common.settings'))),
    el('div', { id: 'update-slot' }),
    el('div', { class: 'sidebar-footer' },
      el('div', { class: 'state', id: 'sidebar-state' }),
      el('button', { class: 'btn icon-only', title: t('main.password_generator_ctrl_g'), onclick: openGenerator }, icon('dice', 'sm')),
      el('button', { class: 'btn icon-only', title: t('main.lock_ctrl_l'), onclick: lockNow }, icon('lock', 'sm'))));
  $app().replaceChildren(el('div', { class: 'layout' }, sidebar, el('main', { class: 'content', id: 'content' })));
  updateSidebarState();
  renderUpdateSlot();
  renderView();
}

function navButton(view, iconName, label, count, countClass = '') {
  return el('button', {
    class: state.view === view ? 'active' : '', 'data-view': view,
    onclick: () => { if (state.view !== view) clearToasts(); state.view = view; renderMain(); },
  }, icon(iconName), el('span', { class: 'label' }, label), count ? el('span', { class: `count ${countClass}` }, count) : null);
}

function updateSidebarState() {
  const node = document.getElementById('sidebar-state');
  if (!node || !state.status) return;
  const status = state.status;
  const minutes = status.auto_lock_minutes;
  const lockSpan = minutes >= 60 ? t('time.hours_short', { count: minutes / 60 }) : t('time.minutes_short', { count: minutes });
  const until = status.session_unlock ? t('update_sidebar_state.unlocked_follows_windows')
    : minutes ? t('update_sidebar_state.unlocked', { value: lockSpan }) : t('update_sidebar_state.unlocked_2');
  // Green while all is normal; amber only for something to do; red when something is stuck.
  const review = (status.drafts || 0) + teamAttention().length;
  const blocked = status.team === 'reconnect';
  const [tone, text] = blocked ? ['blocked', t('update_sidebar_state.team_not_synced')]
    : status.ai_paused ? ['warn', t('common.ai_paused')]
      : review ? ['warn', tn('sidebar.to_review', review)]
        : ['', until];
  node.replaceChildren(el('span', { class: `dot ${tone}` }), el('span', {}, text));
  node.title = [
    text,  // in full: it may end in an ellipsis in long languages
    blocked ? t('update_sidebar_state.your_team_session_has_expired') : null,
    status.ai_paused ? t('update_sidebar_state.ai_is_paused_can_use') : null,
    status.drafts ? tn('sidebar.drafts_waiting', status.drafts) : null,
    teamAttention().length ? t('update_sidebar_state.there_are_team_changes_review') : null,
    status.session_unlock ? (minutes ? t('sidebar.closes_with_windows_or_idle') : t('sidebar.closes_with_windows'))
      : minutes ? t('update_sidebar_state.vault_locks_after_unused', { value: lockSpan }) : t('update_sidebar_state.vault_doesn_lock_by_itself'),
    status.isolated ? t('update_sidebar_state.service_uses_its_own_windows') : t('update_sidebar_state.unisolated_mode_service_uses_your'),
  ].filter(Boolean).join('\n');
  if (state.paused !== state.status.ai_paused) {  // paused or resumed from the icon next to the clock
    const first = state.paused === undefined;
    state.paused = state.status.ai_paused;
    if (!first) renderMain();
  }
  updateTeamNav();
}

async function lockNow() {
  clearToasts();
  await api().call('lock');
  state.revealed = {};
  state.exposure = null;
  refreshStatus();
}

function renderView() {
  const content = document.getElementById('content');
  if (!content) return;
  if (state.view === 'credentials') renderCredentials(content);
  else if (state.view === 'exposure') renderExposure(content);
  else if (state.view === 'activity') renderActivity(content);
  else if (state.view === 'access') renderAccess(content);
  else if (state.view === 'team') renderTeam(content);
  else renderSettings(content);
}

// ----------------------------------------------------------------------- credentials

function subtitleOf(entry) {
  const f = entry.fields;
  switch (entry.template) {
    case 'web_login': return [f.username, hostOf(f.url)].filter(Boolean).join(' · ');
    case 'api_key': return hostOf(f.base_url) || 'API key';
    case 'ssh': return `${f.username || ''}@${f.host || ''}${f.port && f.port !== '22' ? ':' + f.port : ''}`;
    case 'database': return [(DB_ENGINES[f.engine] || {}).label, f.host].filter(Boolean).join(' · ');
    case 'aws': return [f.access_key_id, f.region].filter(Boolean).join(' · ');
    default: return f.username || hostOf(f.url) || t('subtitle_of.secret');
  }
}

// How the list is ordered (remembered on this PC): [value, label].
const SORTS = localized(() => ([['name', t('common.name')], ['used', t('sort.recently_used')], ['changed', t('sort.recently_changed')], ['attention', t('sort.need_attention')]]));
const SORT_KEY = 'credentialSort';

function savedSort() {
  try { const value = localStorage.getItem(SORT_KEY); return SORTS.some(([v]) => v === value) ? value : 'name'; } catch { return 'name'; }
}

// 0: something is broken or exposed, 1: something to do soon, 2: nothing (the order of «Necesitan atención»).
function attentionOf(entry) {
  const reminder = state.reminders && state.reminders[entry.id];
  const level = (exposureOf(entry.id) || {}).level;
  if (entry.draft || level === 'exposed' || (entry.failed_uploads || []).length || (reminder && reminderTone(reminder))) return 0;
  if (reminder || level === 'warning' || entry.pending_rotation || entry.retired || unsentText(entry)
    || (entry.shared && entry.shared.pending_change)) return 1;
  return 2;
}

function sortEntries(items, sort) {
  const byName = (a, b) => compareText(a.name, b.name);
  const newest = (key) => (a, b) => String(b[key] || '').localeCompare(String(a[key] || '')) || byName(a, b);
  const order = { used: newest('last_used'), changed: newest('updated'), attention: (a, b) => attentionOf(a) - attentionOf(b) || byName(a, b) }[sort] || byName;
  return [...items].sort(order);
}

function renderCredentials(content) {
  const search = el('input', { class: 'input', placeholder: t('credentials.search'), value: state.search, 'aria-label': t('credentials.search_credentials') });
  search.addEventListener('input', () => { state.search = search.value; renderList(true); });
  search.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') { search.value = ''; state.search = ''; renderList(true); }
    else if (e.key === 'ArrowDown' || e.key === 'Enter') { e.preventDefault(); focusRow(0); }
  });
  const header = el('div', { class: 'content-header' },
    el('h1', {}, t('common.credentials')),
    state.entries.length ? el('div', { class: 'search' }, icon('search', 'sm'), search) : null,
    importExportMenu(),  // personal.js: «…» with Importar and Exportar
    el('button', { class: 'btn primary', title: t('credentials.new_ctrl_n'), onclick: () => openEditor(null) }, icon('plus', 'sm'), t('common.new')));

  if (!state.entries.length) {
    content.replaceChildren(header, el('div', { class: 'content-body' }, emptyCredentials()));  // connect.js
    state.listView = null;
    return;
  }

  // The list takes the arrows (and Enter opens the selected one); the search box hands over with ↓ or Enter.
  const list = el('div', { class: 'list', role: 'listbox', tabindex: '0', 'aria-label': t('common.credentials') });
  const detail = el('div', { class: 'detail' });
  let shown = [];
  const sortSelect = el('select', { class: 'input compact', title: t('credentials.sort'), 'aria-label': t('credentials.sort') },
    SORTS.map(([value, label]) => el('option', { value }, label)));
  sortSelect.value = savedSort();
  sortSelect.addEventListener('change', () => {
    try { localStorage.setItem(SORT_KEY, sortSelect.value); } catch { /* the order is only kept until closing */ }
    renderList();
  });
  const countText = el('span', { class: 'list-count', 'aria-live': 'polite' });
  const select = (id, focus) => {
    state.selected = id;
    renderList();
    renderDetail(detail);
    if (focus) focusRow(shown.findIndex((e) => e.id === id));
  };
  const focusRow = (index) => {
    const rows = list.querySelectorAll('.row');
    if (!rows.length) return;
    const row = rows[Math.max(0, Math.min(index, rows.length - 1))];
    if (row.dataset.id !== state.selected) { select(row.dataset.id, true); return; }
    row.focus();
    row.scrollIntoView({ block: 'nearest' });
  };
  list.addEventListener('keydown', (event) => {
    const at = shown.findIndex((e) => e.id === state.selected);
    const step = { ArrowDown: 1, ArrowUp: -1, PageDown: 10, PageUp: -10 }[event.key];
    if (step) { event.preventDefault(); focusRow(at < 0 ? 0 : at + step); }
    else if (event.key === 'Home' || event.key === 'End') { event.preventDefault(); focusRow(event.key === 'Home' ? 0 : shown.length - 1); }
    else if (event.key === 'Enter' && at >= 0) { event.preventDefault(); openEditor(shown[at]); }
  });
  const allTags = [...new Set(state.entries.flatMap((e) => e.tags || []))].sort();
  if (state.tag && !allTags.includes(state.tag)) state.tag = null;
  // Team collections the credentials are in: a filter like the tags, marked with the team icon.
  const collections = [...new Map(state.entries.filter((e) => e.shared)
    .map((e) => [e.shared.collection, collectionLabel(e.shared) || t('credentials.collection')])).entries()]
    .sort((a, b) => a[1].localeCompare(b[1]));
  if (state.collection && !collections.some(([cid]) => cid === state.collection)) state.collection = null;
  const tagBar = allTags.length || collections.length ? el('div', { class: 'tag-bar' }) : null;
  const filter = (tag, collection) => { state.tag = tag; state.collection = collection; renderTags(); renderList(true); };
  const renderTags = () => tagBar && tagBar.replaceChildren(
    el('button', { class: `tag ${state.tag || state.collection ? '' : 'active'}`, onclick: () => filter(null, null) }, t('credentials.all')),
    collections.map(([cid, name]) => el('button', {
      class: `tag team-tag ${state.collection === cid ? 'active' : ''}`, title: t('credentials.team_collection'),
      onclick: () => filter(null, state.collection === cid ? null : cid),
    }, icon('users', 'sm'), name)),
    allTags.map((t) => el('button', { class: `tag ${state.tag === t ? 'active' : ''}`, onclick: () => filter(state.tag === t ? null : t, null) }, t)));
  // With a team account: tick several (checkbox on hover, shift-click for a range) to share them at once.
  const picking = !!(state.team && state.team.connected);
  const known = new Set(state.entries.map((e) => e.id));
  state.picked = new Set([...state.picked].filter((id) => picking && known.has(id)));
  let lastPicked = null;
  const bulkBar = el('div', { class: 'bulk-bar hidden' });
  const renderBulk = () => {
    const picked = state.entries.filter((e) => state.picked.has(e.id));
    const shareable = picked.filter((e) => !e.shared && !e.draft);
    list.classList.toggle('picking', picked.length > 0);
    bulkBar.classList.toggle('hidden', !picked.length);
    bulkBar.replaceChildren(
      el('span', { class: 'small' }, tn('list.selected', picked.length)),
      el('div', { class: 'spacer' }),
      el('button', {
        class: 'btn primary', disabled: !shareable.length || teamOffline(),
        title: shareable.length < picked.length ? t('credentials.ones_already_shared_or_missing') : null,
        onclick: () => shareEntries(shareable, () => { state.picked.clear(); }),
      }, icon('share', 'sm'), t('credentials.share_count', { length: shareable.length })),
      el('button', { class: 'btn icon-only', title: t('credentials.clear_selection_esc'), onclick: () => { state.picked.clear(); renderList(); } }, icon('x', 'sm')));
  };
  const toggle = (entry, items, range) => {
    const ids = items.map((e) => e.id);
    const targets = range && lastPicked && ids.includes(lastPicked)
      ? ids.slice(Math.min(ids.indexOf(lastPicked), ids.indexOf(entry.id)), Math.max(ids.indexOf(lastPicked), ids.indexOf(entry.id)) + 1)
      : [entry.id];
    const on = range ? true : !state.picked.has(entry.id);
    targets.forEach((id) => (on ? state.picked.add(id) : state.picked.delete(id)));
    lastPicked = entry.id;
    renderList();
  };
  const listBadge = (entry) => {
    const unsent = unsentText(entry);
    const reminder = state.reminders && state.reminders[entry.id];
    if (entry.draft) return el('span', { class: 'draft-badge' }, t('common.key_missing'));
    if (entry.shared && entry.shared.pending_delete) return el('span', { class: 'draft-badge is-danger', title: t('credentials.deleted_for_team_along_with') }, t('credentials.deletion_on_hold'));
    if (entry.shared && entry.shared.pending_change) return el('span', { class: 'draft-badge', title: changeSummary(entry.shared.pending_change) }, t('credentials.review_change'));
    if (unsent) return el('span', { class: 'draft-badge', title: unsent }, t('common.not_sent'));
    const rotating = rotationBadge(entry);
    if (rotating) return rotating;
    if (reminder) return el('span', { class: `draft-badge ${reminderTone(reminder)}`, title: reminderText(reminder) }, reminderShort(reminder));
    return levelDot(entry.id);
  };
  // `pickFirst`: the search or a filter changed, so the first match is selected when the current one is gone.
  const renderList = (pickFirst = false) => {
    const query = state.search.trim().toLowerCase();
    const items = sortEntries(state.entries.filter((e) => (!state.tag || (e.tags || []).includes(state.tag))
      && (!state.collection || (e.shared && e.shared.collection === state.collection)) && (!query
      || [e.name, e.id, e.description, subtitleOf(e), TEMPLATES[e.template].label, ...(e.tags || []),
        e.shared ? collectionLabel(e.shared) : ''].join(' ').toLowerCase().includes(query))), sortSelect.value);
    shown = items;
    if (pickFirst && items.length && !items.some((e) => e.id === state.selected)) {
      state.selected = items[0].id;
      renderDetail(detail);
    }
    const filtered = items.length !== state.entries.length;
    countText.textContent = filtered ? t('approval.position', { position: items.length, total: state.entries.length })
      : tn('common.credentials_count', state.entries.length);
    const scroll = list.scrollTop;
    const focused = list.contains(document.activeElement) && document.activeElement.dataset.id;
    list.replaceChildren(items.map((entry) => el('div', {
      class: `row ${state.selected === entry.id ? 'selected' : ''} ${state.picked.has(entry.id) ? 'picked' : ''}`,
      role: 'option', tabindex: '-1', 'aria-selected': String(state.selected === entry.id), 'data-id': entry.id,
      onclick: (event) => {
        if (picking && (event.shiftKey || event.ctrlKey)) { event.preventDefault(); toggle(entry, items, event.shiftKey); return; }
        state.selected = entry.id; lastPicked = entry.id; renderList(); renderDetail(detail);
        list.querySelector('.row.selected')?.focus({ preventScroll: true });
      },
      ondblclick: () => openEditor(entry),
    }, picking ? el('div', { class: 'pick-slot' }, glyph(entry.template),
      el('input', { type: 'checkbox', class: 'pick', checked: state.picked.has(entry.id), title: t('credentials.select_shift_click_several_in'),
        'aria-label': t('credentials.select', { name: entry.name }), onclick: (event) => { event.stopPropagation(); event.preventDefault(); toggle(entry, items, event.shiftKey); } }))
      : glyph(entry.template), el('div', { class: 'meta' },
      el('div', { class: 'title' }, el('span', { class: 'name' }, entry.name), entry.shared ? el('span', { class: 'shared-mark', title: sharedText(entry.shared) }, icon('users', 'sm')) : null),
      el('div', { class: 'subtitle' }, subtitleOf(entry))),
    listBadge(entry))));
    if (!items.length) list.append(el('p', { class: 'muted', style: 'padding:12px 10px' }, t('credentials.nothing_matches')));
    list.scrollTop = scroll;
    if (focused) list.querySelector(`.row[data-id="${CSS.escape(focused)}"]`)?.focus({ preventScroll: true });
    renderBulk();
  };
  list.addEventListener('keydown', (event) => { if (event.key === 'Escape' && state.picked.size) { state.picked.clear(); renderList(); } });

  if (!state.selected) state.selected = sortEntries(state.entries, sortSelect.value)[0].id;
  content.replaceChildren(header, tagBar, el('div', { class: 'split', style: 'flex:1;min-height:0' },
    el('div', { class: 'list-pane' }, el('div', { class: 'list-tools' }, countText, sortSelect), bulkBar, list),
    el('div', { class: 'rule' }), detail));
  renderTags();
  renderList();
  renderDetail(detail);
  // Redrawn in place when something changes behind (the AI, sb, the team): same scroll, focus and selection.
  state.listView = {
    alive: () => list.isConnected,
    refresh: () => { renderTags(); renderList(true); refreshDetail(detail); },
  };
}

// Redraw the detail keeping where the user was: its scroll and the focused control (by position and label).
function refreshDetail(panel) {
  const scroll = panel.scrollTop;
  const active = panel.contains(document.activeElement) ? document.activeElement : null;
  const controls = () => [...panel.querySelectorAll('button, input, select, textarea, a[href]')];
  const index = active ? controls().indexOf(active) : -1;
  const label = active ? (active.innerText || active.title || '').trim() : '';
  renderDetail(panel);
  panel.scrollTop = scroll;
  if (index >= 0) {
    const all = controls();
    const same = all.find((c) => (c.innerText || c.title || '').trim() === label && Math.abs(all.indexOf(c) - index) <= 3) || all[index];
    same?.focus({ preventScroll: true });
  }
}

// Something changed outside this window (the AI, sb import, the team sync, an approval): reload and redraw what
// is on screen without rebuilding it, so nothing jumps under the user's cursor.
async function refreshInPlace() {
  if (!await loadEntries(true) || state.screen !== 'main') return;
  updateSidebarState();
  updateNavCounts();
  if (state.view !== 'credentials') return;
  const view = state.listView;
  if (view && view.alive() && state.entries.length) view.refresh();
  else if (!view !== !state.entries.length || (view && !view.alive())) renderView();  // first one in, or the last one gone
}

function updateNavCounts() {
  const counts = { credentials: [state.entries.length, ''], exposure: [exposedCount(), 'danger'] };
  for (const [view, [count, tone]] of Object.entries(counts)) {
    const button = document.querySelector(`.nav button[data-view="${view}"]`);
    if (!button) continue;
    let badge = button.querySelector('.count');
    if (!count) { badge?.remove(); continue; }
    if (!badge) { badge = el('span', { class: `count ${tone}` }); button.append(badge); }
    badge.textContent = count;
  }
}

// The same tone in the list badge and in the banner of the detail: red when it no longer works or may have leaked.
function reminderTone(r) {
  return ['expired', 'team_access'].includes(r.kind) ? 'is-danger' : '';
}

function reminderShort(r) {
  if (r.kind === 'team_access') {
    const people = r.people || [];
    if (r.unshared) return people.length > 2 ? t('reminder_short.change_had_it', { length: people.length }) : tn('reminder.change_people_had_it', people.length, { names: listJoin(people) });
    return people.length > 2 ? t('reminder_short.change_left', { length: people.length }) : tn('reminder.change_people_left', people.length, { names: listJoin(people) });
  }
  return { expired: t('reminder_short.expired'), expiring: t('reminder_short.expires_in_d', { days: r.days }), old: t('reminder_short.old_key'), old_alive: t('common.revoke_old_one') }[r.kind];
}

function reminderText(r) {
  if (r.kind === 'team_access') {
    const count = (r.people || []).length;
    return `${tn(r.unshared ? 'reminder.unshared_access' : 'reminder.team_access_left', count, { names: listJoin(r.people) })} ${
      r.can_rotate ? tn('reminder.change_in_case', count) : tn('reminder.ask_manager_in_case', count)}`;
  }
  if (r.kind === 'old_alive') return t('reminder_text.you_rotated_key_but_old', { value: r.provider || t('common.provider_website') });
  if (r.kind === 'expired') return tn('reminder.expired_ago', r.days);
  if (r.kind === 'expiring') return tn('reminder.expires_in', r.days);
  return tn('reminder.key_age', r.days);
}

// A rotation left halfway, or what it could not finish: shown before any other reminder in the list.
function rotationBadge(entry) {
  if (entry.pending_rotation) return el('span', { class: 'draft-badge', title: t('common.new_password_is_ready_but') }, t('common.rotation_half_done'));
  if ((entry.failed_uploads || []).length) return el('span', { class: 'draft-badge is-danger', title: t('rotation_badge.couldn_upload', { value: entry.failed_uploads.map((u) => u.label).join(', ') }) }, t('rotation_badge.upload_failed'));
  if (entry.retired) return el('span', { class: 'draft-badge', title: t('common.new_key_active_old_one') }, t('common.revoke_old_one'));
  return null;
}

function activeSpecs(templateId, fields) {
  const specs = TEMPLATES[templateId].fields;
  const resolved = {};
  for (const s of specs) resolved[s.name] = s.default;
  for (const [k, v] of Object.entries(fields)) if (v) resolved[k] = v;
  return specs.filter((s) => !s.show_if || Object.entries(s.show_if).every(([k, v]) => resolved[k] === v));
}

function shortLabel(label) { return label.replace(/\s*\((opcional|si tiene|optional|if any)\)$/, ''); }

// Where a template's label says too little: [in the detail, in the editor].
const FIELD_LABELS = localized(() => ({ 'api_key.username': [t('field.app_identifier'), t('field.app_identifier_e_g_client')] }));
function fieldLabel(templateId, spec) { return (FIELD_LABELS[`${templateId}.${spec.name}`] || [shortLabel(spec.label)])[0]; }
function editorLabel(templateId, spec) { return (FIELD_LABELS[`${templateId}.${spec.name}`] || [null, shortLabel(spec.label)])[1]; }

// A message of the service in the editor's words: field labels instead of {{placeholders}} and internal ids.
function friendlyError(message, templateId) {
  const specs = (TEMPLATES[templateId] || { fields: [] }).fields;
  const label = (name) => { const spec = specs.find((s) => s.name === name); return spec ? fieldLabel(templateId, spec) : name === 'connection_url' ? t('friendly_error.connection_url') : name; };
  return String(message || '')
    .replace(/el dato \{\{\s*([a-z_]+)\s*\}\} no existe en esta credencial/, (_, n) => t('friendly_error.uses_which_this_credential_doesn', { label: label(n) }))
    .replace(/\{\{\s*([a-z_]+)\s*\}\}/g, (_, n) => `«${label(n)}»`)
    .replace(/^Ya existe una credencial con el identificador '[^']*'$/, t('friendly_error.another_credential_already_has_same'))
    .replace(/^El identificador solo admite.*$/, t('friendly_error.name_for_ai_in_ai'));
}

// A free id for a new credential, from its name: the user never has to think about it.
function uniqueId(name, templateId) {
  const base = slugify(name) || templateId.replace('_', '-');
  const taken = new Set(state.entries.map((e) => e.id));
  if (!taken.has(base)) return base;
  for (let n = 2; ; n++) {
    const candidate = `${base.slice(0, 60)}-${n}`;
    if (!taken.has(candidate)) return candidate;
  }
}

function displayValue(spec, value) {
  if (spec.kind === 'select') {
    const option = spec.options.find((o) => o.value === value);
    return option ? option.label : value;
  }
  return value;
}

function copyButton(text) {
  return el('button', { class: 'btn icon-only', title: t('common.copy'), onclick: async () => { await api().copy_text(text); toast(t('common.copied')); } }, icon('copy', 'sm'));
}

function renderDetail(panel) {
  const entry = state.entries.find((e) => e.id === state.selected);
  if (!entry) { panel.replaceChildren(); return; }
  const template = TEMPLATES[entry.template];

  const props = activeSpecs(entry.template, entry.fields).map((spec) => {
    if (spec.secret) {
      if (!entry.secrets_set.includes(spec.name)) return null;
      if (useOnly(entry)) {
        return el('div', { class: 'prop' },
          el('div', { style: 'min-width:0' }, el('div', { class: 'k' }, shortLabel(spec.label)), el('div', { class: 'v secret' }, '••••••••••')),
          el('span', { class: 'faint small', title: PERMISSION_HELP.use }, t('common.use_only')));
      }
      if (spec.name === 'totp') return totpProp(entry, spec);  // personal.js: the live 2FA code
      const key = `${entry.id}:${spec.name}`;
      const revealed = state.revealed[key];
      const reveal = el('button', { class: 'btn icon-only', title: revealed ? t('common.hide') : t('common.show') }, icon(revealed ? 'eyeOff' : 'eye', 'sm'));
      reveal.addEventListener('click', async () => {
        if (state.revealed[key]) { delete state.revealed[key]; renderDetail(panel); return; }
        const result = await withProof((p) => api().call('reveal', { id: entry.id, field: spec.name }, p), t('detail.show', { label: spec.label, name: entry.name }));
        if (!result.ok) { if (result.code !== 'cancelled') toast(result.error, 'error'); return; }
        state.revealed[key] = result.result;
        renderDetail(panel);
        setTimeout(() => { if (state.revealed[key]) { delete state.revealed[key]; if (state.selected === entry.id) renderDetail(panel); } }, 30000);
      });
      const copy = el('button', { class: 'btn icon-only', title: t('common.copy') }, icon('copy', 'sm'));
      copy.addEventListener('click', async () => {
        const result = await withProof((p) => api().copy_secret(entry.id, spec.name, p), t('detail.copy', { label: spec.label, name: entry.name }));
        if (result.ok) toast(t('detail.copied_cleared_in', { result: result.result }));
        else if (result.code !== 'cancelled') toast(result.error, 'error');
      });
      return el('div', { class: 'prop' },
        el('div', { style: 'min-width:0' }, el('div', { class: 'k' }, shortLabel(spec.label)),
          el('div', { class: `v ${revealed ? 'revealed selectable' : 'secret'}` }, revealed || '••••••••••')),
        el('div', { class: 'actions' }, reveal, copy));
    }
    const raw = entry.fields[spec.name];
    if (!raw) return null;
    return el('div', { class: 'prop' },
      el('div', { style: 'min-width:0' }, el('div', { class: 'k' }, fieldLabel(entry.template, spec)),
        el('div', { class: 'v selectable', title: raw }, displayValue(spec, raw))),
      el('div', { class: 'actions' }, spec.kind === 'select' ? null : copyButton(raw)));
  });

  const perms = describePermissions(entry);
  const reminder = state.reminders && state.reminders[entry.id];
  const canShare = state.team && state.team.connected && !entry.shared && !entry.draft;
  panel.replaceChildren(
    el('div', { class: 'detail-head' },
      glyph(entry.template, 'lg'),
      el('div', { class: 'meta' }, el('h2', {}, entry.name),
        el('div', { class: 'muted small head-sub' }, template.label, entry.shared ? sharedBadge(entry.shared) : null)),
      canShare ? el('button', { class: 'btn ghost', onclick: () => shareEntry(entry), disabled: teamOffline(),
        title: teamOffline() ? t('common.no_connection_team_server') : null }, icon('share', 'sm'), t('common.share')) : null,
      el('button', { class: 'btn', onclick: () => openEditor(entry) }, t('detail.edit')),
      canWrite(entry) ? el('button', { class: 'btn icon-only', title: t('common.delete'), onclick: () => deleteEntry(entry) }, icon('trash', 'sm')) : null),
    entry.draft ? null : statusStrip(entry),
    entry.draft ? draftSection(entry, () => renderMain()) : null,
    entry.shared && entry.shared.pending_delete ? el('div', { class: 'warning is-danger', style: 'margin-bottom:12px' }, icon('trash', 'sm'),
      el('span', {}, entry.shared.pending_delete.gone
        ? t('detail.its_collection_no_longer_appears')
        : t('detail.deleted_along_with_others_nothing', { value: entry.shared.pending_delete.by || t('common.someone_2') }),
      el('button', { class: 'link', onclick: () => { state.view = 'team'; renderMain(); } }, t('detail.decide_in_team')), '.')) : null,
    entry.shared && entry.shared.pending_change ? pendingChangeBox(entry) : null,
    reminder && reminder.kind === 'team_access' ? el('div', { class: `warning ${reminderTone(reminder)}` }, icon('clock', 'sm'), el('span', {}, reminderText(reminder),
      reminder.can_rotate && entry.rotation
        ? [' ', el('button', { class: 'link small', onclick: () => rotateWithHelp(entry) }, t('common.rotate_with_help'))] : null)) : null,
    pendingRotationBox(entry),
    failedUploadsBox(entry),
    entry.retired && canWrite(entry) ? retiredBox(entry) : null,
    (entry.tags || []).length || entry.expires ? el('div', { class: 'tag-line' },
      (entry.tags || []).map((t) => el('span', { class: 'tag static' }, t)),
      entry.expires ? el('span', { class: 'muted small' }, t('detail.expires_on', { expires: entry.expires })) : null) : null,
    el('div', { class: 'section' }, props),
    entry.description ? el('div', { class: 'section' }, el('h3', { class: 'with-icon' }, icon('bot', 'sm'), t('common.instructions_for_ai')),
      el('p', { class: 'notes selectable muted' }, entry.description)) : null,
    providerSection(entry),
    rotationSection(entry),
    sharedSection(entry),
    el('div', { class: 'section' },
      el('h3', {}, t('common.what_ai_can_do')),
      perms.length ? perms : el('p', { class: 'muted' }, t('detail.nothing_yet_edit_credential_and')),
      el('p', { class: 'help', style: 'margin-top:6px' }, t('detail.ai_knows_as'), el('code', { class: 'selectable' }, entry.id))),
    entry.draft ? null : recentActivity(entry));
}

// The AI's last uses of a credential: when, which app, what (method and host) and how it went.
const RECENT_USES = 5;

function recentActivity(entry) {
  const box = el('div', { class: 'section recent' }, el('h3', {}, t('recent_activity.recent_activity')));
  const cache = state.recentCache || (state.recentCache = {});
  const draw = (events) => {
    const uses = events.filter((e) => eventActor(e)[0] === 'ai' && MONO_EVENT_ACTIONS.has(e.action)).slice(0, RECENT_USES);
    box.replaceChildren(el('h3', {}, t('recent_activity.recent_activity')), uses.length
      ? el('div', { class: 'recent-list' }, uses.map(recentRow))
      : el('p', { class: 'muted small' }, t('recent_activity.ai_hasn_used_yet')),
    uses.length ? el('button', { class: 'link small', style: 'align-self:flex-start;margin-top:4px', onclick: () => {
      state.activityFilter = { kind: null, secret: entry.id }; state.view = 'activity'; renderMain();
    } }, t('recent_activity.see_all_activity')) : null);
  };
  const known = cache[entry.id];
  const revision = (state.status || {}).revision;
  if (known) draw(known.events);
  if (!known || known.revision !== revision) {
    api().call('audit', { secret_id: entry.id, limit: 50 }).then((result) => {
      if (!result.ok) return;
      cache[entry.id] = { revision, events: result.result };
      if (box.isConnected) draw(result.result);
    });
  }
  return box;
}

function recentRow(e) {
  const [what, where] = useSummary(e);
  const failed = e.status === 'denied' || e.status === 'error';
  return el('div', { class: 'recent-row', title: [e.detail, e.message].filter(Boolean).join(' — ') },
    el('span', { class: 'when', title: e.ts ? fmtDate(e.ts, { dateStyle: 'full', timeStyle: 'short' }) : '' }, e.ts ? sinceText(e.ts) : ''),
    el('span', { class: 'who' }, icon('bot', 'sm'), e.client || t('common.ai')),
    el('span', { class: 'what' }, what ? el('b', {}, what) : null, what && where ? ' ' : null, where ? el('span', { class: 'mono' }, where) : null),
    el('span', { class: `chip ${failed ? 'is-exposed failed' : 'is-ok'}` }, e.status === 'denied' ? t('common.denied') : e.status === 'error' ? t('common.error') : t('recent_row.successful')));
}

// [verb, target] of a use in the activity: «GET» «api.example.com», «SSH» «deploy@server», «psql» «».
function useSummary(e) {
  const detail = (e.detail || '').split('\n')[0];
  if (e.action === 'http_request') {
    const [method, url] = detail.split(' ');
    return [method, hostOf(url || '')];
  }
  if (e.action === 'ssh_exec') return ['SSH', detail.split('$')[0]];
  if (e.action === 'ssh_upload' || e.action === 'ssh_download') return [e.action === 'ssh_upload' ? t('use_summary.upload') : t('use_summary.download'), (detail.match(/[^\s]+@[^\s:]+/) || [''])[0]];
  if (e.action === 'run_command') return [detail.split(' ')[0], ''];
  if (e.action === 'release_env') return ['sb run', ''];
  return [ACTION_LABELS[e.action] || e.action, ''];
}

// «ahora», «hace 5 min», «hace 3 h», «ayer 18:20», «12 oct 09:15».
function sinceText(iso) {
  const date = new Date(iso);
  const minutes = Math.round((Date.now() - date) / 60000);
  if (minutes < 1) return t('time.now');
  if (minutes < 60) return tn('time.minutes_ago', minutes);
  if (minutes < 6 * 60) return tn('time.hours_ago', Math.round(minutes / 60));
  const days = dayOffset(date);
  const time = fmtDate(date, { hour: 'numeric', minute: '2-digit' });
  if (days === 0) return time;
  return days === -1 ? t('time.day_time', { day: fmtRelative(-1, 'day'), time }) : formatTime(iso);
}

function describePermissions(entry) {
  const policy = entry.policy || {};
  const items = [];
  const http = policy.http || {};
  if (http.allowed_hosts && http.allowed_hosts.length) items.push(['globe', t('describe_permissions.requests', { value: http.allowed_hosts.join(', ') })]);
  if (entry.template === 'ssh') items.push(['server', t('describe_permissions.commands_and_files_on', { host: entry.fields.host })]);
  const commands = policy.commands || {};
  if (commands.allowed && commands.allowed.length) items.push(['terminal', t('describe_permissions.run_on_this_pc', { value: commands.allowed.join(', ') })]);
  if (!items.length) return [];
  const approval = policy.approval || 'session';
  items.push(['fingerprint', { session: t('describe_permissions.asks_you_once_per_session'), always: t('describe_permissions.asks_you_every_time'), never: t('describe_permissions.doesn_ask_you') }[approval]]);
  return items.map(([i, text]) => el('div', { class: 'perm' }, icon(i, 'sm'), el('span', {}, text)));
}

// ----------------------------------------------------------------------- provider links

function providerSection(entry) {
  const provider = entry.provider;
  if (!provider) return null;
  return el('div', { class: 'section' },
    el('h3', {}, provider.provider),
    provider.kind ? el('div', { class: 'provider-kind' },
      el('div', { style: 'font-weight:600' }, provider.kind.label),
      el('p', { class: 'help' }, provider.kind.help)) : null,
    linkList(provider.links));
}

function linkList(links) {
  return el('div', { class: 'link-list' }, links.map((link) => el('button', {
    class: 'link-row', type: 'button', title: link.url, onclick: () => api().open_link(link.url),
  }, el('div', { style: 'min-width:0' }, el('div', { class: 'link-label' }, link.label),
    link.hint ? el('div', { class: 'help' }, link.hint) : null), icon('external', 'sm'))));
}

// "Where do I get the key?": the provider's key pages, from the new-key form.
function keySourcePicker() {
  const providers = state.info.providers || [];
  const select = el('select', { class: 'input' }, el('option', { value: '' }, t('key_source_picker.choose_provider')),
    providers.map((p, i) => el('option', { value: String(i) }, p.provider)));
  const details = el('div', {});
  select.addEventListener('change', () => {
    const provider = providers[Number(select.value)];
    details.replaceChildren(provider ? el('div', { style: 'margin-top:6px' },
      provider.help ? el('p', { class: 'help' }, provider.help) : null, linkList(provider.links)) : '');
  });
  return el('div', { class: 'field' }, el('label', {}, t('key_source_picker.where_do_i_get_key'), el('span', { class: 'req' }, t('common.optional_suffix'))),
    select, details);
}

// ----------------------------------------------------------------------- rotation

function destinationLabel(d) {
  return t('destination_label.github', { repo: d.repo, value: d.environment ? ` (${d.environment})` : '', name: d.name });
}

const ROTATE_EVERY = localized(() => ([[null, t('common.general_setting')], [30, t('rotate_every.30_days')], [60, tn('time.months', 2)], [90, tn('time.months', 3)], [180, tn('time.months', 6)], [365, t('common.1_year')], [0, t('common.never')]]));

// «cada año», «cada 6 meses», «cada 30 días».
function everyLabel(days) {
  if (days % 365 === 0) return days === 365 ? t('every_label.every_year') : t('every_label.every_years', { value: days / 365 });
  if (days % 30 === 0 && days >= 60) return tn('time.every_months', days / 30);
  return days === 1 ? t('every_label.every_day') : t('every_label.every_days', { days });
}

// Days between rotation reminders for this credential (0: never), and whether it is the general setting.
function rotateEvery(entry) {
  const own = entry.rotate_every_days;
  const general = own === null || own === undefined;
  return { days: general ? (state.status.rotate_reminder_days ?? 365) : own, general };
}

function cadenceText(entry) {
  const { days, general } = rotateEvery(entry);
  if (!days) return general ? t('cadence_text.rotation_reminders_are_turned_off') : t('cadence_text.doesn_remind_you_rotate');
  let text = t('cadence_text.reminds_you_rotate', { every: everyLabel(days), value: general ? t('common.general_setting_suffix') : '' });
  if (entry.secret_since) {
    const due = new Date(new Date(entry.secret_since).getTime() + days * 86400000);
    text += t('cadence_text.next_time_around', { value: fmtDate(due, { day: 'numeric', month: 'long', year: 'numeric' }) });
  }
  return t('cadence_text.you_can_change_when_you', { text });
}

// «en 3 meses», «en 12 días», «en un año», «mañana».
function inTime(days) {
  if (days <= 1) return fmtRelative(days === 1 ? 1 : 0, 'day');
  if (days < 45) return tn('time.in_days', days);
  if (days < 330) return tn('time.in_months', Math.round(days / 30));
  return tn('time.in_years', Math.max(1, Math.round(days / 365)));
}

// «hoy a las 10:02», «ayer a las 18:40», «el 3 oct a las 10:02».
function atText(iso) {
  const date = new Date(iso);
  const time = fmtDate(date, { hour: 'numeric', minute: '2-digit' });
  const days = dayOffset(date);
  if (days === 0 || days === -1) return t('time.relative_day_at', { day: fmtRelative(days, 'day'), time });
  return t('time.date_at', { date: fmtDate(date, { day: 'numeric', month: 'short' }), time });
}

// Days from today to `date` by the calendar: 0 today, -1 yesterday, 1 tomorrow.
function dayOffset(date) {
  const start = (d) => new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime();
  return Math.round((start(date) - start(new Date())) / 86400000);
}

function capitalized(text) { return text.charAt(0).toUpperCase() + text.slice(1); }

// «hoy 10:02», «ayer 18:40», «3 oct 10:02».
function whenText(iso) {
  if (!iso) return '';
  const date = new Date(iso);
  const time = fmtDate(date, { hour: 'numeric', minute: '2-digit' });
  const days = dayOffset(date);
  const day = days === 0 || days === -1 ? fmtRelative(days, 'day') : fmtDate(date, { day: 'numeric', month: 'short' });
  return t('time.day_time', { day, time });
}

// How often each key is tested with its provider: hours, -1 once per value, 0 never, null the general setting.
const CHECK_EVERY = localized(() => ([[1, t('check_every.every_hour')], [6, t('check_every.every_6_hours')], [12, t('check_every.every_12_hours')], [24, t('check_every.every_day')], [168, t('check_every.every_week')],
  [720, t('check_every.every_month')], [8760, t('check_every.every_year')], [-1, t('check_every.only_once_each_new_key')], [0, t('common.never')]]));

function checkLabel(hours) {
  const found = CHECK_EVERY.find(([h]) => h === hours);
  if (found) return lowerFirst(found[1]);
  return hours % 24 === 0 ? t('check_label.every_days', { value: hours / 24 }) : tn('time.every_hours', hours);
}

// A select with the usual intervals plus «Cada X horas…»; value() is the number (or null for the general setting).
function checkEveryControl(current, withGeneral, onChange) {
  const presets = CHECK_EVERY.map(([h]) => h);
  const custom = current !== null && current !== undefined && !presets.includes(current);
  const select = el('select', { class: 'input', style: 'width:auto' },
    withGeneral ? el('option', { value: '' }, t('common.general_setting')) : null,
    CHECK_EVERY.map(([h, label]) => el('option', { value: String(h) }, label)),
    el('option', { value: 'custom' }, t('check_every_control.every_x_hours')));
  select.value = custom ? 'custom' : current === null || current === undefined ? (withGeneral ? '' : '24') : String(current);
  const hours = el('input', { class: 'input', type: 'number', min: '1', max: '87600', step: '1', style: 'width:90px',
    value: custom ? String(current) : '48', title: t('check_every_control.hours_between_checks') });
  const hoursBox = el('span', { style: 'display:inline-flex;gap:6px;align-items:center' }, hours, el('span', { class: 'muted small' }, t('time.hours_label')));
  const sync = () => { hoursBox.style.display = select.value === 'custom' ? 'inline-flex' : 'none'; };
  const value = () => {
    if (select.value === '') return null;
    if (select.value !== 'custom') return Number(select.value);
    const n = Number(hours.value);
    if (!Number.isInteger(n) || n < 1 || n > 87600) throw new Error(t('check_every_control.hours_between_checks_must_be'));
    return n;
  };
  select.addEventListener('change', () => { sync(); if (onChange && select.value !== 'custom') onChange(); });
  hours.addEventListener('change', () => { if (onChange) onChange(); });
  sync();
  return { node: el('span', { style: 'display:inline-flex;gap:8px;align-items:center;flex-wrap:wrap' }, select, hoursBox), value, select };
}

function checkCadenceText(entry) {
  const own = entry.check_every_hours;
  const hours = own === null || own === undefined ? (state.status.check_every_hours ?? 24) : own;
  const general = own === null || own === undefined ? t('common.general_setting_suffix') : '';
  if (hours === 0) return t('check_cadence_text.isn_tested_automatically_you_can', { general });
  if (hours === -1) return t('check_cadence_text.each_new_key_is_tested', { general });
  return t('check_cadence_text.tested', { check: checkLabel(hours), general });
}

// What a credential needs at a glance, under its name: copies found, when to rotate it, where it is used
// and when it was last tested. Each chip opens what it talks about.
function statusStrip(entry) {
  const chips = [];
  const chip = (level, text, title, onclick) => {
    const button = el('button', { class: `status-chip is-${level}`, title, onclick: () => onclick(button) },
      el('span', { class: 'level-dot' }), el('span', {}, text));
    chips.push(button);
  };
  const item = exposureOf(entry.id);
  if (item) {
    const text = { exposed: t('common.exposed'), warning: item.found_before ? t('status_strip.was_exposed') : t('common.review'), ok: t('common.no_known_copies'), unknown: t('status_strip.not_searched_for_copies') }[item.level];
    chip(item.level, text, item.reasons.map((r) => r.text).join(' ') || t('status_strip.see_copies_found'), () => openHealth(entry.id));
  }
  const writable = canWrite(entry);
  if (entry.pending_rotation) {
    chip('warning', t('common.rotation_half_done'), t('common.new_password_is_ready_but'), () => rotateWithHelp(entry));
  } else if (entry.retired) {
    chip('warning', t('status_strip.old_one_still_needs_revoking'), t('common.new_key_active_old_one'), () => document.querySelector('.retired-box')?.scrollIntoView({ block: 'center', behavior: 'smooth' }));
  } else if (entry.secret_since && (entry.rotation || canChangePassword(entry) || entry.guide)) {
    const reminder = state.reminders && state.reminders[entry.id];
    const { days } = rotateEvery(entry);
    const age = Math.floor((Date.now() - new Date(entry.secret_since).getTime()) / 86400000);
    const due = days ? days - age : null;
    const late = reminder && ['old', 'expired', 'expiring'].includes(reminder.kind);
    const text = late ? (reminder.kind === 'old' ? t('status_strip.time_rotate') : reminderShort(reminder))
      : due !== null ? t('status_strip.rotate', { inTime: inTime(due) }) : t('status_strip.set', { age: ageText(age) });
    chip(late ? 'warning' : 'neutral', text, `${late ? reminderText(reminder) : t('status_strip.value_set', { age: ageText(age) })} ${cadenceText(entry)}`,
      () => (writable ? rotateWithHelp(entry) : toast(t('status_strip.whoever_manages_team_collection_rotates'))));
  }
  if (entry.rotation || entry.template === 'database' || (entry.used_in || []).length) {
    const n = (entry.used_in || []).length;
    chip(n ? 'neutral' : 'unknown', n ? tn('status.used_in_places', n) : t('status_strip.no_places_noted'),
      n ? entry.used_in.join(' · ') : t('status_strip.note_where_used_when_you'), () => usedInModal(entry));
  }
  if (item && item.checkable) {
    const alive = item.alive;
    const checked = alive && alive.checked;
    const level = !alive ? 'unknown' : alive.status === 'ok' ? 'ok' : alive.status === 'invalid' ? 'exposed' : 'warning';
    const text = !alive ? t('status_strip.not_tested') : alive.status === 'ok' ? t('status_strip.works', { when: whenText(checked) })
      : alive.status === 'invalid' ? t('status_strip.doesn_work', { when: whenText(checked) }) : t('status_strip.no_response', { when: whenText(checked) });
    chip(level, text, t('status_strip.click_test_now', { value: alive && alive.message ? `${alive.message}. ` : '', checkCadence: checkCadenceText(entry) }), (button) => checkOne(entry, button));
  } else if (['api_key', 'generic'].includes(entry.template) && writable) {
    chip('unknown', t('status_strip.can_be_tested'), t('status_strip.app_doesn_know_how_test'), () => testRequestModal(entry));
  }
  return chips.length ? el('div', { class: 'status-strip' }, chips) : null;
}

function openHealth(focus) {
  state.view = 'exposure';
  state.healthFocus = focus || null;
  renderMain();
}

async function checkOne(entry, button) {
  busy(button, true);
  const result = await api().check_exposure(entry.id);
  busy(button, false);
  if (!result.ok) { toast(result.error, 'error'); return; }
  state.exposure = result.result;
  renderMain();
  const alive = (exposureOf(entry.id) || {}).alive;
  if (!alive) toast(t('common.couldn_test'));
  else if (alive.status === 'ok') toast(t('check_one.works_accepts', { provider: alive.provider }));
  else toast(alive.message || t('common.couldn_test'), 'error');
}

function usedInModal(entry) {
  const places = entry.used_in || [];
  const modal = openModal({
    title: t('used_in_modal.where_is_used', { name: entry.name }),
    body: [places.length ? el('ul', { class: 'used-in' }, places.map((p) => el('li', {}, p)))
      : el('p', { class: 'muted' }, t('used_in_modal.where_used_hasn_been_noted')),
    el('p', { class: 'help' }, t('used_in_modal.when_you_rotate_app_asks'))],
    footer: [el('div', { class: 'spacer' }), el('button', { class: 'btn', onclick: () => modal.close() }, t('common.close')),
      canWrite(entry) ? el('button', { class: 'btn primary', onclick: () => { modal.close(); openEditor(entry); } }, places.length ? t('common.change') : t('used_in_modal.note_them')) : null],
  });
}

// How to test a key the app does not know: a read-only request to one of its allowed hosts.
function testRequestModal(entry) {
  const test = entry.test_request || {};
  const base = (entry.fields.base_url || entry.fields.url || '').replace(/\/+$/, '');
  const shown = test.url && base && test.url.startsWith(base) ? test.url.slice(base.length) || '/' : test.url || '';
  const method = el('select', { class: 'input', style: 'width:auto' }, ['GET', 'HEAD'].map((m) => el('option', { value: m, selected: (test.method || 'GET') === m }, m)));
  const url = el('input', { class: 'input mono', value: shown, placeholder: base ? '/v1/me' : 'https://api.ejemplo.com/v1/me', spellcheck: 'false' });
  const status = el('input', { class: 'input', type: 'number', min: '200', max: '399', value: String(test.status || 200), style: 'width:90px' });
  const errorText = el('div', { class: 'error-text' });
  const save = el('button', { class: 'btn primary' }, t('test_request_modal.save_and_test'));
  const remove = entry.test_request ? el('button', { class: 'btn ghost' }, t('common.remove')) : null;
  const ask = t('test_request_modal.look_up_in_api_documentation', { name: entry.name, id: entry.id });
  const modal = openModal({
    title: t('test_request_modal.how_test', { name: entry.name }),
    body: [
      el('p', { class: 'muted' }, t('test_request_modal.read_only_request_get_or')),
      el('div', { class: 'field' }, el('label', {}, t('test_request_modal.request')),
        el('div', { style: 'display:flex;gap:8px' }, method, el('div', { style: 'flex:1' }, url)),
        el('div', { class: 'help' }, base ? t('test_request_modal.path_under_or_full_address', { base }) : t('test_request_modal.full_address_on_its_allowed'))),
      el('div', { class: 'field' }, el('label', {}, t('test_request_modal.response_working_key')), el('div', { style: 'display:flex;gap:8px;align-items:center' }, el('span', { class: 'muted' }, 'HTTP'), status)),
      el('div', { class: 'help' }, t('test_request_modal.not_sure_which_ask_ai'), el('button', { class: 'link small', onclick: async () => { await api().copy_text(ask); toast(t('common.copied_paste_ai')); } }, t('test_request_modal.copy_request_for_ai'))),
      errorText,
    ],
    footer: [remove, el('div', { class: 'spacer' }), el('button', { class: 'btn', onclick: () => modal.close() }, t('common.cancel')), save],
  });
  const send = async (button, value) => {
    errorText.textContent = '';
    busy(button, true);
    const result = await withProof((p) => api().call('set_test_request', { id: entry.id, test: value, check: !!value }, p), t('test_request_modal.change_how_is_tested', { name: entry.name }));
    busy(button, false);
    if (!result.ok) { if (result.code !== 'cancelled') errorText.textContent = result.error; return; }
    modal.close();
    await loadEntries();
    renderMain();
    const check = result.result.check;
    if (!value) toast(t('test_request_modal.test_removed'));
    else if (check && check.status === 'ok') toast(t('test_request_modal.saved_key_works'));
    else toast(t('test_request_modal.saved', { value: check ? check.message : t('common.couldn_test') }), 'error');
  };
  save.addEventListener('click', () => {
    if (!url.value.trim()) { errorText.textContent = t('test_request_modal.type_path_or_address_request'); return; }
    send(save, { method: method.value, url: url.value.trim(), status: Number(status.value) || 200 });
  });
  if (remove) remove.addEventListener('click', () => send(remove, {}));
  setTimeout(() => url.focus(), 50);
}

function rotationSection(entry) {
  const rotation = entry.rotation;
  if (!rotation) return null;
  if (!canWrite(entry)) {
    return el('div', { class: 'section' }, el('h3', {}, t('rotation_section.rotation')),
      el('p', { class: 'help' }, t('rotation_section.belongs_team_and_your_permission', { value: PERMISSION_LABELS[entry.shared.permission] })));
  }
  const destinations = entry.destinations || [];
  const guide = entry.guide || {};
  const apply = guide.apply || {};
  const apiButton = rotation.supported
    ? el('button', { class: 'btn', onclick: () => rotateEntry(entry) }, icon('rotate', 'sm'), t('rotation_section.rotate_key')) : null;
  const guidedButton = el('button', { class: rotation.supported ? 'btn ghost' : 'btn', onclick: () => rotateGuided(entry) },
    rotation.supported ? null : icon('rotate', 'sm'), rotation.supported ? t('rotation_section.rotate_manually') : t('common.rotate_with_help'));
  const testButton = ['api_key', 'generic'].includes(entry.template) && !rotation.supported && guide.kind !== 'database'
    && (!guide.testable || entry.test_request)
    ? el('button', { class: 'btn ghost', onclick: () => testRequestModal(entry) }, entry.test_request ? t('rotation_section.change_test') : t('rotation_section.how_test')) : null;
  const ask = t('rotation_section.look_up_in_official_documentation', { name: entry.name });
  // One line: what the app does for this one.
  const line = rotation.supported
    ? (destinations.length ? t('rotation.provider_rotates_uploads', { provider: rotation.provider, where: destinations.length === 1 ? destinationLabel(destinations[0]) : tn('rotation.n_places', destinations.length) })
      : t('rotation.provider_rotates', { provider: rotation.provider }))
    : guide.kind === 'database'
      ? (apply.available ? t('rotation_section.app_changes_in_database_with', { client: apply.client })
        : t(`rotation.app_gives_${guide.command ? 'command' : 'steps'}${guide.links && guide.links.length ? '_or_dashboard' : ''}`))
      : (guide.testable ? t('rotation.with_help_tested') : t('rotation.with_help'));
  return el('div', { class: 'section' },
    el('h3', {}, t('rotation_section.rotation'), guide.source === 'ai'
      ? el('span', { class: 'chip', title: (guide.written ? t('rotation.ai_guide_written_on', { date: guide.written }) : t('rotation.ai_guide_written')) }, t('rotation_section.ai_guide'))
      : guide.source === 'team'  // synced from a teammate: theirs, not this user's AI
        ? el('span', { class: 'chip', title: t('rotation.team_guide_written', { name: guide.by }) }, t('rotation_section.team_guide', { name: guide.by })) : null),
    el('p', { class: 'help' }, line,
      guide.source === 'generic' ? [' ', el('button', { class: 'link small', title: ask, onclick: async () => { await api().copy_text(ask); toast(t('common.copied_paste_ai')); } }, t('rotation_section.ask_ai_for_guide'))] : null),
    el('div', { style: 'margin-top:8px;display:flex;gap:8px;flex-wrap:wrap' }, apiButton, guidedButton, testButton));
}

// A rotation left halfway: the new password is kept in the vault (it may already be set somewhere).
function pendingRotationBox(entry) {
  const pending = entry.pending_rotation;
  if (!pending || !canWrite(entry)) return null;
  return el('div', { class: 'draft-box' },
    el('div', { class: 'warning is-warning' }, icon('alert', 'sm'), el('span', {}, t(entry.template === 'database' || canChangePassword(entry) ? 'rotation.half_done_password' : 'rotation.half_done_key', { at: atText(pending.since) }))),
    el('div', { style: 'margin-top:8px;display:flex;gap:8px' },
      el('button', { class: 'btn', onclick: () => rotateWithHelp(entry) }, t('common.finish_rotation'))));
}

// Places a rotated secret could not be uploaded to: they still have the old one.
function failedUploadsBox(entry) {
  const failed = entry.failed_uploads || [];
  if (!failed.length) return null;
  const retry = el('button', { class: 'btn' }, t('common.retry_upload'));
  retry.addEventListener('click', () => retryUploads(entry, retry));
  return el('div', { class: 'draft-box is-danger' },
    el('div', { class: 'warning' }, icon('alert', 'sm'), el('span', {}, t('failed_uploads_box.couldn_upload_new_one_old', { value: failed.map((u) => u.label).join(', ') }))),
    el('p', { class: 'help' }, failed[0].error),
    el('div', { style: 'margin-top:8px;display:flex;gap:8px' }, retry));
}

async function retryUploads(entry, button) {
  busy(button, true);
  const result = await withProof((p) => api().call('retry_uploads', { id: entry.id }, p), t('retry_uploads.upload_again', { name: entry.name }));
  busy(button, false);
  if (!result.ok) { if (result.code !== 'cancelled') toast(result.error, 'error'); return null; }
  await loadEntries();
  renderMain();
  const failed = result.result.uploads.filter((u) => !u.ok);
  if (failed.length) toast(t('retry_uploads.still_can_upload', { value: failed.map((u) => u.label).join(', '), value2: failed[0].error }), 'error');
  else toast(t('retry_uploads.uploaded_again'));
  return result.result;
}

// After a rotation by hand, the old key is kept until it is confirmed dead at the provider.
function retiredBox(entry) {
  const retired = entry.retired;
  const guide = entry.guide || {};
  const where = retired.provider || t('common.provider_website');
  const refresh = async () => { await loadEntries(); renderMain(); };
  const checkButton = retired.checkable ? el('button', { class: 'btn', onclick: async () => {
    busy(checkButton, true);
    const result = await api().call('check_retired', { id: entry.id });
    busy(checkButton, false);
    if (!result.ok) { toast(result.error, 'error'); return; }
    if (result.result.status === 'done') { toast(t('retired_box.old_key_no_longer_works')); refresh(); }
    else if (result.result.status === 'alive') toast(t('retired_box.old_key_still_works_revoke', { where }), 'error');
    else toast(result.result.message || t('retired_box.couldn_check'), 'error');
  } }, t('retired_box.check')) : null;
  const forget = el('button', { class: 'btn ghost', onclick: async () => {
    const result = await api().call('forget_retired', { id: entry.id });
    if (!result.ok) { toast(result.error, 'error'); return; }
    toast(t('common.rotation_complete'));
    refresh();
  } }, t('common.i_ve_revoked'));
  return el('div', { class: 'draft-box retired-box' },
    el('div', { class: 'warning is-warning' }, icon('alert', 'sm'), el('span', {}, retired.status === 'alive'
      ? t('retired_box.new_key_active_but_old', { where })
      : t('retired_box.new_key_active_old_one', { where }))),
    el('p', { class: 'help' }, guide.revoke || t('retired_box.delete_or_revoke_on_same'),
      (entry.used_in || []).length ? t('retired_box.first_check_that_they_re', { value: entry.used_in.join('; ') }) : ''),
    guide.links && guide.links.length ? linkList(guide.links.slice(0, 1)) : null,
    el('div', { style: 'margin-top:8px;display:flex;gap:8px' }, checkButton, forget));
}

function guideSteps(steps) {
  return el('ol', { class: 'guide-steps' }, steps.map((text) => el('li', {}, text)));
}

// The guided rotation. A new password is kept by the service from the moment it is shown (pending), so
// closing, locking or Esc never lose one that is already set somewhere; reopening offers to finish it.
// `after(saved)` runs when the dialog closes (the offboarding queue goes on to the next credential).
function rotateGuided(entry, after) {
  const guide = entry.guide || { create: [], links: [], sources: [] };
  const known = guide.provider || (entry.rotation && entry.rotation.provider);
  const provider = known || t('rotate_guided.provider');
  const site = known ? t('rotate_guided.website', { known }) : t('rotate_guided.service_website');
  const database = guide.kind === 'database';
  const apply = guide.apply || {};
  const exposureBefore = exposureOf(entry.id);  // its findings are for the old value: gone once it changes
  const suggested = `${entry.id}-${new Date().toISOString().slice(0, 7)}`;
  const env = Object.keys(((entry.policy || {}).commands || {}).env || {});
  const automatic = [
    ...(entry.destinations || []).map((d) => t('rotate_guided.uploaded_again_automatically', { destination: destinationLabel(d) })),
    ...(env.length ? [t('rotate_guided.your_programs_with_sb_run', { value: env.join(', ') })] : []),
  ];
  const titles = database
    ? [t('common.where_used'), t('rotate_guided.change_password'), t('rotate_guided.put_in_each_place')]
    : [t('common.where_used'), t('rotate_guided.create_new_key'), guide.generate ? t('rotate_guided.new_secret') : t('rotate_guided.paste_new_key'), t('rotate_guided.put_in_each_place'), t('rotate_guided.revoke_old_key')];
  const body = el('div', {});
  const foot = el('div', { style: 'display:contents' });
  let places = [...(entry.used_in || [])];
  let pending = entry.pending_rotation;  // {since, generated}: a new one kept by the service, never its value
  let saved = false;  // the new one is the current one
  let finished = false;
  let current = 1;  // the step shown: from the second one on, something may already be done at the provider
  const modal = openModal({
    title: t('rotate_guided.rotate', { name: entry.name }), wide: true, body, footer: [foot],
    confirmClose: () => (finished || (current === 1 && !pending && !saved) ? null
      : pending ? t(database ? 'rotation.pending_kept_password' : 'rotation.pending_kept_key')
        : saved ? t('rotate_guided.new_one_is_already_saved')
          : database ? t('common.nothing_has_been_changed_yet') : t('rotate_guided.if_you_already_created_new')),
    onClose: () => { if (after) after(saved); },
  });
  // The credential behind the dialog shows each step as it happens.
  const refresh = async () => { await loadEntries(); renderMain(); };
  const show = (step, nodes, buttons, title) => {
    current = step;
    body.replaceChildren(el('div', {},
      el('div', { class: 'steps', style: 'margin-bottom:14px' }, titles.map((_, i) => el('span', { class: i < step ? 'done' : '' }))),
      el('h3', {}, title || `${step} · ${titles[step - 1]}`), nodes));
    foot.replaceChildren(el('div', { class: 'spacer' }), ...buttons.filter(Boolean));
  };
  const line = (ok, text) => el('div', { class: 'perm' }, icon(ok ? 'check' : 'alert', 'sm'), el('span', {}, text));
  const done = (message, kind) => { finished = true; modal.close(); toast(message, kind); };

  // The new one prepared: generated by the service (it never reaches this page) or typed by the user.
  const begin = async (params, errorText) => {
    const result = await withProof((p) => api().call('rotation_begin', { id: entry.id, ...params }, p),
      t(database ? 'rotation.proof_prepare_password' : 'rotation.proof_prepare_key', { name: entry.name }));
    if (!result.ok) { if (result.code !== 'cancelled' && errorText) errorText.textContent = result.error; return false; }
    pending = result.result.pending_rotation;
    refresh();
    return true;
  };
  const copyPending = async (what) => {
    const result = await withProof((p) => api().copy_rotation_secret(entry.id, what, p), t(database ? 'rotation.proof_copy_password' : 'rotation.proof_copy_key', { name: entry.name }));
    if (result.ok) toast(t(what === 'command' ? 'rotation.copied_command' : 'rotation.copied_secret', { result: result.result }));
    else if (result.code !== 'cancelled') toast(result.error, 'error');
  };
  const masked = '••••••••••••';
  const pendingBox = (label, what = 'value') => el('div', { class: 'prop' },
    el('div', { style: 'min-width:0' }, el('div', { class: 'k' }, label), what === 'command'
      ? el('div', { class: 'v mono', style: 'white-space:normal' }, guide.command.replace('{password}', masked))
      : el('div', { class: 'v secret' }, masked)),
    el('div', { class: 'actions' }, el('button', { class: 'btn icon-only', title: t('common.copy'), onclick: () => copyPending(what) }, icon('copy', 'sm'))));

  // 0 · A rotation left halfway: did the new one get set where it lives?
  function resume() {
    const errorText = el('div', { class: 'error-text' });
    const yes = el('button', { class: 'btn primary' }, database || canChangePassword(entry) ? t('common.yes_i_changed_save') : t('rotate_guided.save_as_current_one'));
    yes.addEventListener('click', () => save(yes, errorText, { pending: true }));
    const discard = el('button', { class: 'btn', onclick: async () => {
      const result = await withProof((p) => api().call('rotation_discard', { id: entry.id }, p), t('common.discard_new_one', { name: entry.name }));
      if (!result.ok) { if (result.code !== 'cancelled') errorText.textContent = result.error; return; }
      pending = null;
      refresh();
      where();
    } }, t('common.no_discard'));
    const applyButton = database && apply.available ? el('button', { class: 'btn', onclick: () => applyNow(applyButton, errorText) }, t('rotate_guided.apply_now')) : null;
    show(0, [
      el('p', { class: 'muted' }, t(database ? 'rotation.half_done_unsaved_password' : 'rotation.half_done_unsaved_key', { capitalized: capitalized(atText(pending.since)) })
        + t(database ? 'rotation.already_put_database' : 'rotation.already_put_place')),
      pendingBox(database ? t('common.new_password') : t('rotate_guided.new_key'), 'value'),
      database && guide.command ? pendingBox(t('rotate_guided.command_with_new_password'), 'command') : null,
      errorText,
    ], [discard, applyButton, yes], t('common.rotation_half_done_did_you'));
  }

  // 1 · Every place that will need the new one: asked first, kept with the credential for next time.
  function where() {
    const list = el('div', { class: 'used-in-edit' });
    const input = el('input', { class: 'input', placeholder: t('rotation.used_in_placeholder') });
    const render = () => list.replaceChildren(places.length
      ? places.map((place, i) => el('div', { class: 'perm' }, el('span', { class: 'muted' }, '•'), el('span', { style: 'flex:1' }, place),
        el('button', { class: 'btn icon-only', title: t('common.remove'), onclick: () => { places.splice(i, 1); render(); } }, icon('x'))))
      : el('p', { class: 'help' }, t('rotate_guided.no_places_noted_yet')));
    const add = () => {
      const value = input.value.trim();
      if (value && !places.includes(value)) places.push(value);
      input.value = '';
      render();
      input.focus();
    };
    input.addEventListener('keydown', (event) => { if (event.key === 'Enter') add(); });
    render();
    show(1, [
      el('p', { class: 'muted' }, database
        ? t('rotate_guided.as_soon_as_password_changes')
        : t('rotate_guided.once_you_have_new_one')),
      list,
      el('div', { style: 'display:flex;gap:8px;margin-top:8px' }, input, el('button', { class: 'btn', onclick: add }, t('common.add'))),
      automatic.length ? el('p', { class: 'help', style: 'margin-top:10px' }, t('rotate_guided.app_takes_care_this', { value: automatic.join('; ') })) : null,
      el('p', { class: 'help' }, t('rotate_guided.saved_in_credential_for_next')),
    ], [el('button', { class: 'btn', onclick: () => modal.close() }, t('common.cancel')),
      el('button', { class: 'btn primary', onclick: () => { if (input.value.trim()) add(); (database ? change : create)(); } }, t('rotate_guided.next'))]);
    setTimeout(() => input.focus(), 50);
  }

  const save = async (button, errorText, params, aiApplies = false) => {
    busy(button, true);
    const result = await withProof((p) => api().call('replace_key', { id: entry.id, used_in: places, ...params }, p),
      t(database ? 'rotation.proof_save_password' : 'rotation.proof_save_key', { name: entry.name }));
    busy(button, false);
    if (!result.ok) { if (result.code !== 'cancelled') errorText.textContent = result.error; return; }
    pending = null;
    saved = true;
    refresh();
    update(result.result, aiApplies ? 'ai' : 'user');
  };

  const applyNow = async (button, errorText, manual) => {
    errorText.textContent = '';
    busy(button, true);
    const result = await withProof((p) => api().call('rotation_apply', { id: entry.id, used_in: places }, p), t('rotate_guided.change_password_2', { name: entry.name }));
    busy(button, false);
    if (!result.ok) {
      if (result.code === 'cancelled') return;
      errorText.textContent = result.code === 'unverified'
        ? t('rotate_guided.new_one_is_still_saved', { error: result.error })
        : t('rotate_guided.nothing_has_been_changed_you', { error: result.error });
      if (manual) manual();
      refresh();
      return;
    }
    pending = null;
    saved = true;
    refresh();
    update(result.result, 'service');
  };

  // 2 · Databases: the service changes it itself when it can; otherwise the exact command (or the panel).
  async function change() {
    const errorText = el('div', { class: 'error-text' });
    if (guide.generate && !pending) {
      show(2, [el('div', { class: 'spinner' })], []);
      if (!await begin({ generate: true }, errorText)) { show(2, [errorText], [el('button', { class: 'btn', onclick: where }, t('rotate_guided.back'))]); return; }
    }
    const saveButton = el('button', { class: 'btn primary' }, t('common.i_ve_changed_save'));
    const aiButton = guide.command ? el('button', { class: 'btn', title: t('rotate_guided.saved_now_and_ai_applies') }, t('rotate_guided.save_and_let_ai_apply')) : null;
    // A managed database whose panel makes the password: the user pastes it, and it is kept at once.
    const pasted = guide.generate ? null : passwordInput({ placeholder: t('rotate_guided.paste_one_dashboard_gave_you') });
    if (pasted) pasted.input.addEventListener('change', () => { if (pasted.input.value) begin({ value: pasted.input.value }, errorText); });
    const submit = async (button, ai) => {
      errorText.textContent = '';
      if (pasted) {
        if (!pasted.input.value) { errorText.textContent = t('rotate_guided.paste_password_dashboard_gave_you'); return; }
        save(button, errorText, { value: pasted.input.value }, ai);
      } else save(button, errorText, { pending: true }, ai);
    };
    saveButton.addEventListener('click', () => submit(saveButton, false));
    if (aiButton) aiButton.addEventListener('click', () => submit(aiButton, true));
    const own = el('button', { class: 'link small', onclick: () => {
      const typed = passwordInput({ placeholder: t('rotate_guided.your_new_password') });
      const use = el('button', { class: 'btn', onclick: async () => {
        if (!typed.input.value) return;
        if (await begin({ value: typed.input.value }, errorText)) { toast(t('rotate_guided.saved_as_pending')); change(); }
      } }, t('common.use_this_one'));
      own.replaceWith(el('div', { style: 'display:flex;gap:8px;margin-top:6px' }, el('div', { style: 'flex:1' }, typed), use));
      setTimeout(() => typed.input.focus(), 50);
    } }, t('rotate_guided.i_d_rather_type_my'));
    const manualNodes = [
      guideSteps(guide.create || []),
      guide.command ? pendingBox(t('rotate_guided.command_when_copied_includes_new'), 'command') : null,
      guide.command_note ? el('p', { class: 'help' }, guide.command_note) : null,
      guide.links && guide.links.length ? linkList(guide.links) : null,
    ];
    const manualBox = el('div', { class: 'manual-box' });
    const manualButtons = [el('button', { class: 'btn', onclick: where }, t('rotate_guided.back')), aiButton, saveButton];
    const showManual = () => {
      manualBox.replaceChildren(...manualNodes.filter(Boolean));
      foot.replaceChildren(el('div', { class: 'spacer' }), ...manualButtons.filter(Boolean));
    };
    const canApply = apply.available && guide.generate;
    const applyButton = canApply ? el('button', { class: 'btn primary' }, t('rotate_guided.apply_now_2')) : null;
    if (applyButton) applyButton.addEventListener('click', () => applyNow(applyButton, errorText, showManual));
    show(2, [
      guide.warning ? el('div', { class: 'warning' }, icon('alert', 'sm'), el('span', {}, guide.warning)) : null,
      pasted ? [guideSteps(guide.create || []), el('div', { class: 'field' }, el('label', {}, t('common.new_password')), pasted,
        el('div', { class: 'help' }, t('rotate_guided.saved_here_as_pending_as'))),
      guide.links && guide.links.length ? linkList(guide.links) : null]
        : [pendingBox(t('rotate_guided.new_password_saved_here_not')),
          el('div', { class: 'help' }, t('rotate_guided.32_random_letters_and_numbers'), own)],
      canApply ? el('p', { class: 'muted', style: 'margin-top:10px' }, t('rotate_guided.app_connects_with_current_one', { client: apply.client }))
        : !pasted && apply.reason ? el('p', { class: 'help', style: 'margin-top:10px' }, apply.reason) : null,
      pasted ? null : manualBox,
      errorText,
    ], canApply
      ? [el('button', { class: 'btn', onclick: where }, t('rotate_guided.back')), el('button', { class: 'btn', onclick: showManual }, t('rotate_guided.i_ll_do_myself')), applyButton]
      : [el('button', { class: 'btn', onclick: where }, t('rotate_guided.back')), aiButton, saveButton]);
    if (!canApply && !pasted) manualBox.replaceChildren(...manualNodes.filter(Boolean));
  }

  // 2 · API keys: where to create the new one.
  const paired = guide.paired;
  let idChoice = null;  // 'same' | 'new': the user must say it, never assumed
  const oldId = paired ? paired.value : '';
  const create = () => show(2, [
    el('p', { class: 'muted' }, t('rotate_guided.create_at_current_one_keeps', { site })),
    guide.warning ? el('div', { class: 'warning' }, icon('alert', 'sm'), el('span', {}, guide.warning)) : null,
    guideSteps(guide.create || []),
    el('div', { class: 'prop' }, el('div', { style: 'min-width:0' }, el('div', { class: 'k' }, t('rotate_guided.suggested_name_for_key')),
      el('div', { class: 'v selectable' }, suggested)), el('div', { class: 'actions' }, copyButton(suggested))),
    guide.links && guide.links.length ? linkList(guide.links) : null,
    ['ai', 'team'].includes(guide.source) ? el('p', { class: 'help' }, icon(guide.source === 'team' ? 'users' : 'sparkles', 'sm'),
      guide.source === 'team' ? t('rotate_guided.guide_written_by_teammate_sources', { name: guide.by }) : t('rotate_guided.guide_written_by_ai_sources'),
      (guide.sources || []).map((url, i) => [i ? ', ' : '', el('button', { class: 'link small', onclick: () => api().open_link(url) }, hostOf(url))])) : null,
  ], [el('button', { class: 'btn', onclick: where }, t('rotate_guided.back')),
    el('button', { class: 'btn primary', onclick: paste }, t('rotate_guided.i_have'))]);

  // 3 · Paste it: tested before it replaces the current one (when it can be tested).
  function paste() {
    const group = passwordInput({ placeholder: t('rotate_guided.paste_new_key_here') });
    const errorText = el('div', { class: 'error-text' });
    const saveButton = el('button', { class: 'btn primary' }, guide.testable ? t('rotate_guided.test_and_save') : t('common.save'));
    const idInput = el('input', { class: 'input mono', placeholder: paired && paired.hint ? paired.hint : '', spellcheck: 'false' });
    saveButton.addEventListener('click', () => {
      errorText.textContent = '';
      const value = group.input.value.trim();
      if (!value && !pending) { errorText.textContent = t('rotate_guided.paste_new_key_2'); return; }
      const params = value ? { value } : { pending: true };
      if (paired) {
        if (!idChoice) { errorText.textContent = t('rotate_guided.say_whether_is_same_or', { label: paired.label }); return; }
        params.paired_id = idChoice === 'same' ? oldId : idInput.value.trim();
        if (idChoice === 'new' && (!params.paired_id || params.paired_id === oldId)) {
          errorText.textContent = t('rotate_guided.paste_new', { label: paired.label }); idInput.focus(); return;
        }
      }
      save(saveButton, errorText, params);
    });
    group.input.addEventListener('keydown', (event) => { if (event.key === 'Enter') saveButton.click(); });
    const idField = el('div', { class: 'field hidden' }, el('label', {}, t('rotate_guided.new_label', { label: paired ? paired.label : '' })), idInput);
    const choice = (value, text) => el('label', { class: 'perm', style: 'cursor:pointer' },
      el('input', { type: 'radio', name: 'id-choice', value, checked: idChoice === value, onchange: () => {
        idChoice = value;
        errorText.textContent = '';
        idField.classList.toggle('hidden', value !== 'new');
        if (value === 'new') idInput.focus();
      } }), el('span', {}, text));
    const idQuestion = paired ? el('div', { class: 'field' },
      el('label', {}, t('rotate_guided.and', { label: paired.label })),
      choice('same', paired.value ? t('rotate_guided.same_i_only_created_new', { value: paired.value }) : t('rotate_guided.same_i_only_created_new_2')),
      choice('new', t(guide.provider === 'Microsoft Entra' ? 'rotation.id_changed_app' : 'rotation.id_changed_client')),
      idField) : null;
    // A secret of the user's own: generated and kept by the service, then copied to where it is used.
    const field = el('div', { class: 'field' });
    const renderField = () => field.replaceChildren(pending
      ? [pendingBox(t('rotate_guided.new_secret_saved_here_not')), el('div', { class: 'help' }, t('rotate_guided.copy_where_used_and_save'))]
      : [el('label', {}, t('rotate_guided.new_key')), group,
        el('div', { class: 'help' }, guide.testable
          ? t('rotate_guided.tested_with_before_replacing_current', { value: known || t('rotate_guided.its_api') })
          : t('rotate_guided.this_key_can_be_tested'))]);
    renderField();
    const generate = guide.generate ? el('button', { class: 'btn', onclick: async () => {
      if (await begin({ generate: true }, errorText)) { renderField(); toast(t('rotate_guided.generated_and_saved_as_pending')); }
    } }, pending ? t('rotate_guided.generate_another') : t('rotate_guided.generate_random_one')) : null;
    show(3, [field, generate, idQuestion, errorText], [el('button', { class: 'btn', onclick: create }, t('rotate_guided.back')), saveButton]);
    if (!pending) setTimeout(() => group.input.focus(), 50);
  }

  // Put it in every place: each one ticked before the old one is revoked (or, for a database, before finishing).
  // `how`: user (said it is changed), service (the app changed it and logged in with it) or ai (the AI will apply it).
  function update(result, how) {
    const check = result.check;
    const applyPrompt = t('rotate_guided.apply_new_password_database_already', { name: entry.name, id: entry.id })
      + `${(guide.command || '').replace("'{password}'", t('rotate_guided.new_one')).replace('"{password}"', t('rotate_guided.new_one')).replace('{password}', t('rotate_guided.new_one'))} `
      + t('rotate_guided.use_sb_run_or_run');
    const step = database ? 3 : 4;
    const next = el('button', { class: 'btn primary', onclick: () => {
      if (!database) revoke(result.entry.retired, result.id_changed);
      else if (how === 'ai') done(t('rotate_guided.new_password_saved_ai_still'));
      else done(t('common.rotation_complete'));
    } }, database ? t('rotate_guided.finish') : t('rotate_guided.next'));
    const left = el('div', { class: 'help' });
    const boxes = places.map(() => el('input', { type: 'checkbox' }));
    const sync = () => {
      const missing = boxes.filter((box) => !box.checked).length;
      next.disabled = missing > 0;
      left.textContent = missing ? tn('rotation.places_missing', missing, { then: database ? t('rotate_guided.until_you_put_there_those') : t('rotate_guided.don_revoke_old_one_until') }) : '';
    };
    boxes.forEach((box) => box.addEventListener('change', sync));
    sync();
    const uploads = el('div', {});
    const renderUploads = (list) => {
      const failed = list.filter((u) => !u.ok);
      const retry = failed.length ? el('button', { class: 'btn', onclick: async () => {
        const again = await retryUploads(entry, retry);
        if (again) renderUploads([...list.filter((u) => u.ok), ...again.uploads]);
      } }, t('common.retry_upload')) : null;
      uploads.replaceChildren(...list.map((u) => line(u.ok, u.ok ? t('rotate_guided.uploaded_as', { label: u.label, name: u.name }) : t('rotate_guided.couldn_upload_old_one_is', { label: u.label, error: u.error }))),
        retry ? el('div', { style: 'margin:4px 0 0 26px' }, retry) : '');
    };
    renderUploads(result.uploads);
    show(step, [
      how === 'ai' ? el('div', { class: 'warning' }, icon('alert', 'sm'), el('span', {},
        t('rotate_guided.saved_here_but_database_still'))) : null,
      how === 'ai' ? el('div', { class: 'prop' }, el('div', { class: 'v selectable', style: 'white-space:normal' }, applyPrompt),
        el('div', { class: 'actions' }, copyButton(applyPrompt))) : null,
      how === 'service' ? line(true, t('rotate_guided.changed_in_database_with_and', { client: apply.client })) : null,
      database ? line(true, t('rotate_guided.saved_connection_url_already_includes'))
        : check && check.status === 'ok' ? line(true, t('rotate_guided.works_accepts', { provider: check.provider }))
          : !guide.testable ? line(false, t('rotate_guided.this_key_can_be_tested_2'))
            : line(false, t('rotate_guided.couldn_test_with_was_saved', { provider, value: check && check.message ? ` (${check.message})` : '' })),
      line(true, t('rotate_guided.ai_already_uses_new_one')),
      result.id_changed ? line(true, t('rotate_guided.new_id_saved', { label: paired.label, value: result.entry.fields.username })) : null,
      (result.also_updated || []).map((o) => line(true, t('rotate_guided.id_has_also_been_changed', { name: o.name }))),
      uploads,
      env.length ? line(true, t('rotate_guided.your_programs_with_sb_run_2', { value: env.join(', ') })) : null,
      exposureBefore && exposureBefore.found && !database ? line(false, tn('rotation.old_key_exposed', exposureBefore.found)) : null,
      places.length
        ? el('div', { class: 'field', style: 'margin-top:10px' },
          el('label', {}, (result.id_changed ? t('rotation.put_in_each_place_with_id', { label: paired.label }) : t('rotation.put_in_each_place'))),
          places.map((place, i) => el('label', { class: 'perm', style: 'cursor:pointer' }, boxes[i], el('span', {}, place))), left)
        : el('p', { class: 'help', style: 'margin-top:8px' }, t(database ? 'rotation.no_places_noted' : 'rotation.no_places_noted_revoke')),
    ], [next]);
  }

  // Revoke the old key at the provider, and check it is dead. Only then is the rotation complete.
  function revoke(retired, idChanged) {
    const status = el('div', {});
    const checkable = retired && retired.checkable;
    const checkButton = el('button', { class: 'btn primary' }, t('rotate_guided.check_that_no_longer_works'));
    checkButton.addEventListener('click', async () => {
      busy(checkButton, true);
      const result = await api().call('check_retired', { id: entry.id });
      busy(checkButton, false);
      if (!result.ok) { status.replaceChildren(el('div', { class: 'error-text' }, result.error)); return; }
      const answer = result.result;
      refresh();
      if (answer.status === 'done') {
        finished = true;
        status.replaceChildren(el('div', { class: 'perm' }, icon('check', 'sm'), el('span', {}, t('rotate_guided.old_key_no_longer_works'))));
        foot.replaceChildren(el('div', { class: 'spacer' }), el('button', { class: 'btn primary', onclick: () => modal.close() }, t('rotate_guided.finish')));
      } else {
        status.replaceChildren(el('div', { class: 'warning' }, icon('alert', 'sm'), el('span', {}, answer.status === 'alive'
          ? t('rotate_guided.still_works_revoke_at_and', { provider })
          : answer.message || t('rotate_guided.couldn_check'))));
      }
    });
    const forget = el('button', { class: checkable ? 'btn ghost' : 'btn primary', onclick: async () => {
      const result = await api().call('forget_retired', { id: entry.id });
      if (!result.ok) { toast(result.error, 'error'); return; }
      refresh();
      done(t('common.rotation_complete'));
    } }, t('common.i_ve_revoked'));
    show(5, [
      el('p', { class: 'muted' }, idChanged
        ? t(guide.provider === 'Microsoft Entra' ? 'rotation.delete_old_app' : 'rotation.delete_old_client', { oldId, provider })
        : guide.revoke || t('rotate_guided.delete_or_revoke_old_key', { provider })),
      guide.links && guide.links.length ? linkList(guide.links.slice(0, 1)) : null,
      el('p', { class: 'help' }, checkable
        ? t('rotate_guided.then_app_checks_with_provider')
        : t('rotate_guided.this_key_can_be_checked')),
      status,
    ], [el('button', { class: 'btn', onclick: () => done(t('common.new_key_active_old_one')) }, t('common.later')),
      forget, checkable ? checkButton : null]);
  }

  if (pending) resume();
  else where();
}

async function rotateEntry(entry) {
  const destinations = entry.destinations || [];
  const modal = openModal({
    title: t('rotate_entry.rotate', { name: entry.name }),
    body: el('div', {},
      el('p', { class: 'muted' }, t('rotate_entry.will_create_new_key_and', { provider: entry.rotation.provider }),
        t('rotate_entry.apps_already_running_with_old')),
      destinations.length ? el('p', { class: 'muted' }, t('rotate_entry.new_one_will_also_be'), destinations.map(destinationLabel).join(', '), '.') : null),
    footer: [
      el('button', { class: 'btn', onclick: () => modal.close() }, t('common.cancel')),
      el('button', { class: 'btn primary', onclick: async () => {
        modal.close();
        const result = await withProof((p) => api().call('rotate', { id: entry.id }, p), t('rotate_entry.rotate_2', { name: entry.name }));
        if (!result.ok) { if (result.code !== 'cancelled') toast(result.error, 'error'); return; }
        await loadEntries();
        renderMain();
        const failed = result.result.uploads.filter((u) => !u.ok);
        const check = result.result.check;
        if (failed.length) toast(t('rotate_entry.rotated_but_couldn_upload_you', { value: failed.map((u) => u.label).join(', ') }), 'error');
        else if (check && check.status === 'invalid') toast(t('rotate_entry.rotated_but', { message: check.message }), 'error');
        else toast(destinations.length ? t('rotate_entry.rotation_complete_old_one_no') : t('rotate_entry.rotation_complete_old_one_no_2'));
      } }, t('rotate_entry.rotate_3')),
    ],
  });
}

async function deleteEntry(entry) {
  const modal = openModal({
    title: t('delete_entry.delete', { name: entry.name }),
    body: [el('p', { class: 'muted' }, t('delete_entry.will_be_removed_from_vault')),
      entry.shared ? el('div', { class: 'warning' }, icon('alert', 'sm'), el('span', {},
        entry.shared.with
          ? (entry.shared.by_me ? t('delete_entry.shared_with_will_be_deleted', { name: entry.shared.with }) : t('delete_entry.shared_by_will_be_deleted', { name: entry.shared.with }))
          : t('delete_entry.belongs_team_will_be_deleted', { collection_name: entry.shared.collection_name }))) : null],
    footer: [
      el('button', { class: 'btn', onclick: () => modal.close() }, t('common.cancel')),
      el('button', { class: 'btn solid-danger', onclick: async () => {
        modal.close();
        const result = await withProof((p) => api().call('delete_entry', { id: entry.id }, p), t('delete_entry.delete_2', { name: entry.name }));
        if (!result.ok) { if (result.code !== 'cancelled') toast(result.error, 'error'); return; }
        state.selected = null;
        await loadEntries();
        renderMain();
        toast(t('common.deleted'));
      } }, t('common.delete')),
    ],
  });
}

// ----------------------------------------------------------------------- editor

function openEditor(entry) {
  if (entry) { showForm(entry.template, entry); return; }
  const modal = openModal({
    title: t('open_editor.new_credential'),
    wide: true,
    body: el('div', { class: 'template-list' }, Object.values(TEMPLATES).map((t) => el('button', {
      class: 'template-option', onclick: () => { modal.close(); showForm(t.id, null); },
    }, glyph(t.id), el('div', {}, el('div', { class: 'title' }, t.label), el('div', { class: 'summary' }, t.summary))))),
  });
}

function showForm(templateId, entry) {
  const template = TEMPLATES[templateId];
  const isNew = !entry;
  const values = isNew ? {} : { ...entry.fields };
  const secretsSet = isNew ? [] : entry.secrets_set;
  const inputs = {};
  const policy = isNew ? { approval: 'session' } : JSON.parse(JSON.stringify(entry.policy || {}));
  const touched = { id: !isNew, hosts: !isNew, auth: !isNew, commands: !isNew, env: !isNew };

  const namePlaceholders = { web_login: t('show_form.hostinger_dashboard'), api_key: t('show_form.openai_production'), ssh: t('show_form.production_vps'), database: t('show_form.shop_database'), aws: t('editor.aws_placeholder'), generic: t('show_form.deploy_token') };
  const nameInput = el('input', { class: 'input', value: isNew ? '' : entry.name, placeholder: namePlaceholders[templateId] });
  const idInput = el('input', { class: 'input mono', value: isNew ? '' : entry.id, spellcheck: 'false' });
  nameInput.addEventListener('input', () => { if (!touched.id) idInput.value = slugify(nameInput.value); });
  idInput.addEventListener('input', () => { touched.id = true; });

  const fieldsBox = el('div', { class: 'form-grid' });
  const labelFor = (spec) => spec.name === 'notes'
    ? el('label', { class: 'with-icon' }, icon('lock', 'sm'), t('common.private_notes'), el('span', { class: 'req' }, t('show_form.only_you_encrypted')))
    : el('label', {}, editorLabel(templateId, spec), !spec.required ? el('span', { class: 'req' }, t('common.optional_suffix')) : null);

  const buildField = (spec) => {
    const existingSecret = spec.secret && secretsSet.includes(spec.name);
    const placeholder = existingSecret ? t('show_form.saved_type_change') : (spec.hint || '');
    let control;
    let node;
    if (spec.kind === 'select') {
      control = el('select', { class: 'input' }, spec.options.map((o) => el('option', { value: o.value }, o.label)));
      control.value = values[spec.name] || spec.default;
      control.addEventListener('change', onFieldChange);
      node = el('div', { class: 'field' }, labelFor({ ...spec, required: true }), control, spec.help ? el('div', { class: 'help' }, spec.help) : null);
    } else if (spec.kind === 'multiline') {
      control = el('textarea', { class: 'input mono', rows: 5, placeholder, spellcheck: 'false' });
      const file = el('input', { type: 'file', class: 'hidden' });
      file.addEventListener('change', () => {
        const reader = new FileReader();
        reader.onload = () => { control.value = String(reader.result).trim(); control.dispatchEvent(new Event('input')); };
        if (file.files[0]) reader.readAsText(file.files[0]);
      });
      control.addEventListener('input', onFieldChange);
      node = el('div', { class: 'field full' }, labelFor(spec, existingSecret), control,
        spec.note ? el('div', { class: 'help' }, spec.help)
          : el('div', {}, el('button', { class: 'link small', type: 'button', onclick: () => file.click() }, t('show_form.load_from_file')), file));
    } else if (spec.kind === 'secret') {
      const group = passwordInput({ placeholder });
      control = group.input;
      control.addEventListener('input', onFieldChange);
      const wide = ['value', 'secret_access_key'].includes(spec.name) || (templateId === 'ssh' && spec.name === 'password');
      const generate = generatorButtons(templateId, spec.name, control);  // personal.js; null where it makes no sense
      const withGenerate = generate ? el('div', { style: 'display:flex;gap:8px' }, el('div', { style: 'flex:1' }, group), generate) : group;
      if (templateId === 'database' && spec.name === 'password') {
        const note = el('div', { class: 'warning hidden' }, icon('alert', 'sm'), el('span', {}, existingSecret
          ? t('show_form.saving_here_doesn_change_password')
          : t('show_form.if_user_doesn_exist_yet')));
        const input = control;
        input.addEventListener('input', () => note.classList.toggle('hidden', !input.value));
        node = el('div', { class: 'field full' }, labelFor(spec, existingSecret), withGenerate, note);
      } else {
        node = el('div', { class: `field ${wide || generate ? 'full' : ''}` }, labelFor(spec, existingSecret), withGenerate, spec.help ? el('div', { class: 'help' }, spec.help) : null);
      }
    } else {
      const dbPort = spec.name === 'port' && templateId === 'database' ? (DB_ENGINES[(inputs.engine || {}).value || 'postgresql'] || {}).port : null;
      control = el('input', { class: 'input', value: values[spec.name] || '', placeholder: dbPort || spec.hint || spec.default, spellcheck: 'false', inputmode: spec.kind === 'number' ? 'numeric' : null });
      if (spec.kind === 'number' && spec.default && !values[spec.name] && isNew) control.value = spec.default;
      control.addEventListener('input', onFieldChange);
      const wide = ['url', 'base_url'].includes(spec.name) || !!FIELD_LABELS[`${templateId}.${spec.name}`];
      node = el('div', { class: `field ${wide ? 'full' : ''}` }, labelFor(spec), control, spec.help ? el('div', { class: 'help' }, spec.help) : null);
    }
    inputs[spec.name] = control;
    return node;
  };

  const currentFields = () => Object.fromEntries(Object.entries(inputs).map(([name, control]) => [name, control.value]));

  const renderFields = () => {
    const snapshot = { ...values, ...currentFields() };
    Object.assign(values, snapshot);
    for (const key of Object.keys(inputs)) delete inputs[key];
    const nodes = activeSpecs(templateId, snapshot).map(buildField);
    // Short fields go two to a row (server and port, engine and server…). One with no partner beside it takes the
    // whole row, so a form never mixes a half-width username with a full-width password under it.
    for (let i = 0; i < nodes.length; i++) {
      if (nodes[i].classList.contains('full')) continue;
      if (nodes[i + 1] && !nodes[i + 1].classList.contains('full')) { i++; continue; }
      nodes[i].classList.add('full');
    }
    fieldsBox.replaceChildren(...nodes);
    for (const [name, control] of Object.entries(inputs)) if (snapshot[name]) control.value = snapshot[name];
  };

  const notes = el('textarea', { class: 'input', rows: 3, placeholder: t('show_form.e_g_production_account_use') }, isNew ? '' : entry.description);
  const tagsInput = el('input', { class: 'input', placeholder: t('editor.tags_placeholder'), value: isNew ? '' : (entry.tags || []).join(', ') });
  const expiresInput = el('input', { class: 'input', type: 'date', value: isNew ? '' : (entry.expires || '') });
  const currentEvery = isNew ? null : (entry.rotate_every_days ?? null);
  const everyInput = el('select', { class: 'input' }, ROTATE_EVERY.map(([days, label]) =>
    el('option', { value: days === null ? '' : String(days), selected: days === currentEvery }, label)));
  const checkEvery = checkEveryControl(isNew ? null : (entry.check_every_hours ?? null), true);
  const autofillBox = templateId === 'web_login' ? autofillEditor(entry) : null;
  const usedInput = el('textarea', { class: 'input', rows: 3, placeholder: t('show_form.used_in_placeholder') },
    isNew ? '' : (entry.used_in || []).join('\n'));

  const approval = el('div', { class: 'segmented' });
  const renderApproval = () => approval.replaceChildren(Object.entries(APPROVAL_LABELS).map(([k, label]) => el('button', {
    type: 'button', class: (policy.approval || 'session') === k ? 'active' : '', onclick: () => { policy.approval = k; renderApproval(); },
  }, label)));
  renderApproval();

  const hostsInput = el('input', { class: 'input mono', placeholder: t('editor.hosts_placeholder'), spellcheck: 'false' });
  const authKind = el('select', { class: 'input' }, Object.entries(AUTH_LABELS).map(([k, v]) => el('option', { value: k }, v)));
  const authName = el('input', { class: 'input mono', placeholder: t('show_form.authorization'), spellcheck: 'false' });
  const authTemplate = el('input', { class: 'input mono', placeholder: t('show_form.bearer'), spellcheck: 'false' });
  const authDetails = el('div', { class: 'form-grid' },
    el('div', { class: 'field' }, el('label', {}, t('common.name')), authName),
    el('div', { class: 'field' }, el('label', {}, t('show_form.value')), authTemplate));
  const commandsInput = el('input', { class: 'input mono', placeholder: 'gh, psql, aws', spellcheck: 'false' });
  const envInput = el('textarea', { class: 'input mono', rows: 3, placeholder: 'GITHUB_TOKEN={{value}}', spellcheck: 'false' });
  const placeholderList = el('div', { class: 'placeholder-list' });
  // A login's 2FA code is never the AI's unless the user says so here (then it can type {{totp_code}}).
  const totpForAi = el('input', { type: 'checkbox', checked: !!policy.ai_totp });
  totpForAi.addEventListener('change', () => updatePlaceholders());

  const syncAuthDetails = () => authDetails.classList.toggle('hidden', !['header', 'query'].includes(authKind.value));
  const applyPolicy = (p, onlyUntouched) => {
    const http = p.http || {};
    const auth = http.auth || { kind: 'none' };
    const commands = p.commands || {};
    if (!onlyUntouched || !touched.hosts) hostsInput.value = (http.allowed_hosts || []).join(', ');
    if (!onlyUntouched || !touched.auth) {
      authKind.value = auth.kind || 'none';
      authName.value = auth.name || '';
      authTemplate.value = auth.template || '';
    }
    if (!onlyUntouched || !touched.commands) commandsInput.value = (commands.allowed || []).join(', ');
    if (!onlyUntouched || !touched.env) envInput.value = Object.entries(commands.env || {}).map(([k, v]) => `${k}=${v}`).join('\n');
    syncAuthDetails();
  };
  hostsInput.addEventListener('input', () => { touched.hosts = true; });
  [authKind, authName, authTemplate].forEach((c) => c.addEventListener('input', () => { touched.auth = true; syncAuthDetails(); }));
  commandsInput.addEventListener('input', () => { touched.commands = true; });
  envInput.addEventListener('input', () => { touched.env = true; });

  const updatePlaceholders = () => {
    const f = currentFields();
    const names = activeSpecs(templateId, { ...values, ...f })
      .filter((s) => s.substitutable && (f[s.name] || (s.secret && secretsSet.includes(s.name)) || values[s.name]))
      .map((s) => s.name);
    if (templateId === 'database') names.push('connection_url');
    if (totpForAi.checked && (f.totp || secretsSet.includes('totp'))) names.push('totp_code');
    placeholderList.replaceChildren(names.map((n) => el('code', {}, `{{${n}}}`)));
  };

  let suggestTimer = null;
  function onFieldChange(event) {
    if (event && event.target === inputs.auth_method) renderFields();
    if (event && event.target === inputs.engine && inputs.port) inputs.port.placeholder = (DB_ENGINES[inputs.engine.value] || {}).port || '';
    updatePlaceholders();
    clearTimeout(suggestTimer);
    suggestTimer = setTimeout(async () => {
      const f = currentFields();
      for (const spec of TEMPLATES[templateId].fields) if (spec.secret && (f[spec.name] || secretsSet.includes(spec.name))) f[spec.name] = 'x';
      applyPolicy(await api().suggest_policy(templateId, f), true);
    }, 250);
  }

  renderFields();
  applyPolicy(isNew ? {} : policy, false);
  updatePlaceholders();
  if (isNew) onFieldChange();

  const advanced = el('details', { class: 'advanced' },
    el('summary', {}, el('span', { class: 'chev' }, icon('chevronRight', 'sm')), t('common.ai_permissions'),
      el('span', { class: 'hint' }, t('show_form.what_can_do_and_when'))),
    el('div', { class: 'inner' },
      el('div', { class: 'field' }, el('label', {}, t('show_form.ask_for_your_approval')), approval),
      templateId !== 'ssh' ? el('div', { class: 'field' }, el('label', {}, t('show_form.websites_where_can_use')), hostsInput,
        el('div', { class: 'help' }, t('show_form.domains_separated_by_commas_will'))) : null,
      templateId !== 'ssh' ? el('div', { class: 'field' }, el('label', {}, t('show_form.add_requests')), authKind, authDetails) : null,
      el('div', { class: 'field' }, el('label', {}, t('show_form.programs_that_can_use')), commandsInput,
        el('div', { class: 'help' }, t('show_form.just_names_like_gh_or'))),
      el('div', { class: 'field' }, el('label', {}, t('show_form.environment_variables')), envInput),
      templateId === 'web_login' ? el('div', { class: 'field' }, el('label', { class: 'check-row' }, totpForAi, t('show_form.let_ai_type_2fa_code')),
        el('div', { class: 'help' }, t('show_form.as'), el('code', {}, '{{totp_code}}'), t('show_form.without_seeing_leave_off_unless'))) : null,
      el('div', { class: 'field' }, el('label', {}, t('show_form.name_for_ai')), idInput),
      el('div', { class: 'field' }, el('label', {}, t('show_form.data_ai_can_insert_without')), placeholderList)));

  const errorText = el('div', { class: 'error-text' });
  const saveButton = el('button', { class: 'btn primary' }, t('common.save'));
  const readOnly = !isNew && !canWrite(entry);
  if (readOnly) advanced.open = true;

  const collect = () => {
    const f = currentFields();
    const fields = {};
    for (const spec of activeSpecs(templateId, f)) {
      let value = f[spec.name];
      if (value === undefined) continue;
      if (spec.kind !== 'secret' && spec.kind !== 'multiline') value = value.trim();
      if (spec.kind === 'multiline' && value) value = value.trim() + '\n';
      if (spec.secret && !value) { fields[spec.name] = secretsSet.includes(spec.name) ? null : ''; continue; }
      fields[spec.name] = value;
    }
    const env = {};
    for (const line of envInput.value.split('\n')) {
      if (!line.trim()) continue;
      const index = line.indexOf('=');
      if (index < 1) throw new Error(t('show_form.variable_is_missing_its', { value: line.trim() }));
      env[line.slice(0, index).trim()] = line.slice(index + 1).trim();
    }
    const newPolicy = { approval: policy.approval || 'session' };
    if (templateId !== 'ssh') {
      const auth = { kind: authKind.value };
      if (['header', 'query'].includes(auth.kind)) {
        auth.name = authName.value.trim();
        auth.template = authTemplate.value.trim() || '{{value}}';
      }
      newPolicy.http = { allowed_hosts: hostsInput.value.split(',').map((h) => h.trim().toLowerCase()).filter(Boolean), auth };
    }
    const allowed = commandsInput.value.split(',').map((c) => c.trim()).filter(Boolean);
    if (allowed.length || Object.keys(env).length) newPolicy.commands = { allowed, env };
    if (templateId === 'web_login' && totpForAi.checked) newPolicy.ai_totp = true;
    return {
      // Derived from the name without asking; the advanced field changes it on purpose.
      id: (touched.id && idInput.value.trim()) || (isNew ? uniqueId(nameInput.value, templateId) : entry.id),
      name: nameInput.value.trim(), template: templateId,
      description: notes.value.trim(), fields, policy: newPolicy,
      tags: [...new Set(tagsInput.value.split(',').map((t) => slugify(t.trim())).filter(Boolean))],
      ...(expiresInput.value ? { expires: expiresInput.value } : {}),
      ...(everyInput.value !== '' ? { rotate_every_days: Number(everyInput.value) } : {}),
      ...(checkEvery.value() !== null ? { check_every_hours: checkEvery.value() } : {}),
      used_in: usedInput.value.split('\n').map((line) => line.trim()).filter(Boolean),
      ...(autofillBox && autofillBox.value() ? { autofill: autofillBox.value() } : {}),
    };
  };

  // The version this edit started from: if it changes meanwhile (the AI, a rotation, the team), saving says so.
  let base = isNew ? null : entry.updated;
  let baseVersion = isNew ? null : entry.version || null;  // any change, even within the same second
  const conflictBox = el('div', { class: 'warning conflict hidden', role: 'alert' });
  const showConflict = (fresh) => {
    const changed = changedFields(entry, fresh);
    conflictBox.replaceChildren(icon('alert', 'sm'), el('div', { class: 'conflict-body' },
      el('div', {}, el('b', {}, t('show_form.changed_while_you_were_editing')), changed.length ? `: ${listJoin(changed)}.` : '.'),
      el('div', { class: 'muted small' }, t('show_form.reload_discards_your_changes_and')),
      el('div', { class: 'conflict-actions' },
        el('button', { class: 'btn', onclick: () => { modal.close(); showForm(fresh.template, fresh); } }, t('show_form.reload')),
        el('button', { class: 'btn', onclick: () => { base = fresh.updated; baseVersion = fresh.version || null; conflictBox.classList.add('hidden'); save(); } }, t('show_form.overwrite')))));
    conflictBox.classList.remove('hidden');
    conflictBox.scrollIntoView({ block: 'nearest' });
  };

  const save = async () => {
    errorText.textContent = '';
    let newEntry;
    try { newEntry = collect(); } catch (error) { errorText.textContent = error.message; return; }
    if (!newEntry.name) { errorText.textContent = t('show_form.give_name'); nameInput.focus(); return; }
    busy(saveButton, true);
    const result = await withProof((p) => api().call('save_entry', { entry: newEntry, replaces: isNew ? null : entry.id, base_updated: base, base_version: baseVersion }, p), t('show_form.save', { name: newEntry.name }));
    busy(saveButton, false);
    if (!result.ok && result.code === 'conflict') {
      await loadEntries();
      const fresh = state.entries.find((e) => e.id === entry.id);
      if (fresh) showConflict(fresh);
      else errorText.textContent = t('show_form.was_deleted_while_you_were');
      return;
    }
    if (!result.ok) { if (result.code !== 'cancelled') errorText.textContent = friendlyError(result.error, templateId); return; }
    modal.close();
    state.selected = result.result.id;
    state.view = 'credentials';
    await loadEntries();
    renderMain();
    toast(isNew ? t('common.saved') : t('show_form.changes_saved'));
  };
  saveButton.addEventListener('click', save);

  const modal = openModal({
    title: isNew ? template.label : entry.name,
    wide: true,
    lead: glyph(templateId),
    body: [
      readOnly ? el('div', { class: 'warning' }, icon('info', 'sm'), el('span', {},
        t('show_form.belongs_team_and_your_permission', { value: PERMISSION_LABELS[entry.shared.permission] }))) : null,
      conflictBox,
      el('div', { class: 'field' }, el('label', {}, t('common.name')), nameInput),
      isNew && ['api_key', 'generic'].includes(templateId) ? keySourcePicker() : null,
      fieldsBox,
      el('div', { class: 'field' }, el('label', { class: 'with-icon' }, icon('bot', 'sm'), t('common.instructions_for_ai'),
        el('span', { class: 'req' }, t('show_form.ai_reads_them_optional'))), notes,
        el('div', { class: 'help' }, t('show_form.what_is_and_how_should'))),
      el('div', { style: 'display:flex;gap:12px' },
        el('div', { class: 'field', style: 'flex:2' }, el('label', {}, t('common.tags'), el('span', { class: 'req' }, t('common.optional_suffix'))), tagsInput,
          el('div', { class: 'help' }, t('show_form.group_them_for_example_by'))),
        el('div', { class: 'field', style: 'flex:1' }, el('label', {}, t('common.expires'), el('span', { class: 'req' }, t('common.optional_suffix'))), expiresInput),
        el('div', { class: 'field', style: 'flex:1' }, el('label', {}, t('common.remind_me_rotate')), everyInput)),
      el('div', { class: 'field' }, el('label', {}, t('common.check_that_works')), checkEvery.node,
        el('div', { class: 'help' }, t('show_form.read_only_call_provider_or'))),
      el('div', { class: 'field' }, el('label', {}, t('common.where_used'), el('span', { class: 'req' }, t('common.optional_suffix'))), usedInput,
        el('div', { class: 'help' }, t('show_form.one_place_per_line_develop'))),
      advanced,
      autofillBox ? autofillBox.node : null,
      errorText,
    ],
    footer: [
      isNew ? el('button', { class: 'btn ghost', onclick: () => { changingType = true; modal.dismiss(); } }, icon('arrowLeft', 'sm'), t('show_form.change_type')) : null,
      el('div', { class: 'spacer' }),
      el('button', { class: 'btn', onclick: () => { changingType = false; modal.dismiss(); } }, t('common.cancel')),
      saveButton,
    ],
    // Esc, the X or «Cancelar» with changes: ask first. A click outside never closes it.
    confirmClose: () => (dirty ? { title: t('show_form.discard_changes'), text: t('show_form.what_you_changed_in_this') } : null),
    onClose: () => { if (changingType) openEditor(null); },
  });
  let dirty = false;
  let changingType = false;
  const modalBody = modal.overlay.querySelector('.modal-body');
  ['input', 'change'].forEach((type) => modalBody.addEventListener(type, () => { dirty = true; }, true));  // capture: also what doesn't bubble (the generator)
  modalBody.addEventListener('click', (event) => { if (event.target.closest('.segmented button')) dirty = true; });
  modal.overlay.addEventListener('keydown', (event) => {
    if (event.key === 'Enter' && event.ctrlKey) { event.preventDefault(); save(); }  // Ctrl+Enter saves
  });
  setTimeout(() => nameInput.focus(), 50);
}

// Labels of what differs between two versions of a credential (for «Cambió mientras editabas»).
function changedFields(before, after) {
  const same = (a, b) => JSON.stringify(a ?? null) === JSON.stringify(b ?? null);
  const labels = [];
  if (!same(before.name, after.name)) labels.push(t('common.name'));
  const specs = TEMPLATES[after.template] ? TEMPLATES[after.template].fields : [];
  for (const spec of specs) {
    const changed = spec.secret
      ? before.secrets_set.includes(spec.name) !== after.secrets_set.includes(spec.name) || (!spec.note && before.secret_since !== after.secret_since)
      : !same(before.fields[spec.name] || null, after.fields[spec.name] || null);
    if (changed) labels.push(spec.name === 'notes' ? t('common.private_notes') : fieldLabel(after.template, spec));
  }
  if (!same(before.description, after.description)) labels.push(t('common.instructions_for_ai'));
  if (!same(before.tags, after.tags)) labels.push(t('common.tags'));
  if (!same(before.expires, after.expires)) labels.push(t('common.expires'));
  if (!same(before.rotate_every_days, after.rotate_every_days)) labels.push(t('common.remind_me_rotate'));
  if (!same(before.check_every_hours, after.check_every_hours)) labels.push(t('common.check_that_works'));
  if (!same(before.used_in, after.used_in)) labels.push(t('common.where_used'));
  if (!same(before.policy, after.policy)) labels.push(t('common.ai_permissions'));
  return [...new Set(labels)];
}

// ----------------------------------------------------------------------- exposure

const LEVELS = localized(() => ({
  exposed: { label: t('common.exposed'), order: 0 },
  warning: { label: t('common.review'), order: 1 },
  unknown: { label: t('level.not_checked'), order: 2 },
  ok: { label: t('common.no_known_copies'), order: 3 },
}));
const SOURCE_LABELS = localized(() => ({
  ai: t('source.ai_conversation'), history: t('source.terminal_history'), config: t('source.settings'), env: t('source.environment_variable'),
  project: t('source.project_file'), git: t('source.git_history'),
}));

function exposureOf(id) {
  return state.exposure ? state.exposure.entries.find((item) => item.id === id) : null;
}

function exposedCount() {
  return state.exposure ? state.exposure.entries.filter((item) => item.level === 'exposed').length : 0;
}

function levelBadge(level) {
  return el('span', { class: `level is-${level}` }, el('span', { class: 'level-dot' }), LEVELS[level].label);
}

function levelDot(id) {
  const item = exposureOf(id);
  if (!item || !['exposed', 'warning'].includes(item.level)) return null;
  return el('span', { class: `level-dot is-${item.level}`, title: LEVELS[item.level].label });
}

function ageText(days) {
  if (days < 1) return fmtRelative(0, 'day');
  if (days < 45) return tn('time.days_ago', days);
  if (days < 365) return tn('time.months_ago', Math.round(days / 30));
  return tn('time.years_ago', Math.floor(days / 365));
}

function exposureFacts(item) {
  const facts = [];
  const alive = item.alive;
  if (alive && alive.status === 'ok') facts.push(t('exposure_facts.works_at', { provider: alive.provider, time: formatTime(alive.checked) }));
  if (alive && alive.status === 'unknown') facts.push(`${alive.provider}: ${alive.message}`);
  if (item.pwned && !item.pwned.count) facts.push(t('exposure_facts.not_in_any_known_leak'));
  facts.push(item.age_days !== null ? t('exposure_facts.value_set', { age: ageText(item.age_days) }) : t('exposure_facts.age_unknown'));
  if (item.revealed) facts.push(tn('exposure.revealed_times', item.revealed));
  return el('div', { class: 'facts faint small' }, facts.join(' · '));
}

function scanProgress() {
  const scan = state.scan || {};
  const read = t('scan_progress.files_read_mb', { value: scan.files || 0, value2: Math.round((scan.bytes || 0) / 1e6) });
  return el('div', { class: 'scan-progress' }, el('div', { class: 'spinner' }),
    el('div', { class: 'meta' }, el('div', {}, scan.phase || t('scan_progress.preparing')),
      el('div', { class: 'muted small' }, read, scan.skipped ? t('scan_progress.unchanged', { skipped: scan.skipped }) : '')),
    el('button', { class: 'btn ghost', onclick: () => api().cancel_scan() }, t('common.cancel')));
}

async function pollScan() {
  if (!state.scan || !state.scan.running) return;
  const progress = await api().scan_status();
  if (!progress) return;
  state.scan = progress;
  if (progress.running) {
    const node = document.querySelector('.scan-progress');
    if (node) node.replaceWith(scanProgress());
    return;
  }
  if (progress.error) toast(progress.error, 'error');
  if (progress.report) {
    state.exposure = progress.report;
    const exposed = exposedCount();
    if (exposed) toast(tn('exposure.search_done_exposed', exposed), 'error');
    else toast(t('poll_scan.search_finished_no_copies_your'));
  }
  if (state.screen === 'main') renderMain();
}

async function startScan(button) {
  busy(button, true);
  const result = await withProof((p) => api().start_scan(p), t('common.search_files_on_this_pc'));
  busy(button, false);
  if (!result.ok) { if (result.code !== 'cancelled') toast(result.error, 'error'); return; }
  state.scan = { running: true };
  renderMain();
}

// «Revisar ahora»: search for copies and test every key with its provider, at once.
async function reviewNow(button) {
  busy(button, true);
  const [scan, check] = await Promise.all([
    withProof((p) => api().start_scan(p), t('common.search_files_on_this_pc')),
    api().check_exposure(),
  ]);
  busy(button, false);
  if (check.ok) state.exposure = check.result;
  else toast(check.error, 'error');
  if (scan.ok) state.scan = { running: true };
  else if (scan.code !== 'cancelled') toast(scan.error, 'error');
  renderMain();
}

async function showWhere() {
  const result = await withProof((p) => api().open_exposure_session(p), t('show_where.see_which_files_your_keys'));
  if (!result.ok) { if (result.code !== 'cancelled') toast(result.error, 'error'); return; }
  await loadExposure();
  renderMain();
}

function renderExposure(content) {
  const report = state.exposure;
  const scanning = !!(state.scan && state.scan.running);
  const complete = !!(report && report.last_scan && report.last_check);
  const reviewButton = el('button', { class: `btn ${complete ? '' : 'primary'}`, disabled: scanning,
    title: t('exposure.searches_this_pc_for_copies') }, icon('search', 'sm'), t('exposure.check_now'));
  reviewButton.addEventListener('click', () => reviewNow(reviewButton));
  const header = el('div', { class: 'content-header' }, el('h1', {}, t('common.health')), reviewButton);
  if (!report) {
    content.replaceChildren(header, el('div', { class: 'content-body' }, el('div', { class: 'empty' }, el('p', {}, t('exposure.couldn_load_status')))));
    return;
  }

  const entries = Object.fromEntries(state.entries.map((e) => [e.id, e]));
  const items = report.entries.filter((item) => entries[item.id])
    .sort((a, b) => LEVELS[a.level].order - LEVELS[b.level].order || entries[a.id].name.localeCompare(entries[b.id].name));
  const found = items.filter((item) => ['exposed', 'warning'].includes(item.level) || item.ignored);
  const hidden = !report.details && items.some((item) => item.found || item.found_before);
  const scanButton = el('button', { class: 'btn ghost', disabled: scanning }, t('exposure.search_for_copies'));
  scanButton.addEventListener('click', () => startScan(scanButton));
  const body = el('div', { class: 'content-body' },
    offboardingPeople().map((person) => offboardingCard(person, true)),  // someone left the team: keys to change
    healthSection(),  // personal.js: score, weak / reused / old secrets, unfinished rotations
    el('div', { class: 'section-head' }, el('h2', { class: 'section-title' }, t('exposure.copies_found')), scanButton),
    scanning ? scanProgress() : null,
    el('div', { class: 'exposure-summary' },
      el('p', { class: 'muted' }, t('exposure.looks_for_your_keys_in')),
      el('div', { class: 'faint small' },
        report.last_scan ? t('exposure.last_search_files', { when: whenText(report.last_scan.ts), files: report.last_scan.files }) : t('exposure.no_search_for_copies_yet')),
      hidden ? el('div', { class: 'small' }, el('span', { class: 'muted' }, t('exposure.paths_are_only_shown_after')),
        el('button', { class: 'link small', onclick: showWhere }, t('exposure.see_which_files'))) : null),
    found.length ? el('div', { class: 'exposure-list' }, found.map((item) => exposureCard(item, entries[item.id])))
      : report.last_scan ? el('p', { class: 'muted small' }, t('exposure.no_copies_your_keys_in')) : null);
  content.replaceChildren(header, body);
  if (state.healthFocus) {
    const card = body.querySelector(`[data-entry="${CSS.escape(state.healthFocus)}"]`);
    state.healthFocus = null;
    if (card) setTimeout(() => { card.scrollIntoView({ block: 'center' }); card.classList.add('focus'); }, 50);
  }
}

// A long path keeps its start and its file name: C:\Users\ana\…\projects\demo\s1.jsonl
function shortPath(path) {
  return path.length > 56 ? `${path.slice(0, 16)}…${path.slice(-38)}` : path;
}

// One credential with copies: rotate it (the copies stop mattering), and per place ignore it or, in an AI
// conversation or a shell history, remove it from the file.
function exposureCard(item, entry) {
  const findings = item.findings || [];
  const place = (location) => location.replace(/^(env|git):/, '');
  const backup = (location) => location.endsWith('.secretbroker.bak');
  const redactable = (f) => ['ai', 'history'].includes(f.source) && !backup(f.location) && !/\.sqlite(-wal)?$/i.test(f.location);
  const act = async (button, call, message) => {
    busy(button, true);
    const result = await call();
    busy(button, false);
    if (!result.ok) { if (result.code === 'session_expired') showWhere(); else toast(result.error, 'error'); return; }
    if (message) toast(typeof message === 'function' ? message(result.result) : message);
    await loadExposure();
    renderMain();
  };
  const redact = (f, button) => confirmModal({
    title: t('exposure_card.remove_key_from_this_file'),
    text: t('exposure_card.replaced_with_redacted_in_copy', { id: entry.id, place: place(f.location) }),
    warning: f.source === 'ai' ? t('exposure_card.ai_already_saw_and_sent') : null,
    action: t('exposure_card.remove_from_this_file'),
    onConfirm: async () => {
      act(button, () => api().redact_finding(entry.id, f.location), (r) => (r.count ? tn('exposure.removed_from_file', r.count) : t('exposure_card.was_no_longer_in_file')));
      return true;
    },
  });
  const actions = (f) => {
    const buttons = [];
    if (f.ignored) {
      buttons.push(el('button', { class: 'btn ghost sm', onclick: (e) => act(e.currentTarget, () => api().ignore_finding(entry.id, f.location, false)) }, t('exposure_card.count_again')));
      return buttons;
    }
    if (f.redacted && !f.present && redactable(f)) {
      // The copy left next to the file still has it: once the user is happy, delete it too.
      buttons.push(el('button', { class: 'btn ghost sm', onclick: async (e) => {
        const button = e.currentTarget;
        toast(await api().delete_redaction_backup(`${f.location}.secretbroker.bak`) ? t('exposure_card.copy_deleted') : t('exposure_card.there_was_no_copy_anymore'));
        button.remove();
      } }, t('exposure_card.delete_copy')));
    }
    if (!f.present) return buttons;
    if (backup(f.location)) {
      buttons.push(el('button', { class: 'btn ghost sm', onclick: async () => {
        if (await api().delete_redaction_backup(f.location)) { toast(t('exposure_card.copy_deleted_next_search_won')); }
      } }, t('exposure_card.delete_copy')));
    } else if (redactable(f)) {
      buttons.push(el('button', { class: 'btn ghost sm', onclick: (e) => redact(f, e.currentTarget) }, t('exposure_card.remove_from_this_file')));
    }
    buttons.push(el('button', { class: 'btn ghost sm', title: t('exposure_card.test_file_copy_you_want'),
      onclick: (e) => act(e.currentTarget, () => api().ignore_finding(entry.id, f.location, true), t('exposure_card.ignored')) }, t('exposure_card.ignore')));
    if (!f.location.startsWith('env:')) {
      buttons.push(el('button', { class: 'btn icon-only', title: t('exposure_card.show_in_folder'), onclick: () => api().show_location(f.location) }, icon('external', 'sm')));
    }
    return buttons;
  };
  const writable = canWrite(entry);
  return el('div', { class: `exposure-card is-${item.level}`, 'data-entry': entry.id },
    el('div', { class: 'exposure-head' },
      glyph(entry.template),
      el('div', { class: 'meta' }, el('div', { class: 'title' }, entry.name), el('div', { class: 'subtitle' }, subtitleOf(entry))),
      levelBadge(item.level),
      el('button', { class: 'btn ghost', onclick: () => { state.selected = entry.id; state.view = 'credentials'; renderMain(); } }, t('common.open')),
      writable && ['exposed', 'warning'].includes(item.level)
        ? el('button', { class: 'btn primary', onclick: () => rotateWithHelp(entry) }, icon('rotate', 'sm'), t('common.rotate_with_help')) : null),
    item.reasons.length ? el('ul', { class: 'reasons' }, item.reasons.map((r) => el('li', { class: `is-${r.level}` }, r.text))) : null,
    exposureFacts(item),
    findings.length ? el('details', { class: 'findings', open: item.level === 'exposed' || findings.some((f) => f.redacted || f.ignored) },
      el('summary', {}, `${tn('exposure.places', findings.length)}${item.ignored ? ` · ${tn('exposure.ignored_count', item.ignored)}` : ''}`),
      findings.map((f) => el('div', { class: `finding ${f.present && !f.ignored ? '' : 'gone'}` },
        el('span', { class: 'source' }, backup(f.location) ? t('common.backup_copy') : SOURCE_LABELS[f.source] || f.source),
        el('span', { class: 'path selectable', title: place(f.location) }, shortPath(place(f.location))),
        el('span', { class: 'faint' }, f.ignored ? t('exposure.ignored') : f.redacted && !f.present ? t('exposure_card.removed_from_here') : f.present ? t('exposure.since', { time: formatTime(f.first_seen) }) : t('exposure_card.gone')),
        el('span', { class: 'finding-actions' }, actions(f))))) : null);
}

// ----------------------------------------------------------------------- activity

// Events written before the service recorded who did what: the AI is known by its actions.
const AI_EVENT_ACTIONS = new Set(['http_request', 'ssh_exec', 'ssh_upload', 'ssh_download', 'run_command', 'release_env',
  'push_github_secret', 'draft', 'request_access', 'import_env']);
const TEAM_EVENT_ACTIONS = new Set(['share', 'unshare']);
// Only hosts, paths and commands go in monospace.
const MONO_EVENT_ACTIONS = new Set(['http_request', 'ssh_exec', 'ssh_upload', 'ssh_download', 'run_command', 'release_env']);
const ACTIVITY_PAGE = 200;
const ACTIVITY_FILTERS = localized(() => ([[null, t('activity_filter.all'), null], ['ai', t('common.ai'), 'bot'], ['browser', t('common.browser'), 'globe'], ['denied', t('activity_filter.denied'), null], ['team', t('common.team'), 'users']]));

// [kind, icon, label]: who did it.
// The vault's own events keep a short detail written by the service: a code (how it was unlocked) or, in older
// entries and for a few events, a Spanish phrase. Those known ones are shown in the app's language; others as stored.
function eventDetail(e) {
  const detail = e.detail || '';
  const unlockedWith = { master_password: t('activity_detail.with_master_password'), 'contraseña maestra': t('activity_detail.with_master_password'),
    session: t('activity_detail.with_windows_session'), hello: t('activity_detail.with_windows_hello'),
    windows_password: t('activity_detail.with_windows_password') };
  if (e.secret === 'vault') {
    if (e.action === 'unlock' && unlockedWith[detail]) return unlockedWith[detail];
    if (e.action === 'lock') {
      if (detail === 'manual') return t('activity_detail.by_hand');
      const idle = detail.match(/^inactividad \((\d+) min\)$/);
      if (idle) return t('activity_detail.idle_minutes', { minutes: Number(idle[1]) });
      if (/^\S+ bloqueado$/.test(detail)) return t('activity_detail.session_locked');
    }
    if (e.action === 'session_unlock' && (detail === 'activado' || detail === 'desactivado')) {
      return detail === 'activado' ? t('activity_detail.turned_on') : t('activity_detail.turned_off');
    }
    const count = detail.match(/^(\d+) credenciales$/);
    if (count && (e.action === 'create' || e.action === 'restore')) return tn('activity_detail.credentials', Number(count[1]));
  }
  const sharing = [[/^Compartida en (.+)$/, 'activity_detail.in_collection'], [/^Compartida con (.+)$/, 'activity_detail.with_person'],
    [/^Ya no está en (.+)$/, 'activity_detail.from_collection'], [/^Ya no compartida con (.+)$/, 'activity_detail.with_person']];
  for (const [pattern, key] of sharing) {
    const found = ['share', 'unshare'].includes(e.action) && detail.match(pattern);
    if (found) return t(key, { name: found[1] });
  }
  const saved = { creada: t('activity_detail.created'), modificada: t('activity_detail.changed'), 'clave añadida': t('activity_detail.key_added') };
  if (e.action === 'save' && saved[detail]) return saved[detail];
  if (e.action === 'edit') return aiEditLines({ detail })[0];  // the first line of an AI's edit, in the app's words
  return detail;
}

function eventActor(e) {
  const actor = e.actor || (AI_EVENT_ACTIONS.has(e.action) ? 'ai' : e.action === 'team_conflict' ? 'team' : 'user');
  if (actor === 'ai') return ['ai', 'bot', t('common.ai')];
  if (actor === 'browser') return ['browser', 'globe', t('common.browser')];
  if (actor === 'team') return ['team', 'users', e.by || t('common.team')];
  if (actor === 'system') return ['system', 'shield', t('common.secretbroker')];
  return ['user', 'user', t('event_actor.you')];
}

function isTeamEvent(e) {
  return e.actor === 'team' || e.action.startsWith('team_') || TEAM_EVENT_ACTIONS.has(e.action);
}

function dayLabel(date) {
  const today = new Date();
  const days = Math.round((new Date(today.getFullYear(), today.getMonth(), today.getDate())
    - new Date(date.getFullYear(), date.getMonth(), date.getDate())) / 86400000);
  if (days === 0) return t('day_label.today');
  if (days === 1) return t('day_label.yesterday');
  const text = fmtDate(date, { weekday: 'long', day: 'numeric', month: 'long',
    year: date.getFullYear() === today.getFullYear() ? undefined : 'numeric' });
  return text.charAt(0).toUpperCase() + text.slice(1);
}

async function renderActivity(content) {
  const filter = state.activityFilter || (state.activityFilter = { kind: null, secret: '' });
  const body = el('div', { class: 'content-body' }, el('div', { class: 'spinner' }));
  const filters = el('div', { class: 'activity-filters' });
  content.replaceChildren(el('div', { class: 'content-header' }, el('h1', {}, t('common.activity')),
    el('button', { class: 'btn ghost', onclick: () => renderActivity(content) }, t('common.refresh'))), filters, body);
  const result = await api().call('audit', { limit: ACTIVITY_PAGE });
  let events = result.ok ? result.result : [];
  let more = events.length === ACTIVITY_PAGE;
  if (!events.length) { filters.remove(); body.replaceChildren(el('div', { class: 'empty' }, el('p', {}, t('common.no_activity_yet')))); return; }
  const names = Object.fromEntries(state.entries.map((e) => [e.id, e.name]));

  const credentials = el('select', { class: 'input compact', title: t('activity.only_one_credential') },
    el('option', { value: '' }, t('activity.all_credentials')),
    [...state.entries].sort((a, b) => a.name.localeCompare(b.name)).map((e) => el('option', { value: e.id }, e.name)));
  credentials.value = filter.secret;
  if (credentials.value !== filter.secret) { filter.secret = ''; credentials.value = ''; }
  credentials.addEventListener('change', () => { filter.secret = credentials.value; renderFilters(); renderEvents(); });
  const renderFilters = () => filters.replaceChildren(
    ACTIVITY_FILTERS.map(([kind, label, iconName]) => el('button', {
      class: `tag ${filter.kind === kind ? 'active' : ''}`, 'aria-pressed': String(filter.kind === kind),
      onclick: () => { filter.kind = kind; renderFilters(); renderEvents(); },
    }, iconName ? icon(iconName, 'sm') : null, label)),
    credentials);

  const shown = (e) => (!filter.secret || e.secret === filter.secret)
    && (filter.kind === 'ai' ? eventActor(e)[0] === 'ai'
      : filter.kind === 'browser' ? eventActor(e)[0] === 'browser'
      : filter.kind === 'denied' ? e.status === 'denied'
        : filter.kind === 'team' ? isTeamEvent(e) : true);
  const row = (e) => {
    const [kind, actorIcon, actorLabel] = eventActor(e);
    const date = e.ts ? new Date(e.ts) : null;
    const failed = e.status === 'denied' || e.status === 'error';
    const detail = (e.message === 'Contraseña incorrecta' ? t('activity_detail.wrong_password') : e.message) || eventDetail(e);
    return el('div', { class: 'event' },
      el('span', { class: 'time', title: date ? fmtDate(date, { dateStyle: 'full', timeStyle: 'short' }) : '' },
        date ? fmtDate(date, { hour: 'numeric', minute: '2-digit' }) : ''),
      el('span', { class: `actor is-${kind}` }, icon(actorIcon, 'sm'), el('span', {}, actorLabel)),
      el('div', { class: 'what' },
        el('div', {}, ACTION_LABELS[e.action] || e.action,
          e.secret && e.secret !== 'vault' ? el('span', { class: 'credential' }, ` · ${names[e.secret] || e.secret}`) : null),
        detail ? el('div', { class: `event-detail selectable ${MONO_EVENT_ACTIONS.has(e.action) && !e.message ? 'mono' : ''}`,
          title: [e.detail, e.message].filter(Boolean).join(' — ') }, detail) : null),
      failed ? el('span', { class: 'chip is-exposed failed' }, e.status === 'denied' ? t('common.denied') : t('common.error')) : el('span'));
  };
  const loadMore = async (button) => {
    busy(button, true);
    const next = await api().call('audit', { limit: ACTIVITY_PAGE, offset: events.length });
    busy(button, false);
    if (!next.ok) { toast(next.error, 'error'); return; }
    events = events.concat(next.result);
    more = next.result.length === ACTIVITY_PAGE;
    renderEvents();
  };
  const renderEvents = () => {
    const list = el('div', { class: 'activity' });
    let day = null;
    const matching = events.filter(shown);
    for (const e of matching) {
      const label = e.ts ? dayLabel(new Date(e.ts)) : t('activity.no_date');
      if (label !== day) { day = label; list.append(el('div', { class: 'day-head' }, label)); }
      list.append(row(e));
    }
    if (!matching.length) list.append(el('p', { class: 'muted', style: 'padding:12px 0' }, more ? t('activity.nothing_like_that_in_most') : t('activity.nothing_like_that_in_activity')));
    if (more) {
      const button = el('button', { class: 'btn' }, t('activity.load_more'));
      button.addEventListener('click', () => loadMore(button));
      list.append(el('div', { class: 'activity-more' }, button));
    }
    body.replaceChildren(list);
  };
  renderFilters();
  renderEvents();
}

// ----------------------------------------------------------------------- the AI's access

async function setPaused(paused) {
  const result = paused ? await api().call('pause_ai') : await withProof((p) => api().call('resume_ai', {}, p), t('set_paused.resume_ai'));
  if (!result.ok) { if (result.code !== 'cancelled') toast(result.error, 'error'); return; }
  toast(paused ? t('common.ai_paused') : t('activity.ai_resumed'));
  await refreshStatus();
  renderMain();
}

async function renderAccess(content) {
  const paused = state.status.ai_paused;
  const body = el('div', { class: 'content-body' }, el('div', { class: 'spinner' }));
  content.replaceChildren(el('div', { class: 'content-header' }, el('h1', {}, t('common.ai_access'))), body);
  const [result, permissions, clients] = await Promise.all([api().call('grants'), api().call('ai_permissions'), loadAiClients()]);
  const grants = result.ok ? result.result : [];
  const approved = grants.filter((g) => g.kind === 'approved');
  const free = grants.filter((g) => g.kind === 'never');
  const revoke = async (secretId) => {
    await api().call('revoke_sessions', secretId ? { secret_id: secretId } : {});
    toast(secretId ? t('common.approval_withdrawn') : t('access.approvals_withdrawn'));
    await refreshStatus();
    renderAccess(content);
  };
  const row = (g, control) => el('div', { class: 'access-row' }, glyph(g.template),
    el('div', { class: 'meta' }, el('div', { class: 'title' }, g.name),
      el('div', { class: 'subtitle' }, g.kind === 'never' ? t('access.never_asks') : g.until ? t('access.until', { time: formatTime(g.until) }) : t('access.until_you_lock'))),
    control);
  body.replaceChildren(el('div', { class: 'settings' },
    aiClientsGroup(clients, () => renderAccess(content)),  // connect.js
    el('div', { class: `pause-card ${paused ? 'paused' : ''}` },
      el('div', { class: 'meta' },
        el('h3', {}, paused ? t('access.ai_is_paused') : t('access.ai_can_work')),
        el('p', {}, paused
          ? t('access.can_use_create_or_see')
          : t('access.uses_your_credentials_according_their'))),
      el('button', { class: `btn ${paused ? 'primary' : 'danger'}`, onclick: () => setPaused(!paused) }, icon('power', 'sm'), paused ? t('access.resume') : t('access.pause_ai'))),
    permissions.ok ? permissionsGroup(permissions.result, () => renderAccess(content)) : null,
    el('div', { class: 'settings-group' },
      el('div', { class: 'group-head' }, el('h3', { class: 'muted' }, t('access.approved_now')),
        approved.length > 1 ? el('button', { class: 'btn ghost', onclick: () => revoke(null) }, t('access.withdraw_all')) : null),
      approved.length
        ? approved.map((g) => row(g, el('button', { class: 'btn', onclick: () => revoke(g.secret_id) }, t('access.withdraw'))))
        : el('p', { class: 'muted small' }, t('access.none_next_time_ai_uses'))),
    el('div', { class: 'settings-group' }, el('h3', { class: 'muted' }, t('access.never_ask')),
      free.length
        ? free.map((g) => row(g, el('button', { class: 'btn', onclick: () => { state.view = 'credentials'; state.selected = g.secret_id; renderMain(); } }, t('common.change'))))
        : el('p', { class: 'muted small' }, t('access.every_credential_asks_for_your')))));
}

const AI_LEVEL_LABELS = localized(() => ([['free', t('ai_level.free')], ['notify', t('ai_level.notify_me')], ['ask', t('ai_level.ask_me')], ['off', t('common.never')]]));
const AI_LEVEL_HELP = localized(() => ({
  free: t('ai_level_help.free_acts_within_each_credential'),
  notify: t('ai_level_help.notify_me_same_as_free'),
  ask: t('ai_level_help.ask_me_asks_you_every'),
  off: t('ai_level_help.never_denied'),
}));
// The capabilities in three groups; one the app doesn't know yet goes with «Modificar».
const AI_CAPABILITY_GROUPS = localized(() => ([[t('ai_group.use'), ['local_env']], [t('ai_group.modify'), ['create', 'edit_notes', 'edit_config', 'rotate']], [t('ai_group.publish'), ['github']]]));

function permissionsGroup(data, rerender) {
  const save = async (changes) => {
    const result = await withProof((p) => api().call('set_ai_permissions', changes, p), t('permissions_group.give_ai_more_permissions'));
    if (result.ok) toast(t('common.saved_2')); else if (result.code !== 'cancelled') toast(result.error, 'error');
    rerender();
  };
  const notify = el('input', { type: 'checkbox', checked: data.notify_uses });
  notify.addEventListener('change', () => save({ notify_uses: notify.checked }));
  const known = new Set(AI_CAPABILITY_GROUPS.flatMap(([, ids]) => ids));
  const groups = AI_CAPABILITY_GROUPS.map(([label, ids]) => [label, [
    ...ids.map((id) => data.capabilities.find((c) => c.id === id)).filter(Boolean),
    ...(ids.includes('edit_config') ? data.capabilities.filter((c) => !known.has(c.id)) : []),
  ]]).filter(([, caps]) => caps.length);
  const levelName = (level) => AI_LEVEL_LABELS.find(([l]) => l === level)[1];
  const row = (c) => el('div', { class: `ai-row ${c.level === 'off' ? 'is-off' : ''}`, role: 'radiogroup', 'aria-label': c.label },
    el('div', { class: 'meta' }, el('div', { class: 'title' }, c.label),
      c.level === c.default ? null : el('div', { class: 'changed' }, t('permissions_group.changed'),
        el('button', { class: 'link', title: t('permissions_group.back_recommended', { levelName: levelName(c.default) }),
          onclick: () => save({ permissions: { [c.id]: c.default } }) }, t('permissions_group.reset')))),
    AI_LEVEL_LABELS.map(([level, label]) => {
      const radio = el('input', { type: 'radio', name: `ai-${c.id}`, value: level, checked: c.level === level, 'aria-label': label });
      radio.addEventListener('change', () => { if (radio.checked && c.level !== level) save({ permissions: { [c.id]: level } }); });
      return el('label', { title: AI_LEVEL_HELP[level] }, radio);
    }));
  return el('div', { class: 'settings-group' },
    el('h3', { class: 'muted' }, t('common.what_ai_can_do')),
    el('p', { class: 'muted small', style: 'margin:2px 0 10px' }, t('permissions_group.on_top_using_credentials_hover')),
    el('div', { class: 'ai-grid' },
      el('div', { class: 'ai-grid-head' }, el('span'),
        AI_LEVEL_LABELS.map(([level, label]) => el('span', { title: AI_LEVEL_HELP[level] }, label))),
      groups.map(([label, caps]) => [el('div', { class: 'ai-group' }, label), caps.map(row)])),
    setting(t('permissions_group.notify_me_when_uses_credentials'), t('permissions_group.windows_notification_at_most_one'), notify));
}

// ----------------------------------------------------------------------- teams
//
// Team logic and crypto live in the service (teams.py). Here: the Equipo view, sharing credentials,
// and the team side of a credential. The account password is typed once, when linking the account;
// every other change is one click (presence), like the rest of the app.
//
// The Equipo view draws at once from what this PC knows (team_overview: no network), then asks the server
// with short timeouts and redraws only if something changed. Changes need the server: offline, their
// buttons are disabled.

const ROLE_LABELS = localized(() => ({ owner: t('role.owner'), admin: t('common.admin'), member: t('common.member') }));
const PERMISSION_LABELS = localized(() => ({ manage: t('permission.manager'), edit: t('permission.editor'), view: t('permission.viewer'), use: t('common.use_only') }));
const PERMISSION_HELP = localized(() => ({
  manage: t('permission_help.manager_adds_and_removes_people'),
  edit: t('permission_help.editor_changes_credentials_and_rotates'),
  view: t('permission_help.viewer_ai_and_your_programs'),
  use: t('permission_help.use_only_ai_and_your'),
}));
// Server audit actions → their message (with {who}, {collection}, {role}, {permission}).
const EVENT_LABELS = {
  'org.create': 'team_event.org_create', invite: 'team_event.invite', 'invite.delete': 'team_event.invite_delete',
  join: 'team_event.join', 'member.confirm': 'team_event.member_confirm', 'member.remove': 'team_event.member_remove',
  'member.leave': 'team_event.member_leave', 'member.role': 'team_event.member_role',
  'collection.create': 'team_event.collection_create', 'collection.delete': 'team_event.collection_delete',
  grant: 'team_event.grant', revoke: 'team_event.revoke', rotate: 'team_event.rotate', 'item.put': 'team_event.item_put',
  'item.delete': 'team_event.item_delete', 'invite.renew': 'team_event.invite_renew', 'invite.send': 'team_event.invite_send',
  'member.disable': 'team_event.member_disable', 'member.delete': 'team_event.member_delete',
  'account.recover': 'team_event.account_recover', 'password.reset': 'team_event.password_reset',
  'invite.replace': 'team_event.invite_replace',
};
const RELEASES_URL = 'https://github.com/xBofi/SecretBroker/releases/latest';

// «Bob», «Bob y Carol», «Bob, Carol e Inés» (Intl.ListFormat, in the language shown).
function listJoin(names) {
  return fmtList((names || []).filter(Boolean).map(String));
}

function canWrite(entry) {
  return !entry.shared || ['manage', 'edit'].includes(entry.shared.permission);
}

function useOnly(entry) {
  return !!entry.shared && entry.shared.permission === 'use';
}

// Changes need the server; reads and everything local keep working.
function teamOffline() {
  return !!state.team && ['offline', 'reconnect'].includes(state.team.state);
}

// A shared credential in a few words: «Compartida · Producción», or for a direct share «Compartida con Bob»
// (this user shared it) / «Compartida por Alicia» (received).
function sharedText(shared) {
  if (shared.with) return shared.by_me ? t('shared_badge.shared_with', { name: shared.with }) : t('shared_badge.shared_by', { name: shared.with });
  return t('shared_badge.shared', { value: shared.collection_name || t('common.team') });
}

// Where a shared credential lives, as a name: the collection, or «Con Bob» for a direct share.
function collectionLabel(shared) {
  return shared.with ? t('direct_share.with_name', { name: shared.with }) : shared.collection_name;
}

function sharedBadge(shared) {
  const title = shared.with && shared.by_me && shared.with_permission
    ? t('shared_badge.their_permission', { name: shared.with, value: PERMISSION_LABELS[shared.with_permission] })
    : t('shared_badge.your_permission', { value: PERMISSION_LABELS[shared.permission], value2: PERMISSION_HELP[shared.permission].split(': ')[1] });
  return el('span', { class: 'shared-badge', title }, icon('users', 'sm'), sharedText(shared));
}

// Why a shared credential's edit has not reached the team yet (null: nothing waiting, or it goes out now).
function unsentText(entry) {
  const shared = entry.shared;
  if (!shared || !shared.unsent) return null;
  if (shared.unsent === 'rekey') {
    return t('unsent_text.your_change_is_waiting_has', { collection_name: shared.collection_name });
  }
  const st = (state.team || {}).state;
  if (st === 'offline') return t('unsent_text.your_change_will_be_sent');
  if (st === 'reconnect') return t('unsent_text.your_change_will_be_sent_2');
  if (st === 'error') return t('unsent_text.your_change_hasn_reached_team');
  return null;
}

// What needs the user in the team: changes to review and keys to change because someone left.
function teamAttention() {
  const reminders = state.reminders || {};
  return state.entries.filter((e) => (e.shared && e.shared.pending_change) || (reminders[e.id] || {}).kind === 'team_access');
}

function teamAttentionCount() {
  const team = state.team || {};
  return teamAttention().length + (team.waiting || []).length + (team.held_deletions || []).length
    + (team.connected && team.verified === false ? 1 : 0);
}

// The Equipo button in the sidebar: a warning when the team can't sync, else what needs attention.
function updateTeamNav() {
  const button = document.querySelector('.nav button[data-view="team"]');
  if (!button || !state.status) return;
  const held = state.status.team_held || 0;
  const problem = {
    reconnect: t('update_team_nav.your_team_session_has_expired'),
    offline: t('update_team_nav.no_connection_team_server_everything'),
    error: t('update_team_nav.there_problem_syncing_with_team'),
  }[state.status.team] || (held ? tn('team.changes_wait_rekey', held) : null);
  const count = teamAttentionCount();
  const [cls, text] = problem ? ['count warn', '!'] : count ? ['count', String(count)] : [null, null];
  let badge = button.querySelector('.count');
  if (!cls) { if (badge) badge.remove(); }
  else {
    if (!badge) { badge = el('span', {}); button.append(badge); }
    badge.className = cls;
    badge.textContent = text;
  }
  button.title = problem || '';
}

async function teamAct(op, params, reason, button) {
  busy(button, true);
  const result = await withProof((p) => api().call(op, params, p), reason);
  busy(button, false);
  if (!result.ok && result.code !== 'cancelled') toast(result.error, 'error');
  return result;
}

function confirmModal({ title, text, warning, action, danger = false, onConfirm }) {
  const button = el('button', { class: `btn ${danger ? 'solid-danger' : 'primary'}` }, action);
  const modal = openModal({
    title,
    body: [el('p', { class: 'muted' }, text),
      warning ? el('div', { class: `warning ${danger ? 'is-danger' : ''}` }, icon('alert', 'sm'), el('span', {}, warning)) : null],
    footer: [el('button', { class: 'btn', onclick: () => modal.close() }, t('common.cancel')), button],
  });
  button.addEventListener('click', async () => { if (await onConfirm(button)) modal.close(); });
}

// A «?» that opens a short explanation next to a control.
function helpPopover(label, title, content) {
  const pop = el('div', { class: 'popover hidden', role: 'dialog', 'aria-label': title },
    el('div', { class: 'popover-title' }, title), content);
  const button = el('button', { class: 'btn icon-only help-btn', type: 'button', title: label, 'aria-label': label }, '?');
  const wrap = el('span', { class: 'popover-wrap' }, button, pop);
  const outside = (event) => { if (!wrap.contains(event.target)) close(); };
  const close = () => { pop.classList.add('hidden'); document.removeEventListener('mousedown', outside); };
  button.addEventListener('click', () => {
    if (!pop.classList.contains('hidden')) { close(); return; }
    pop.classList.remove('hidden');
    document.addEventListener('mousedown', outside);
  });
  pop.addEventListener('keydown', (event) => { if (event.key === 'Escape') { event.stopPropagation(); close(); } });
  return wrap;
}

function permissionHelp() {
  return helpPopover(t('permission_help.what_each_permission_allows'), t('permission_help.permissions_in_collection'), [
    el('div', { class: 'perm-legend' }, Object.keys(PERMISSION_LABELS).map((p) => {
      const [label, text] = PERMISSION_HELP[p].split(': ');
      return el('div', {}, el('b', {}, label), el('span', {}, text));
    })),
    el('p', { class: 'faint small', style: 'margin-top:8px' }, t('permission_help.use_only_is_enforced_by'))]);
}

function permissionSelect(value) {
  const select = el('select', { class: 'input compact', title: PERMISSION_HELP[value] || t('permission_select.permission'), 'aria-label': t('permission_select.permission') },
    Object.entries(PERMISSION_LABELS).map(([p, text]) => el('option', { value: p, title: PERMISSION_HELP[p] }, text)));
  select.value = value;
  select.addEventListener('change', () => { select.title = PERMISSION_HELP[select.value]; });
  return select;
}

// The sync state: a short line for the header, and the whole story for its tooltip.
function syncLine(team) {
  if (!team || !team.connected) return ['', '', ''];
  const every = t('sync_line.syncs_by_itself_when_you');
  if (state.teamRefreshing && team.state !== 'syncing') return ['', t('sync_line.updating'), t('sync_line.asking_server_for_latest_meanwhile')];
  switch (team.state) {
    case 'syncing': return ['', t('sync_line.syncing'), every];
    case 'offline': return ['warn', t('sync_line.offline'), team.error || t('sync_line.can_reach_server_retries_by')];
    case 'reconnect': return ['warn', t('sync_line.session_expired'), t('sync_line.sign_in_again_keep_syncing')];
    case 'error': return ['warn', t('common.couldn_sync'), team.error || t('sync_line.will_retry_by_itself')];
    default: return ['', team.last_sync ? t('sync_line.synced', { time: formatTime(team.last_sync) }) : t('sync_line.not_synced'), every];
  }
}

function updateTeamSync() {
  const node = document.getElementById('team-sync');
  if (!node) return;
  const [kind, text, detail] = syncLine(state.team);
  node.className = `state-text ${kind}`;
  node.textContent = text;
  node.title = detail;
}

// After each sync round: reload when something arrived, otherwise just refresh the sync line.
async function pollTeam() {
  const seen = `${state.status.team}|${state.status.team_sync}|${state.status.team_held || 0}`;
  const before = state.teamSeen;
  state.teamSeen = seen;
  if (before === undefined || before === seen) return;
  const wasOffline = teamOffline();
  if (state.team) state.team.state = state.status.team;
  if (state.status.team === 'syncing') { updateTeamSync(); return; }
  const result = await api().call('team_status');
  if (!result.ok) return;
  state.team = result.result;
  const last = state.team.last || {};
  const arrived = ['added', 'updated', 'removed', 'conflicts', 'quarantined', 'rotate', 'pushed', 'held'].some((k) => last[k]);
  if ((arrived || wasOffline !== teamOffline()) && state.screen === 'main') {
    if (state.view === 'team') { await loadEntries(); renderView(); } else await refreshInPlace();
  }
  updateTeamSync();
  updateTeamNav();
}

// ----- the team side of a credential

function sharedSection(entry) {
  const shared = entry.shared;
  if (!shared) return null;
  const author = shared.author && typeof shared.author === 'object' ? shared.author.name : shared.author;
  const unsent = unsentText(entry);
  const direct = !!shared.with;
  const unshare = () => confirmModal({
    title: direct ? t('shared_section.stop_sharing_with', { name: entry.name, person: shared.with }) : t('shared_section.stop_sharing', { name: entry.name }),
    text: direct ? t('shared_section.direct_removed', { person: shared.with })
      : t('shared_section.removed_from_for_whole_team', { collection_name: shared.collection_name }),
    warning: direct ? t('shared_section.direct_may_have_copied', { person: shared.with }) : t('shared_section.anyone_who_had_may_have'),
    action: t('shared_section.stop_sharing_2'),
    onConfirm: async (button) => {
      const result = await teamAct('team_unshare_entry', { id: entry.id }, t('shared_section.stop_sharing_3', { name: entry.name }), button);
      if (!result.ok) return false;
      await loadEntries();
      renderMain();
      toast(direct ? t('shared_section.no_longer_shared_with', { person: shared.with }) : t('common.no_longer_shared'));
      return true;
    },
  });
  let where;
  if (direct && shared.by_me) {
    where = [el('p', {}, t('shared_section.shared_with_person', { name: shared.with }), el('b', {}, PERMISSION_LABELS[shared.with_permission] || ''), t('shared_section.end')),
      el('p', { class: 'help' }, t('shared_section.only_the_two_of_you', { name: shared.with }))];
  } else if (direct) {
    where = [el('p', {}, t('shared_section.shared_by_person', { name: shared.with }), el('b', {}, PERMISSION_LABELS[shared.permission]), t('shared_section.end')),
      el('p', { class: 'help' }, PERMISSION_HELP[shared.permission].split(': ')[1])];
  } else {
    where = [el('p', {}, t('shared_section.shared_in'), el('b', {}, shared.collection_name || t('common.collection')), shared.org_name ? t('shared_section.of_org', { org: shared.org_name }) : '',
      t('shared_section.your_permission'), el('b', {}, PERMISSION_LABELS[shared.permission]), t('shared_section.end')),
    el('p', { class: 'help' }, PERMISSION_HELP[shared.permission].split(': ')[1])];
  }
  return el('div', { class: 'section' },
    el('h3', {}, t('common.team')),
    where,
    author ? el('p', { class: 'help' }, t('shared_section.last_change', { author, value: shared.changed ? ` · ${formatTime(shared.changed)}` : '' })) : null,
    unsent ? el('p', { class: 'help unsent-line' }, icon('clock', 'sm'), el('span', {}, el('b', {}, t('shared_section.not_sent')), unsent)) : null,
    canWrite(entry) && (!direct || shared.by_me) ? el('div', { style: 'margin-top:6px' }, el('button', {
      class: 'btn ghost', onclick: unshare, disabled: teamOffline(), title: teamOffline() ? t('common.no_connection_team_server') : null,
    }, direct ? t('shared_section.stop_sharing_with_person', { person: shared.with }) : t('shared_section.stop_sharing_2'))) : null);
}

// A change waiting for review comes from teams.widening_changes as {kind, field?, template?, old?, new?, values?}
// and is worded here, in the page's language. Vaults from before 0.16 keep Spanish lines: each known start is
// translated, the rest of the line (names, hosts) shown as it is.
const CHANGE_LINES = [
  ['Tipo de credencial: ', 'change_line.credential_type'],
  ['Webs nuevas: ', 'change_line.new_websites'],
  ['Autorrellenado del navegador en webs nuevas: ', 'change_line.new_autofill_sites'],
  ['Cómo se envía la clave: ', 'change_line.how_key_is_sent'],
  ['Programas nuevos: ', 'change_line.new_programs'],
  ['Variables nuevas o cambiadas: ', 'change_line.new_variables'],
];
const CHANGE_KINDS = { template: 'change_line.credential_type', hosts: 'change_line.new_websites', fill_sites: 'change_line.new_autofill_sites',
  auth: 'change_line.how_key_is_sent', programs: 'change_line.new_programs', env: 'change_line.new_variables' };

function isTextChange(change) {
  return typeof change === 'string' ? change.startsWith('Instrucciones') : ['description', 'rotation_guide'].includes(change.kind);
}

// Whether a change to review rewrites the description (the other text a teammate's change can bring is a new
// rotation guide). Changes kept by versions before 0.17 only had descriptions.
function textsDescribed(change) {
  return !!change.texts && (change.description != null || !change.rotation_guide);
}

// The AI's edits of a credential (service._describe_changes): {kind: setting, key, value} for its context, and
// allowed_hosts / programs / env_vars with the whole new list. Requests from before 0.16 only have the Spanish
// `detail`: each known start of a line is translated (AI_EDIT_LINES), the rest shown as it is.
const AI_EDIT_LINES = [
  ['Nombre: ', 'common.name'], ['Notas para la IA: ', 'common.instructions_for_ai'], ['Etiquetas: ', 'common.tags'],
  ['Caduca: ', 'common.expires'], ['Rotar cada (días): ', 'common.remind_me_rotate'], ['Guía de rotación: ', 'ai_change.rotation_guide'],
  ['Dónde se usa: ', 'common.where_used'], ['Comprobar cada (horas): ', 'common.check_that_works'],
  ['Petición de prueba: ', 'ai_change.test_request'], ['Webs permitidas: ', 'show_form.websites_where_can_use'],
  ['Programas: ', 'show_form.programs_that_can_use'], ['Variables: ', 'show_form.environment_variables'],
];
const SETTING_LABELS = { name: 'common.name', description: 'common.instructions_for_ai', tags: 'common.tags', expires: 'common.expires',
  rotate_every_days: 'common.remind_me_rotate', rotation_guide: 'ai_change.rotation_guide', used_in: 'common.where_used',
  check_every_hours: 'common.check_that_works', test_request: 'ai_change.test_request' };
const LIST_KINDS = { allowed_hosts: 'show_form.websites_where_can_use', programs: 'show_form.programs_that_can_use', env_vars: 'show_form.environment_variables' };

function settingValue(key, value) {
  if (value === null || value === undefined || value === '') return '—';
  if (key === 'tags') return listJoin(value);
  if (key === 'used_in') return value.join('; ');
  if (key === 'expires') return /^\d{4}-\d\d-\d\d$/.test(value) ? fmtDate(`${value}T00:00:00`, { dateStyle: 'medium' }) : value;
  if (key === 'rotate_every_days') return value ? t('every_label.every_days', { days: value }) : lowerFirst(t('common.never'));
  if (key === 'check_every_hours') return checkLabel(value);
  if (key === 'rotation_guide') return [tn('ai_change.steps', value.steps || 0), (value.sources || []).length ? t('ai_change.sources', { sources: value.sources.join(', ') }) : ''].filter(Boolean).join('; ');
  if (key === 'test_request') return `${value.method} ${value.url} → HTTP ${value.status}`;
  return `«${String(value).slice(0, 200)}»`;
}

// The lines of an AI's request to edit a credential, in the app's language.
function aiEditLines(request) {
  if (Array.isArray(request.changes) && request.changes.length) return request.changes.map(changeLine);
  return (request.detail || '').split('\n').map((line) => {
    const known = AI_EDIT_LINES.find(([start]) => line.startsWith(start));
    return known ? `${t(known[1])}: ${line.slice(known[0].length)}` : line;
  });
}

function changeLine(change) {
  if (typeof change === 'string') {
    const known = CHANGE_LINES.find(([start]) => change.startsWith(start));
    return known ? `${t(known[1])}: ${change.slice(known[0].length)}` : change;
  }
  if (change.kind === 'field') {
    const spec = ((TEMPLATES[change.template] || {}).fields || []).find((f) => f.name === change.field);
    return `${spec ? fieldLabel(change.template, spec) : change.field}: ${change.old || '—'} → ${change.new || '—'}`;
  }
  if (change.kind === 'setting') return `${SETTING_LABELS[change.key] ? t(SETTING_LABELS[change.key]) : change.key}: ${settingValue(change.key, change.value)}`;
  if (LIST_KINDS[change.kind]) return `${t(LIST_KINDS[change.kind])}: ${(change.values || []).join(', ') || '—'}`;
  const value = change.values ? listJoin(change.values)
    : change.kind === 'template' ? (TEMPLATES[change.new] || {}).label || change.new : change.new;
  return CHANGE_KINDS[change.kind] ? `${t(CHANGE_KINDS[change.kind])}: ${value}` : String(value ?? '');
}

// One line for a change waiting for review: new destinations, or new instructions for the AI.
function changeSummary(change) {
  const who = change.by || t('common.teammate');
  const hosts = change.only_hosts ? change.hosts || [] : [];
  const destinations = (change.changes || []).some((c) => !isTextChange(c));
  if (hosts.length) return t('change_summary.wants_ai_be_able_send', { who, names: listJoin(hosts) });
  if (change.texts && !destinations && !textsDescribed(change)) return t('change_summary.changed_rotation_guide', { who });
  if (change.texts && !destinations) return t('change_summary.changed_instructions_ai_reads', { who });
  if (change.texts) return t('change_summary.changed_where_this_key_can', { who });
  return t('change_summary.changed_where_this_key_can_2', { who });
}

// A teammate widened where the key can go, or rewrote the description the AI reads as instructions: it keeps
// working as before until this user decides.
function pendingChangeBox(entry) {
  const change = entry.shared.pending_change;
  const write = canWrite(entry);
  const who = change.by || t('common.teammate');
  const hosts = change.only_hosts ? change.hosts || [] : [];
  const destinations = (change.changes || []).filter((c) => !isTextChange(c));
  const decide = async (accept, button) => {
    const result = await teamAct('team_accept_change', { id: entry.id, accept },
      accept ? t('pending_change_box.allow_change_in', { name: entry.name }) : t('pending_change_box.keep_as_was', { name: entry.name }), button);
    if (!result.ok) return;
    await loadEntries();
    renderMain();
    toast(accept ? t('pending_change_box.change_allowed') : t('pending_change_box.rejected_stays_as_was_for'));
  };
  const reject = write ? el('button', { class: 'btn primary', title: t('pending_change_box.reject_and_keep_as_was') }, t('pending_change_box.reject')) : null;
  if (reject) reject.addEventListener('click', () => decide(false, reject));
  const guide = change.rotation_guide;
  const described = textsDescribed(change);
  const allow = el('button', { class: write ? 'btn' : 'btn primary' }, hosts.length === 1 ? t('pending_change_box.allow', { value: hosts[0] })
    : change.texts && !destinations.length
      ? (described || !guide ? t('pending_change_box.accept_new_description') : t('pending_change_box.accept_new_guide'))
      : t('pending_change_box.allow_changes'));
  allow.addEventListener('click', () => decide(true, allow));
  return el('div', { class: 'section draft-box review-box' },
    hosts.length
      ? el('h3', {}, t('pending_change_box.wants_ai_be_able_send', { who }), hosts.map((h, i) => [i ? ', ' : '', el('code', { class: 'selectable' }, h)]))
      : el('h3', {}, changeSummary(change)),
    hosts.length || !destinations.length ? null : el('ul', { class: 'used-in' }, destinations.map((c) => el('li', { class: 'selectable' }, changeLine(c)))),
    described ? el('div', { class: 'field' },
      el('div', { class: 'k small muted' }, t('pending_change_box.new_description_ai_reads_as')),
      el('blockquote', { class: 'quote selectable' }, change.description || '')) : null,
    guide ? el('div', { class: 'field' },
      el('div', { class: 'k small muted' }, t('pending_change_box.new_rotation_guide')),
      el('blockquote', { class: 'quote selectable' },
        el('ol', {}, (guide.create || []).map((step) => el('li', {}, step))),
        [...(guide.links || []).map((link) => link.url), ...(guide.sources || [])].length
          ? el('div', { class: 'small' }, listJoin([...new Set([...(guide.links || []).map((link) => hostOf(link.url)), ...(guide.sources || []).map(hostOf)])]))
          : null)) : null,
    el('p', { class: 'help' }, change.texts && !destinations.length
      ? (described ? t('pending_change_box.while_you_decide_ai_keeps') : t('pending_change_box.while_you_decide_old_guide'))
      : t('pending_change_box.while_you_decide_ai_can'), write
      ? t('pending_change_box.rejecting_undoes_change_for_whole')
      : t('pending_change_box.only_someone_who_can_edit')),
    el('div', { style: 'margin-top:8px;display:flex;gap:8px;flex-wrap:wrap' }, reject, allow));
}

// ----- sharing one credential or several: with one person, or in a collection

async function shareEntry(entry) {
  return shareEntries([entry]);
}

// The confirmed teammates (not this user) of the organizations this user is in, with whether they are verified
// on this PC (`trusted`). From what this PC knows; `refresh` asks the server for the latest (codes, newcomers).
async function teamPeople(refresh) {
  if (!state.teamData) {  // Equipo not opened yet: what this PC knows of the organizations is enough here
    const known = await api().call('team_overview');
    if (known.ok) state.teamData = known.result;
  }
  const data = state.teamData || {};
  const orgs = (data.orgs || []).filter((o) => !o.status || o.status === 'confirmed');
  if (refresh) {
    await Promise.all(orgs.map(async (o) => {
      const result = await api().call('team_members', { org: o.id });
      if (result.ok) (data.members = data.members || {})[o.id] = result.result;
    }));
  }
  return orgs.flatMap((o) => ((data.members || {})[o.id] || [])
    .filter((m) => !m.me && m.user_id && m.status === 'confirmed')
    .map((m) => ({ ...m, org: o.id, org_name: o.name, label: m.name || m.email })))
    .sort((a, b) => compareText(a.label, b.label));
}

// What this user already shares with each person: {`${org}|${user}`: collection}.
function directShares(collections) {
  return Object.fromEntries((collections || []).filter((c) => c.direct && c.permission === 'manage' && c.with)
    .map((c) => [`${c.org}|${c.with.user_id}`, c]));
}

const DIRECT_PERMISSIONS = ['edit', 'view', 'use'];

// Editor / Lector / Solo uso for someone a credential is shared with, and one line on what it allows.
function directPermissionPicker(value, onChange) {
  const help = el('p', { class: 'help' });
  const buttons = DIRECT_PERMISSIONS.map((p) => el('button', { type: 'button', 'data-permission': p }, PERMISSION_LABELS[p]));
  const picker = { value, touched: false };
  const show = () => {
    buttons.forEach((b) => {
      b.classList.toggle('active', b.dataset.permission === picker.value);
      b.setAttribute('aria-pressed', b.dataset.permission === picker.value ? 'true' : 'false');
    });
    help.textContent = t(`direct_share.permission_${picker.value}`);
  };
  // What a share with that person already has, until the user picks one here.
  picker.suggest = (permission) => { if (!picker.touched && permission) { picker.value = permission; show(); } };
  buttons.forEach((b) => b.addEventListener('click', () => {
    picker.value = b.dataset.permission;
    picker.touched = true;
    show();
    if (onChange) onChange(picker.value);
  }));
  show();
  picker.node = el('div', { class: 'field' }, el('label', {}, t('direct_share.they_can')),
    el('div', { class: 'segmented', role: 'group', 'aria-label': t('permission_select.permission') }, buttons), help);
  return picker;
}

// Someone not verified on this PC: nothing is sealed to their key until this user compares their code. One click.
function verifyFirstBox(person, onVerified) {
  if (person.key_changed) {
    return el('div', { class: 'warning' }, icon('alert', 'sm'), el('span', {},
      t('direct_share.key_changed', { name: person.label }), ' ',
      el('button', { class: 'link', onclick: () => { closeAllModals(); state.view = 'team'; state.teamTab = 'people'; state.teamOrg = person.org; renderMain(); } },
        t('direct_share.go_to_people'))));
  }
  const button = el('button', { class: 'btn primary' }, t('direct_share.verify_name', { name: person.label }));
  button.addEventListener('click', async () => {
    const result = await teamAct('team_confirm_member', { org: person.org, user_id: person.user_id }, t('common.verify_2', { label: person.label }), button);
    if (!result.ok) return;
    person.trusted = true;
    toast(t('verify_row.verified', { label: person.label }));
    onVerified();
  });
  return el('div', { class: 'verify-first' },
    el('p', {}, el('b', {}, t('direct_share.not_verified_yet', { name: person.label }))),
    el('p', { class: 'muted small' }, t('direct_share.compare_code', { name: person.label })),
    el('div', { class: 'fingerprint selectable' }, person.fingerprint || ''),
    el('div', { style: 'margin-top:8px' }, button));
}

function closeAllModals() {
  document.querySelectorAll('.overlay').forEach((o) => o.dispatchEvent(new Event('dismiss')));
}

// The result of team_share_with, said once.
function sharedWithToast(result, entries) {
  const { shared: done, failed, person } = result;
  if (failed.length) toast(`${tn('share.shared_with_count', done.length, { name: person })}; ${tn('share.not_shared', failed.length, { error: failed[0].error })}`, 'error');
  else if (entries.length === 1) toast(t('share.shared_with_one', { name: person }));
  else toast(tn('share.shared_with_count', done.length, { name: person }));
}

async function shareEntries(entries, onDone) {
  const result = await api().call('team_collections');
  if (!result.ok) { toast(result.error, 'error'); return; }
  const collections = result.result;
  const writable = collections.filter((c) => ['manage', 'edit'].includes(c.permission) && !c.direct);
  // Who this PC knows; nobody known yet (Equipo never opened here): ask the server before drawing.
  let people = await teamPeople(false);
  const asked = !people.length;
  if (asked) people = await teamPeople(true);
  const overview = state.teamData || {};
  const adminOrgs = (overview.orgs || []).filter((o) => ['owner', 'admin'].includes(o.role) && (!o.status || o.status === 'confirmed'));
  const inOrg = (overview.orgs || []).some((o) => !o.status || o.status === 'confirmed');
  const what = entries.length === 1 ? entries[0].name : tn('common.credentials_count', entries.length);
  if (!writable.length && !adminOrgs.length && !inOrg) {
    const modal = openModal({
      title: t('share_entries.share', { what }),
      body: el('p', { class: 'muted' }, t('share_entries.you_don_have_any_collection')),
      footer: [el('button', { class: 'btn', onclick: () => modal.close() }, t('common.cancel')),
        el('button', { class: 'btn primary', onclick: () => { modal.close(); state.view = 'team'; renderMain(); } }, t('share_entries.go_team'))],
    });
    return;
  }
  const canCollection = writable.length > 0 || adminOrgs.length > 0;
  let mode = !canCollection ? 'person' : state.shareMode || 'person';
  const shares = directShares(collections);
  let chosen = writable.length === 1 ? writable[0].id : writable.length ? null : 'new';
  let personKey = state.sharePerson && people.some((p) => `${p.org}|${p.user_id}` === state.sharePerson) ? state.sharePerson
    : people.length ? `${people[0].org}|${people[0].user_id}` : null;
  const errorText = el('div', { class: 'error-text' });
  const button = el('button', { class: 'btn primary' });
  const personPanel = el('div', { class: 'share-panel' });
  const permission = directPermissionPicker('view');
  const multiOrg = new Set(people.map((p) => p.org)).size > 1;
  const current = () => people.find((p) => `${p.org}|${p.user_id}` === personKey) || null;
  const label = () => {
    const person = current();
    button.textContent = mode === 'person'
      ? (person ? t('direct_share.share_with', { name: person.label }) : t('common.share'))
      : entries.length === 1 ? t('common.share') : t('share_entries.share_2', { length: entries.length });
    button.disabled = mode === 'person' && !(person && person.trusted);
  };
  const drawPerson = () => {
    errorText.textContent = '';
    const person = current();
    if (!people.length) {
      personPanel.replaceChildren(el('p', { class: 'muted' }, t('direct_share.nobody_yet')),
        el('button', { class: 'btn', onclick: () => { modal.close(); state.view = 'team'; state.teamTab = 'people'; renderMain(); } }, t('direct_share.go_to_people')));
      label();
      return;
    }
    const select = el('select', { class: 'input', 'aria-label': t('collection_block.person') },
      people.map((p) => el('option', { value: `${p.org}|${p.user_id}` },
        [p.label, p.name && p.email ? ` (${p.email})` : '', multiOrg ? ` · ${p.org_name}` : ''].join(''))));
    select.value = personKey;
    select.addEventListener('change', () => { personKey = select.value; drawPerson(); });
    const existing = person && shares[`${person.org}|${person.user_id}`];
    if (existing && existing.with) permission.suggest(existing.with.permission);
    personPanel.replaceChildren(
      el('p', { class: 'muted' }, t('direct_share.lead')),
      el('div', { class: 'field' }, el('label', {}, t('direct_share.with_whom')), select),
      person && !person.trusted ? verifyFirstBox(person, () => { drawPerson(); }) : [
        permission.node,
        existing ? el('p', { class: 'help' }, tn('direct_share.already_sharing', existing.entries, { name: person.label })) : null]);
    label();
  };
  // Collections: the existing choice, or a new one (admins).
  const newName = el('input', { class: 'input', placeholder: t('common.name_e_g_production') });
  const newOrg = el('select', { class: 'input compact' }, adminOrgs.map((o) => el('option', { value: o.id }, o.name)));
  if (adminOrgs.some((o) => o.id === state.teamOrg)) newOrg.value = state.teamOrg;
  const newForm = el('div', { class: `inline-form ${chosen === 'new' ? '' : 'hidden'}`, style: 'margin:4px 0 0 34px' },
    newName, adminOrgs.length > 1 ? newOrg : null);
  const pick = (id) => { chosen = id; errorText.textContent = ''; newForm.classList.toggle('hidden', id !== 'new'); if (id === 'new') newName.focus(); };
  const collectionPanel = el('div', { class: 'share-panel' },
    el('p', { class: 'muted' }, t('share_entries.choose_collection_reaches_people_in')),
    el('div', { class: 'choice-list' }, writable.map((c) => el('label', { class: 'choice' },
      el('input', { type: 'radio', name: 'share-collection', value: c.id, checked: chosen === c.id, onchange: () => pick(c.id) }),
      el('div', { class: 'meta' }, el('div', { class: 'title' }, c.name),
        el('div', { class: 'subtitle' }, `${c.org_name} · ${tn('common.credentials_count', c.entries)}${c.needs_rekey ? t('share_entries.will_be_re_encrypted') : ''}`)))),
    adminOrgs.length ? el('label', { class: 'choice' },
      el('input', { type: 'radio', name: 'share-collection', value: 'new', checked: chosen === 'new', onchange: () => pick('new') }),
      el('div', { class: 'meta' }, el('div', { class: 'title' }, t('share_entries.new_collection')),
        el('div', { class: 'subtitle' }, t('share_entries.new_shared_folder_then_you')))) : null),
    newForm);
  const modes = el('div', { class: 'share-modes', role: 'tablist' },
    [['person', t('direct_share.with_a_person')], ['collection', t('direct_share.in_a_collection')]].map(([id, text]) =>
      el('button', { type: 'button', role: 'tab', 'data-mode': id }, text)));
  const setMode = (value) => {
    mode = value;
    state.shareMode = value;
    modes.querySelectorAll('button').forEach((b) => {
      b.classList.toggle('active', b.dataset.mode === mode);
      b.setAttribute('aria-selected', b.dataset.mode === mode ? 'true' : 'false');
    });
    personPanel.classList.toggle('hidden', mode !== 'person');
    collectionPanel.classList.toggle('hidden', mode !== 'collection');
    errorText.textContent = '';
    label();
  };
  modes.querySelectorAll('button').forEach((b) => b.addEventListener('click', () => setMode(b.dataset.mode)));
  const modal = openModal({
    title: t('share_entries.share', { what }),
    body: [canCollection ? modes : null, personPanel, collectionPanel,
      el('p', { class: 'help' }, t('share_entries.shared_whole_key_notes_and')),
      errorText],
    footer: [el('button', { class: 'btn', onclick: () => modal.close() }, t('common.cancel')), button],
    className: 'share-dialog',
  });
  drawPerson();
  setMode(mode);
  // The latest from the server (who joined, who is verified here) without making the dialog wait for it.
  (asked ? Promise.resolve(people) : teamPeople(true)).then((fresh) => {
    if (JSON.stringify(fresh) === JSON.stringify(people) || !document.body.contains(personPanel)) return;
    if (personPanel.contains(document.activeElement) && document.activeElement.tagName === 'SELECT') return;
    people = fresh;
    if (!people.some((p) => `${p.org}|${p.user_id}` === personKey)) personKey = people.length ? `${people[0].org}|${people[0].user_id}` : null;
    drawPerson();
  });
  newName.addEventListener('keydown', (e) => { if (e.key === 'Enter') button.click(); });
  button.addEventListener('click', async () => {
    if (mode === 'person') {
      const person = current();
      if (!person || !person.trusted) return;
      state.sharePerson = personKey;
      const shared = await teamAct('team_share_with', { ids: entries.map((e) => e.id), org: person.org, user_id: person.user_id, permission: permission.value },
        t('direct_share.proof', { what, name: person.label }), button);
      if (!shared.ok) return;
      modal.close();
      sharedWithToast(shared.result, entries);
      if (onDone) onDone();
      await loadEntries();
      renderMain();
      return;
    }
    if (!chosen) { errorText.textContent = t('share_entries.choose_collection'); return; }
    let cid = chosen;
    if (chosen === 'new') {
      if (!newName.value.trim()) { errorText.textContent = t('share_entries.give_collection_name'); newName.focus(); return; }
      const created = await teamAct('team_create_collection', { org: newOrg.value || adminOrgs[0].id, name: newName.value.trim() }, t('common.create_collection'), button);
      if (!created.ok) return;
      cid = created.result.id;
      state.openCollection = cid;
    }
    if (entries.length === 1) {
      const shared = await teamAct('team_share_entry', { id: entries[0].id, collection: cid }, t('share_entries.share_3', { value: entries[0].name }), button);
      if (!shared.ok) return;
      modal.close();
      toast(t('share_entries.shared_in', { collection_name: shared.result.collection_name }));
    } else {
      const shared = await teamAct('team_share_entries', { ids: entries.map((e) => e.id), collection: cid }, t('share_entries.share_4', { what }), button);
      if (!shared.ok) return;
      modal.close();
      const { shared: done, failed, collection_name: name } = shared.result;
      if (failed.length) toast(`${tn('share.shared_in', done.length, { name })}; ${tn('share.not_shared', failed.length, { error: failed[0].error })}`, 'error');
      else toast(tn('share.credentials_shared_in', done.length, { name }));
    }
    if (onDone) onDone();
    await loadEntries();
    renderMain();
  });
}

// From Equipo › Personas: pick which of this user's own credentials to share with that person.
async function shareWithPerson(person) {
  const result = await api().call('team_collections');
  if (!result.ok) { toast(result.error, 'error'); return; }
  const existing = directShares(result.result)[`${person.org}|${person.user_id}`];
  const already = state.entries.filter((e) => existing && e.shared && e.shared.collection === existing.id);
  const mine = state.entries.filter((e) => !e.shared && !e.draft).sort((a, b) => compareText(a.name, b.name));
  const picked = new Set();
  const search = el('input', { class: 'input', type: 'search', placeholder: t('share_with_person.search'), 'aria-label': t('share_with_person.search') });
  const list = el('div', { class: 'pick-list' });
  const button = el('button', { class: 'btn primary' });
  const permission = directPermissionPicker(existing && existing.with ? existing.with.permission : 'view');
  const label = () => {
    button.textContent = picked.size ? tn('share_with_person.share_count', picked.size) : t('common.share');
    button.disabled = !picked.size;
  };
  const row = (entry, done) => el('label', { class: `pick-row ${done ? 'done' : ''}` },
    el('input', { type: 'checkbox', checked: done || picked.has(entry.id), disabled: done, onchange: (event) => {
      if (event.target.checked) picked.add(entry.id); else picked.delete(entry.id);
      label();
    } }),
    glyph(entry.template, 'sm'),
    el('span', { class: 'meta' }, el('span', { class: 'title' }, entry.name),
      done ? el('span', { class: 'subtitle' }, t('share_with_person.already_shared')) : null));
  const draw = () => {
    const query = search.value.trim().toLowerCase();
    const match = (e) => !query || e.name.toLowerCase().includes(query);
    const rows = [...already.filter(match).map((e) => row(e, true)), ...mine.filter(match).map((e) => row(e, false))];
    list.replaceChildren(...(rows.length ? rows : [el('p', { class: 'muted small', style: 'padding:8px 4px' },
      mine.length || already.length ? t('share_with_person.nothing_matches') : t('share_with_person.nothing_to_share'))]));
  };
  search.addEventListener('input', draw);
  const modal = openModal({
    title: t('direct_share.share_with', { name: person.label }),
    body: [
      el('p', { class: 'muted' }, t('share_with_person.choose', { name: person.label })),
      search, list, permission.node,
      existing ? el('p', { class: 'help' }, tn('direct_share.already_sharing', existing.entries, { name: person.label })) : null],
    footer: [el('button', { class: 'btn', onclick: () => modal.close() }, t('common.cancel')), button],
    className: 'share-dialog',
  });
  draw();
  label();
  search.focus();
  button.addEventListener('click', async () => {
    const entries = mine.filter((e) => picked.has(e.id));
    const shared = await teamAct('team_share_with', { ids: entries.map((e) => e.id), org: person.org, user_id: person.user_id, permission: permission.value },
      t('direct_share.proof', { what: entries.length === 1 ? entries[0].name : tn('common.credentials_count', entries.length), name: person.label }), button);
    if (!shared.ok) return;
    modal.close();
    sharedWithToast(shared.result, entries);
    await loadEntries();
    renderMain();
  });
}

// ----- after someone leaves: change, one after the other, what they could see

function offboardingPeople() {
  // From the reminders: who left and how many of their credentials are still to change (Salud, Equipo).
  const people = {};
  const unshared = {};
  for (const r of Object.values(state.reminders || {})) {
    if (r.kind !== 'team_access') continue;
    for (const name of r.people || []) {
      (people[name] = people[name] || []).push(r.id);
      unshared[name] = (unshared[name] !== false) && !!r.unshared;
    }
  }
  return Object.entries(people).map(([person, ids]) => ({ person, pending: ids, unshared: unshared[person] }));
}

function offboardingSummary(person) {
  const total = person.total === undefined ? null : person.total;
  if (total === null) return tn(person.unshared ? 'offboarding.unshared_to_change' : 'offboarding.gone_to_change', person.pending.length, { person: person.person });
  return `${tn('offboarding.could_see', total, { person: person.person })} · ${tn('offboarding.changed', total - person.pending.length)}`;
}

function offboardingCard(person, compact = false) {
  const total = person.total === undefined ? person.pending.length : person.total;
  const done = total - person.pending.length;
  return el('div', { class: 'offboard-card' },
    icon('rotate'),
    el('div', { class: 'meta' },
      el('div', { class: 'title' }, offboardingSummary(person)),
      compact ? null : el('div', { class: 'subtitle' }, total === 1
        ? t('offboarding_card.they_could_see_or_copy')
        : t('offboarding_card.they_could_see_or_copy_2')),
      el('div', { class: 'progress', title: t('approval.position', { position: done, total }) }, el('span', { style: `width:${total ? Math.round(100 * done / total) : 100}%` }))),
    el('button', { class: 'btn primary', onclick: () => openOffboarding(person.person) }, done ? t('common.keep_going') : t('common.get_started')));
}

async function openOffboarding(name) {
  const skipped = new Set();
  const body = el('div', { class: 'offboard' });
  const foot = el('div', { style: 'display:contents' });
  const modal = openModal({ title: t('open_offboarding.change_what_could_see', { name }), wide: true, body, footer: [foot] });
  let pending = [];
  const next = () => pending.find((e) => canWrite(e) && !skipped.has(e.id));
  const runNext = () => {
    const entry = next();
    if (!entry) { draw(); return; }
    rotateGuided(entry, async (changed) => {
      if (!changed) skipped.add(entry.id);  // closed without changing it: the user decides what's next
      await draw();
      if (changed && next()) runNext();
    });
  };
  const draw = async () => {
    const [result] = await Promise.all([api().call('team_offboarding'), loadEntries()]);
    const person = (result.ok ? result.result : []).find((p) => p.person === name) || { person: name, total: 0, pending: [] };
    const byId = Object.fromEntries(state.entries.map((e) => [e.id, e]));
    pending = person.pending.map((id) => byId[id]).filter(Boolean);
    const done = person.total - pending.length;
    const row = (entry) => {
      const mine = canWrite(entry);
      const change = el('button', { class: 'btn' }, t('common.change'));
      change.addEventListener('click', () => { skipped.delete(entry.id); rotateGuided(entry, async () => { await draw(); }); });
      return el('div', { class: `access-row ${skipped.has(entry.id) ? 'skipped' : ''}` }, glyph(entry.template),
        el('div', { class: 'meta' }, el('div', { class: 'title' }, entry.name),
          el('div', { class: 'subtitle' }, [entry.shared ? collectionLabel(entry.shared) : null,
            !mine ? t('open_offboarding.whoever_manages_changes_will_reach') : skipped.has(entry.id) ? t('open_offboarding.skipped') : null].filter(Boolean).join(' · '))),
        mine ? [skipped.has(entry.id) ? null : el('button', { class: 'btn ghost', onclick: () => { skipped.add(entry.id); draw(); } }, t('open_offboarding.skip')), change] : null);
    };
    body.replaceChildren(
      el('p', { class: 'muted' }, person.unshared ? t('open_offboarding.no_longer_shared_with', { name }) : t('open_offboarding.is_no_longer_on_team', { name })),
      el('div', { class: 'offboard-progress' },
        el('div', { class: 'progress' }, el('span', { style: `width:${person.total ? Math.round(100 * done / person.total) : 100}%` })),
        el('span', { class: 'muted small' }, tn('offboarding.done_of_total', person.total, { done }))),
      pending.length ? el('div', {}, pending.map(row))
        : el('p', { class: 'ok-text' }, icon('check', 'sm'), t('open_offboarding.done_no_longer_has_any', { name })));
    const following = next();
    foot.replaceChildren(el('div', { class: 'spacer' }),
      el('button', { class: 'btn', onclick: () => modal.close() }, pending.length ? t('common.later') : t('common.close')),
      following ? el('button', { class: 'btn primary', onclick: runNext }, done || skipped.size ? t('open_offboarding.continue_with', { name: following.name }) : t('common.get_started')) : null);
  };
  await draw();
}

// ----- the Equipo view

async function renderTeam(content) {
  if (!content.querySelector('.team-view')) {
    content.replaceChildren(el('div', { class: 'content-header' }, el('h1', {}, t('common.team'))),
      el('div', { class: 'content-body team-view' }, el('div', { class: 'spinner' })));
  }
  const result = await api().call('team_overview');
  if (state.view !== 'team') return;
  if (!result.ok) {
    content.replaceChildren(el('div', { class: 'content-header' }, el('h1', {}, t('common.team'))),
      el('div', { class: 'content-body team-view' }, el('div', { class: 'warning' }, icon('alert', 'sm'), el('span', {}, result.error))));
    return;
  }
  state.team = result.result.status;
  if (!state.team.connected) { renderTeamConnect(content); return; }
  state.teamData = result.result;
  drawTeam(content);
  refreshTeam(content);
}

function teamOrgOf(data) {
  const orgs = data.orgs || [];
  if (!orgs.some((o) => o.id === state.teamOrg)) state.teamOrg = orgs.length ? orgs[0].id : null;
  return orgs.find((o) => o.id === state.teamOrg) || null;
}

// Ask the server for the latest (short timeouts) and redraw if anything changed.
async function refreshTeam(content, again = true) {
  const ticket = (state.teamRefresh = (state.teamRefresh || 0) + 1);
  state.teamRefreshing = true;
  updateTeamSync();
  const org = teamOrgOf(state.teamData);
  const confirmed = org && (!org.status || org.status === 'confirmed');
  const calls = [api().call('team_orgs'), api().call('team_invites')];
  if (confirmed) calls.push(api().call('team_members', { org: org.id }));
  if (confirmed && ['owner', 'admin'].includes(org.role)) calls.push(api().call('team_events', { org: org.id }));
  if (state.openCollection) calls.push(api().call('team_collection_members', { collection: state.openCollection }));
  if (!org || state.teamTab === 'account') calls.push(api().call('team_devices'));
  if (state.teamTab === 'server' && state.team.server_admin) {
    for (const op of ['team_admin_overview', 'team_admin_users', 'team_admin_orgs', 'team_admin_events', 'team_admin_backups']) calls.push(api().call(op));
  }
  const results = await Promise.all(calls);
  const fresh = await api().call('team_overview');
  if (ticket !== state.teamRefresh || state.view !== 'team') return;
  state.teamRefreshing = false;
  const failed = results.find((r) => !r.ok);
  state.teamReadError = failed && !['offline', 'reconnect'].includes(failed.code) ? failed.error : null;
  if (!fresh.ok) { updateTeamSync(); return; }
  state.team = fresh.result.status;
  if (!state.team.connected) { renderTeamConnect(content); return; }
  const changed = JSON.stringify(fresh.result) !== JSON.stringify(state.teamData);
  state.teamData = fresh.result;
  if (changed || failed) redrawTeam(content);
  else updateTeamSync();
  const now = teamOrgOf(state.teamData);
  if (again && now && (!org || now.id !== org.id)) refreshTeam(content, false);  // first time: its members too
  updateTeamNav();
}

// Redraw, but never under the user's fingers: while they type in the view, wait until they leave the field.
function redrawTeam(content) {
  const active = document.activeElement;
  if (active && content.contains(active) && ['INPUT', 'SELECT', 'TEXTAREA'].includes(active.tagName)) {
    if (state.teamRedrawWaiting) return;
    state.teamRedrawWaiting = true;
    active.addEventListener('blur', () => setTimeout(() => {
      state.teamRedrawWaiting = false;
      if (state.view === 'team' && content.isConnected) drawTeam(content);
    }, 150), { once: true });
    return;
  }
  drawTeam(content);
}

function drawTeam(content) {
  const data = state.teamData;
  const org = teamOrgOf(data);
  const rerender = () => renderTeam(content);
  const admin = !!org && ['owner', 'admin'].includes(org.role);
  const confirmed = !!org && (!org.status || org.status === 'confirmed');
  const collections = org ? (data.collections || []).filter((c) => c.org === org.id) : [];
  const members = org ? (data.members || {})[org.id] || [] : [];
  const tabs = [];
  if (confirmed) {
    tabs.push(['collections', t('draw_team.collections'), collections.length]);
    tabs.push(['people', t('draw_team.people'), members.filter((m) => m.status !== 'invited').length]);
    if (admin) tabs.push(['activity', t('common.activity'), null]);
  }
  const serverAdmin = !!state.team.server_admin;
  if (org) tabs.push(['account', t('common.your_account'), null]);
  else tabs.push(['none', serverAdmin ? t('common.organization') : '', null]);  // no organization yet: one page (no tabs)
  if (serverAdmin) tabs.push(['server', t('server_admin.tab'), null]);  // the team server's admin: the whole server
  if (!tabs.some(([id]) => id === state.teamTab)) state.teamTab = tabs[0][0];

  const [kind, text, detail] = syncLine(state.team);
  const syncButton = el('button', { class: 'btn' }, icon('rotate', 'sm'), t('draw_team.sync_now'));
  syncButton.addEventListener('click', async () => {
    busy(syncButton, true);
    const result = await api().call('team_sync');
    busy(syncButton, false);
    if (!result.ok) { toast(result.error, 'error'); return; }
    await loadEntries();
    rerender();
    if (result.result.state === 'ok') toast(t('draw_team.synced'));
    else toast(result.result.error || t('common.couldn_sync'), 'error');
  });
  const orgPicker = data.orgs && data.orgs.length ? el('select', { class: 'input compact org-picker', title: t('common.organization') },
    data.orgs.map((o) => el('option', { value: o.id }, o.name)), el('option', { value: '__new' }, t('draw_team.new_organization'))) : null;
  if (orgPicker) {
    orgPicker.value = state.teamOrg;
    orgPicker.addEventListener('change', () => {
      if (orgPicker.value === '__new') { orgPicker.value = state.teamOrg; newOrgModal(rerender); return; }
      state.teamOrg = orgPicker.value;
      state.teamTab = 'collections';
      drawTeam(content);
      refreshTeam(content, false);
    });
  }
  const peopleAlert = verificationsFor(org, members, admin).length;
  const top = el('div', { class: 'team-top' },
    el('div', { class: 'content-header' }, el('h1', {}, t('common.team')), state.teamTab === 'server' ? null : orgPicker,
      org && state.teamTab !== 'server' ? el('span', { class: 'muted small' }, ROLE_LABELS[org.role] || org.role) : null,
      el('div', { class: 'spacer' }),
      el('span', { id: 'team-sync', class: `state-text ${kind}`, title: detail }, text), syncButton),
    org || serverAdmin ? el('div', { class: 'team-tabs', role: 'tablist' }, tabs.map(([id, label, count]) => el('button', {
      class: `${state.teamTab === id ? 'active' : ''} ${id === 'server' ? 'server-tab' : ''}`, role: 'tab', 'aria-selected': state.teamTab === id ? 'true' : 'false',
      onclick: () => { state.teamTab = id; drawTeam(content); if (id === 'account' || id === 'server') refreshTeam(content, false); },
    }, label, count !== null && count !== undefined ? el('span', { class: 'tab-count' }, count) : null,
    id === 'people' && peopleAlert ? el('span', { class: 'tab-dot', title: tn('team.people_to_verify', peopleAlert) }) : null))) : null);

  let panel;
  if (state.teamTab === 'server') panel = teamServerPanel(content, rerender);
  else if (!org) panel = [teamNoOrg(data, rerender), el('div', { style: 'margin-top:28px' }, teamAccountPanel(null, rerender))];
  else if (!confirmed && state.teamTab !== 'account') panel = teamWaitingForAdmin(org);
  else if (state.teamTab === 'collections') panel = teamCollectionsPanel(org, collections, members, admin, content);
  else if (state.teamTab === 'people') panel = teamPeoplePanel(org, members, admin, rerender);
  else if (state.teamTab === 'activity') panel = teamEventsPanel((data.events || {})[org.id], members, collections);
  else panel = teamAccountPanel(org, rerender);

  const old = content.querySelector('.content-body.team-view');
  const scroll = old && state.teamTabShown === state.teamTab ? old.scrollTop : 0;
  state.teamTabShown = state.teamTab;
  // Servidor is about the whole server: only what says whether the server can be reached goes above it.
  const banners = state.teamTab === 'server' ? teamStatusBanners() : teamBanners(org, members, admin, rerender);
  const body = el('div', { class: 'content-body team-view' }, banners, panel);
  content.replaceChildren(top, body);
  body.scrollTop = scroll;
  const scrolled = () => top.classList.toggle('scrolled', body.scrollTop > 2);
  body.addEventListener('scroll', scrolled, { passive: true });
  scrolled();
  if (teamOffline()) {
    content.querySelectorAll('[data-mutates]').forEach((node) => {
      node.disabled = true;
      node.title = t('draw_team.no_connection_team_server_try');
    });
  }
}

// People whose security code this user should compare now: they can't share (or be shared with) until then.
function verificationsFor(org, members, admin) {
  const waiting = ((state.team && state.team.waiting) || []).map((p) => ({ ...p, kind: 'waiting' }));
  const seen = new Set(waiting.map((p) => p.user_id));
  const rows = members.filter((m) => !m.me && m.user_id && m.fingerprint && !seen.has(m.user_id)
    && (m.key_changed || (m.status === 'accepted' && admin)));
  return [...waiting, ...rows.map((m) => ({ ...m, org: org.id, kind: m.key_changed ? 'changed' : 'confirm' }))];
}

function teamBanners(org, members, admin, rerender) {
  const team = state.team;
  const data = state.teamData || {};
  const detail = team.error || (team.state === 'offline' ? t('sync_line.can_reach_server_retries_by') : t('sync_line.will_retry_by_itself'));
  const verify = verificationsFor(org, members, admin);
  const reviews = state.entries.filter((e) => e.shared && e.shared.pending_change);
  const unsent = state.entries.filter((e) => unsentText(e));
  const leavers = (data.offboarding || []).filter((p) => p.pending.length);
  const open = (entry) => { state.view = 'credentials'; state.selected = entry.id; state.tag = null; state.collection = null; renderMain(); };
  return el('div', { class: 'team-banners' },
    team.state === 'reconnect' ? el('div', { class: 'pause-card paused' },
      el('div', { class: 'meta' }, el('h3', {}, t('team_banners.your_team_session_has_expired')),
        el('p', {}, t('team_banners.everything_keeps_working_with_what'))),
      el('button', { class: 'btn primary', onclick: () => reconnectTeam(rerender) }, t('common.sign_in_again'))) : null,
    ['offline', 'error'].includes(team.state) ? el('div', { class: 'warning banner-line' }, icon('alert', 'sm'), el('span', {}, detail)) : null,
    state.teamReadError ? el('div', { class: 'warning banner-line' }, icon('alert', 'sm'), el('span', {}, state.teamReadError)) : null,
    team.verified === false ? verifyEmailCard(team, rerender) : null,
    (team.held_deletions || []).map((held) => heldDeletionsCard(held, rerender)),
    (data.invites || []).length ? teamInvitesGroup(data.invites, rerender) : null,
    verify.length ? el('div', { class: 'banner' },
      el('div', { class: 'banner-head' }, icon('fingerprint', 'sm'), el('h3', {}, t('team_banners.verify', { length: verify.length })),
        el('span', { class: 'muted small' }, t('team_banners.compare_their_security_code_by'))),
      verify.map((person) => verifyRow(person, rerender))) : null,
    leavers.map((person) => offboardingCard(person)),
    reviews.length || unsent.length ? el('div', { class: 'banner' },
      el('div', { class: 'banner-head' }, icon('alert', 'sm'), el('h3', {}, t('team_banners.review', { count: reviews.length + unsent.length }))),
      reviews.map((entry) => el('div', { class: 'access-row' }, glyph(entry.template),
        el('div', { class: 'meta' }, el('div', { class: 'title' }, entry.name),
          el('div', { class: 'subtitle' }, changeSummary(entry.shared.pending_change))),
        el('button', { class: 'btn', onclick: () => open(entry) }, t('common.review')))),
      unsent.map((entry) => el('div', { class: 'access-row' }, glyph(entry.template),
        el('div', { class: 'meta' }, el('div', { class: 'title' }, entry.name, el('span', { class: 'draft-badge', style: 'margin-left:8px' }, t('common.not_sent'))),
          el('div', { class: 'subtitle' }, unsentText(entry))),
        el('button', { class: 'btn ghost', onclick: () => open(entry) }, t('common.open'))))) : null);
}

// Above «Servidor»: the session, the connection and a read that failed (a server too old for these pages).
function teamStatusBanners() {
  const team = state.team;
  const detail = team.error || (team.state === 'offline' ? t('sync_line.can_reach_server_retries_by') : t('sync_line.will_retry_by_itself'));
  return el('div', { class: 'team-banners' },
    ['offline', 'error', 'reconnect'].includes(team.state) ? el('div', { class: 'warning banner-line' }, icon('alert', 'sm'),
      el('span', {}, team.state === 'reconnect' ? t('team_banners.your_team_session_has_expired') : detail)) : null,
    state.teamReadError ? el('div', { class: 'warning banner-line' }, icon('alert', 'sm'), el('span', {}, state.teamReadError)) : null);
}

// The account has not proved it owns its e-mail: until then nobody's invites reach it (someone could have
// registered the address first). One code, typed once.
function verifyEmailCard(team, rerender) {
  const email = (team.user && team.user.email) || '';
  if (team.verification === 'admin') {
    return el('div', { class: 'banner' },
      el('div', { class: 'banner-head' }, icon('shield', 'sm'), el('h3', {}, t('verify_email_card.your_e_mail_still_needs'))),
      el('p', { class: 'muted small' }, t('verify_email_card.this_server_doesn_send_e'),
        el('b', {}, email), t('verify_email_card.they_do_on_server_with')));
  }
  const code = el('input', { class: 'input verify-code', placeholder: t('verify_email_card.e_mail_code'), inputmode: 'numeric', autocomplete: 'one-time-code',
    maxlength: '12', 'aria-label': t('verify_email_card.e_mail_code') });
  const verify = el('button', { class: 'btn primary', 'data-mutates': '1' }, t('common.verify'));
  const resend = el('button', { class: 'link small muted-link', 'data-mutates': '1' }, t('verify_email_card.send_another_code'));
  const submit = async () => {
    if (!code.value.trim()) { code.focus(); return; }
    const result = await teamAct('team_verify_email', { code: code.value.trim() }, t('verify_email_card.verify_your_e_mail'), verify);
    if (!result.ok) { code.select(); return; }
    state.team = { ...state.team, ...result.result };
    toast(t('activity.email_verified'));
    rerender();
  };
  verify.addEventListener('click', submit);
  code.addEventListener('keydown', (event) => { if (event.key === 'Enter') submit(); });
  resend.addEventListener('click', async () => {
    const result = await teamAct('team_send_code', {}, t('verify_email_card.send_you_another_code'), resend);
    if (result.ok) toast(result.result.sent ? t('verify_email_card.we_ve_sent_another_code', { email }) : t('verify_email_card.this_server_doesn_send_e_2'));
  });
  return el('div', { class: 'banner' },
    el('div', { class: 'banner-head' }, icon('shield', 'sm'), el('h3', {}, t('verify_email_card.verify_your_e_mail_2'))),
    el('p', { class: 'muted small' }, t('verify_email_card.we_ve_sent_8_digit'), el('b', {}, email),
      t('verify_email_card.invitations_only_reach_verified_addresse')),
    el('div', { class: 'inline-form', style: 'margin-top:8px' }, code, verify, resend));
}

// Many credentials deleted for the team at once (or a collection that vanished): nothing was deleted here.
// One click either way.
function heldDeletionsCard(held, rerender) {
  const who = held.by && held.by.length ? listJoin(held.by) : null;
  const what = tn('common.credentials_count', held.count);
  const decide = async (apply, button) => {
    const result = await teamAct('team_resolve_deletions', { collection: held.collection, apply },
      apply ? tn('held.proof_delete', held.count) : tn('held.proof_keep', held.count), button);
    if (!result.ok) return;
    await loadEntries();
    toast(apply ? tn('held.deleted', held.count) : held.can_restore ? tn('held.restored', held.count) : tn('held.kept', held.count));
    rerender();
  };
  const remove = el('button', { class: 'btn danger', 'data-mutates': '1' }, t('held_deletions_card.delete_them_here_too'));
  remove.addEventListener('click', () => decide(true, remove));
  const keep = el('button', { class: 'btn primary', 'data-mutates': '1' }, held.can_restore ? t('held_deletions_card.restore_them_for_team') : t('held_deletions_card.keep_them_on_this_pc'));
  keep.addEventListener('click', () => decide(false, keep));
  const reason = held.gone
    ? t('held_deletions_card.collection_no_longer_appears_on', { collection_name: held.collection_name })
    : tn('held.deleted_by', held.count, { who: who || t('common.someone_2'), collection_name: held.collection_name });
  return el('div', { class: 'banner' },
    el('div', { class: 'banner-head' }, icon('trash', 'sm'), el('h3', {}, tn('held.waiting', held.count))),
    el('p', { class: 'muted small' }, reason, t('held_deletions_card.in_case_mistake_or_attack'),
      held.can_restore ? t('held_deletions_card.restoring_them_puts_them_back') : t('held_deletions_card.if_you_keep_them_they')),
    el('div', { style: 'margin-top:8px;display:flex;gap:8px;flex-wrap:wrap' }, keep, remove));
}

// One person to verify: their code to compare, and one click («Confirmar» lets them in, «Verificar» trusts
// them on this PC). A key that changed is only re-verified by typing the code the person reads out: the one
// shown comes from the server, so sending it back would prove nothing.
function verifyRow(person, rerender) {
  const label = person.name || person.email || t('common.someone_2');
  const pending = person.kind === 'confirm';
  const typed = person.kind === 'changed' ? el('input', { class: 'input mono', placeholder: t('verify_row.code_that_person_reads_you'), autocomplete: 'off', spellcheck: 'false' }) : null;
  const button = el('button', { class: 'btn primary', 'data-mutates': '1' }, pending ? t('common.confirm') : t('common.verify'));
  button.addEventListener('click', async () => {
    if (typed && !typed.value.trim()) { typed.focus(); toast(t('verify_row.type_code_that_person_reads'), 'error'); return; }
    const params = { org: person.org, user_id: person.user_id };
    if (typed) params.fingerprint = typed.value.trim();
    const result = await teamAct('team_confirm_member', params, t('common.verify_2', { label }), button);
    if (!result.ok) return;
    toast(pending ? t('verify_row.confirmed', { label }) : t('verify_row.verified', { label }));
    await api().call('team_sync');
    await loadEntries();
    rerender();
  });
  const subtitle = person.kind === 'waiting' && person.reason === 'recovery'
    ? t('verify_row.they_own_organization_verify_them')
    : person.kind === 'waiting'
    ? tn('verify.shares_collections', person.collections)
    : person.kind === 'changed' ? t('verify_row.their_key_has_changed_since')
      : t('verify_row.waiting_for_confirmation', { value: person.email ? `${person.email} · ` : '' });
  return el('div', { class: 'member' },
    el('div', { class: 'access-row' }, el('div', { class: 'meta' }, el('div', { class: 'title' }, label),
      el('div', { class: 'subtitle' }, subtitle)), button),
    el('div', { class: 'fingerprint-box' },
      el('div', { class: 'k' }, typed ? t('verify_row.ask_for_their_security_code') : t('common.code', { label })),
      typed || el('div', { class: 'fingerprint selectable' }, person.fingerprint),
      typed ? null : el('p', { class: 'help' }, t('verify_row.ask_them_read_theirs_you'))));
}

function teamInvitesGroup(invites, rerender) {
  return el('div', { class: 'banner' },
    el('div', { class: 'banner-head' }, icon('users', 'sm'), el('h3', {}, invites.length === 1 ? t('team_invites_group.you_ve_been_invited') : t('team_invites_group.you_ve_been_invited_2', { length: invites.length }))),
    invites.map((invite) => {
      const button = el('button', { class: 'btn primary', 'data-mutates': '1' }, t('team_invites_group.accept'));
      button.addEventListener('click', async () => {
        const result = await teamAct('team_accept_invite', { id: invite.id, fingerprint: invite.invited_by_fingerprint || undefined }, t('team_invites_group.join', { org_name: invite.org_name }), button);
        if (!result.ok) return;
        state.teamOrg = invite.org_id;
        toast(t('team_invites_group.accepted_admin_still_needs_confirm'));
        rerender();
      });
      const by = invite.invited_by_name || invite.invited_by_email;
      const row = el('div', { class: 'access-row' }, el('div', { class: 'meta' }, el('div', { class: 'title' }, invite.org_name),
        el('div', { class: 'subtitle' }, t('team_invites_group.as_by_accepting_you_trust', { value: by ? t('team_invites_group.invites_you', { by }) : t('team_invites_group.you_re_invited'), value2: lowerFirst(ROLE_LABELS[invite.role] || invite.role) }))), button);
      // Their code, to compare with the one they read out if you can: accepting stays one click.
      if (!invite.invited_by_fingerprint) return row;
      return el('div', { class: 'member' }, row, el('div', { class: 'fingerprint-box' },
        el('div', { class: 'k' }, t('common.code', { label: by || invite.org_name })),
        el('div', { class: 'fingerprint selectable' }, invite.invited_by_fingerprint),
        el('p', { class: 'help' }, t('team_invites_group.compare_code_if_you_can'))));
    }));
}

function createOrgForm(onCreated) {
  const nameInput = el('input', { class: 'input', placeholder: t('create_org_form.name_team_or_company') });
  const create = el('button', { class: 'btn primary', 'data-mutates': '1' }, t('create_org_form.create_organization'));
  const submit = async () => {
    if (!nameInput.value.trim()) { nameInput.focus(); return; }
    const result = await teamAct('team_create_org', { name: nameInput.value.trim() }, t('create_org_form.create_organization_2'), create);
    if (!result.ok) return;
    state.teamOrg = result.result.id;
    state.teamTab = 'collections';
    toast(t('create_org_form.organization_created'));
    onCreated();
  };
  create.addEventListener('click', submit);
  nameInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });
  return el('div', { class: 'inline-form' }, nameInput, create);
}

function newOrgModal(rerender) {
  let modal = null;
  modal = openModal({ title: t('new_org_modal.new_organization'), body: [
    el('p', { class: 'muted' }, t('new_org_modal.organization_is_team_has_its')),
    createOrgForm(() => { modal.close(); rerender(); })] });
  setTimeout(() => modal.overlay.querySelector('input').focus(), 50);
}

function teamNoOrg(data, rerender) {
  return el('div', { class: 'settings-group team-panel' }, el('h3', { class: 'muted' }, t('common.organization')),
    el('p', { class: 'muted small', style: 'margin-bottom:10px' },
      (data.invites || []).length ? t('team_no_org.accept_invitation_above_or_create')
        : t('team_no_org.create_one_for_your_team', { email: state.team.user.email })),
    createOrgForm(rerender));
}

function teamWaitingForAdmin(org) {
  return el('div', { class: 'settings-group team-panel' },
    el('p', { class: 'muted' }, t('team_waiting_for_admin.you_accepted_invitation_admin_still', { name: org.name })),
    el('p', { class: 'fingerprint selectable', style: 'margin:6px 0' }, state.team.fingerprint),
    el('p', { class: 'help' }, t('team_waiting_for_admin.then_you_ll_see_their')));
}

function teamAccountPanel(org, rerender) {
  const team = state.team;
  const disconnect = () => confirmModal({
    title: t('team_account_panel.disconnect_team_account'),
    text: tn('team.disconnect_removes', team.shared),
    warning: t('team_account_panel.reconnect_you_ll_need_account'),
    action: t('common.disconnect'),
    danger: true,
    onConfirm: async (button) => {
      const result = await teamAct('team_disconnect', {}, t('team_account_panel.disconnect_team_account_2'), button);
      if (!result.ok) return false;
      state.teamData = null;
      await loadEntries();
      renderMain();
      toast(t('team_account_panel.disconnected'));
      return true;
    },
  });
  const user = team.user || {};
  const me = org ? ((state.teamData.members || {})[org.id] || []).find((m) => m.me) : null;
  const leave = me && org.role !== 'owner' ? el('button', { class: 'btn ghost', 'data-mutates': '1', onclick: () => removeMember(org, me, rerender) }, t('team_account_panel.leave', { name: org.name })) : null;
  return el('div', { class: 'settings team-panel' }, recoveryOffer(rerender), el('div', { class: 'settings-group' }, org ? null : el('h3', { class: 'muted' }, t('common.your_account')),
    setting(user.name || user.email, `${user.email} · ${hostOf(team.server_url)}${team.device ? ` · ${t('team.this_pc', { device: team.device })}` : ''}`,
      el('button', { class: 'btn danger', onclick: disconnect }, t('common.disconnect'))),
    el('div', { class: 'setting' }, el('div', { class: 'meta' }, el('h3', {}, t('team_account_panel.your_security_code')),
      el('p', {}, el('span', { class: 'fingerprint big selectable' }, team.fingerprint)),
      el('p', {}, t('team_account_panel.whoever_confirms_or_verifies_you'))),
    copyButton(team.fingerprint)),
    teamDevicesSetting(rerender),
    setting(t('team_password.title'), t('team_password.help'), el('div', { class: 'setting-buttons' },
      el('button', { class: 'btn ghost', 'data-mutates': '1', onclick: resetTeamPassword }, t('team_reset.forgot')),
      el('button', { class: 'btn', 'data-mutates': '1', onclick: changeTeamPassword }, t('team_password.change')))),
    recoverySetting(rerender),
    setting(t('move_pc.title'), t('move_pc.account_help'), el('button', { class: 'btn', onclick: moveComputerGuide }, t('move_pc.open'))),
    org ? setting(org.name, t('team_account_panel.your_role', { value: lowerFirst(ROLE_LABELS[org.role] || org.role) }), leave) : null));
}

// The account's devices (sessions on the server): a lost or old PC is logged out from here.
function teamDevicesSetting(rerender) {
  const devices = (state.teamData && state.teamData.devices) || [];
  const rows = devices.map((device) => {
    const out = device.current ? null : el('button', { class: 'btn ghost', 'data-mutates': '1' }, t('team_devices.log_out'));
    if (out) out.addEventListener('click', async () => {
      const result = await teamAct('team_revoke_device', { id: device.id }, t('team_devices.log_out_reason'), out);
      if (!result.ok) return;
      state.teamData.devices = devices.filter((d) => d.id !== device.id);
      toast(t('team_devices.logged_out', { name: device.name || '' }));
      rerender();
    });
    return el('div', { class: 'access-row' }, el('div', { class: 'meta' },
      el('div', { class: 'title' }, device.name || '—'),
      el('div', { class: 'subtitle' }, device.current ? t('team_devices.this_device') : t('team_devices.last_seen', { when: whenText(device.last_seen) }))), out);
  });
  return el('div', { class: 'setting' }, el('div', { class: 'meta' }, el('h3', {}, t('team_devices.title')),
    el('p', {}, t('team_devices.help')), ...rows));
}

function changeTeamPassword() {
  const current = passwordInput({ autocomplete: 'current-password' });
  const next = passwordInput();
  const save = el('button', { class: 'btn primary', 'data-mutates': '1' }, t('team_password.change'));
  const modal = openModal({
    title: t('team_password.title'),
    body: [el('p', { class: 'muted' }, t('team_password.other_devices_log_out')),
      el('div', { class: 'field' }, el('label', {}, t('team_password.current')), current,
        el('button', { class: 'link small', type: 'button', style: 'align-self:flex-start', onclick: () => { modal.close(); resetTeamPassword(); } }, t('team_reset.dont_remember'))),
      el('div', { class: 'field' }, el('label', {}, t('team_password.new')), next, strengthMeter(next.input))],
    footer: [el('button', { class: 'btn', onclick: () => modal.close() }, t('common.cancel')), save],
  });
  save.addEventListener('click', async () => {
    if (!current.input.value) { current.input.focus(); return; }
    const result = await teamAct('team_change_password', { current: current.input.value, password: next.input.value }, t('team_password.title'), save);
    if (!result.ok) return;
    modal.close();
    toast(t('team_password.changed'));
  });
  current.input.focus();
}

function teamPeoplePanel(org, members, admin, rerender) {
  const iAmOwner = org.role === 'owner';
  const verifying = new Set(verificationsFor(org, members, admin).map((p) => p.user_id));
  const row = (m) => {
    const label = m.name || m.email;
    const invited = m.status === 'invited';
    const waiting = verifying.has(m.user_id);
    // A pending invite says until when it works, in the warning colour in its last two days.
    const expiresIn = invited && m.expires ? Date.parse(m.expires) - Date.now() : NaN;
    const warn = invited && (m.expired || expiresIn < 2 * 86400000);
    const pending = [t('team_people_panel.invited_hasn_joined_yet'),
      m.expires ? t('team_people_panel.expires_on', { date: fmtDate(m.expires, { day: 'numeric', month: 'short' }) }) : null].filter(Boolean).join(' · ');
    const status = invited ? (m.expired ? t('team_people_panel.invitation_expired') : pending)
      : m.status === 'accepted' && !waiting ? t('team_people_panel.waiting_for_confirmation') : ROLE_LABELS[m.role] || m.role;
    const controls = [];
    // Someone already in the org not verified on this PC: one click, after comparing their code.
    const verify = !m.me && m.fingerprint && m.status === 'confirmed' && !m.trusted && !verifying.has(m.user_id);
    if (invited && admin) {
      controls.push(...inviteControls(org, m, rerender));
    } else if (verify) {
      const button = el('button', { class: 'btn', 'data-mutates': '1' }, t('common.verify'));
      button.addEventListener('click', async () => {
        const result = await teamAct('team_confirm_member', { org: org.id, user_id: m.user_id }, t('common.verify_2', { label }), button);
        if (!result.ok) return;
        toast(t('verify_row.verified', { label }));
        rerender();
      });
      controls.push(button);
    } else if (admin && !m.me && m.status === 'confirmed' && (iAmOwner || m.role !== 'owner')) {
      const roles = el('select', { class: 'input compact', 'data-mutates': '1', 'aria-label': t('team_people_panel.role', { label }) }, Object.entries(ROLE_LABELS)
        .filter(([r]) => iAmOwner || r !== 'owner').map(([r, text]) => el('option', { value: r }, text)));
      roles.value = m.role;
      roles.addEventListener('change', async () => {
        const result = await teamAct('team_set_role', { org: org.id, user_id: m.user_id, role: roles.value }, t('team_people_panel.change_role', { label }));
        if (!result.ok) { roles.value = m.role; return; }
        toast(t('team_people_panel.role_changed'));
        rerender();
      });
      controls.push(roles);
    }
    // Verified here: pass them a credential in one step (a direct share).
    if (!m.me && m.user_id && m.status === 'confirmed' && m.trusted) {
      controls.unshift(el('button', { class: 'btn ghost', 'data-mutates': '1', onclick: () => shareWithPerson({ ...m, org: org.id, label }) },
        icon('share', 'sm'), t('team_people_panel.share_with', { name: label })));
    }
    if (admin && !m.me && m.user_id && !invited && (iAmOwner || m.role !== 'owner') && state.team.recovery_supported) {
      controls.push(el('button', { class: 'btn ghost', 'data-mutates': '1', title: t('lost_access.button_help', { label }), onclick: () => lostAccess(org, m, rerender) }, t('lost_access.button')));
    }
    if (admin && !m.me && m.user_id && !invited && (iAmOwner || m.role !== 'owner')) {
      controls.push(el('button', { class: 'btn icon-only', 'data-mutates': '1', title: t('team_people_panel.remove_from_organization'), 'aria-label': t('team_people_panel.remove_from_organization'), onclick: () => removeMember(org, m, rerender) }, icon('trash', 'sm')));
    }
    return el('div', { class: 'member' },
      el('div', { class: 'access-row' },
        el('div', { class: `avatar ${invited ? 'invited' : ''}` }, (label || '?').trim().charAt(0).toUpperCase()),
        el('div', { class: 'meta' }, el('div', { class: 'title' }, label, m.me ? el('span', { class: 'faint' }, t('common.you')) : null,
          waiting ? el('span', { class: 'draft-badge', style: 'margin-left:8px' },
            m.status === 'accepted' ? t('team_people_panel.waiting_for_confirmation') : t('team_people_panel.verify')) : null),
          el('div', { class: 'subtitle', style: warn ? 'color:var(--warning)' : null }, [m.name && !invited ? m.email : null, status].filter(Boolean).join(' · '))),
        controls),
      verify ? el('div', { class: 'fingerprint-box' }, el('div', { class: 'k' }, t('common.code', { label })),
        el('div', { class: 'fingerprint selectable' }, m.fingerprint),
        el('p', { class: 'help' }, t('team_people_panel.you_haven_verified_them_on'))) : null);
  };

  const draft = state.teamDraft || (state.teamDraft = {});
  const email = el('input', { class: 'input', type: 'email', placeholder: t('team_people_panel.person_e_mail'), value: draft.email || '' });
  email.addEventListener('input', () => { draft.email = email.value; });
  const role = el('select', { class: 'input compact', 'aria-label': t('team_people_panel.role_2') }, el('option', { value: 'member' }, t('common.member')), el('option', { value: 'admin' }, t('common.admin')));
  const invite = el('button', { class: 'btn primary', 'data-mutates': '1' }, t('team_people_panel.invite'));
  const submit = async () => {
    if (!email.value.trim()) { email.focus(); return; }
    const address = email.value.trim();
    const result = await teamAct('team_invite', { org: org.id, email: address, role: role.value }, t('team_people_panel.invite_person'), invite);
    if (!result.ok) return;
    draft.email = '';
    rerender();
    inviteInstructions(org, address, result.result.id, true, result.result.emailed);
  };
  invite.addEventListener('click', submit);
  email.addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });
  const people = members.filter((m) => m.status !== 'invited');
  const invited = members.filter((m) => m.status === 'invited');
  return el('div', { class: 'settings-group team-panel' },
    admin ? el('div', { class: 'invite-box' }, el('div', { class: 'inline-form' }, email, role, invite),
      el('p', { class: 'help' }, state.team.mail ? t('team_people_panel.server_emails_invitations')
        : t('team_people_panel.secretbroker_doesn_send_invitations_by'))) : null,
    people.map(row),
    invited.length ? [el('h3', { class: 'muted sub-head' }, t('team_people_panel.invitations', { length: invited.length })), invited.map(row)] : null);
}

function joinLink(server, email, code) {
  const params = new URLSearchParams({ server });
  if (email) params.set('email', email);
  if (code) params.set('code', code);
  return `secretbroker://join?${params}`;
}

function parseJoinLink(text) {
  try {
    const url = new URL(String(text || '').trim());
    if (url.protocol !== 'secretbroker:' || (url.host || url.pathname.replace(/^\/+/, '')).toLowerCase() !== 'join') return null;
    const get = (name) => (url.searchParams.get(name) || '').trim();
    return get('server') ? { server: get('server'), email: get('email'), code: get('code') } : null;
  } catch {
    return null;
  }
}

// A pending invite: copy its instructions, e-mail it again (if the server e-mailed it), withdraw it. An expired
// one: renew it (a new code, e-mailed again if the server can) or withdraw it.
function inviteControls(org, m, rerender) {
  const button = (label, op, params, reason, done) => {
    const node = el('button', { class: 'btn', 'data-mutates': '1' }, label);
    node.addEventListener('click', async () => {
      const result = await teamAct(op, params, reason, node);
      if (result.ok) done(result.result);
    });
    return node;
  };
  // The invite's code works as a sign-up code for that e-mail: the list of people never has it, the service looks
  // it up inside each of these (one click with the token).
  const which = { org: org.id, email: m.email };
  const renew = button(t('team_people_panel.renew'), 'team_renew_invite', which,
    t('team_people_panel.renew_invitation'), (r) => { rerender(); inviteInstructions(org, m.email, r.id, true, r.emailed); });
  const resend = button(t('team_people_panel.resend'), 'team_resend_invite', which,
    t('team_people_panel.resend_invitation'), (r) => {
      toast(r.emailed ? t('team_people_panel.invitation_resent', { email: m.email }) : t('team_people_panel.couldn_send_email'), r.emailed ? undefined : 'error');
      rerender();
    });
  const withdraw = button(t('team_people_panel.withdraw'), 'team_drop_invite', which,
    t('team_people_panel.withdraw_invitation'), () => { toast(t('team_people_panel.invitation_withdrawn')); rerender(); });
  withdraw.classList.add('ghost');
  if (m.expired) return [renew, withdraw];
  const copy = button([icon('copy', 'sm'), t('common.copy_instructions')], 'team_invite_code', which,
    t('team_people_panel.copy_invitation'), (r) => inviteInstructions(org, m.email, r.code, false, m.emailed));
  return [copy, m.emailed ? resend : null, withdraw].filter(Boolean);
}

// The admin passes these on (chat, e-mail, in person); a server with e-mail has also sent them itself.
function inviteInstructions(org, email, code, justInvited = false, emailed = false, { note = null, onClose = null } = {}) {
  const noteBox = note ? el('div', { class: 'warning subtle' }, icon('info', 'sm'), el('span', {}, note)) : null;
  const server = state.team.server_url;
  const link = joinLink(server, email, code);
  const text = [
    t('invite_instructions.i_ve_invited_you_team', { name: org.name }),
    '',
    t('invite.step_install', { url: RELEASES_URL }),
    t('invite.step_open_link', { link }),
    t('invite_instructions.if_doesn_open_go_team'),
    t('invite.step_server', { server }),
    t('invite.step_email', { email }),
    code ? t('invite_instructions.invitation_code_if_asked', { code }) : null,
    t('invite_instructions.3_create_your_account_and'),
    t('invite_instructions.4_i_ll_confirm_you'),
  ].filter((line) => line !== null).join('\n');
  const copy = el('button', { class: `btn ${justInvited && emailed ? '' : 'primary'}` }, icon('copy', 'sm'), t('common.copy_instructions'));
  copy.addEventListener('click', async () => { await api().copy_text(text); toast(t('invite_instructions.instructions_copied')); });
  const copyLink = el('button', { class: 'btn' }, t('invite_instructions.copy_only_link'));
  copyLink.addEventListener('click', async () => { await api().copy_text(link); toast(t('invite_instructions.link_copied')); });
  if (justInvited && emailed) {
    // The server sent it: nothing to do but close. The instructions stay one click away, for another channel.
    const more = el('div', { class: 'hidden' },el('pre', { class: 'instructions selectable' }, text),
      el('div', { style: 'display:flex;gap:8px;margin-top:10px' }, copy, copyLink));
    const toggle = el('button', { class: 'link small', style: 'margin-top:14px;align-self:flex-start;text-align:left;padding:0' },
      t('invite_instructions.show_instructions'));
    toggle.addEventListener('click', () => { more.classList.remove('hidden'); toggle.remove(); });
    const done = el('button', { class: 'btn primary', onclick: () => modal.close() }, t('common.done'));
    const modal = openModal({
      title: t('invite_instructions.invitation_created_for', { email }),
      wide: true,
      body: [el('div', { class: 'notice' }, icon('check', 'sm'), el('span', { class: 'notice-text' }, t('invite_instructions.sent_to', { email }))),
        noteBox, toggle, more],
      footer: [el('div', { class: 'spacer' }), done],
      onClose,
    });
    return;
  }
  const modal = openModal({
    title: justInvited ? t('invite_instructions.invitation_created_for', { email }) : t('invite_instructions.instructions_for', { email }),
    wide: true,
    body: [
      emailed ? el('div', { class: 'notice' }, icon('check', 'sm'), el('span', { class: 'notice-text' }, t('invite_instructions.emailed_to', { email })))
        : el('p', { class: 'muted' }, state.team.mail ? t('team_people_panel.couldn_send_email') : t('invite_instructions.secretbroker_doesn_send_invitations_by')),
      noteBox,
      el('pre', { class: 'instructions selectable' }, text)],
    footer: [copyLink, el('div', { class: 'spacer' }), el('button', { class: 'btn', onclick: () => modal.close() }, t('common.close')), copy],
    onClose,
  });
}

function removeMember(org, member, rerender) {
  const label = member.name || member.email;
  const self = member.me;
  // What this user shares only with them (a direct share) ends too: say so.
  const direct = !self && ((state.teamData || {}).collections || []).some((c) => c.direct && c.permission === 'manage'
    && c.org === org.id && c.with && c.with.user_id === member.user_id);
  confirmModal({
    title: self ? t('common.leave', { name: org.name }) : t('remove_member.remove', { label }),
    text: self ? t('remove_member.credentials_in_its_collections_will')
      : [t('remove_member.they_ll_lose_access_and', { name: org.name }), direct ? t('remove_member.direct_shares_end', { name: label }) : null].filter(Boolean).join(' '),
    warning: self ? null : t('remove_member.collections_they_could_open_will'),
    action: self ? t('common.leave_2') : t('common.remove'),
    danger: true,
    onConfirm: async (button) => {
      const result = await teamAct('team_remove_member', { org: org.id, user_id: member.user_id },
        self ? t('common.leave_3', { name: org.name }) : t('common.remove_2', { label }), button);
      if (!result.ok) return false;
      await loadEntries();
      const { failed = [], pending = [], offline = false, credentials = 0, person = label } = result.result;
      if (self) {
        toast(t('remove_member.you_ve_left'));
        state.teamOrg = null;
      } else {
        toast([t('remove_member.removed'),
          failed.length ? tn(offline ? 'team.rekey_on_reconnect' : 'team.rekey_next_sync', failed.length) : '',
          pending.length ? tn('team.rekey_by_managers', pending.length) : ''].filter(Boolean).join(' '));
      }
      renderMain();
      if (!self && credentials) setTimeout(() => openOffboarding(person), 50);
      return true;
    },
  });
}

function teamCollectionsPanel(org, collections, members, admin, content) {
  const draft = state.teamDraft || (state.teamDraft = {});
  const name = el('input', { class: 'input', placeholder: t('common.name_e_g_production'), value: draft.collection || '' });
  name.addEventListener('input', () => { draft.collection = name.value; });
  const create = el('button', { class: 'btn', 'data-mutates': '1' }, icon('plus', 'sm'), t('team_collections_panel.create_collection'));
  const submit = async () => {
    if (!name.value.trim()) { name.focus(); return; }
    const result = await teamAct('team_create_collection', { org: org.id, name: name.value.trim() }, t('common.create_collection'), create);
    if (!result.ok) return;
    draft.collection = '';
    state.openCollection = result.result.id;
    toast(t('team_collections_panel.collection_created'));
    renderTeam(content);
  };
  create.addEventListener('click', submit);
  name.addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });
  // A credential shared with one person lives in a private collection of the two: listed apart, as «Con Bob».
  const team = collections.filter((c) => !c.direct);
  const direct = collections.filter((c) => c.direct).sort((a, b) => compareText((a.with || {}).name || '', (b.with || {}).name || ''));
  return el('div', { class: 'settings-group team-panel' },
    el('div', { class: 'panel-head' },
      el('p', { class: 'muted small' }, team.length
        ? t('team_collections_panel.each_collection_is_shared_folder')
        : t('team_collections_panel.collection_is_shared_folder_you')),
      permissionHelp()),
    team.map((c) => collectionBlock(c, members, content)),
    admin ? el('div', { class: 'inline-form', style: 'margin-top:12px' }, name, create) : null,
    direct.length ? [el('h3', { class: 'muted sub-head direct-head' }, t('team_collections_panel.with_one_person')),
      el('p', { class: 'help' }, t('team_collections_panel.with_one_person_help')),
      direct.map((c) => directBlock(c, content))] : null);
}

// A direct share: what this user shares with one person (or what that person shares with this user).
function directBlock(collection, content) {
  const other = collection.with || {};
  const name = other.name || t('common.someone_2');
  const mine = collection.permission === 'manage';
  const shown = state.entries.filter((e) => e.shared && e.shared.collection === collection.id);
  const subtitle = [tn('common.credentials_count', collection.entries),
    mine ? t('direct_block.their_permission', { name, value: PERMISSION_LABELS[other.permission] || '' })
      : t('direct_block.shared_by_your_permission', { name, value: PERMISSION_LABELS[collection.permission] })].join(' · ');
  const body = el('div', { class: 'collection-members' });
  const block = el('details', { class: 'collection direct', open: state.openCollection === collection.id },
    el('summary', {}, el('span', { class: 'chev' }, icon('chevronRight', 'sm')),
      el('div', { class: 'avatar small' }, name.trim().charAt(0).toUpperCase()),
      el('div', { class: 'meta' }, el('div', { class: 'title' }, t('direct_share.with_name', { name })), el('div', { class: 'subtitle' }, subtitle)),
      collection.needs_rekey ? el('span', { class: 'draft-badge', title: t('collection_block.someone_left_whoever_manages_re') }, t('collection_block.will_be_re_encrypted')) : null),
    body);
  block.addEventListener('toggle', () => {
    if (block.open) state.openCollection = collection.id;
    else if (state.openCollection === collection.id) state.openCollection = null;
  });
  const links = shown.length ? el('p', { class: 'help' }, t('collection_block.credentials'),
    shown.map((e, i) => [i ? ', ' : '', el('button', { class: 'link small', onclick: () => {
      state.view = 'credentials'; state.selected = e.id; state.tag = null; state.collection = collection.id; renderMain();
    } }, e.name)])) : null;
  let controls;
  if (mine) {
    const select = el('select', { class: 'input compact', 'data-mutates': '1', 'aria-label': t('direct_block.permission_of', { name }) },
      DIRECT_PERMISSIONS.map((p) => el('option', { value: p, title: t(`direct_share.permission_${p}`) }, PERMISSION_LABELS[p])));
    select.value = other.permission || 'view';
    select.addEventListener('change', async () => {
      const changed = await teamAct('team_grant', { collection: collection.id, user_id: other.user_id, permission: select.value },
        t('collection_block.change_permission', { label: name }));
      if (!changed.ok) { select.value = other.permission; return; }
      toast(`${name}: ${PERMISSION_LABELS[select.value]}`);
      renderTeam(content);
    });
    const stop = el('button', { class: 'btn danger', 'data-mutates': '1' }, t('direct_block.stop_sharing_with', { name }));
    stop.addEventListener('click', () => confirmModal({
      title: t('direct_block.stop_title', { name }),
      text: tn('direct_block.stop_text', collection.entries, { name }),
      warning: tn('direct_block.stop_warning', collection.entries, { name }),
      action: t('shared_section.stop_sharing_2'), danger: true,
      onConfirm: async (button) => {
        const ended = await teamAct('team_unshare_with', { collection: collection.id }, t('direct_block.stop_proof', { name }), button);
        if (!ended.ok) return false;
        state.openCollection = null;
        await loadEntries();
        toast(t('direct_block.stopped', { name }));
        renderTeam(content);
        if (ended.result.credentials) setTimeout(() => openOffboarding(ended.result.person), 50);
        return true;
      },
    }));
    controls = el('div', { class: 'direct-controls' },
      el('label', { class: 'small muted' }, t('direct_block.can', { name })), select, el('div', { class: 'spacer' }), stop);
  } else {
    controls = el('button', { class: 'link small muted-link', 'data-mutates': '1', onclick: () => confirmModal({
      title: t('direct_block.leave_title', { name }),
      text: t('direct_block.leave_text', { name }),
      action: t('common.leave_2'), danger: true,
      onConfirm: async (button) => {
        const left = await teamAct('team_revoke', { collection: collection.id, user_id: state.team.user.id }, t('direct_block.leave_proof', { name }), button);
        if (!left.ok) return false;
        await loadEntries();
        toast(t('direct_block.left', { name }));
        renderTeam(content);
        return true;
      },
    }) }, t('direct_block.leave', { name }));
  }
  body.replaceChildren(links, controls);
  if (teamOffline()) body.querySelectorAll('[data-mutates]').forEach((node) => { node.disabled = true; });
  return block;
}


function collectionBlock(collection, orgMembers, content) {
  const manage = collection.permission === 'manage';
  const list = el('div', { class: 'collection-members' });
  const cached = ((state.teamData || {}).collection_members || {})[collection.id];
  // The count follows the member list each time it loads (the cached one may be from before a grant).
  const subtitle = el('div', { class: 'subtitle' });
  const describe = (members) => { subtitle.textContent = [tn('common.credentials_count', collection.entries),
    members ? tn('common.people_count', members.length) : null,
    t('collection_block.your_permission', { value: PERMISSION_LABELS[collection.permission] })].filter(Boolean).join(' · '); };
  describe(cached);
  const block = el('details', { class: 'collection', open: state.openCollection === collection.id },
    el('summary', {}, el('span', { class: 'chev' }, icon('chevronRight', 'sm')),
      el('div', { class: 'meta' }, el('div', { class: 'title' }, collection.name), subtitle),
      collection.needs_rekey ? el('span', { class: 'draft-badge', title: t('collection_block.someone_left_whoever_manages_re') }, t('collection_block.will_be_re_encrypted'))
        : collection.single_manager ? el('span', { class: 'draft-badge', title: t('collection.only_one_person_manages_if') }, t('collection_block.single_manager')) : null),
    collection.single_manager && manage ? el('div', { class: 'warning', style: 'margin:4px 0 8px' }, icon('alert', 'sm'), el('span', {}, t('collection.only_one_person_manages_if'))) : null,
    list);
  const draw = (inside) => {
    describe(inside);
    const mine = state.team.user.id;
    const row = (m) => {
      const label = m.name || m.email || t('common.someone_2');
      let control = el('span', { class: 'muted small', title: PERMISSION_HELP[m.permission] }, PERMISSION_LABELS[m.permission]);
      if (manage && m.user_id !== mine) {
        const select = permissionSelect(m.permission);
        select.setAttribute('data-mutates', '1');
        select.addEventListener('change', async () => {
          const changed = await teamAct('team_grant', { collection: collection.id, user_id: m.user_id, permission: select.value },
            t('collection_block.change_permission', { label }));
          if (!changed.ok) { select.value = m.permission; return; }
          toast(`${label}: ${PERMISSION_LABELS[select.value]}`);
          load();
        });
        control = [select, el('button', { class: 'btn icon-only', 'data-mutates': '1', title: t('collection_block.remove_from_collection'), onclick: () => confirmModal({
          title: t('collection_block.remove_from', { label, name: collection.name }),
          text: t('collection_block.they_ll_stop_receiving_its'),
          warning: t('collection_block.collection_will_be_re_encrypted'),
          action: t('common.remove'), danger: true,
          onConfirm: async (button) => {
            const revoked = await teamAct('team_revoke', { collection: collection.id, user_id: m.user_id }, t('common.remove_2', { label }), button);
            if (!revoked.ok) return false;
            await loadEntries();
            toast(t('collection_block.removed_collection_has_been_re'));
            load();
            return true;
          },
        }) }, icon('x', 'sm'))];
      }
      return el('div', { class: 'access-row' }, el('div', { class: 'meta' },
        el('div', { class: 'title' }, label, m.user_id === mine ? el('span', { class: 'faint' }, t('common.you')) : null),
        m.name && m.email ? el('div', { class: 'subtitle' }, m.email) : null), control);
    };
    let add = null;
    if (manage) {
      const candidates = orgMembers.filter((m) => m.status === 'confirmed' && m.user_id && !inside.some((i) => i.user_id === m.user_id));
      if (candidates.length) {
        const who = el('select', { class: 'input', 'aria-label': t('collection_block.person') }, candidates.map((m) => el('option', { value: m.user_id }, m.name ? `${m.name} (${m.email})` : m.email)));
        const permission = permissionSelect('use');
        const button = el('button', { class: 'btn', 'data-mutates': '1' }, t('common.add'));
        button.addEventListener('click', async () => {
          const granted = await teamAct('team_grant', { collection: collection.id, user_id: who.value, permission: permission.value },
            t('collection_block.give_access_collection'), button);
          if (!granted.ok) return;
          toast(t('collection_block.added'));
          load();
        });
        add = el('div', { class: 'inline-form', style: 'margin-top:8px' }, who, permission, button);
      } else {
        add = el('p', { class: 'help', style: 'margin-top:6px' }, t('collection_block.add_someone_invite_them_organization'));
      }
    }
    const leave = !manage ? el('button', { class: 'link small muted-link', 'data-mutates': '1', style: 'margin-top:8px', onclick: () => confirmModal({
      title: t('common.leave', { name: collection.name }),
      text: t('collection_block.its_credentials_will_be_removed'),
      action: t('common.leave_2'), danger: true,
      onConfirm: async (button) => {
        const left = await teamAct('team_revoke', { collection: collection.id, user_id: mine }, t('common.leave_3', { name: collection.name }), button);
        if (!left.ok) return false;
        await loadEntries();
        toast(t('collection_block.you_ve_left_collection'));
        renderTeam(content);
        return true;
      },
    }) }, t('collection_block.leave_collection')) : null;
    const shown = state.entries.filter((e) => e.shared && e.shared.collection === collection.id);
    list.replaceChildren(inside.map(row), add,
      shown.length ? el('p', { class: 'help', style: 'margin-top:8px' }, t('collection_block.credentials'),
        shown.map((e, i) => [i ? ', ' : '', el('button', { class: 'link small', onclick: () => {
          state.view = 'credentials'; state.selected = e.id; state.tag = null; state.collection = collection.id; renderMain();
        } }, e.name)])) : null,
      leave);
    if (teamOffline()) list.querySelectorAll('[data-mutates]').forEach((node) => { node.disabled = true; });
  };
  const load = async () => {
    if (!list.firstChild) list.append(el('div', { class: 'spinner' }));
    const result = await api().call('team_collection_members', { collection: collection.id });
    if (!result.ok) {
      if (!cached) list.replaceChildren(el('p', { class: 'error-text' }, result.error));
      return;
    }
    if (state.teamData) (state.teamData.collection_members = state.teamData.collection_members || {})[collection.id] = result.result;
    draw(result.result);
  };
  if (cached) draw(cached);
  block.addEventListener('toggle', () => {
    if (block.open) { state.openCollection = collection.id; load(); }
    else if (state.openCollection === collection.id) state.openCollection = null;
  });
  if (block.open && !cached) load();
  return block;
}

function teamEventsPanel(events, members, collections) {
  const names = Object.fromEntries([...members.filter((m) => m.user_id).map((m) => [m.user_id, m.name || m.email]),
    ...collections.map((c) => [c.id, c.name])]);
  const name = (id, fallback) => names[id] || fallback;
  const describe = (e) => {
    const [left, extra] = String(e.target || '').split(':');
    const [cid, uid] = left.split('/');
    const someone = t('common.someone');
    const collection = name(cid, t('common.collection'));
    const params = {
      invite: { who: e.target }, 'invite.delete': { who: e.target }, 'invite.renew': { who: e.target },
      'invite.send': { who: e.target }, 'member.disable': { who: e.target }, 'member.delete': { who: e.target },
      'member.confirm': { who: name(e.target, someone) }, 'member.remove': { who: name(e.target, someone) },
      'account.recover': { who: name(e.target, someone) }, 'password.reset': { who: name(e.target, someone) },
      'invite.replace': { who: e.target },
      'member.role': { who: name(left, someone), role: lowerFirst(ROLE_LABELS[extra] || extra || '') },
      grant: { who: name(uid, someone), collection, permission: PERMISSION_LABELS[extra] || extra },
      revoke: { who: name(uid, someone), collection },
      rotate: { collection }, 'item.put': { collection }, 'item.delete': { collection },
      'collection.create': { collection: name(e.target, '') }, 'collection.delete': { collection: name(e.target, '') },
    }[e.action];
    return EVENT_LABELS[e.action] ? t(EVENT_LABELS[e.action], params).trim() : t('team_events_panel.other_action');
  };
  return el('div', { class: 'settings-group team-panel' },
    el('p', { class: 'help', style: 'margin-bottom:8px' }, t('team_events_panel.server_records_who_did_what')),
    events === undefined ? el('div', { class: 'spinner' })
      : !events.length ? el('p', { class: 'muted' }, t('common.no_activity_yet'))
        : el('table', { class: 'table' }, el('tbody', {}, events.slice(0, 50).map((e) => el('tr', {},
          el('td', { class: 'muted', style: 'white-space:nowrap' }, formatTime(e.time)),
          el('td', {}, e.actor ? name(e.actor, t('common.someone')) : ''),  // none: the server admin (it says so)
          el('td', {}, describe(e)))))));
}

// ----- recovery (docs/ARCHITECTURE.md 2.1): nobody on a team loses access for good

// The account's recovery code, shown once: nothing of it is kept, here or on the server.
function showRecoveryCode(code, { onClose, used = false } = {}) {
  const team = state.team || {};
  const email = (team.user || {}).email || '';
  const server = team.server_url || '';
  const fileText = [t('recovery_code.file_title'), '', code, '', t('recovery_code.file_account', { email, server }), '',
    t('recovery_code.file_what'), t('recovery_code.file_keep')].join('\n');
  let kept = false;
  const copy = el('button', { class: 'btn' }, icon('copy', 'sm'), t('common.copy'));
  copy.addEventListener('click', async () => {
    const seconds = await api().copy_recovery_code(code);
    kept = true;
    toast(t('recovery_code.copied', { seconds }));
  });
  const save = el('button', { class: 'btn' }, icon('download', 'sm'), t('recovery_code.save_file'));
  save.addEventListener('click', async () => {
    busy(save, true);
    const result = await api().save_recovery_code(fileText);
    busy(save, false);
    if (result.ok) { kept = true; toast(t('recovery_code.saved_file', { path: result.result.path })); } else if (result.code !== 'cancelled') toast(result.error, 'error');
  });
  const vault = el('button', { class: 'btn ghost' }, icon('lock', 'sm'), t('recovery_code.save_vault'));
  vault.addEventListener('click', async () => {
    const id = 'secretbroker-team-recovery';
    const entry = { id, name: t('recovery_code.entry_name'), template: 'generic', description: t('recovery_code.entry_description', { email, server }),
      fields: { value: code, username: email, url: server }, policy: { approval: 'never' }, tags: [] };
    busy(vault, true);
    const exists = state.entries.some((e) => e.id === id);
    const result = await withProof((p) => api().call('save_entry', { entry, replaces: exists ? id : null }, p), t('recovery_code.save_vault'));
    busy(vault, false);
    if (!result.ok) { if (result.code !== 'cancelled') toast(result.error, 'error'); return; }
    kept = true;
    vault.replaceChildren(icon('check', 'sm'), t('recovery_code.in_vault'));
    vault.disabled = true;
    await loadEntries();
    toast(t('recovery_code.saved_vault'));
  });
  const done = el('button', { class: 'btn primary' }, t('recovery_code.done'));
  const modal = openModal({
    title: t('recovery_code.title'),
    lead: el('div', { class: 'glyph lock' }, icon('key')),
    body: [
      used ? el('div', { class: 'notice' }, icon('info', 'sm'), el('span', { class: 'notice-text' }, t('recovery_code.used'))) : null,
      el('p', { class: 'muted' }, t('recovery_code.lead')),
      el('div', { class: 'recovery-code selectable', 'aria-label': t('recovery_code.title') }, code),
      el('p', { class: 'help' }, t('recovery_code.shown_once')),
      el('div', { class: 'recovery-actions' }, copy, save, vault),
      el('div', { class: 'warning subtle' }, icon('info', 'sm'), el('span', {}, t('recovery_code.vault_note')))],
    footer: [el('div', { class: 'spacer' }), done],
    // Closing without keeping it: say once that it won't be shown again.
    confirmClose: () => kept ? null : { title: t('recovery_code.close_title'), text: t('recovery_code.close_text') },
    onClose,
  });
  done.addEventListener('click', () => modal.close());
}

// Make the account's recovery code (or a new one: the old one stops working) and show it once.
async function makeRecoveryCode(button, rerender) {
  const result = await teamAct('team_recovery_code', {}, t('recovery.reason'), button);
  if (!result.ok) return false;
  state.team.recovery = { created: result.result.created };
  try { localStorage.removeItem(`recoveryOffer:${(state.team.user || {}).id}`); } catch { /* storage may be off */ }
  showRecoveryCode(result.result.code, { onClose: rerender });
  return true;
}

function recoverySetting(rerender) {
  const team = state.team;
  if (!team.recovery_supported) return null;
  const made = team.recovery && team.recovery.created;
  const button = el('button', { class: `btn ${made ? '' : 'primary'}`, 'data-mutates': '1' }, made ? t('recovery.make_new') : t('recovery.make'));
  button.addEventListener('click', () => {
    if (!made) { makeRecoveryCode(button, rerender); return; }
    confirmModal({
      title: t('recovery.new_title'),
      text: t('recovery.new_text'),
      action: t('recovery.make_new'),
      onConfirm: (node) => makeRecoveryCode(node, rerender),
    });
  });
  return setting(t('recovery.title'),
    made ? `${t('recovery.made_on', { date: fmtDate(made, { day: 'numeric', month: 'long', year: 'numeric' }) })} ${t('recovery.help')}`
      : t('recovery.none_help'), button);
}

// Offered once to accounts made before recovery codes existed (or that skipped it): «Ahora no» hides it here.
function recoveryOffer(rerender) {
  const team = state.team;
  const key = `recoveryOffer:${(team.user || {}).id}`;
  let dismissed = false;
  try { dismissed = localStorage.getItem(key) === 'no'; } catch { /* storage may be off */ }
  if (!team.recovery_supported || (team.recovery && team.recovery.created) || dismissed) return null;
  const make = el('button', { class: 'btn primary', 'data-mutates': '1' }, t('recovery.make'));
  make.addEventListener('click', () => makeRecoveryCode(make, rerender));
  const later = el('button', { class: 'btn ghost', onclick: () => { try { localStorage.setItem(key, 'no'); } catch { /* */ } rerender(); } }, t('recovery.not_now'));
  return el('div', { class: 'pause-card recovery-offer' },
    el('div', { class: 'meta' }, el('h3', {}, t('recovery.offer_title')), el('p', {}, t('recovery.offer_text'))),
    later, make);
}

// «He olvidado la contraseña» on a PC still connected: it has the keys, so it sets a new one without the old one.
function resetTeamPassword() {
  const next = passwordInput({ autocomplete: 'new-password' });
  const repeat = passwordInput({ autocomplete: 'new-password' });
  const errorText = el('div', { class: 'error-text' });
  const save = el('button', { class: 'btn primary', 'data-mutates': '1' }, t('team_reset.button'));
  const modal = openModal({
    title: t('team_reset.title'),
    body: [el('p', { class: 'muted' }, t('team_reset.lead')),
      el('div', { class: 'field' }, el('label', {}, t('team_password.new')), next, strengthMeter(next.input)),
      el('div', { class: 'field' }, el('label', {}, t('common.repeat')), repeat),
      el('p', { class: 'help' }, t('team_reset.other_devices')),
      errorText],
    footer: [el('button', { class: 'btn', onclick: () => modal.close() }, t('common.cancel')), save],
  });
  const submit = async () => {
    errorText.textContent = '';
    if (next.input.value.length < 12) { errorText.textContent = t('team_connect_form.account_password_needs_at_least'); next.input.focus(); return; }
    if (next.input.value !== repeat.input.value) { errorText.textContent = t('common.two_passwords_don_match'); repeat.input.focus(); return; }
    const result = await teamAct('team_reset_password', { password: next.input.value }, t('team_reset.reason'), save);
    if (!result.ok) return;
    modal.close();
    toast(t('team_reset.done'));
  };
  save.addEventListener('click', submit);
  repeat.input.addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });
  setTimeout(() => next.input.focus(), 50);
}

// «Ha perdido el acceso»: someone who can't get into their account at all. They are removed like anyone (re-keys,
// «cambiar» flags) and their e-mail invited again; their new account takes the old one's place.
function lostAccess(org, member, rerender) {
  const label = member.name || member.email;
  const button = el('button', { class: 'btn solid-danger' }, t('lost_access.action'));
  const modal = openModal({
    title: t('lost_access.title', { label }),
    body: [
      el('p', { class: 'muted' }, t('lost_access.when', { label })),
      el('ul', { class: 'plain-list' },
        el('li', {}, t('lost_access.removed', { name: org.name })),
        el('li', {}, t('lost_access.invited', { email: member.email })),
        el('li', {}, t('lost_access.give_back', { label }))),
      el('div', { class: 'warning subtle' }, icon('info', 'sm'), el('span', {}, t('lost_access.not_needed')))],
    footer: [el('button', { class: 'btn', onclick: () => modal.close() }, t('common.cancel')), button],
  });
  button.addEventListener('click', async () => {
    const result = await teamAct('team_replace_member', { org: org.id, user_id: member.user_id }, t('lost_access.reason', { label }), button);
    if (!result.ok) return;
    modal.close();
    await loadEntries();
    const { invite, email, collections = [], credentials = 0, person = label } = result.result;
    rerender();
    inviteInstructions(org, email, invite.id, true, invite.emailed, {
      note: collections.length ? t('lost_access.had', { label, names: listJoin(collections) }) : t('lost_access.had_none', { label }),
      onClose: credentials ? () => setTimeout(() => openOffboarding(person), 50) : null,
    });
  });
}

// «Pasar a otro PC»: what to take, what to do on the new one, and closing the session here. Each step says how.
function moveComputerGuide() {
  const team = state.team && state.team.connected ? state.team : null;
  const backupState = el('div', { class: 'step-state' });
  const backup = el('button', { class: 'btn primary' }, icon('download', 'sm'), t('move_pc.backup_button'));
  backup.addEventListener('click', async () => {
    busy(backup, true);
    const result = await withProof((p) => api().backup_to_file(p), t('move_pc.backup_reason'));
    busy(backup, false);
    if (!result.ok) { if (result.code !== 'cancelled') toast(result.error, 'error'); return; }
    backup.classList.remove('primary');
    backupState.replaceChildren(el('span', { class: 'state-text ok' }, icon('check', 'sm'), t('move_pc.backup_saved', { path: result.result.path })));
  });
  const copyLink = el('button', { class: 'btn' }, icon('copy', 'sm'), t('move_pc.copy_download_link'));
  copyLink.addEventListener('click', async () => { await api().copy_text(RELEASES_URL); toast(t('invite_instructions.link_copied')); });
  const step = (title, ...rest) => el('li', {}, el('div', { class: 'step-title' }, title), ...rest);
  const noRecovery = team && team.recovery_supported && !(team.recovery && team.recovery.created);
  const steps = [
    step(t('move_pc.step_backup'), el('p', { class: 'muted' }, t('move_pc.step_backup_text')), el('div', { class: 'step-actions' }, backup), backupState),
    step(t('move_pc.step_restore'), el('p', { class: 'muted' }, t('move_pc.step_restore_text')), el('div', { class: 'step-actions' }, copyLink)),
    team ? step(t('move_pc.step_team'), el('p', { class: 'muted' }, t('move_pc.step_team_text', { email: team.user.email, host: hostOf(team.server_url) })),
      noRecovery ? el('p', { class: 'help' }, t('move_pc.step_team_no_code')) : null) : null,
    step(team ? t('move_pc.step_close') : t('move_pc.step_close_no_team'),
      el('p', { class: 'muted' }, team ? t('move_pc.step_close_text') : t('move_pc.step_close_no_team_text'))),
  ].filter(Boolean);
  const modal = openModal({
    title: t('move_pc.title'),
    wide: true,
    body: [el('p', { class: 'muted' }, t('move_pc.lead')), el('ol', { class: 'install-steps move-steps' }, steps),
      el('div', { class: 'warning subtle' }, icon('info', 'sm'), el('span', {}, t('move_pc.unlock_note')))],
    footer: [el('div', { class: 'spacer' }), el('button', { class: 'btn primary', onclick: () => modal.close() }, t('common.done'))],
  });
}

// ----- «Servidor»: the team server's admin (docs/ARCHITECTURE.md 5.2). Accounts, organizations, backups and sign-ups;
// never contents: the server has none to show.

const SIGNUP_LABELS = localized(() => ({ open: t('server_admin.signups_open'), invite: t('server_admin.signups_invite'), closed: t('server_admin.signups_closed') }));
const SIGNUP_HELP = localized(() => ({ open: t('server_admin.signups_open_help'), invite: t('server_admin.signups_invite_help'), closed: t('server_admin.signups_closed_help') }));
// The server admin's own log (accounts and server settings; organizations keep theirs in Actividad).
const ADMIN_EVENT_LABELS = {
  'user.disable': 'server_admin.event_disable', 'user.enable': 'server_admin.event_enable', 'user.delete': 'server_admin.event_delete',
  'user.verify': 'server_admin.event_verify', 'signup_token.create': 'server_admin.event_signup_token',
  'backup.create': 'server_admin.event_backup', 'settings.signups': 'server_admin.event_signups',
  'settings.auto_update': 'server_admin.event_auto_update', 'org.owner': 'server_admin.event_owner',
  'email.verify': 'server_admin.event_verify', register: 'server_admin.event_register', login: 'server_admin.event_login',
  'password.change': 'server_admin.event_password', 'password.fail': 'server_admin.event_password_fail',
  'device.revoke': 'server_admin.event_device',
};

function fmtBytes(bytes) {
  const [unit, size] = [['gigabyte', 1e9], ['megabyte', 1e6], ['kilobyte', 1e3]].find(([, s]) => bytes >= s) || ['byte', 1];
  return fmtNumber(bytes / size, { style: 'unit', unit, unitDisplay: 'short', maximumFractionDigits: 1 });
}

function quoted(name) {
  return t('server_admin.quoted', { name });
}

// What a server could put in a backup's name goes into a command the admin pastes into a shell: letters, digits,
// dots, dashes and underscores only.
function safeFileName(name) {
  return /^[\w.-]{1,120}$/.test(String(name || '')) ? name : null;
}

function teamServerPanel(content, rerender) {
  const admin = (state.teamData && state.teamData.admin) || {};
  const panes = [['overview', t('server_admin.pane_overview'), null], ['accounts', t('server_admin.pane_accounts'), (admin.users || []).length],
    ['orgs', t('server_admin.pane_orgs'), (admin.orgs || []).length], ['log', t('server_admin.pane_log'), null]];
  if (!panes.some(([id]) => id === state.serverPane)) state.serverPane = 'overview';
  const nav = el('div', { class: 'segmented small server-nav', role: 'tablist' }, panes.map(([id, label, count]) => el('button', {
    class: state.serverPane === id ? 'active' : '', role: 'tab', 'aria-selected': state.serverPane === id ? 'true' : 'false',
    onclick: () => { state.serverPane = id; drawTeam(content); refreshTeam(content, false); },
  }, label, count ? el('span', { class: 'tab-count' }, count) : null)));
  const pane = {
    overview: () => serverOverview(admin, rerender),
    accounts: () => serverAccounts(admin, rerender),
    orgs: () => serverOrgs(admin, rerender),
    log: () => serverLog(admin),
  }[state.serverPane]();
  return el('div', { class: 'team-panel server-panel' }, nav, pane);
}

function serverOverview(admin, rerender) {
  const o = admin.overview;
  if (!o) return el('div', { class: 'spinner' });
  const counts = o.counts || {};
  const updates = o.updates || {};
  const backups = o.backups || {};
  const since = Number(o.uptime_s) > 0 ? new Date(Date.now() - Number(o.uptime_s) * 1000).toISOString() : null;
  // Whether it is up to date: only when the server knows the latest version.
  const fresh = !o.latest ? null : o.latest === o.version
    ? el('div', { class: 'state-text ok server-version' }, icon('check', 'sm'), t('server_admin.up_to_date'))
    : el('div', { class: 'state-text warn server-version' }, icon('alert', 'sm'),
      t(updates.auto ? 'server_admin.new_version_auto' : 'server_admin.new_version_manual', { version: o.latest }));
  const head = el('div', { class: 'server-head' },
    el('div', { class: 'start-icon' }, icon('server')),
    el('div', { class: 'meta' },
      el('div', { class: 'title' }, hostOf(state.team.server_url)),
      el('div', { class: 'subtitle' }, [t('server_admin.version', { version: o.version || '?' }),
        since ? t('server_admin.running_since', { when: whenText(since) }) : null,
        o.db_bytes ? t('server_admin.database_size', { size: fmtBytes(o.db_bytes) }) : null].filter(Boolean).join(' · ')),
      fresh));
  const stats = el('div', { class: 'server-stats' }, [['users', t('server_admin.stat_accounts')], ['orgs', t('server_admin.stat_orgs')],
    ['collections', t('server_admin.stat_collections')], ['items', t('server_admin.stat_credentials')]]
    .map(([key, label]) => el('div', { class: 'stat' }, el('div', { class: 'stat-value' }, fmtNumber(Number(counts[key]) || 0)),
      el('div', { class: 'stat-label' }, label))));

  const auto = el('input', { type: 'checkbox', role: 'switch', class: 'switch', checked: !!updates.auto, 'data-mutates': '1', 'aria-label': t('server_admin.auto_updates') });
  auto.addEventListener('change', async () => {
    const result = await teamAct('team_admin_settings', { auto_update: auto.checked }, t('server_admin.settings_reason'));
    if (!result.ok) { auto.checked = !auto.checked; return; }
    toast(auto.checked ? t('server_admin.auto_on_done') : t('server_admin.auto_off_done'));
    rerender();
  });
  const autoHelp = [updates.auto ? t('server_admin.auto_on_help') : t('server_admin.auto_off_help'),
    updates.last_check ? t('server_admin.last_check', { when: whenText(updates.last_check) }) : null].filter(Boolean).join(' ');

  const backupNow = el('button', { class: 'btn', 'data-mutates': '1' }, t('server_admin.backup_now'));
  backupNow.addEventListener('click', async () => {
    const result = await teamAct('team_admin_backup_now', {}, t('server_admin.backup_reason'), backupNow);
    if (!result.ok) return;
    toast(t('server_admin.backup_done'));
    rerender();
  });
  const backupHelp = [backups.last ? t('server_admin.backup_last', { when: whenText(backups.last) }) : t('server_admin.backup_none'),
    backups.count ? tn('server_admin.backups_kept', Number(backups.count)) : null,
    Number(backups.keep) > 0 ? t('server_admin.backup_daily_keep', { keep: Number(backups.keep) }) : t('server_admin.backup_daily')]
    .filter(Boolean).join(' · ');

  const signups = el('select', { class: 'input', 'data-mutates': '1', 'aria-label': t('server_admin.signups') },
    ['open', 'invite', 'closed'].map((mode) => el('option', { value: mode }, SIGNUP_LABELS[mode])));
  signups.value = o.signups;
  signups.addEventListener('change', async () => {
    const result = await teamAct('team_admin_settings', { signups: signups.value }, t('server_admin.settings_reason'));
    if (!result.ok) { signups.value = o.signups; return; }
    toast(t('server_admin.signups_done', { mode: lowerFirst(SIGNUP_LABELS[signups.value]) }));
    rerender();
  });
  const code = el('button', { class: 'btn', 'data-mutates': '1' }, t('server_admin.signup_code'));
  code.addEventListener('click', async () => {
    const result = await teamAct('team_admin_signup_token', { days: 7 }, t('server_admin.signup_code_reason'), code);
    if (result.ok) signupInstructions(result.result);
  });

  const mail = o.mail
    ? el('span', { class: 'state-text ok' }, icon('check', 'sm'), t('server_admin.mail_on'))
    : el('span', { class: 'state-text warn' }, t('server_admin.mail_off'));
  return el('div', { class: 'server-overview' }, head, stats,
    el('div', { class: 'settings-group' },
      setting(t('server_admin.auto_updates'), autoHelp, auto),
      setting(t('server_admin.backups'), backupHelp, backupNow),
      serverRestore(admin),
      o.signups === 'open'  // anyone who finds the address can sign up: said in the warning colour, with what to choose
        ? el('div', { class: 'setting' }, el('div', { class: 'meta' }, el('h3', {}, t('server_admin.signups')),
          el('p', { class: 'warn-text' }, `${SIGNUP_HELP.open} ${t('server_admin.signups_open_suggest')}`)), el('div', { class: 'control' }, signups))
        : setting(t('server_admin.signups'), SIGNUP_HELP[o.signups] || '', signups),
      o.signups === 'invite' ? setting(t('server_admin.signup_code_title'), t('server_admin.signup_code_help'), code) : null,
      setting(t('server_admin.mail'), o.mail ? t('server_admin.mail_on_help') : t('server_admin.mail_off_help'), mail)));
}

// Restoring puts the whole team back in time, so it is done on the server, by hand: the exact commands to paste.
// The server's own lines when it sends them (checked by the service), else those of how it was installed, else its guide.
const SERVER_README = 'https://github.com/xBofi/SecretBroker/blob/main/server/README.md#backups-and-restore';

function restoreCommands(overview, file) {
  const own = overview.restore_command;
  if (Array.isArray(own) && own.length) return { where: 'server_admin.restore_where_server', lines: own.map((line) => line.replace('<file>', file)) };
  if (overview.install === 'systemd') {
    // The installer's command stops and starts the service itself.
    return { where: 'server_admin.restore_where_systemd', lines: [`sudo secretbroker-server restore /var/lib/secretbroker-server/backups/${file}`] };
  }
  if (overview.install === 'docker') {
    return { where: 'server_admin.restore_where', lines: ['sudo docker compose stop server backup',
      `sudo docker compose run --rm --no-deps backup secretbroker-server restore /backups/${file}`, 'sudo docker compose up -d'] };
  }
  return null;
}

function serverRestore(admin) {
  const newest = ((admin.backups || [])[0] || {}).file;
  const file = safeFileName(newest);
  const meta = el('div', { class: 'meta' }, el('h3', {}, t('server_admin.restore')),
    el('p', {}, file ? t('server_admin.restore_help') : t('server_admin.restore_none')));
  if (!file) return el('div', { class: 'setting' }, meta);
  const how = restoreCommands(admin.overview || {}, file);
  const command = how ? how.lines.join('\n') : '';
  const steps = how
    ? el('div', { class: 'restore-steps hidden' }, el('p', {}, t(how.where)),
      el('div', { class: 'command-box' }, el('pre', { class: 'instructions selectable' }, command), copyButton(command)),
      el('p', {}, t('server_admin.restore_after')))
    : el('div', { class: 'restore-steps hidden' }, el('p', {}, t('server_admin.restore_readme')),
      el('button', { class: 'link small restore-show', onclick: () => api().open_link(SERVER_README) }, t('server_admin.restore_readme_open')));
  const show = el('button', { class: 'link small restore-show' }, t('server_admin.restore_show'));
  show.addEventListener('click', () => { steps.classList.remove('hidden'); show.remove(); });
  meta.append(show, steps);
  return el('div', { class: 'setting' }, meta);
}

function signupInstructions(token) {
  const server = state.team.server_url;
  const link = joinLink(server, '', token.token);
  const expires = token.expires ? new Date(typeof token.expires === 'number' ? token.expires * 1000 : token.expires) : null;
  const text = [
    t('server_admin.signup_text_intro'),
    '',
    t('invite.step_install', { url: RELEASES_URL }),
    t('invite.step_open_link', { link }),
    t('invite_instructions.if_doesn_open_go_team'),
    t('invite.step_server', { server }),
    t('server_admin.signup_text_code', { code: token.token }),
    t('server_admin.signup_text_create'),
  ].join('\n');
  const copy = el('button', { class: 'btn primary' }, icon('copy', 'sm'), t('common.copy_instructions'));
  copy.addEventListener('click', async () => { await api().copy_text(text); toast(t('invite_instructions.instructions_copied')); });
  const copyCode = el('button', { class: 'btn' }, t('server_admin.copy_code_only'));
  copyCode.addEventListener('click', async () => { await api().copy_text(token.token); toast(t('common.copied')); });
  const modal = openModal({
    title: t('server_admin.signup_code_title'),
    wide: true,
    body: [el('p', { class: 'muted' }, expires && !Number.isNaN(expires.getTime())
      ? t('server_admin.signup_code_once', { date: fmtDate(expires, { day: 'numeric', month: 'long' }) }) : t('server_admin.signup_code_once_no_date')),
    el('pre', { class: 'instructions selectable' }, text)],
    footer: [copyCode, el('div', { class: 'spacer' }), el('button', { class: 'btn', onclick: () => modal.close() }, t('common.close')), copy],
  });
}

function serverAccounts(admin, rerender) {
  if (!admin.users) return el('div', { class: 'spinner' });
  const users = [...admin.users].sort((a, b) => (b.me ? 1 : 0) - (a.me ? 1 : 0) || compareText(a.name || a.email || '', b.name || b.email || ''));
  return el('div', { class: 'settings-group' },
    el('p', { class: 'help', style: 'margin-bottom:4px' }, t('server_admin.accounts_help')),
    users.map((u) => serverAccountRow(u, admin, rerender)));
}

function serverAccountRow(u, admin, rerender) {
  const label = u.name || u.email;
  const [cls, status] = u.disabled ? ['is-exposed', t('server_admin.status_disabled')]
    : u.replacing ? ['is-warning', t('server_admin.status_new_account')]
    : u.verified === false ? ['is-warning', t('server_admin.status_unverified')] : ['is-ok', t('server_admin.status_verified')];
  const orgs = (u.orgs || []).map((o) => `${o.name} (${lowerFirst(ROLE_LABELS[o.role] || o.role || '')})`);
  const seen = u.last_seen ? t('server_admin.last_seen', { when: whenText(u.last_seen) }) : t('server_admin.never_seen');
  const controls = [];
  const oneClick = (text, op, reason, done, ghost = false) => {
    const node = el('button', { class: `btn ${ghost ? 'ghost' : ''}`, 'data-mutates': '1' }, text);
    node.addEventListener('click', async () => {
      const result = await teamAct(op, { user_id: u.id }, reason, node);
      if (!result.ok) return;
      toast(done);
      rerender();
    });
    return node;
  };
  // A new account of someone who lost access to theirs (Equipo › Personas › «Ha perdido el acceso»): it waits to
  // prove the e-mail; verifying it here makes it take the old account's place.
  const replacing = !!u.replacing;
  const replaced = (admin.users || []).find((x) => x.replacing === u.id);
  if (replacing && !u.disabled) {
    const verify = el('button', { class: 'btn primary', 'data-mutates': '1' }, t('server_admin.verify_replacement'));
    verify.addEventListener('click', () => confirmModal({
      title: t('server_admin.replace_title', { name: label }),
      text: t('server_admin.replace_text', { name: label, email: u.email }),
      action: t('server_admin.verify_replacement'),
      onConfirm: async (button) => {
        const result = await teamAct('team_admin_verify', { user_id: u.id }, t('server_admin.verify_reason', { name: label }), button);
        if (!result.ok) return false;
        toast(t('server_admin.replaced_done', { name: label }));
        rerender();
        return true;
      },
    }));
    controls.push(verify);
  } else if (!u.me) {
    if (!u.disabled && u.verified === false) {
      controls.push(oneClick(t('server_admin.verify_email'), 'team_admin_verify', t('server_admin.verify_reason', { name: label }),
        t('server_admin.verified_done', { name: label })));
    }
    controls.push(u.disabled
      ? oneClick(t('server_admin.enable'), 'team_admin_enable', t('server_admin.enable_reason', { name: label }), t('server_admin.enabled_done', { name: label }))
      : el('button', { class: 'btn ghost', 'data-mutates': '1', onclick: () => disableAccount(u, admin, rerender) }, t('server_admin.disable')));
    controls.push(el('button', { class: 'btn icon-only', 'data-mutates': '1', title: t('server_admin.delete_account'), 'aria-label': t('server_admin.delete_account'),
      onclick: () => deleteAccount(u, admin, rerender) }, icon('trash', 'sm')));
  }
  return el('div', { class: `member server-account${u.disabled ? ' is-disabled' : ''}` }, el('div', { class: 'access-row' },
    el('div', { class: `avatar ${u.disabled ? 'invited' : ''}` }, (label || '?').trim().charAt(0).toUpperCase()),
    el('div', { class: 'meta' },
      el('div', { class: 'title' }, el('span', { class: 'name' }, label), u.me ? el('span', { class: 'faint' }, t('common.you')) : null,
        el('span', { class: `chip ${cls}` }, status), u.admin ? el('span', { class: 'chip' }, t('server_admin.status_admin')) : null),
      el('div', { class: 'subtitle' }, [u.name ? u.email : null, replacing ? null : seen].filter(Boolean).join(' · ')),
      replacing ? el('div', { class: 'subtitle warn-line' }, t('server_admin.replacing_status'))
        : replaced ? el('div', { class: 'subtitle warn-line' }, t('server_admin.being_replaced'))
          : el('div', { class: 'subtitle' }, orgs.length ? orgs.join(', ') : t('server_admin.in_no_org'))),
    el('div', { class: 'row-actions' }, controls)));
}

function disableAccount(u, admin, rerender) {
  const label = u.name || u.email;
  // The only owner of an organization stays in it (unable to sign in) until it has another owner.
  const owners = Object.fromEntries((admin.orgs || []).map((o) => [o.id, (o.owners || []).length]));
  const stays = (u.orgs || []).filter((o) => o.role === 'owner' && owners[o.id] === 1);
  const leaves = (u.orgs || []).filter((o) => !stays.includes(o));
  confirmModal({
    title: t('server_admin.disable_title', { name: label }),
    text: [t('server_admin.disable_text', { name: label }),
      leaves.length ? t('server_admin.disable_leaves', { orgs: listJoin(leaves.map((o) => quoted(o.name))) }) : null,
      stays.length ? t('server_admin.disable_stays', { orgs: listJoin(stays.map((o) => quoted(o.name))) }) : null].filter(Boolean).join(' '),
    warning: t('server_admin.disable_warning'),
    action: t('server_admin.disable'),
    danger: true,
    onConfirm: async (button) => {
      const result = await teamAct('team_admin_disable', { user_id: u.id }, t('server_admin.disable_reason', { name: label }), button);
      if (!result.ok) return false;
      const { left = [], held = [] } = result.result;
      toast(left.length ? t('server_admin.disabled_left', { name: label, orgs: listJoin(left.map((l) => quoted(l.name))) })
        : t('server_admin.disabled_done', { name: label }));
      if (held.length) toast(t('server_admin.disabled_held', { name: label, orgs: listJoin(held.map((h) => quoted(h.name))) }), 'warning');
      // This PC re-encrypts what it manages now, and flags what they could see.
      await api().call('team_sync');
      await loadEntries();
      rerender();
      return true;
    },
  });
}

// Deleting can't be undone: the e-mail typed to confirm. The server refuses while the account is an organization's
// only owner or a collection's only manager; the dialog then says so in one sentence, with the fix next to it.
function deleteAccount(u, admin, rerender) {
  const label = u.name || u.email;
  const typed = el('input', { class: 'input', autocomplete: 'off', spellcheck: 'false', placeholder: u.email });
  const go = el('button', { class: 'btn solid-danger', 'data-mutates': '1', disabled: true }, t('server_admin.delete'));
  const fix = el('div', { class: 'delete-fix' });
  typed.addEventListener('input', () => { go.disabled = typed.value.trim().toLowerCase() !== String(u.email || '').toLowerCase(); });
  const modal = openModal({
    title: t('server_admin.delete_title', { name: label }),
    body: [el('p', { class: 'muted' }, t('server_admin.delete_text', { name: label })),
      el('div', { class: 'warning is-danger' }, icon('alert', 'sm'), el('span', {}, t('server_admin.delete_warning'))),
      el('div', { class: 'field' }, el('label', {}, t('server_admin.delete_type_email', { email: u.email })), typed),
      fix],
    footer: [el('button', { class: 'btn', onclick: () => modal.close() }, t('common.cancel')), go],
  });
  go.addEventListener('click', async () => {
    const result = await teamAct('team_admin_delete', { user_id: u.id }, t('server_admin.delete_reason', { name: label }), go);
    if (!result.ok) return;
    if (!result.result.deleted) {
      // Who can take over: the accounts as they are now, not as the list was drawn.
      const fresh = await api().call('team_admin_users');
      if (fresh.ok) admin.users = fresh.result;
      fix.replaceChildren(deleteBlocked(result.result, u, admin, modal));
      go.textContent = t('server_admin.delete_again');
      return;
    }
    modal.close();
    toast(t('server_admin.deleted_done', { name: label }));
    await api().call('team_sync');
    await loadEntries();
    rerender();
  });
  setTimeout(() => typed.focus(), 50);
}

function deleteBlocked(refused, u, admin, modal) {
  const fixes = [];
  if (refused.code === 'last_owner') {
    for (const org of refused.orgs || []) {
      const name = org.name ? quoted(org.name) : t('common.organization');
      const candidates = (admin.users || []).filter((x) => !x.disabled && x.id !== u.id && (x.orgs || []).some((o) => o.id === org.id));
      if (!candidates.length) {
        fixes.push(el('p', { class: 'help' }, t('server_admin.no_one_else_in', { org: name })));
        continue;
      }
      const pick = el('select', { class: 'input compact', 'aria-label': t('server_admin.new_owner_of', { org: name }) },
        candidates.map((x) => el('option', { value: x.id }, x.name || x.email)));
      const make = el('button', { class: 'btn primary', 'data-mutates': '1' }, t('server_admin.make_owner'));
      const line = el('div', { class: 'fix-line' }, el('span', {}, t('server_admin.new_owner_of', { org: name })), pick, make);
      make.addEventListener('click', async () => {
        const who = candidates.find((x) => x.id === pick.value);
        const result = await teamAct('team_admin_transfer_owner', { org: org.id, user_id: pick.value }, t('server_admin.owner_reason', { org: name }), make);
        if (!result.ok) return;
        line.replaceWith(el('p', { class: 'ok-text' }, icon('check', 'sm'), t('server_admin.owner_done', { name: who ? who.name || who.email : '', org: name })));
      });
      fixes.push(line);
    }
  } else if (refused.code === 'last_manager') {
    for (const c of refused.collections || []) {
      if (!c.name || !c.org) continue;
      fixes.push(el('button', { class: 'link fix-link', onclick: () => {
        modal.close();
        state.view = 'team'; state.teamTab = 'collections'; state.teamOrg = c.org; state.openCollection = c.id;
        renderMain();
      } }, t('server_admin.open_collection', { name: c.name })));
    }
  }
  return el('div', { class: 'warning' }, icon('alert', 'sm'), el('div', { class: 'fix-body' }, el('span', {}, refused.error), fixes));
}

function serverOrgs(admin, rerender) {
  if (!admin.orgs) return el('div', { class: 'spinner' });
  if (!admin.orgs.length) return el('p', { class: 'muted' }, t('server_admin.no_orgs'));
  return el('div', { class: 'settings-group' }, admin.orgs.map((org) => {
    const owners = (org.owners || []).map((w) => w.name || w.email);
    return el('div', { class: 'access-row' },
      el('div', { class: 'avatar' }, (org.name || '?').trim().charAt(0).toUpperCase()),
      el('div', { class: 'meta' }, el('div', { class: 'title' }, org.name),
        el('div', { class: 'subtitle' }, [owners.length ? t('server_admin.owners', { names: listJoin(owners) }) : t('server_admin.no_owner'),
          tn('common.people_count', Number(org.members) || 0), tn('server_admin.collections_count', Number(org.collections) || 0)].join(' · '))),
      el('button', { class: 'btn', 'data-mutates': '1', onclick: () => changeOwner(org, admin, rerender) }, t('server_admin.change_owner')));
  }));
}

function changeOwner(org, admin, rerender) {
  const oname = quoted(org.name);
  const owners = new Set((org.owners || []).map((w) => w.id));
  const candidates = (admin.users || []).filter((u) => !u.disabled && !owners.has(u.id) && (u.orgs || []).some((o) => o.id === org.id));
  const pick = candidates.length ? el('select', { class: 'input', 'aria-label': t('server_admin.new_owner_of', { org: oname }) },
    candidates.map((u) => el('option', { value: u.id }, u.email && u.name ? `${u.name} · ${u.email}` : u.name || u.email))) : null;
  const make = el('button', { class: 'btn primary', 'data-mutates': '1', disabled: !pick }, t('server_admin.make_owner'));
  const modal = openModal({
    title: t('server_admin.change_owner_title', { org: oname }),
    body: [el('p', { class: 'muted' }, t('server_admin.change_owner_text')),
      pick ? el('div', { class: 'field' }, el('label', {}, t('server_admin.new_owner_of', { org: oname })), pick)
        : el('div', { class: 'warning subtle' }, icon('info', 'sm'), el('span', {}, t('server_admin.no_one_else_in', { org: oname })))],
    footer: [el('button', { class: 'btn', onclick: () => modal.close() }, t('common.cancel')), make],
  });
  make.addEventListener('click', async () => {
    const who = candidates.find((u) => u.id === pick.value);
    const result = await teamAct('team_admin_transfer_owner', { org: org.id, user_id: pick.value }, t('server_admin.owner_reason', { org: oname }), make);
    if (!result.ok) return;
    modal.close();
    toast(t('server_admin.owner_done', { name: who ? who.name || who.email : '', org: oname }));
    rerender();
  });
}

function serverLog(admin) {
  const events = admin.events;
  const names = Object.fromEntries((admin.users || []).map((u) => [u.id, u.name || u.email]));
  // The server's log names accounts by id, with the e-mail they had in `detail` / `actor_email` (also once deleted).
  const detail = (e) => (e.detail && typeof e.detail === 'object' ? e.detail : {});
  const who = (id, email) => names[id] || email || t('server_admin.deleted_account');
  const onOff = (value) => (value ? t('server_admin.on') : t('server_admin.off'));
  const describe = (e) => {
    const d = detail(e);
    if (e.action === 'settings') {  // {signups?, auto_update?}: what changed
      const parts = [];
      if (typeof d.signups === 'string') parts.push(t('server_admin.event_signups', { value: lowerFirst(SIGNUP_LABELS[d.signups] || '') }));
      if (typeof d.auto_update === 'boolean') parts.push(t('server_admin.event_auto_update', { value: onOff(d.auto_update) }));
      return parts.join(' · ') || t('team_events_panel.other_action');
    }
    if (e.action === 'settings.signups') return t('server_admin.event_signups', { value: lowerFirst(SIGNUP_LABELS[e.target] || '') });
    if (e.action === 'settings.auto_update') return t('server_admin.event_auto_update', { value: onOff(e.target !== 'off') });
    const key = ADMIN_EVENT_LABELS[e.action];
    if (!key) return t('team_events_panel.other_action');
    if (e.action === 'user.delete' && !names[e.target] && !d.email) return t('server_admin.event_delete_gone');
    if (e.action === 'email.verify' && e.actor && e.actor === e.target) return t('server_admin.event_verify_own');
    if (e.action === 'org.owner') return t(key, { who: who(d.user, d.email) });  // the target is the organization
    return t(key, { who: who(e.target, d.email) });
  };
  const actor = (e) => (e.actor ? capitalized(who(e.actor, e.actor_email)) : t('server_admin.from_the_server'));
  return el('div', { class: 'settings-group' },
    el('p', { class: 'help', style: 'margin-bottom:8px' }, t('server_admin.log_help')),
    events === undefined ? el('div', { class: 'spinner' })
      : !events.length ? el('p', { class: 'muted' }, t('common.no_activity_yet'))
        : el('table', { class: 'table' }, el('tbody', {}, events.slice(0, 100).map((e) => el('tr', {},
          el('td', { class: 'muted', style: 'white-space:nowrap' }, formatTime(e.time)),
          el('td', {}, actor(e)),
          el('td', {}, describe(e)))))));
}
// ----- linking the account (the only time its password is typed on this PC)

function teamConnectForm({ server = '', email = '', code = '', mode = 'register', lockMode = false, invited = false, restored = false, pending = null, onDone }) {
  let current = mode;
  const serverInput = el('input', { class: 'input', placeholder: 'https://equipo.tuempresa.com', value: server, spellcheck: 'false' });
  const nameInput = el('input', { class: 'input', placeholder: t('team_connect_form.how_your_team_will_see') });
  const emailInput = el('input', { class: 'input', type: 'email', value: email, spellcheck: 'false' });
  const pw = passwordInput({ autocomplete: current === 'register' ? 'new-password' : 'current-password' });
  const repeat = passwordInput();
  const tokenInput = el('input', { class: 'input mono', spellcheck: 'false', value: code });
  // «¿Has olvidado la contraseña?»: the recovery code opens the keys here and a new password wraps them (2.1).
  const recoveryInput = el('input', { class: 'input mono', spellcheck: 'false', autocomplete: 'off', placeholder: 'XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX' });
  const pwLabel = el('label', {});
  const forgot = el('button', { class: 'link small', type: 'button', style: 'align-self:flex-start;margin-top:6px',
    onclick: () => { current = 'recover'; errorText.textContent = ''; render(); recoveryInput.focus(); } }, t('team_recover.forgot'));
  const back = el('button', { class: 'link small', type: 'button', style: 'align-self:flex-start',
    onclick: () => { current = 'login'; errorText.textContent = ''; render(); } }, t('team_recover.back'));
  const recoverHead = el('div', { class: 'recover-head' }, el('h3', {}, t('team_recover.title')), el('p', { class: 'muted' }, t('team_recover.lead')));
  const recoverField = el('div', { class: 'field' }, el('label', {}, t('team_recover.code')), recoveryInput,
    el('div', { class: 'help' }, t('team_recover.code_help')));
  const noCode = el('div', { class: 'warning subtle' }, icon('info', 'sm'), el('div', {},
    el('b', {}, t('team_recover.no_code_title')), ' ', t('team_recover.no_code_text')));
  const onlyOnce = el('p', { class: 'help' }, t('team_connect_form.only_asked_for_this_once'));
  // A new account replacing one whose owner lost access: it proves the e-mail first (the e-mailed code, or the
  // server admin), so an invite code alone never takes an address.
  let replacing = pending;  // {email, mail}: shown at once (the sign-up said the e-mail must be proven)
  if (pending) current = 'replace';
  const replaceText = el('p', { class: 'muted' });
  const replaceHead = el('div', { class: 'recover-head' }, el('h3', {}, t('team_replace.title')), replaceText);
  const replaceInput = el('input', { class: 'input mono', spellcheck: 'false', autocomplete: 'one-time-code', inputmode: 'numeric' });
  const replaceField = el('div', { class: 'field' }, el('label', {}, t('team_replace.code')), replaceInput);
  const errorText = el('div', { class: 'error-text' });
  const button = el('button', { class: 'btn primary lg' });
  const tabs = el('div', { class: 'segmented' });
  const linkNote = el('div', { class: `notice ${invited ? '' : 'hidden'}` }, icon('users', 'sm'), el('span', { class: 'notice-text' }));
  const serverField = el('div', { class: 'field' }, el('label', {}, t('team_connect_form.server')), serverInput,
    el('div', { class: 'help' }, t('team_connect_form.address_your_secretbroker_server_you')));
  const emailField = el('div', { class: 'field' }, el('label', {}, 'E-mail'), emailInput);
  const registerOnly = [
    el('div', { class: 'field' }, el('label', {}, t('team_connect_form.your_name'), el('span', { class: 'req' }, t('common.optional_suffix'))), nameInput),
  ];
  const meter = strengthMeter(pw.input);
  const repeatField = el('div', { class: 'field' }, el('label', {}, t('common.repeat')), repeat);
  const tokenField = el('div', { class: 'field' }, el('label', {}, t('team_connect_form.invitation_code'), el('span', { class: 'req' }, t('team_connect_form.if_your_server_asks_for'))), tokenInput);
  const pwField = el('div', { class: 'field' }, pwLabel, pw, meter, forgot);
  const render = () => {
    tabs.replaceChildren([['register', t('team_connect_form.create_account')], ['login', t('team_connect_form.sign_in')]].map(([m, text]) => el('button', {
      type: 'button', class: m === current ? 'active' : '', onclick: () => { current = m; errorText.textContent = ''; render(); },
    }, text)));
    const register = current === 'register';
    const recover = current === 'recover';
    const replace = current === 'replace';
    tabs.classList.toggle('hidden', recover || replace);
    replaceHead.classList.toggle('hidden', !replace);
    replaceField.classList.toggle('hidden', !replace || !(replacing && replacing.mail));
    [serverField, emailField, pwField].forEach((n) => n.classList.toggle('hidden', replace));
    [recoverHead, recoverField, noCode, back].forEach((n) => n.classList.toggle('hidden', !recover));
    forgot.classList.toggle('hidden', current !== 'login');
    onlyOnce.classList.toggle('hidden', recover || replace);
    registerOnly.forEach((n) => n.classList.toggle('hidden', !register));
    meter.forEach((n) => n.classList.toggle('hidden', !register && !recover));
    repeatField.classList.toggle('hidden', (!register && !recover) || replace);
    tokenField.classList.toggle('hidden', !register);
    pwLabel.textContent = recover ? t('team_recover.new_password') : t('team_connect_form.account_password');
    pw.input.autocomplete = register || recover ? 'new-password' : 'current-password';
    button.textContent = replace ? (replacing && replacing.mail ? t('team_replace.button') : t('team_connect_form.sign_in'))
      : recover ? t('team_recover.button') : register ? t('team_connect_form.create_account') : t('team_connect_form.sign_in');
    if (replace) replaceText.textContent = replacing.mail ? t('team_replace.mail_text', { email: replacing.email })
      : t('team_replace.no_mail_text', { email: replacing.email });
  };
  render();
  const showLink = (link) => {
    linkNote.classList.remove('hidden');
    linkNote.querySelector('.notice-text').textContent = t('team_connect_form.invitation_for_on_check_that', { value: link.email || 'ti', host: hostOf(link.server) });
  };
  if (invited) showLink({ server, email });
  if (restored) {  // a vault restored on a new PC: the account is here, the old PC's session is not
    linkNote.classList.remove('hidden');
    linkNote.querySelector('.notice-text').textContent = t('team_connect_form.restored_sign_in', { email, host: hostOf(server) });
  }
  // A pasted invite link (secretbroker://join?…) fills in the form.
  serverInput.addEventListener('input', () => {
    const link = parseJoinLink(serverInput.value);
    if (!link) return;
    serverInput.value = link.server;
    if (link.email) emailInput.value = link.email;
    if (link.code) tokenInput.value = link.code;
    current = 'register';
    render();
    showLink(link);
    (link.email ? pw.input : emailInput).focus();
  });
  const submit = async () => {
    errorText.textContent = '';
    if (current === 'replace') { await submitReplace(); return; }
    const register = current === 'register';
    const recover = current === 'recover';
    if (!serverInput.value.trim()) { errorText.textContent = t('team_connect_form.type_server_address'); serverInput.focus(); return; }
    if (!emailInput.value.trim()) { errorText.textContent = t('team_connect_form.type_your_e_mail'); emailInput.focus(); return; }
    if (recover && !recoveryInput.value.trim()) { errorText.textContent = t('team_recover.type_code'); recoveryInput.focus(); return; }
    if (!pw.input.value) { errorText.textContent = recover ? t('team_recover.type_new_password') : t('team_connect_form.type_account_password'); pw.input.focus(); return; }
    if ((register || recover) && pw.input.value.length < 12) { errorText.textContent = t('team_connect_form.account_password_needs_at_least'); return; }
    if ((register || recover) && pw.input.value !== repeat.input.value) { errorText.textContent = t('common.two_passwords_don_match'); return; }
    busy(button, true);
    const params = { server_url: serverInput.value.trim(), email: emailInput.value.trim(), password: pw.input.value, mode: current };
    if (register && nameInput.value.trim()) params.name = nameInput.value.trim();
    if (register && tokenInput.value.trim()) params.invite_token = tokenInput.value.trim();
    if (recover) { delete params.mode; params.code = recoveryInput.value.trim(); }
    const result = await withProof((p) => api().call(recover ? 'team_recover' : 'team_connect', params, p),
      recover ? t('team_recover.reason') : t('team_connect_form.connect_team_account'));
    busy(button, false);
    if (!result.ok) { if (result.code !== 'cancelled') errorText.textContent = result.error; return; }
    if (result.result.replace_pending) {  // the e-mail had an account whose owner lost access: prove it first
      replacing = result.result.replace_pending;
      current = 'replace';
      render();
      if (replacing.mail) replaceInput.focus();
      return;
    }
    await finish(result.result, recover ? t('team_recover.done') : register ? t('team_connect_form.account_created_and_connected') : t('common.connected'));
  };
  const finish = async (status, message) => {
    pw.input.value = '';
    repeat.input.value = '';
    recoveryInput.value = '';
    replaceInput.value = '';
    toast(message);
    const code = status.recovery_code;
    const used = !!status.recovery_used;
    delete status.recovery_code;
    await onDone(status);
    // A new account, or a recovery code that was just used: the (new) code, shown once.
    if (code) showRecoveryCode(code, { used });
  };
  const submitReplace = async () => {
    const params = { server_url: serverInput.value.trim(), email: emailInput.value.trim(), password: pw.input.value };
    if (replacing.mail && !replaceInput.value.trim()) { errorText.textContent = t('team_replace.type_code'); replaceInput.focus(); return; }
    busy(button, true);
    const result = replacing.mail
      ? await withProof((p) => api().call('team_confirm_replacement', { ...params, code: replaceInput.value.trim() }, p), t('team_replace.reason'))
      : await withProof((p) => api().call('team_connect', { ...params, mode: 'login' }, p), t('team_connect_form.connect_team_account'));
    busy(button, false);
    if (!result.ok) {
      if (result.code === 'cancelled') return;
      errorText.textContent = !replacing.mail && result.code === 'invalid_credentials' ? t('team_replace.not_yet') : result.error;
      return;
    }
    await finish(result.result, t('team_replace.done'));
  };
  button.addEventListener('click', submit);
  [pw.input, repeat.input, tokenInput, replaceInput].forEach((i) => i.addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); }));
  if (lockMode) tabs.remove();
  return el('div', { class: 'team-form' },
    lockMode ? null : tabs,
    recoverHead,
    replaceHead,
    linkNote,
    serverField,
    registerOnly,
    emailField,
    recoverField,
    noCode,
    pwField,
    replaceField,
    repeatField,
    tokenField,
    onlyOnce,
    errorText,
    el('div', { class: 'form-actions' }, button, back));
}

function renderTeamConnect(content) {
  const link = state.joinLink;
  state.joinLink = null;
  const hint = !link && state.team && state.team.hint;  // a vault restored on a new PC
  const form = teamConnectForm({ server: link ? link.server : hint ? hint.server_url : '', email: link ? link.email : hint ? hint.email : '',
    code: link ? link.code : '', invited: !!link, restored: !!hint, mode: hint ? 'login' : 'register',
    onDone: async () => { await loadEntries(); renderMain(); } });
  content.replaceChildren(el('div', { class: 'content-header' }, el('h1', {}, t('common.team'))),
    el('div', { class: 'content-body team-view' }, el('div', { class: 'team-connect' },
      el('div', { class: 'team-intro' },
        el('h2', {}, t('team_connect.share_credentials_with_your_team')),
        el('p', { class: 'muted' }, t('team_connect.create_collections_and_decide_who')),
        el('div', { class: 'points' },
          el('div', {}, icon('lock'), el('div', {}, el('b', {}, t('team_connect.server_sees_nothing')), el('span', { class: 'muted' }, t('team_connect.encrypted_on_this_pc_before')))),
          el('div', {}, icon('users'), el('div', {}, el('b', {}, t('team_connect.only_what_you_choose')), el('span', { class: 'muted' }, t('team_connect.what_you_put_in_collection')))),
          el('div', {}, icon('server'), el('div', {}, el('b', {}, t('team_connect.on_your_own_server')), el('span', { class: 'muted' }, t('team_connect.secretbroker_server_is_open_source')))),
          el('div', {}, icon('rotate'), el('div', {}, el('b', {}, t('team_connect.if_someone_leaves')), el('span', { class: 'muted' }, t('team_connect.their_collections_are_re_encrypted')))))),
      form)));
  if (link || hint) setTimeout(() => form.querySelector(link && !link.email ? 'input[type=email]' : 'input[type=password]').focus(), 50);
}

function reconnectTeam(rerender) {
  const team = state.team;
  let modal = null;
  const form = teamConnectForm({ server: team.server_url, email: team.user.email, mode: 'login', lockMode: true,
    onDone: () => { modal.close(); rerender(); } });
  modal = openModal({ title: t('common.sign_in_again'), body: form });
}

// An invite link the app was opened with (secretbroker://join?…, see app.py): fill in the team form.
window.onJoinLink = async () => {
  const link = await api().take_join_link();
  if (!link) return;
  state.joinLink = link;
  if (state.screen === 'main') applyJoinLink();
};

function applyJoinLink() {
  const link = state.joinLink;
  if (!link) return;
  if (state.team && state.team.connected) {
    state.joinLink = null;
    toast(t('apply_join_link.this_pc_already_has_team', { email: state.team.user.email, value: link.email || t('team.another_account'), host: hostOf(link.server) }), 'error');
    return;
  }
  state.view = 'team';
  renderMain();
}

// ----------------------------------------------------------------------- settings

// ----------------------------------------------------------------------- browser extension (Ajustes › Navegador)

const EXTENSION_STEPS = {
  chromium: (name, folder) => [
    [t('extension_steps.open_extensions_page', { name }), 'open'],
    [t('extension_steps.turn_on_developer_mode', { value: name === 'Edge' ? t('extension_steps.in_left_menu') : t('extension_steps.top_right') })],
    [t('extension_steps.click_load_unpacked_and_choose'), 'folder'],
    [t('extension_steps.pin_secretbroker_icon_toolbar_open', { name })],
  ],
  firefox: () => [
    [t('extension_steps.open_firefox_debugging_add_ons'), 'open'],
    [t('extension_steps.click_load_temporary_add_on'), 'folder'],
    [t('extension_steps.in_extensions_button_on_toolbar')],
  ],
};

// The browsers the install dialog offers: the ones on this PC (all of them if none is found), and Firefox always,
// with a note when it isn't installed. Ajustes names the same ones, so the two never disagree.
function extensionBrowsers(info) {
  const installed = info.browsers.filter((b) => b.installed);
  const choices = installed.length ? [...installed] : [...info.browsers];
  const firefox = info.browsers.find((b) => b.id === 'firefox');
  if (firefox && !choices.includes(firefox)) choices.push(firefox);
  return { choices, installed: installed.length ? installed : choices };
}

function extensionInstallModal(info, initial) {
  const { choices } = extensionBrowsers(info);
  const anyInstalled = info.browsers.some((b) => b.installed);
  let current = choices.find((b) => b.id === initial) || choices[0];
  const tabs = el('div', { class: 'segmented' });
  const steps = el('ol', { class: 'install-steps' });
  const folder = info.extension_dir;
  const draw = () => {
    tabs.replaceChildren(choices.map((b) => el('button', { type: 'button', class: `${b.id === current.id ? 'active' : ''} ${anyInstalled && !b.installed ? 'not-installed' : ''}`,
      title: anyInstalled && !b.installed ? t('extension_install_modal.not_installed', { name: b.name }) : null,
      onclick: () => { current = b; draw(); } }, b.name)));
    const missing = anyInstalled && !current.installed;
    const recipe = current.id === 'firefox' ? EXTENSION_STEPS.firefox() : EXTENSION_STEPS.chromium(current.name, folder);
    steps.replaceChildren(recipe.map(([text, extra]) => el('li', {}, el('div', {}, text),
      extra === 'open' ? el('button', { class: 'btn', disabled: missing, onclick: async () => {
        if (!await api().open_browser_page(current.id)) toast(t('extension_install_modal.wasn_found_on_this_pc', { name: current.name }), 'error');
      } }, icon('external', 'sm'), current.id === 'firefox' ? t('extension_install_modal.open_firefox') : t('extension_install_modal.open_extensions', { name: current.name })) : null,
      extra === 'folder' ? el('div', { class: 'install-folder' },
        el('code', { class: 'selectable', title: folder }, folder || t('extension_install_modal.extension_folder_wasn_found')),
        el('button', { class: 'btn', disabled: !folder, onclick: async () => { await api().copy_text(folder); toast(t('extension_install_modal.path_copied')); } }, icon('copy', 'sm'), t('extension_install_modal.copy_path')),
        el('button', { class: 'btn', disabled: !folder, onclick: () => api().show_extension_folder() }, icon('folder', 'sm'), t('common.show'))) : null)));
    note.replaceChildren(icon('info', 'sm'), el('span', {}, missing
      ? [el('b', {}, t('extension_install_modal.not_installed', { name: current.name })), ' ',
        current.id === 'firefox' ? t('extension_install_modal.firefox_once_installed') : t('extension_install_modal.once_installed')]
      : current.id === 'firefox'
        ? t('extension_install_modal.firefox_removes_temporary_add_ons')
        : t('extension_install_modal.may_warn_at_startup_that', { name: current.name })));
    // Not installed: say so first, and show the steps for later, dimmed.
    steps.classList.toggle('for-later', missing);
    holder.replaceChildren(...(missing ? [note, steps] : [steps, note]));
  };
  const note = el('div', { class: 'warning subtle' });
  const holder = el('div', { class: 'install-body' });
  draw();
  const modal = openModal({
    title: t('common.install_extension'),
    lead: glyph('web_login'),
    body: [
      el('p', { class: 'muted' }, t('extension_install_modal.fills_in_your_passwords_in')),
      choices.length > 1 ? tabs : null, holder],
    footer: [el('div', { class: 'spacer' }), el('button', { class: 'btn primary', onclick: () => modal.close() }, t('common.done'))],
  });
}

function browserSettingsGroup() {
  const group = el('div', { class: 'settings-group' }, el('h3', { class: 'muted' }, t('common.browser')),
    setting(t('browser_settings_group.browser_extension'), t('browser_settings_group.checking'), null));
  const draw = async () => {
    const response = await api().browser_info();
    if (!response.ok) return;
    const info = response.result;
    const paired = info.paired || [];
    const installButton = el('button', { class: `btn ${paired.length ? '' : 'primary'}`, onclick: () => extensionInstallModal(info) },
      paired.length ? t('browser_settings_group.add_another_browser') : t('common.install_extension'));
    const summary = paired.length
      ? t('browser_settings_group.connected_in_fills_in_username', { names: listJoin([...new Set(paired.map((b) => b.name))]) })
      : t('browser_settings_group.fills_in_passwords_in_names', { names: listJoin(extensionBrowsers(info).installed.map((b) => b.name)) });
    const rows = paired.map((b) => el('div', { class: 'setting browser-row' },
      el('div', { class: 'meta' }, el('h3', { class: 'with-icon' }, icon('globe', 'sm'), b.name),
        el('p', {}, b.last_seen ? t('browser_settings_group.connected_used', { when: whenText(b.last_seen) }) : t('browser_settings_group.connected_on', { value: fmtDate(b.created, { day: 'numeric', month: 'long' }) }))),
      el('div', { class: 'control' }, el('button', { class: 'btn', onclick: () => confirmModal({
        title: t('browser_settings_group.disconnect', { name: b.name }), text: t('browser_settings_group.won_be_able_fill_in'),
        action: t('common.disconnect'), onConfirm: async () => {
          const result = await api().call('browser_forget', { id: b.id });
          if (!result.ok) { toast(result.error, 'error'); return false; }
          toast(t('browser_settings_group.disconnected', { name: b.name }));
          draw();
          return true;
        } }) }, t('common.disconnect')))));
    group.replaceChildren(el('h3', { class: 'muted' }, t('common.browser')),
      setting(t('browser_settings_group.browser_extension'), summary, paired.length
        ? el('div', { style: 'display:flex;gap:12px;align-items:center' }, el('span', { class: 'state-text ok' }, icon('check', 'sm'), t('browser_settings_group.connected')), installButton)
        : installButton),
      ...rows,
      setting(t('browser_settings_group.keyboard_shortcut'), t('browser_settings_group.shortcuts_text'), null));
  };
  draw();
  return group;
}

// A browser asking to connect (from the extension's «Conectar»): one click here, comparing the code.
let pairingModal = null;
async function pollBrowserPairing() {
  const pending = (state.status && state.status.browser_pairing) || [];
  if (pairingModal && !pending.some((r) => r.id === pairingModal.id)) { pairingModal.modal.close(); pairingModal = null; }
  if (pairingModal || !pending.length || state.approvalOpen) return;
  const request = pending[0];
  const connect = el('button', { class: 'btn primary' }, t('common.connect'));
  const deny = el('button', { class: 'btn' }, t('poll_browser_pairing.reject'));
  const modal = openModal({
    title: t('poll_browser_pairing.connect', { name: request.name }),
    lead: glyph('web_login'),
    body: [
      el('p', { class: 'muted' }, t('poll_browser_pairing.will_be_able_fill_in', { name: request.name })),
      el('div', { class: 'pair-code' }, el('span', { class: 'muted small' }, t('poll_browser_pairing.check_that_extension_shows_this')),
        el('div', { class: 'code' }, `${request.code.slice(0, 3)} ${request.code.slice(3)}`)),
      el('div', { class: 'warning subtle' }, icon('info', 'sm'), el('span', {}, t('poll_browser_pairing.if_you_didn_just_click')))],
    footer: [el('div', { class: 'spacer' }), deny, connect],
    onClose: () => { if (pairingModal && pairingModal.id === request.id) pairingModal = null; },
  });
  pairingModal = { id: request.id, modal };  // the extension's «Conectar» already brought the app forward (open_app)
  deny.addEventListener('click', async () => {
    await api().call('browser_pair_answer', { id: request.id, accept: false });
    modal.close();
  });
  connect.addEventListener('click', async () => {
    busy(connect, true);
    const result = await withProof((p) => api().call('browser_pair_answer', { id: request.id, accept: true }, p), t('poll_browser_pairing.connect_2', { name: request.name }));
    busy(connect, false);
    if (result.ok) { modal.close(); toast(t('poll_browser_pairing.connected', { name: request.name })); if (state.view === 'settings') renderView(); }
    else if (result.code !== 'cancelled') toast(result.error, 'error');
  });
}

// The editor's «Navegador» section of a web login: more addresses, and how strictly they match.
const AUTOFILL_MATCH = localized(() => ([['domain', t('autofill.this_website_and_its_subdomains')], ['host', t('autofill.only_this_exact_address')], ['never', t('common.never')]]));

function autofillEditor(entry) {
  const autofill = (entry && entry.autofill) || {};
  const sites = el('textarea', { class: 'input mono', rows: 2, spellcheck: 'false', placeholder: 'https://login.ejemplo.com\nejemplo.es' },
    (autofill.sites || []).join('\n'));
  const match = el('select', { class: 'input' }, AUTOFILL_MATCH.map(([value, label]) => el('option', { value }, label)));
  match.value = autofill.match || 'domain';
  const node = el('details', { class: 'advanced' },
    el('summary', {}, el('span', { class: 'chev' }, icon('chevronRight', 'sm')), t('common.browser'),
      el('span', { class: 'hint' }, t('autofill_editor.where_filled_in'))),
    el('div', { class: 'inner' },
      el('div', { class: 'field' }, el('label', {}, t('autofill_editor.fill_in_on')), match,
        el('div', { class: 'help' }, t('autofill_editor.with_subdomains_one_for_example'))),
      el('div', { class: 'field' }, el('label', {}, t('autofill_editor.other_addresses'), el('span', { class: 'req' }, t('common.optional_suffix'))), sites,
        el('div', { class: 'help' }, t('autofill_editor.besides_web_address_above_one')))));
  if (autofill.sites && autofill.sites.length || (autofill.match && autofill.match !== 'domain')) node.open = true;
  return {
    node,
    value: () => {
      const list = sites.value.split('\n').map((line) => line.trim()).filter(Boolean);
      return list.length || match.value !== 'domain' ? { sites: list, match: match.value } : null;
    },
  };
}

function setting(title, description, control) {
  return el('div', { class: 'setting' }, el('div', { class: 'meta' }, el('h3', {}, title), el('p', {}, description)),
    control ? el('div', { class: 'control' }, control) : null);
}

function renderSettings(content) {
  const status = state.status;
  const helloSupported = state.info.hello_supported;

  const helloControl = !helloSupported
    ? el('span', { class: 'state-text' }, t('settings.not_available_on_this_pc'))
    : status.hello_enrolled
      ? el('div', { style: 'display:flex;gap:12px;align-items:center' }, el('span', { class: 'state-text ok' }, icon('check', 'sm'), t('settings.on')),
        el('button', { class: 'btn', onclick: async () => {
          const result = await withProof((p) => api().disable_hello(p), t('settings.turn_off_windows_hello'));
          if (result.ok) { toast(t('common.windows_hello_turned_off')); await refreshStatus(); renderView(); } else if (result.code !== 'cancelled') toast(result.error, 'error');
        } }, t('settings.turn_off')))
      : el('button', { class: 'btn primary', onclick: async () => {
        const proof = await askProof(t('settings.turn_on_windows_hello_first'));
        if (!proof || proof === 'hello') return;
        const result = await api().enroll_hello(proof);
        if (result.ok) { toast(t('common.windows_hello_turned_on')); await refreshStatus(); renderView(); } else if (result.code !== 'hello_cancelled') toast(result.error, 'error');
      } }, t('common.turn_on'));

  const lockSelect = el('select', { class: 'input' },
    [[15, tn('time.minutes', 15)], [30, tn('time.minutes', 30)], [60, tn('time.hours', 1)], [240, tn('time.hours', 4)], [0, t('common.never')]].map(([v, label]) => el('option', { value: v }, label)));
  lockSelect.value = String(status.auto_lock_minutes || 0);
  lockSelect.addEventListener('change', async () => {
    const minutes = Number(lockSelect.value);
    const result = await withProof((p) => api().call('set_settings', { settings: { auto_lock_minutes: minutes } }, p), t('settings.change_automatic_lock'));
    if (result.ok) { toast(t('common.saved_2')); await refreshStatus(); } else { lockSelect.value = String(status.auto_lock_minutes || 0); if (result.code !== 'cancelled') toast(result.error, 'error'); }
  });

  const sessionToggle = el('input', { type: 'checkbox', checked: !!(status.session_unlock && state.info.session_unlock_here) });
  sessionToggle.addEventListener('change', async () => {
    const result = sessionToggle.checked
      ? await withProof((p) => api().enable_session_unlock(p), t('settings.open_vault_with_your_windows'))
      : await api().disable_session_unlock();
    if (result.ok) {
      state.info.session_unlock_here = sessionToggle.checked;
      toast(sessionToggle.checked ? t('settings.will_open_when_you_sign') : t('settings.off'));
      await refreshStatus(); renderView();
    } else { sessionToggle.checked = !sessionToggle.checked; if (result.code !== 'cancelled') toast(result.error, 'error'); }
  });
  const backupSlot = el('div', { class: 'settings-group' }, el('h3', { class: 'muted' }, t('common.backup_copy')));
  renderBackup(backupSlot);
  const startToggle = el('input', { type: 'checkbox', checked: !!state.info.start_with_windows });
  startToggle.addEventListener('change', async () => {
    await api().set_start_with_windows(startToggle.checked);
    state.info.start_with_windows = startToggle.checked;
    toast(t('common.saved_2'));
  });

  const approvalSelect = el('select', { class: 'input' },
    [[24, tn('time.hours', 24)], [8, tn('time.hours', 8)], [0, t('common.until_i_lock')]].map(([v, label]) => el('option', { value: v }, label)));
  approvalSelect.value = String(status.approval_hours ?? 24);
  approvalSelect.addEventListener('change', async () => {
    const hours = Number(approvalSelect.value);
    const result = await withProof((p) => api().call('set_settings', { settings: { approval_hours: hours } }, p), t('settings.change_how_long_approvals_last'));
    if (result.ok) { toast(t('common.saved_2')); await refreshStatus(); } else { approvalSelect.value = String(status.approval_hours ?? 24); if (result.code !== 'cancelled') toast(result.error, 'error'); }
  });

  const settingSelect = (key, options, fallback, reason) => {
    const select = el('select', { class: 'input' }, options.map(([v, label]) => el('option', { value: v }, label)));
    select.value = String(status[key] ?? fallback);
    select.addEventListener('change', async () => {
      const result = await withProof((p) => api().call('set_settings', { settings: { [key]: Number(select.value) } }, p), reason);
      if (result.ok) { toast(t('common.saved_2')); await refreshStatus(); } else { select.value = String(status[key] ?? fallback); if (result.code !== 'cancelled') toast(result.error, 'error'); }
    });
    return select;
  };
  const usesSelect = settingSelect('max_uses_per_hour', [[50, t('settings.50_uses_in_hour')], [100, t('settings.100_uses_in_hour')], [500, t('settings.500_uses_in_hour')], [0, t('common.never')]], 100, t('settings.change_usage_limit'));
  const reminderSelect = settingSelect('rotate_reminder_days', [[90, tn('time.months', 3)], [180, tn('time.months', 6)], [365, t('common.1_year')], [0, t('common.never')]], 365, t('settings.change_reminder'));
  const checkControl = checkEveryControl(status.check_every_hours ?? 24, false, async () => {
    let hours;
    try { hours = checkControl.value(); } catch (error) { toast(error.message, 'error'); return; }
    const result = await withProof((p) => api().call('set_settings', { settings: { check_every_hours: hours } }, p), t('settings.change_how_often_keys_are'));
    if (result.ok) { toast(t('common.saved_2')); await refreshStatus(); } else if (result.code !== 'cancelled') toast(result.error, 'error');
  });
  checkControl.select.style.width = '';  // the same width as the other selects here

  const autoScan = el('input', { type: 'checkbox', checked: state.info.prefs.auto_scan !== false });
  autoScan.addEventListener('change', async () => {
    state.info.prefs.auto_scan = autoScan.checked;
    await api().set_pref('auto_scan', autoScan.checked);
    toast(t('common.saved_2'));
  });
  const folderList = el('div', { class: 'folder-list' });
  const renderFolders = async () => {
    const folders = await api().scan_folders();
    folderList.replaceChildren(
      folders.detected.map((f) => el('div', { class: 'folder' }, el('span', { class: 'path', title: f }, f), el('span', { class: 'faint' }, t('settings.claude_code')))),
      folders.extra.map((f) => el('div', { class: 'folder' }, el('span', { class: 'path', title: f }, f),
        el('button', { class: 'btn icon-only', title: t('common.remove'), onclick: async () => {
          await api().set_pref('scan_folders', folders.extra.filter((x) => x !== f));
          renderFolders();
        } }, icon('x', 'sm')))));
  };
  renderFolders();
  const addFolder = el('button', { class: 'btn', onclick: async () => { if (await api().add_scan_folder()) renderFolders(); } }, t('settings.add_folder'));

  const palettes = el('div', { class: 'segmented' }, PALETTES.map(([id, label, color]) => el('button', {
    class: (state.info.prefs.palette || DEFAULT_PALETTE) === id ? 'active' : '',
    onclick: async () => { state.info.prefs.palette = id; applyPalette(id); await api().set_pref('palette', id); renderView(); },
  }, el('span', { style: `display:inline-block;width:10px;height:10px;border-radius:50%;background:${color};margin-right:7px;vertical-align:-1px` }), label)));

  const ai = state.info.integrations || {};
  const claudeControl = ai.claude_code === 'connected'
    ? el('span', { class: 'state-text ok' }, icon('check', 'sm'), t('common.connected'))
    : ai.claude_code === 'missing'
      ? el('span', { class: 'state-text' }, t('common.not_installed'))
      : el('button', { class: 'btn', onclick: async () => {
        const result = await api().connect_claude_code();
        if (result.ok) { toast(t('settings.connected_restart_claude_code')); state.info.integrations.claude_code = 'connected'; renderView(); } else toast(result.error, 'error');
      } }, t('common.connect'));
  const desktopControl = ai.claude_desktop === 'connected'
    ? el('span', { class: 'state-text ok' }, icon('check', 'sm'), t('common.connected'))
    : ai.claude_desktop === 'missing'
      ? el('span', { class: 'state-text' }, t('common.not_installed'))
      : el('button', { class: 'btn', onclick: async () => {
        const result = await api().connect_claude_desktop();
        if (result.ok) { toast(t('settings.connected_restart_claude_desktop')); state.info.integrations.claude_desktop = 'connected'; renderView(); } else toast(result.error, 'error');
      } }, t('common.connect'));

  content.replaceChildren(
    el('div', { class: 'content-header' }, el('h1', {}, t('common.settings'))),
    el('div', { class: 'content-body' }, el('div', { class: 'settings' },
      el('div', { class: 'settings-group' }, el('h3', { class: 'muted' }, t('settings.security')),
        ['windows', 'macos'].includes(state.info.os || 'windows') ? setting(t('common.windows_hello'), t('settings.unlock_and_show_passwords_with'), helloControl) : null,
        setting(t('common.master_password'), t('settings.if_you_forget_you_can'),
          el('button', { class: 'btn', onclick: () => changeMasterPassword(false) }, t('common.change'))),
        setting(t('common.open_with_my_windows_session'), t('settings.vault_opens_by_itself_when'), sessionToggle),
        setting(t('settings.automatic_lock'), status.session_unlock
          ? t('settings.locks_vault_after_while_unused')
          : t('settings.locks_vault_after_while_unused_2'), lockSelect),
        setting(t('settings.ask_again_if_used_lot'), t('settings.even_if_you_approved_credential'), usesSelect),
        setting(t('settings.remind_me_rotate_keys'), t('settings.flags_keys_older_than_this'), reminderSelect),
        setting(t('settings.check_that_keys_work'), t('settings.tests_each_key_with_read'), checkControl.node),
        setting(t('settings.remember_approvals'), t('settings.when_you_allow_credential_ai'), approvalSelect),
        setting(t('settings.isolation'), status.isolated
          ? t('settings.service_uses_its_own_windows')
          : t('settings.service_uses_your_windows_account'),
        el('span', { class: `state-text ${status.isolated ? 'ok' : 'warn'}` }, status.isolated ? t('common.active') : t('settings.off')))),
      el('div', { class: 'settings-group' }, el('h3', { class: 'muted' }, t('common.ai')),
        setting(t('settings.claude_code'), t('settings.lets_claude_code_use_your'), claudeControl),
        setting(t('settings.claude_desktop'), t('settings.lets_claude_desktop_app_use'), desktopControl),
        setting(t('common.ai_access'), status.session_grants
          ? tn('settings.approved_now', status.session_grants)
          : t('settings.what_ai_can_use_without'),
        el('button', { class: 'btn', onclick: () => { state.view = 'access'; renderMain(); } }, t('settings.view')))),
      el('div', { class: 'settings-group' }, el('h3', { class: 'muted' }, t('settings.app')),
        setting(t('settings.start_with_windows'), t('settings.secretbroker_stays_next_clock_ready'), startToggle)),
      backupSlot,
      el('div', { class: 'settings-group' }, el('h3', { class: 'muted' }, t('move_pc.group')),
        setting(t('move_pc.settings_title'), t('move_pc.settings_help'), el('button', { class: 'btn', onclick: moveComputerGuide }, t('move_pc.open')))),
      importExportGroup(),  // personal.js
      browserSettingsGroup(),
      el('div', { class: 'settings-group' }, el('h3', { class: 'muted' }, t('settings.copies_your_keys')),
        setting(t('settings.search_for_copies_when_unlocking'), t('settings.searches_this_pc_for_copies'), autoScan),
        setting(t('settings.project_folders'), t('settings.they_re_checked_along_with'), addFolder),
        folderList),
      el('div', { class: 'settings-group' }, el('h3', { class: 'muted' }, t('settings.appearance')),
        setting(t('settings.language'), t('settings.language_help'), languageSelect(() => renderMain())),
        setting(t('settings.color'), t('settings.light_or_dark_theme_follows'), palettes)),
      el('div', { class: 'settings-group' }, el('h3', { class: 'muted' }, t('settings.updates')),
        setting(t('settings.version', { version: state.info.version }), updateSummary(), el('button', { class: 'btn', onclick: async (event) => {
          busy(event.currentTarget, true);
          await checkUpdate(true);
          renderView();
          if (state.update && state.update.available) openUpdate();
          else if (state.update && !state.update.error) toast(t('settings.you_have_latest_version'));
        } }, t('settings.check_now')))),
      el('p', { class: 'faint small' }, t('settings.secretbroker', { version: state.info.version, owner: status.owner })))));
}

// ----------------------------------------------------------------------- backups

async function renderBackup(slot) {
  const info = await api().backup_info();
  const title = slot.firstChild;
  const run = async (button, fn, done) => {
    busy(button, true);
    const result = await fn();
    busy(button, false);
    if (result.ok) { toast(done); renderBackup(slot); } else if (result.code !== 'cancelled') toast(result.error, 'error');
  };
  const nowButton = el('button', { class: 'btn' }, t('backup.back_up_now'));
  nowButton.addEventListener('click', () => run(nowButton, () => api().backup_now(), t('backup.backup_saved')));
  const folderButton = el('button', { class: 'btn' }, info.folder ? t('backup.change_folder') : t('backup.choose_another_folder'));
  folderButton.addEventListener('click', () => run(folderButton, () => api().choose_backup_folder(), t('backup.backup_saved')));
  const enableButton = el('button', { class: 'btn primary' }, t('common.turn_on'));
  enableButton.addEventListener('click', () => run(enableButton, () => api().set_backup_folder(info.suggested), t('backup.backups_turned_on')));
  slot.replaceChildren(title,
    info.folder
      ? setting(t('backup.automatic_daily_backup'), t('backup.in_last_10_are_kept', { folder: info.folder, value: info.last ? t('backup.last', { time: formatTime(info.last) }) : '' }),
        el('div', { style: 'display:flex;gap:8px' }, nowButton, folderButton))
      : setting(t('backup.automatic_daily_backup'), t('backup.saves_encrypted_vault_every_day', { suggested: info.suggested }),
        el('div', { style: 'display:flex;gap:8px' }, enableButton, folderButton)),
    setting(t('common.restore_backup'), t('backup.replaces_vault_with_backup_you'),
      el('button', { class: 'btn', onclick: () => restoreBackup(async () => { await loadEntries(); renderMain(); }) }, t('backup.restore'))));
}

async function restoreBackup(onDone) {
  const path = await api().pick_backup_file();
  if (!path) return;
  const pw = passwordInput({ placeholder: t('restore_backup.master_password_backup'), autocomplete: 'current-password' });
  const errorText = el('div', { class: 'error-text' });
  const button = el('button', { class: 'btn primary' }, t('restore_backup.restore'));
  const modal = openModal({
    title: t('common.restore_backup'),
    body: [el('p', { class: 'muted small selectable' }, path), el('div', { class: 'field' }, el('label', {}, t('common.master_password')), pw), errorText],
    footer: [el('button', { class: 'btn', onclick: () => modal.close() }, t('common.cancel')), button],
  });
  const submit = async () => {
    errorText.textContent = '';
    busy(button, true);
    const restoring = state.status.state === 'no_vault'
      ? await api().restore_backup(path, pw.input.value)
      : await withProof((p) => api().restore_backup(path, pw.input.value, p), t('restore_backup.replace_current_vault'));
    busy(button, false);
    if (!restoring.ok) { if (restoring.code !== 'cancelled') errorText.textContent = restoring.error; return; }
    modal.close();
    toast(t('common.backup_restored'));
    onDone();
  };
  button.addEventListener('click', submit);
  pw.input.addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });
  setTimeout(() => pw.input.focus(), 50);
}

// ----------------------------------------------------------------------- updates

async function checkUpdate(force) {
  const result = await api().update_status(force);
  if (result.ok) state.update = result.result;
  else if (force) toast(result.error, 'error');
  renderUpdateSlot();
}

function updateSummary() {
  const u = state.update;
  if (!u) return t('update_summary.app_checks_github_for_new');
  if (u.error) return t('update_summary.couldn_check', { error: u.error });
  if (u.available) return t('update_summary.there_new_version', { latest: u.latest });
  return t('update_summary.you_have_latest_version');
}

function renderUpdateSlot() {
  const slot = document.getElementById('update-slot');
  if (!slot) return;
  const u = state.update;
  slot.replaceChildren(u && u.available
    ? el('button', { class: 'update-pill', onclick: openUpdate }, icon('sparkles', 'sm'), t('update_slot.update', { latest: u.latest }))
    : '');
}

function openUpdate() {
  const u = state.update;
  const install = el('button', { class: 'btn primary' }, t('common.refresh'));
  const errorText = el('div', { class: 'error-text' });
  const modal = openModal({
    title: t('open_update.secretbroker', { latest: u.latest }),
    body: el('div', {},
      u.notes ? el('p', { class: 'notes selectable muted' }, u.notes) : null,
      el('p', { class: 'help' }, t('open_update.downloaded_from_github_and_only'),
        t('open_update.windows_will_ask_for_administrator')),
      errorText),
    footer: [
      el('button', { class: 'btn', onclick: () => api().open_link(u.url) }, t('open_update.view_on_github')),
      el('button', { class: 'btn', onclick: () => modal.close() }, t('common.later')),
      install,
    ],
  });
  install.addEventListener('click', async () => {
    errorText.textContent = '';
    busy(install, true);
    const result = await api().install_update();
    busy(install, false);
    if (!result.ok) { if (result.code !== 'cancelled') errorText.textContent = result.error; return; }
    modal.close();
    toast(t('open_update.installing_update_app_will_reopen'));
  });
}

function changeMasterPassword(recovering) {
  const pw = passwordInput();
  const confirm = passwordInput();
  const errorText = el('div', { class: 'error-text' });
  const button = el('button', { class: 'btn primary' }, t('common.change'));
  button.addEventListener('click', async () => {
    errorText.textContent = '';
    if (pw.input.value.length < 12) { errorText.textContent = t('change_master_password.needs_at_least_12_characters'); return; }
    if (pw.input.value !== confirm.input.value) { errorText.textContent = t('common.two_passwords_don_match'); return; }
    busy(button, true);
    const result = await withProof((p) => api().call('change_master_password', { new_password: pw.input.value }, p), t('change_master_password.change_master_password'));
    busy(button, false);
    if (!result.ok) { if (result.code !== 'cancelled') errorText.textContent = result.error; return; }
    modal.close();
    toast(t('common.master_password_changed'));
  });
  const modal = openModal({
    title: recovering ? t('change_master_password.choose_new_master_password') : t('change_master_password.change_master_password_2'),
    body: [
      recovering ? el('p', { class: 'muted' }, t('change_master_password.you_signed_in_with_windows')) : null,
      el('div', { class: 'field' }, el('label', {}, t('change_master_password.new_master_password')), pw, strengthMeter(pw.input)),
      el('div', { class: 'field' }, el('label', {}, t('common.repeat')), confirm),
      errorText],
    footer: [el('button', { class: 'btn', onclick: () => modal.close() }, t('common.cancel')), button],
  });
  setTimeout(() => pw.input.focus(), 50);
}

// ======================================================================= drafts (prepared by the AI)

// The secret fields still missing in a draft: the only thing the user has to add.
function draftInputs(entry) {
  return activeSpecs(entry.template, entry.fields).filter((s) => s.secret && s.required).map((spec) => {
    const group = spec.kind === 'multiline'
      ? { input: el('textarea', { class: 'input mono', rows: 5, spellcheck: 'false' }) }
      : passwordInput({ placeholder: t('draft_inputs.paste_key_here') });
    return { spec, input: group.input, node: el('div', { class: 'field' }, el('label', {}, spec.label), group.input.tagName === 'TEXTAREA' ? group.input : group) };
  });
}

async function saveDraftSecret(entry, inputs, button, errorText) {
  const fields = Object.fromEntries(inputs.map(({ spec, input }) => [spec.name, input.value.trim()]));
  if (Object.values(fields).some((v) => !v)) { errorText.textContent = t('save_draft_secret.paste_key'); return false; }
  busy(button, true);
  const result = await withProof((p) => api().call('complete_draft', { id: entry.id, fields }, p), t('save_draft_secret.save_key', { name: entry.name }));
  busy(button, false);
  if (!result.ok) { if (result.code !== 'cancelled') errorText.textContent = result.error; return false; }
  await loadEntries();
  toast(t('save_draft_secret.key_saved'));
  return true;
}

function draftSection(entry, onSaved) {
  const inputs = draftInputs(entry);
  const errorText = el('div', { class: 'error-text' });
  const save = el('button', { class: 'btn primary' }, t('common.save_key'));
  save.addEventListener('click', async () => { if (await saveDraftSecret(entry, inputs, save, errorText)) onSaved(); });
  return el('div', { class: 'section draft-box' },
    el('h3', {}, t('common.key_missing')),
    el('p', { class: 'help' }, t('draft_section.ai_prepared_this_credential_paste')),
    inputs.map((i) => i.node), errorText, el('div', { style: 'margin-top:8px' }, save));
}

async function pollDrafts() {
  const count = state.status.drafts || 0;
  const known = state.knownDrafts;
  state.knownDrafts = count;
  if (known === undefined || count <= known) return;
  await refreshInPlace();
  const drafts = state.entries.filter((e) => e.draft);
  const newest = drafts.sort((a, b) => String(b.updated).localeCompare(String(a.updated)))[0];
  if (newest && !state.approvalOpen && !openOverlays().length) showDraft(newest);
}

function showDraft(entry) {
  const inputs = draftInputs(entry);
  const errorText = el('div', { class: 'error-text' });
  const save = el('button', { class: 'btn primary' }, t('common.save_key'));
  const provider = entry.provider;
  const modal = openModal({
    title: t('show_draft.ai_prepared_credential'),
    body: el('div', { class: 'request' },
      el('div', { class: 'request-who' }, glyph(entry.template),
        el('div', {}, el('div', { style: 'font-weight:600' }, entry.name), el('div', { class: 'muted small' }, TEMPLATES[entry.template].label))),
      entry.description ? el('p', { class: 'notes muted' }, entry.description) : null,
      el('div', { class: 'section' }, el('h3', {}, t('show_draft.ai_will_be_able')), describePermissions(entry)),
      inputs.map((i) => i.node),
      provider && provider.links.length ? el('div', { class: 'section' }, el('h3', {}, t('show_draft.where_do_i_get_key', { provider: provider.provider })), linkList(provider.links)) : null,
      errorText),
    footer: [el('button', { class: 'btn', onclick: () => modal.close() }, t('common.later')), save],
  });
  save.addEventListener('click', async () => {
    if (await saveDraftSecret(entry, inputs, save, errorText)) { modal.close(); state.selected = entry.id; renderMain(); }
  });
  api().focus();
  setTimeout(() => inputs[0] && inputs[0].input.focus(), 50);
}

// ======================================================================= approvals
//
// The moment the product is about: an AI app wants to use a key. Who asks and from where, what for, which
// credential, exactly what it will do (the host stands out), and two ways to say yes (the timed one recommended). Several
// requests queue ("1 de 3"); «Decidir luego» folds them into a banner instead of popping up again.

// approval_hours (Ajustes) → [button, how long, in a sentence].
const APPROVAL_SPANS = localized(() => ({ 24: [t('approval.allow_for_24_hours'), tn('approval.for_hours', 24)], 8: [t('approval.allow_for_8_hours'), tn('approval.for_hours', 8)],
  0: [t('common.until_i_lock'), t('approval.until_you_lock_vault')] }));
const APPROVAL_TITLES = localized(() => ({ request_access: t('approval_title.asks_for_access_for_task'), delete: t('approval_title.proposes_deleting_credential'), rotate: t('approval_title.wants_rotate_key'),
  import_env: t('approval_title.wants_import_keys_from_env'), edit: t('approval_title.wants_change_credential'), draft: t('approval_title.wants_change_credential') }));

async function pollApprovals() {
  const result = await api().call('pending_approvals');
  if (!result.ok) return;
  const approvals = [...result.result].sort((a, b) => String(a.created).localeCompare(String(b.created)));
  const ids = new Set(approvals.map((a) => a.id));
  const gone = [...(state.approvalSeen || [])].filter((id) => !ids.has(id));
  state.approvalSeen = ids;
  state.approvals = approvals;
  state.approvalDeferred = new Set([...(state.approvalDeferred || [])].filter((id) => ids.has(id)));
  if (gone.length) {
    // Answered here or elsewhere, or nobody answered in time: only the last one is news to the user.
    const expired = await api().call('expired_approvals');
    const shown = state.expiredShown || (state.expiredShown = new Set());
    const late = expired.ok ? expired.result.filter((e) => gone.includes(e.id) && !shown.has(e.id)) : [];
    late.forEach((e) => shown.add(e.id));
    if (late.length) toast(t('approval.ai_request_expired_ai_got'), 'error');
  }
  if (state.approvalOpen && !ids.has(state.approvalOpen.id)) state.approvalOpen.modal.close();
  if (state.approvalOpen) state.approvalOpen.update();
  else {
    const next = approvals.find((a) => !state.approvalDeferred.has(a.id));
    if (next) showApproval(next);
  }
  renderApprovalBanner();
}

function approvalSpan() {
  return APPROVAL_SPANS[(state.status || {}).approval_hours ?? 24] || APPROVAL_SPANS[24];
}

function clientOf(request) {
  return (request.client && request.client.name) || t('client_of.ai');
}

function secondsLeft(request) {
  return request.expires ? Math.max(0, Math.round((new Date(request.expires) - Date.now()) / 1000)) : null;
}

function clock(seconds) {
  return `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, '0')}`;
}

function looksDestructive(detail) {
  return /\b(rm\s+-[a-z]*[rf]|rmdir|del\s|drop\s+(table|database|schema)|truncate|delete\s+from|shutdown|reboot|mkfs|dd\s+if=|chmod\s+-R|chown\s+-R|kill(all)?\s|systemctl\s+(stop|disable)|git\s+push\s+.*--force|^DELETE\s)/im.test(detail);
}

// The exact action, in monospace, with the host it goes to marked.
function actionBlock(request) {
  const detail = request.action === 'edit' ? aiEditLines(request).join('\n') : request.detail || '';
  const host = request.host;
  const at = host ? detail.indexOf(host) : -1;
  const lineEnd = detail.indexOf('\n');
  const content = at >= 0 && (lineEnd < 0 || at < lineEnd)
    ? [detail.slice(0, at), el('mark', { class: 'host', title: t('action_block.where_goes') }, host), detail.slice(at + host.length)]
    : [detail];
  return el('div', { class: 'request-detail selectable' }, content);
}

function usageLine(request) {
  if (['request_access', 'import_env', 'draft'].includes(request.action)) return null;
  const today = request.uses_today || 0;
  const last = request.last_used ? t('usage_line.last_used_by_ai', { since: sinceText(request.last_used) }) : t('usage_line.ai_hasn_used_yet');
  return el('div', { class: 'muted small' }, today ? `${last} · ${tn('approval.times_today', today)}` : last);
}

function showApproval(request) {
  const who = clientOf(request);
  const errorText = el('div', { class: 'error-text' });
  const [spanLabel, spanText] = approvalSpan();
  let closing = false;
  const finish = () => { closing = true; modal.close(); };

  const approve = async (ids, scopeOf, button) => {
    errorText.textContent = '';
    busy(button, true);
    for (const id of ids) {
      const target = (state.approvals || []).find((a) => a.id === id) || request;
      const result = await withProof((p) => api().call('approve', { id, scope: scopeOf(target) }, p), target.strong
        ? t('show_approval.approve_ai_deleting_rotating_or') : t('show_approval.approve_using_credential'));
      if (!result.ok && result.code !== 'not_found') {
        busy(button, false);
        if (result.code !== 'cancelled') errorText.textContent = result.error;
        return;
      }
    }
    busy(button, false);
    finish();
  };
  const deny = async () => {
    await api().call('deny', { id: request.id });
    finish();
  };

  const allowOnce = request.allow_once !== false;
  const onceLabel = { edit: t('show_approval.apply_change'), draft: t('show_approval.allow'), rotate: t('show_approval.rotate_now'), delete: t('show_approval.delete'), import_env: t('common.import') }[request.action] || t('show_approval.just_this_once');
  // Two ways to say yes, side by side. Allowing for the span is the recommended one (the AI won't ask again for this
  // credential until then) and is the primary button; «Solo esta vez» stays one obvious click away, outlined.
  const both = allowOnce && request.allow_session;
  const onceButton = allowOnce ? el('button', { class: `btn ${both ? 'secondary' : 'primary'}` }, onceLabel) : null;
  if (onceButton) onceButton.addEventListener('click', () => approve([request.id], () => 'once', onceButton));
  const sessionButton = request.allow_session ? el('button', { class: 'btn primary approve-span' }, spanLabel) : null;
  if (sessionButton) sessionButton.addEventListener('click', () => approve([request.id], () => 'session', sessionButton));
  const batchButton = el('button', { class: 'btn ghost batch hidden' });
  batchButton.addEventListener('click', () => {
    const ids = sameClient().map((a) => a.id);
    approve(ids, (a) => (a.allow_session ? 'session' : 'once'), batchButton);
  });
  const sameClient = () => (state.approvals || []).filter((a) => clientOf(a) === who);

  const explain = request.allow_session ? el('p', { class: 'approval-explain' },
    el('b', {}, `«${spanLabel}»`), t('show_approval.will_be_able_use_without', { who, secret_name: request.secret_name, spanText }),
    allowOnce ? ['; ', el('b', {}, `«${onceLabel}»`), t('show_approval.only_for_this_request')] : t('show_approval.locking_manually_cancels_sooner')) : null;

  const counter = el('span', { class: 'queue-count' });
  const countdown = el('span', { class: 'countdown' });
  const bar = el('div', { class: 'countdown-bar' }, el('span'));
  const folder = request.client && request.client.folder;
  const entry = state.entries.find((e) => e.id === request.secret_id);
  const category = (TEMPLATES[request.template] || {}).icon || 'lock';
  const destructive = looksDestructive(request.detail);

  const modal = openModal({
    title: `${who} ${APPROVAL_TITLES[request.action] || t('show_approval.wants_use_credential')}`,
    lead: el('div', { class: 'client-mark', title: who }, icon('bot')),
    className: 'approval',
    closeLabel: t('show_approval.decide_later'),
    onDismiss: () => {  // «Decidir luego» or Esc: it waits in a banner, it doesn't pop up again
      state.approvalDeferred = new Set([...(state.approvalDeferred || []), ...(state.approvals || []).map((a) => a.id)]);
      finish();
      renderApprovalBanner();
    },
    body: el('div', { class: 'request' },
      el('div', { class: 'request-meta' }, counter,
        folder ? el('span', { class: 'request-folder', title: folder }, icon('folder', 'sm'), el('span', {}, folder)) : null,
        el('span', { class: 'spacer' }), countdown),
      bar,
      request.reason ? el('div', { class: 'request-reason' }, el('span', { class: 'small muted' }, t('show_approval.what_for_according_ai')), el('p', {}, request.reason))
        : el('p', { class: 'muted small' }, t('show_approval.didn_say_what_for', { who })),
      el('div', { class: `cred-card cat-${category}` }, glyph(request.template),
        el('div', { class: 'meta' }, el('div', { class: 'cred-name' }, request.secret_name),
          el('div', { class: 'muted small' }, ACTION_LABELS[request.action] || request.action,
            entry && subtitleOf(entry) ? ` · ${subtitleOf(entry)}` : '')),
        usageLine(request)),
      actionBlock(request),
      destructive ? el('div', { class: 'warning is-danger' }, icon('alert', 'sm'), t('show_approval.looks_like_deletes_stops_or')) : null,
      explain,
      errorText),
    footer: [
      el('button', { class: 'btn danger', onclick: deny }, t('show_approval.deny')),
      el('div', { class: 'spacer' }),
      batchButton, onceButton, sessionButton],
    onClose: () => {
      clearInterval(timer);
      if (state.approvalOpen && state.approvalOpen.id === request.id) state.approvalOpen = null;
      if (!closing) return;
      setTimeout(() => { if (state.screen === 'main') pollApprovals(); }, 0);  // the next one in the queue, at once
    },
  });

  const update = () => {
    const queue = state.approvals || [];
    const position = queue.findIndex((a) => a.id === request.id);
    counter.textContent = queue.length > 1 ? t('approval.position', { position: position + 1, total: queue.length }) : '';
    counter.classList.toggle('hidden', queue.length < 2);
    const batch = sameClient();
    batchButton.textContent = t('show_approval.allow_all_for_this_task', { length: batch.length });
    batchButton.classList.toggle('hidden', batch.length < 2);
  };
  const tickDown = () => {
    if (!modal.overlay.isConnected) { clearInterval(timer); return; }  // closed with all the others
    const left = secondsLeft(request);
    if (left === null) return;
    countdown.textContent = left ? t('show_approval.expires_in', { clock: clock(left) }) : t('show_approval.expiring');
    countdown.classList.toggle('urgent', left <= 20);
    bar.firstChild.style.width = `${Math.min(100, (left / 120) * 100)}%`;
  };
  const timer = setInterval(tickDown, 1000);
  update();
  tickDown();
  state.approvalOpen = { id: request.id, modal, update };
  api().focus();
}

// What is waiting while the user decides later: one line at the top, with the time left.
function renderApprovalBanner() {
  let banner = document.getElementById('approval-banner');
  const waiting = (state.approvals || []).filter((a) => (state.approvalDeferred || new Set()).has(a.id));
  if (!waiting.length || state.screen !== 'main' || state.approvalOpen) { if (banner) banner.remove(); clearInterval(state.bannerTimer); return; }
  if (!banner) {
    banner = el('div', { id: 'approval-banner', role: 'status' });
    document.body.append(banner);
  }
  const first = waiting[0];
  const time = el('span', { class: 'countdown' });
  const draw = () => {
    const left = secondsLeft(first);
    time.textContent = left === null ? '' : t('approval_banner.expires_in', { clock: clock(left) });
    time.classList.toggle('urgent', left !== null && left <= 20);
  };
  banner.replaceChildren(icon('bot', 'sm'),
    el('span', { class: 'text' }, waiting.length === 1
      ? [el('b', {}, clientOf(first)), t('approval_banner.is_waiting_for_your_answer', { secret_name: first.secret_name })]
      : [el('b', {}, t('approval_banner.ai_requests', { length: waiting.length })), t('approval_banner.waiting_for_your_answer')]),
    time,
    el('button', { class: 'btn primary', onclick: () => {
      state.approvalDeferred = new Set();
      banner.remove();
      showApproval(first);
    } }, t('common.review')));
  draw();
  clearInterval(state.bannerTimer);
  state.bannerTimer = setInterval(draw, 1000);
}
