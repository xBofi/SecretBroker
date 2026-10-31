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
// «Windows Hello» is shown only where there is a biometric proof: on macOS it reads «Touch ID» (info().biometric_label).
function osText(text) {
  const label = window.SB_OS_LABEL;
  if (!label || label === 'Windows' || !/Win|Hello|huella o cara/.test(text)) return text;
  const biometric = window.SB_BIOMETRIC_LABEL;
  if (biometric && biometric !== 'Windows Hello') {
    text = text.replace(/Windows Hello \(PIN, huella o cara\)/g, biometric).replace(/tu PIN, huella o cara/g, 'tu huella')
      .replace(/Windows Hello/g, biometric).replace(/con Hello/g, `con ${biometric}`).replace(/\(Hello\)/g, `(${biometric})`);
  }
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
      el('button', { class: 'close', type: 'button', title: 'Cerrar', 'aria-label': 'Cerrar', onclick: () => node.remove() }, icon('x', 'sm')));
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
  const toggle = el('button', { class: 'toggle', type: 'button', title: 'Mostrar' }, icon('eye', 'sm'));
  toggle.addEventListener('click', () => {
    const show = input.type === 'password';
    input.type = show ? 'text' : 'password';
    toggle.title = show ? 'Ocultar' : 'Mostrar';
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
  const label = el('div', { class: 'help' }, 'Al menos 12 caracteres. Una frase larga es fácil de recordar y difícil de adivinar.');
  input.addEventListener('input', () => {
    const level = strengthOf(input.value);
    meter.dataset.level = String(level);
    label.textContent = input.value.length < 12
      ? `Faltan ${12 - input.value.length} caracteres`
      : ['', 'Débil', 'Aceptable', 'Buena', 'Excelente'][level];
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
  return new Date(iso).toLocaleString('es-ES', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' });
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
const PALETTES = [
  ['grafito', 'Grafito', '#171717'],
  ['salvia', 'Salvia', '#0f766e'],
  ['cobalto', 'Cobalto', '#1f5fbf'],
  ['terracota', 'Terracota', '#b5441b'],
];
const ACTION_LABELS = {
  http_request: 'Petición web',
  ssh_exec: 'Comando en el servidor',
  ssh_upload: 'Subir archivo al servidor',
  ssh_download: 'Descargar archivo del servidor',
  run_command: 'Programa en este PC',
  release_env: 'Entregada a una app local',
  rotate: 'Rotada con el proveedor',
  draft: 'Preparada por la IA',
  edit: 'Cambiar la configuración',
  revoke: 'Aprobación retirada',
  request_access: 'Acceso para una tarea',
  ai_permissions: 'Permisos de la IA',
  import_env: 'Importada de un .env',
  import_file: 'Importadas de otro gestor',
  export: 'Bóveda exportada',
  restore: 'Copia restaurada',
  check: 'Comprobada',
  pause_ai: 'IA en pausa',
  resume_ai: 'IA reanudada',
  session_unlock: 'Abrir con la sesión de Windows',
  push_github_secret: 'Subida a GitHub',
  unlock: 'Desbloqueo', lock: 'Bloqueo', save: 'Guardada', delete: 'Eliminada',
  reveal: 'Secreto mostrado', create: 'Bóveda creada', enroll_hello: 'Windows Hello activado',
  remove_hello: 'Windows Hello desactivado', change_master_password: 'Contraseña maestra cambiada',
  exposure: 'Encontrada en claro', check: 'Comprobada con el proveedor',
  team_connect: 'Cuenta de equipo conectada', team_disconnect: 'Cuenta de equipo desconectada',
  share: 'Compartida con el equipo', unshare: 'Ya no se comparte', team_change: 'Cambio del equipo revisado',
  team_conflict: 'Conflicto al sincronizar', team_join: 'Invitación aceptada', team_confirm: 'Miembro confirmado',
  browser_fill: 'Rellenada en el navegador', browser_copy: 'Copiada desde el navegador', browser_save: 'Guardada desde el navegador',
  browser_pair: 'Navegador conectado', browser_forget: 'Navegador desconectado',
  team_remove: 'Miembro quitado', team_grant: 'Acceso a una colección', team_revoke: 'Acceso retirado',
  team_add: 'Llegó del equipo', team_update: 'Cambiada por el equipo', team_delete: 'Borrada por el equipo',
  team_review: 'Cambio del equipo por revisar', team_held: 'Borrados del equipo en espera',
  team_unsigned: 'Cambio sin firma descartado', team_recovery: 'Acceso de recuperación', team_resolve: 'Borrados del equipo decididos',
  team_verify_email: 'E-mail verificado',
};
const APPROVAL_LABELS = { session: 'Una vez por sesión', always: 'Siempre', never: 'Nunca' };
const AUTH_LABELS = { none: 'No añadir', header: 'En una cabecera', query: 'Como parámetro de la URL', basic: 'HTTP Basic (usuario y contraseña)' };

// ======================================================================= boot & polling

async function boot() {
  state.info = await api().info();
  window.SB_OS_LABEL = state.info.os_label;
  window.SB_BIOMETRIC_LABEL = state.info.biometric_label;
  applyPalette(state.info.prefs.palette);
  for (const t of state.info.templates.templates) TEMPLATES[t.id] = t;
  DB_ENGINES = state.info.templates.db_engines;
  document.addEventListener('keydown', onShortcut);
  await refreshStatus();
  window.onJoinLink();
  setInterval(tick, 1500);
  checkUpdate(false);
  setInterval(() => checkUpdate(false), 3 * 3600 * 1000);
}

if (window.pywebview && window.pywebview.api) boot();
else window.addEventListener('pywebviewready', boot);

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
      el('div', { class: 'auth-head' }, brand(), el('h2', {}, 'No se puede conectar con el servicio')),
      el('p', { class: 'lead' }, message || 'El servicio SecretBroker no responde.'),
      el('p', { class: 'help' }, state.info && state.info.installed
        ? 'El servicio arranca con Windows. Si acabas de instalar, espera unos segundos o reinicia el PC.'
        : 'Reintentando…'))));
}

function brand(big = false) {
  return el('div', { class: 'brand' },
    el('div', { class: `mark ${big ? 'big' : ''}` }, icon('shield', big ? 'xl' : 'sm')),
    big ? null : el('div', { class: 'brand-name' }, 'SecretBroker'));
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
    const keep = el('button', { class: 'btn' }, 'Seguir');
    const discard = el('button', { class: 'btn primary' }, 'Descartar');
    const ask = openModal({ title: question.title || '¿Descartar?', body: el('p', { class: 'muted' }, question.text || question),
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
        closeLabel ? el('button', { class: 'btn ghost close-label', onclick: dismiss, title: 'Esc' }, closeLabel)
          : el('button', { class: 'btn icon-only', onclick: dismiss, title: 'Cerrar (Esc)' }, icon('x'))),
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
    if (status.windows_password) kinds.push(['windows_password', 'Contraseña de Windows']);
    kinds.push(['master_password', 'Contraseña maestra']);
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
        ? 'La que usas para iniciar sesión en Windows, no el PIN.'
        : 'La que elegiste al crear la bóveda.';
      tabs.replaceChildren(kinds.map(([k, text]) => el('button', {
        class: k === kind ? 'active' : '', type: 'button',
        onclick: () => { kind = k; renderKind(); pw.input.focus(); },
      }, text)));
    };
    renderKind();

    let done = false;
    const finish = (value) => { if (!done) { done = true; modal.close(); resolve(value); } };
    const submit = () => {
      if (!pw.input.value) { errorText.textContent = 'Escribe la contraseña'; return; }
      localStorage.setItem('proofKind', kind);
      finish({ kind, value: pw.input.value });
    };
    pw.input.addEventListener('keydown', (event) => { if (event.key === 'Enter') submit(); });

    const helloAvailable = status.hello_enrolled && state.info.hello_supported;
    const modal = openModal({
      title: 'Confirma que eres tú',
      body: [
        el('p', { class: 'muted' }, reason || 'Esta acción necesita verificar tu identidad.'),
        note ? el('div', { class: 'warning' }, icon('info', 'sm'), el('span', {}, note)) : null,
        kinds.length > 1 ? tabs : null,
        el('div', { class: 'field' }, label, pw, help),
        errorText,
      ],
      footer: [
        helloAvailable ? el('button', { class: 'btn ghost', onclick: () => finish('hello') }, icon('fingerprint', 'sm'), 'Usar Windows Hello') : null,
        el('div', { class: 'spacer' }),
        el('button', { class: 'btn', onclick: () => finish(null) }, 'Cancelar'),
        el('button', { class: 'btn primary', onclick: submit }, 'Confirmar'),
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
      ? 'Abriste SecretBroker con tu sesión de Windows, que cualquier programa tuyo puede usar. Confirma una vez que eres tú y no volverá a pedírtelo hasta que la bloquees.'
      : null);
    if (!choice) return { ok: false, code: 'cancelled', error: 'Cancelado' };
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
    const start = el('button', { class: 'btn primary lg', style: 'min-width:220px', onclick: () => { thenImport = false; passwordStep(); } }, 'Empezar');
    box.replaceChildren(
      el('div', { class: 'auth-head center' }, brand(true), el('h1', { style: 'margin-top:12px' }, 'Tus claves, usadas sin ser vistas')),
      el('p', { class: 'lead' }, 'Guarda contraseñas, claves de API y accesos. La IA podrá usarlos para trabajar por ti, pero nunca leerlos.'),
      el('div', { class: 'points', style: 'margin:8px auto 12px;max-width:400px' },
        el('div', {}, icon('bot'), el('div', {}, el('b', {}, 'La IA usa, no ve. '), el('span', { class: 'muted' }, 'Las claves se insertan en cada petición y se borran de las respuestas.'))),
        el('div', {}, icon('check'), el('div', {}, el('b', {}, 'Tú decides. '), el('span', { class: 'muted' }, 'Apruebas con un clic, una vez o para todo el día.'))),
        el('div', {}, icon('lock'), el('div', {}, el('b', {}, 'Cifrado en este PC. '), el('span', { class: 'muted' }, 'Si compartes con tu equipo o haces copias, salen ya cifradas.')))),
      status.legacy_vault ? el('p', { class: 'help', style: 'text-align:center' }, 'Hemos encontrado tu bóveda anterior: podrás importarla en el siguiente paso.') : null,
      el('div', { class: 'auth-actions' }, start,
        el('div', { class: 'secondary' },
          el('button', { class: 'link muted-link', onclick: () => restoreBackup(() => { state.setupActive = false; state.screen = null; refreshStatus(); }) }, 'Restaurar una copia'),
          el('button', { class: 'link muted-link', onclick: () => { thenImport = true; passwordStep(); } }, 'Importar de otro gestor'))));
    setTimeout(() => start.focus(), 50);
  };

  const passwordStep = () => {
    const pw = passwordInput();
    const confirm = passwordInput();
    const legacy = passwordInput({ autocomplete: 'current-password' });
    const errorText = el('div', { class: 'error-text' });
    const button = el('button', { class: 'btn primary lg' }, 'Crear bóveda');

    const sameAsNew = el('input', { type: 'checkbox', checked: true });
    const legacyBox = el('div', { class: 'field hidden' }, el('label', {}, 'Contraseña de la bóveda anterior'), legacy);
    sameAsNew.addEventListener('change', () => legacyBox.classList.toggle('hidden', sameAsNew.checked));
    let legacySection = null;
    if (status.legacy_vault) {
      const importToggle = el('input', { type: 'checkbox', checked: true });
      const sameRow = el('label', { class: 'check-row', style: 'padding-left:26px' }, sameAsNew, 'Usaba esta misma contraseña');
      importToggle.addEventListener('change', () => {
        importLegacy = importToggle.checked;
        sameRow.classList.toggle('hidden', !importLegacy);
        legacyBox.classList.toggle('hidden', !importLegacy || sameAsNew.checked);
      });
      legacySection = [el('label', { class: 'check-row' }, importToggle, 'Importar las credenciales de la bóveda anterior'), sameRow, legacyBox];
    }

    const submit = async () => {
      errorText.textContent = '';
      if (pw.input.value.length < 12) { errorText.textContent = 'La contraseña maestra necesita al menos 12 caracteres.'; return; }
      if (pw.input.value !== confirm.input.value) { errorText.textContent = 'Las dos contraseñas no coinciden.'; return; }
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
      el('div', { class: 'auth-head' }, steps(2), el('h2', { style: 'margin-top:12px' }, 'Elige una contraseña maestra')),
      el('p', { class: 'lead' }, `Cifra la bóveda. En el día a día la abrirás con ${state.info.hello_supported ? 'Windows Hello o ' : ''}tu sesión; esta la necesitarás para restaurar copias o en otro PC.`),
      thenImport ? el('p', { class: 'help' }, 'Después elegirás el archivo exportado de tu otro gestor.') : null,
      el('div', { class: 'field' }, el('label', {}, 'Contraseña maestra'), pw, strengthMeter(pw.input)),
      el('div', { class: 'field' }, el('label', {}, 'Repítela'), confirm),
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
      hello && ['hello', 'fingerprint', 'Windows Hello (PIN, huella o cara)',
        'Lo pide al abrir la bóveda y al ver o copiar una contraseña. Si olvidas la contraseña maestra, entras con Hello y eliges otra.'],
      ['session', 'unlock', 'Abrir con mi sesión de Windows',
        'Se abre sola al entrar en Windows y se cierra al bloquearlo. Te protege de los errores de la IA, no de alguien que use tu sesión de Windows: cualquier programa tuyo podría abrirla.'],
      ['master', 'key', 'Escribir la contraseña maestra cada vez', 'Lo más estricto, y lo más pesado.'],
    ].filter(Boolean);
    let choice = options[0][0];
    const list = el('div', { class: 'choice-list', role: 'radiogroup' });
    const draw = () => list.replaceChildren(options.map(([value, iconName, title, text]) => el('label', { class: `choice ${choice === value ? 'active' : ''}` },
      el('input', { type: 'radio', name: 'unlock-way', value, checked: choice === value, onchange: () => { choice = value; draw(); } }),
      el('span', { class: 'choice-icon' }, icon(iconName)),
      el('span', {}, el('b', {}, title), value === options[0][0] ? el('span', { class: 'badge-soft' }, 'Recomendado') : null,
        el('span', { class: 'muted small choice-text' }, text)))));
    draw();
    const button = el('button', { class: 'btn primary lg' }, 'Continuar');
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
      el('div', { class: 'auth-head' }, steps(3), el('h2', { style: 'margin-top:12px' }, '¿Cómo quieres abrirla cada día?')),
      el('p', { class: 'lead' }, 'Escribirás la contraseña maestra solo para restaurar copias o en otro PC.'),
      list,
      el('p', { class: 'help' }, 'Las peticiones de la IA se aprueban siempre con un clic. Puedes cambiarlo en Ajustes.'),
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

  const master = passwordInput({ placeholder: 'Contraseña maestra', autocomplete: 'current-password' });
  const masterButton = el('button', { class: `btn ${primary === 'master' ? 'primary lg block' : ''}` }, 'Desbloquear');
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

  const sessionButton = el('button', { class: `btn ${primary === 'session' ? 'primary' : ''} lg block` }, icon('unlock', 'sm'), 'Abrir con mi sesión de Windows');
  sessionButton.addEventListener('click', async () => {
    errorText.textContent = '';
    busy(sessionButton, true);
    const ok = await api().session_unlock();
    busy(sessionButton, false);
    if (!ok) { errorText.textContent = osText('No se ha podido abrir con la sesión de Windows. Usa la contraseña.'); state.info.session_unlock_here = false; return; }
    done('session');
  });

  const helloButton = el('button', { class: `btn ${primary === 'hello' ? 'primary' : ''} lg block` }, icon('fingerprint', 'sm'), 'Desbloquear con Windows Hello');
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
    const proof = await askProof('Escribe la contraseña de tu cuenta de Windows.');
    if (!proof) return;
    if (proof === 'hello') return unlockHello();
    const result = await api().call('unlock', {}, proof);
    if (!result.ok) { errorText.textContent = result.error; return; }
    done('windows');
  };
  const windowsButton = el('button', { class: `btn ${primary === 'windows' ? 'primary' : ''} lg block`, onclick: unlockWindows },
    icon('key', 'sm'), 'Usar la contraseña de Windows');

  const forgot = () => {
    if (!canDevice) {
      openModal({ title: 'Recuperar el acceso', body: [
        el('p', {}, 'Este PC aún no tiene el desbloqueo con Windows activado, así que solo la contraseña maestra puede abrir la bóveda.'),
        el('p', { class: 'muted' }, 'Por seguridad, no hay otra forma de descifrarla.')] });
      return;
    }
    const modal = openModal({
      title: 'Recuperar el acceso',
      body: el('p', {}, 'Entra con Windows Hello o con tu contraseña de Windows. Después podrás elegir una contraseña maestra nueva. Solo funciona en este PC.'),
      footer: [
        status.windows_password ? el('button', { class: 'btn', onclick: () => { modal.close(); state.afterUnlock = 'change_master'; unlockWindows(); } }, 'Contraseña de Windows') : null,
        helloAvailable ? el('button', { class: 'btn primary', onclick: () => { modal.close(); state.afterUnlock = 'change_master'; unlockHello(); } }, 'Windows Hello') : null,
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
      el('div', { class: 'auth-head center' }, brand(true), el('h2', { style: 'margin-top:10px' }, 'SecretBroker está bloqueado')),
      reopen ? el('p', { class: 'help', style: 'text-align:center' }, 'Se bloqueó por inactividad. Se abrirá sola en cuanto vuelvas a usarla.') : null,
      view(primary),
      errorText,
      others.length ? el('details', { class: 'other-unlock' },
        el('summary', {}, el('span', { class: 'chev' }, icon('chevronRight', 'sm')), 'Otras formas de desbloquear'),
        el('div', { class: 'inner' }, others.map(view))) : null,
      el('div', { style: 'text-align:center' }, el('button', { class: 'link faint-link small', onclick: forgot }, '¿Has olvidado la contraseña maestra?')),
      el('p', { class: 'footnote', style: 'margin-top:24px' }, 'Desbloquea solo en esta ventana. SecretBroker nunca te pedirá la contraseña en otra.'))));
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
      navButton('credentials', 'key', 'Credenciales', state.entries.length),
      navButton('exposure', 'shield', 'Salud', exposedCount(), 'danger'),
      navButton('access', 'bot', 'Acceso de la IA', state.status.ai_paused ? el('span', { title: 'IA en pausa' }, icon('pause', 'sm')) : null, 'is-warning'),
      navButton('team', 'users', 'Equipo', teamAttentionCount()),
      navButton('activity', 'activity', 'Actividad'),
      navButton('settings', 'settings', 'Ajustes')),
    el('div', { id: 'update-slot' }),
    el('div', { class: 'sidebar-footer' },
      el('div', { class: 'state', id: 'sidebar-state' }),
      el('button', { class: 'btn icon-only', title: 'Generador de contraseñas (Ctrl+G)', onclick: openGenerator }, icon('dice', 'sm')),
      el('button', { class: 'btn icon-only', title: 'Bloquear (Ctrl+L)', onclick: lockNow }, icon('lock', 'sm'))));
  $app().replaceChildren(el('div', { class: 'layout' }, sidebar, el('main', { class: 'content', id: 'content' })));
  updateSidebarState();
  renderUpdateSlot();
  renderView();
}

function navButton(view, iconName, label, count, countClass = '') {
  return el('button', {
    class: state.view === view ? 'active' : '', 'data-view': view,
    onclick: () => { if (state.view !== view) clearToasts(); state.view = view; renderMain(); },
  }, icon(iconName), label, count ? el('span', { class: `count ${countClass}` }, count) : null);
}

function updateSidebarState() {
  const node = document.getElementById('sidebar-state');
  if (!node || !state.status) return;
  const status = state.status;
  const minutes = status.auto_lock_minutes;
  const until = status.session_unlock ? 'Desbloqueada · sigue a Windows'
    : minutes ? `Desbloqueada · ${minutes >= 60 ? `${minutes / 60} h` : `${minutes} min`}` : 'Desbloqueada';
  // Green while all is normal; amber only for something to do; red when something is stuck.
  const review = (status.drafts || 0) + teamAttention().length;
  const blocked = status.team === 'reconnect';
  const [tone, text] = blocked ? ['blocked', 'Equipo sin sincronizar']
    : status.ai_paused ? ['warn', 'IA en pausa']
      : review ? ['warn', review === 1 ? '1 cosa por revisar' : `${review} cosas por revisar`]
        : ['', until];
  node.replaceChildren(el('span', { class: `dot ${tone}` }), el('span', {}, text));
  node.title = [
    blocked ? 'La sesión del equipo ha caducado: vuelve a entrar en Equipo para seguir sincronizando.' : null,
    status.ai_paused ? 'La IA está en pausa: no puede usar ninguna credencial. Reanúdala en Acceso de la IA.' : null,
    status.drafts ? `${status.drafts === 1 ? 'Una credencial preparada' : `${status.drafts} credenciales preparadas`} por la IA ${status.drafts === 1 ? 'espera' : 'esperan'} su clave.` : null,
    teamAttention().length ? 'Hay cambios del equipo por revisar en Equipo.' : null,
    status.session_unlock ? `La bóveda se cierra al bloquear Windows${minutes ? ' o tras un rato sin uso, y se vuelve a abrir sola' : ''}.`
      : minutes ? `La bóveda se bloquea tras ${until.split(' · ')[1]} sin uso.` : 'La bóveda no se bloquea sola.',
    status.isolated ? 'El servicio usa una cuenta de Windows propia.' : 'Modo sin aislamiento: el servicio usa tu cuenta de Windows.',
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
    default: return f.username || hostOf(f.url) || 'Secreto';
  }
}

// How the list is ordered (remembered on this PC): [value, label].
const SORTS = [['name', 'Nombre'], ['used', 'Usadas recientemente'], ['changed', 'Cambiadas recientemente'], ['attention', 'Necesitan atención']];
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
  const byName = (a, b) => a.name.localeCompare(b.name, 'es', { sensitivity: 'base' });
  const newest = (key) => (a, b) => String(b[key] || '').localeCompare(String(a[key] || '')) || byName(a, b);
  const order = { used: newest('last_used'), changed: newest('updated'), attention: (a, b) => attentionOf(a) - attentionOf(b) || byName(a, b) }[sort] || byName;
  return [...items].sort(order);
}

function renderCredentials(content) {
  const search = el('input', { class: 'input', placeholder: 'Buscar', value: state.search, 'aria-label': 'Buscar credenciales' });
  search.addEventListener('input', () => { state.search = search.value; renderList(true); });
  search.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') { search.value = ''; state.search = ''; renderList(true); }
    else if (e.key === 'ArrowDown' || e.key === 'Enter') { e.preventDefault(); focusRow(0); }
  });
  const header = el('div', { class: 'content-header' },
    el('h1', {}, 'Credenciales'),
    state.entries.length ? el('div', { class: 'search' }, icon('search', 'sm'), search) : null,
    importExportMenu(),  // personal.js: «…» with Importar and Exportar
    el('button', { class: 'btn primary', title: 'Nueva (Ctrl+N)', onclick: () => openEditor(null) }, icon('plus', 'sm'), 'Nueva'));

  if (!state.entries.length) {
    content.replaceChildren(header, el('div', { class: 'content-body' }, emptyCredentials()));  // connect.js
    state.listView = null;
    return;
  }

  // The list takes the arrows (and Enter opens the selected one); the search box hands over with ↓ or Enter.
  const list = el('div', { class: 'list', role: 'listbox', tabindex: '0', 'aria-label': 'Credenciales' });
  const detail = el('div', { class: 'detail' });
  let shown = [];
  const sortSelect = el('select', { class: 'input compact', title: 'Ordenar', 'aria-label': 'Ordenar' },
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
    .map((e) => [e.shared.collection, e.shared.collection_name || 'Colección'])).entries()]
    .sort((a, b) => a[1].localeCompare(b[1]));
  if (state.collection && !collections.some(([cid]) => cid === state.collection)) state.collection = null;
  const tagBar = allTags.length || collections.length ? el('div', { class: 'tag-bar' }) : null;
  const filter = (tag, collection) => { state.tag = tag; state.collection = collection; renderTags(); renderList(true); };
  const renderTags = () => tagBar && tagBar.replaceChildren(
    el('button', { class: `tag ${state.tag || state.collection ? '' : 'active'}`, onclick: () => filter(null, null) }, 'Todas'),
    collections.map(([cid, name]) => el('button', {
      class: `tag team-tag ${state.collection === cid ? 'active' : ''}`, title: 'Colección del equipo',
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
      el('span', { class: 'small' }, picked.length === 1 ? '1 seleccionada' : `${picked.length} seleccionadas`),
      el('div', { class: 'spacer' }),
      el('button', {
        class: 'btn primary', disabled: !shareable.length || teamOffline(),
        title: shareable.length < picked.length ? 'Las que ya están compartidas o les falta la clave no se incluyen' : null,
        onclick: () => shareEntries(shareable, () => { state.picked.clear(); }),
      }, icon('share', 'sm'), `Compartir ${shareable.length} en…`),
      el('button', { class: 'btn icon-only', title: 'Quitar la selección (Esc)', onclick: () => { state.picked.clear(); renderList(); } }, icon('x', 'sm')));
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
    if (entry.draft) return el('span', { class: 'draft-badge' }, 'Falta la clave');
    if (entry.shared && entry.shared.pending_delete) return el('span', { class: 'draft-badge is-danger', title: 'Borrada para el equipo junto con otras: decide en Equipo si se borra aquí también' }, 'Borrado en espera');
    if (entry.shared && entry.shared.pending_change) return el('span', { class: 'draft-badge', title: changeSummary(entry.shared.pending_change) }, 'Revisar cambio');
    if (unsent) return el('span', { class: 'draft-badge', title: unsent }, 'Sin enviar');
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
        e.shared ? e.shared.collection_name : ''].join(' ').toLowerCase().includes(query))), sortSelect.value);
    shown = items;
    if (pickFirst && items.length && !items.some((e) => e.id === state.selected)) {
      state.selected = items[0].id;
      renderDetail(detail);
    }
    const filtered = items.length !== state.entries.length;
    countText.textContent = filtered ? `${items.length} de ${state.entries.length}`
      : plural(state.entries.length, 'credencial', 'credenciales');
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
      el('input', { type: 'checkbox', class: 'pick', checked: state.picked.has(entry.id), title: 'Seleccionar (Mayús+clic: varias seguidas)',
        'aria-label': `Seleccionar ${entry.name}`, onclick: (event) => { event.stopPropagation(); event.preventDefault(); toggle(entry, items, event.shiftKey); } }))
      : glyph(entry.template), el('div', { class: 'meta' },
      el('div', { class: 'title' }, el('span', { class: 'name' }, entry.name), entry.shared ? el('span', { class: 'shared-mark', title: `Compartida · ${entry.shared.collection_name}` }, icon('users', 'sm')) : null),
      el('div', { class: 'subtitle' }, subtitleOf(entry))),
    listBadge(entry))));
    if (!items.length) list.append(el('p', { class: 'muted', style: 'padding:12px 10px' }, 'Ninguna coincide.'));
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
    return people.length > 2 ? `Cambiar: salieron ${people.length}` : `Cambiar: ${people.length > 1 ? 'salieron' : 'salió'} ${listJoin(people)}`;
  }
  return { expired: 'Caducada', expiring: `Caduca en ${r.days} d`, old: 'Clave antigua', old_alive: 'Anula la anterior' }[r.kind];
}

function reminderText(r) {
  if (r.kind === 'team_access') {
    const many = (r.people || []).length > 1;
    return `${listJoin(r.people)} ${many ? 'tenían' : 'tenía'} acceso a esta credencial del equipo y ya no ${many ? 'están' : 'está'}. `
      + `${r.can_rotate ? 'Cámbiala' : 'Pide a quien la gestiona que la cambie'} por si la ${many ? 'vieron' : 'vio'}.`;
  }
  if (r.kind === 'old_alive') return `Rotaste la clave, pero la anterior sigue funcionando. Anúlala en ${r.provider || 'la web del proveedor'}.`;
  if (r.kind === 'expired') return `Caducó hace ${plural(r.days, 'día', 'días')}. Crea una clave nueva o rótala.`;
  if (r.kind === 'expiring') return `Caduca en ${plural(r.days, 'día', 'días')}. Rótala antes de que deje de funcionar.`;
  return `La clave tiene ${plural(r.days, 'día', 'días')}. Conviene rotarla de vez en cuando.`;
}

// A rotation left halfway, or what it could not finish: shown before any other reminder in the list.
function rotationBadge(entry) {
  if (entry.pending_rotation) return el('span', { class: 'draft-badge', title: 'Hay una contraseña nueva preparada que aún no se ha guardado como la actual' }, 'Rotación a medias');
  if ((entry.failed_uploads || []).length) return el('span', { class: 'draft-badge is-danger', title: `No se pudo subir a ${entry.failed_uploads.map((u) => u.label).join(', ')}` }, 'Subida fallida');
  if (entry.retired) return el('span', { class: 'draft-badge', title: 'Clave nueva activa · falta anular la anterior' }, 'Anula la anterior');
  return null;
}

function activeSpecs(templateId, fields) {
  const specs = TEMPLATES[templateId].fields;
  const resolved = {};
  for (const s of specs) resolved[s.name] = s.default;
  for (const [k, v] of Object.entries(fields)) if (v) resolved[k] = v;
  return specs.filter((s) => !s.show_if || Object.entries(s.show_if).every(([k, v]) => resolved[k] === v));
}

function shortLabel(label) { return label.replace(/\s*\((opcional|si tiene)\)$/, ''); }

// Where a template's label says too little: [in the detail, in the editor].
const FIELD_LABELS = { 'api_key.username': ['Identificador de la app', 'Identificador de la app (p. ej. ID de cliente)'] };
function fieldLabel(templateId, spec) { return (FIELD_LABELS[`${templateId}.${spec.name}`] || [shortLabel(spec.label)])[0]; }
function editorLabel(templateId, spec) { return (FIELD_LABELS[`${templateId}.${spec.name}`] || [null, shortLabel(spec.label)])[1]; }

// A message of the service in the editor's words: field labels instead of {{placeholders}} and internal ids.
function friendlyError(message, templateId) {
  const specs = (TEMPLATES[templateId] || { fields: [] }).fields;
  const label = (name) => { const spec = specs.find((s) => s.name === name); return spec ? fieldLabel(templateId, spec) : name === 'connection_url' ? 'URL de conexión' : name; };
  return String(message || '')
    .replace(/el dato \{\{\s*([a-z_]+)\s*\}\} no existe en esta credencial/, (_, n) => `usa «${label(n)}», que esta credencial no tiene`)
    .replace(/\{\{\s*([a-z_]+)\s*\}\}/g, (_, n) => `«${label(n)}»`)
    .replace(/^Ya existe una credencial con el identificador '[^']*'$/, 'Ya hay otra credencial con el mismo «Nombre para la IA» (en Permisos de la IA): cambia uno de los dos.')
    .replace(/^El identificador solo admite.*$/, '«Nombre para la IA» (en Permisos de la IA) solo admite minúsculas, números, «-», «_» y «.».');
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
  return el('button', { class: 'btn icon-only', title: 'Copiar', onclick: async () => { await api().copy_text(text); toast('Copiado'); } }, icon('copy', 'sm'));
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
          el('span', { class: 'faint small', title: PERMISSION_HELP.use }, 'Solo uso'));
      }
      if (spec.name === 'totp') return totpProp(entry, spec);  // personal.js: the live 2FA code
      const key = `${entry.id}:${spec.name}`;
      const revealed = state.revealed[key];
      const reveal = el('button', { class: 'btn icon-only', title: revealed ? 'Ocultar' : 'Mostrar' }, icon(revealed ? 'eyeOff' : 'eye', 'sm'));
      reveal.addEventListener('click', async () => {
        if (state.revealed[key]) { delete state.revealed[key]; renderDetail(panel); return; }
        const result = await withProof((p) => api().call('reveal', { id: entry.id, field: spec.name }, p), `Para mostrar «${spec.label}» de ${entry.name}.`);
        if (!result.ok) { if (result.code !== 'cancelled') toast(result.error, 'error'); return; }
        state.revealed[key] = result.result;
        renderDetail(panel);
        setTimeout(() => { if (state.revealed[key]) { delete state.revealed[key]; if (state.selected === entry.id) renderDetail(panel); } }, 30000);
      });
      const copy = el('button', { class: 'btn icon-only', title: 'Copiar' }, icon('copy', 'sm'));
      copy.addEventListener('click', async () => {
        const result = await withProof((p) => api().copy_secret(entry.id, spec.name, p), `Para copiar «${spec.label}» de ${entry.name}.`);
        if (result.ok) toast(`Copiado · se borra en ${result.result} s`);
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
        title: teamOffline() ? 'Sin conexión con el servidor del equipo' : null }, icon('share', 'sm'), 'Compartir') : null,
      el('button', { class: 'btn', onclick: () => openEditor(entry) }, 'Editar'),
      canWrite(entry) ? el('button', { class: 'btn icon-only', title: 'Eliminar', onclick: () => deleteEntry(entry) }, icon('trash', 'sm')) : null),
    entry.draft ? null : statusStrip(entry),
    entry.draft ? draftSection(entry, () => renderMain()) : null,
    entry.shared && entry.shared.pending_delete ? el('div', { class: 'warning is-danger', style: 'margin-bottom:12px' }, icon('trash', 'sm'),
      el('span', {}, entry.shared.pending_delete.gone
        ? 'Su colección ya no aparece en el servidor. No se ha borrado nada aquí: '
        : `${entry.shared.pending_delete.by || 'Alguien'} la ha borrado junto con otras. No se ha borrado nada aquí: `,
      el('button', { class: 'link', onclick: () => { state.view = 'team'; renderMain(); } }, 'decide en Equipo'), '.')) : null,
    entry.shared && entry.shared.pending_change ? pendingChangeBox(entry) : null,
    reminder && reminder.kind === 'team_access' ? el('div', { class: `warning ${reminderTone(reminder)}` }, icon('clock', 'sm'), el('span', {}, reminderText(reminder),
      reminder.can_rotate && entry.rotation
        ? [' ', el('button', { class: 'link small', onclick: () => rotateWithHelp(entry) }, 'Rotar con ayuda')] : null)) : null,
    pendingRotationBox(entry),
    failedUploadsBox(entry),
    entry.retired && canWrite(entry) ? retiredBox(entry) : null,
    (entry.tags || []).length || entry.expires ? el('div', { class: 'tag-line' },
      (entry.tags || []).map((t) => el('span', { class: 'tag static' }, t)),
      entry.expires ? el('span', { class: 'muted small' }, `Caduca el ${entry.expires}`) : null) : null,
    el('div', { class: 'section' }, props),
    entry.description ? el('div', { class: 'section' }, el('h3', { class: 'with-icon' }, icon('bot', 'sm'), 'Instrucciones para la IA'),
      el('p', { class: 'notes selectable muted' }, entry.description)) : null,
    providerSection(entry),
    rotationSection(entry),
    sharedSection(entry),
    el('div', { class: 'section' },
      el('h3', {}, 'Qué puede hacer la IA'),
      perms.length ? perms : el('p', { class: 'muted' }, 'Nada todavía. Edita la credencial y abre «Permisos de la IA».'),
      el('p', { class: 'help', style: 'margin-top:6px' }, 'La IA la conoce como ', el('code', { class: 'selectable' }, entry.id))),
    entry.draft ? null : recentActivity(entry));
}

// The AI's last uses of a credential: when, which app, what (method and host) and how it went.
const RECENT_USES = 5;

function recentActivity(entry) {
  const box = el('div', { class: 'section recent' }, el('h3', {}, 'Actividad reciente'));
  const cache = state.recentCache || (state.recentCache = {});
  const draw = (events) => {
    const uses = events.filter((e) => eventActor(e)[0] === 'ai' && MONO_EVENT_ACTIONS.has(e.action)).slice(0, RECENT_USES);
    box.replaceChildren(el('h3', {}, 'Actividad reciente'), uses.length
      ? el('div', { class: 'recent-list' }, uses.map(recentRow))
      : el('p', { class: 'muted small' }, 'La IA aún no la ha usado.'),
    uses.length ? el('button', { class: 'link small', style: 'align-self:flex-start;margin-top:4px', onclick: () => {
      state.activityFilter = { kind: null, secret: entry.id }; state.view = 'activity'; renderMain();
    } }, 'Ver toda la actividad') : null);
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
    el('span', { class: 'when', title: e.ts ? new Date(e.ts).toLocaleString('es-ES') : '' }, e.ts ? sinceText(e.ts) : ''),
    el('span', { class: 'who' }, icon('bot', 'sm'), e.client || 'IA'),
    el('span', { class: 'what' }, what ? el('b', {}, what) : null, what && where ? ' ' : null, where ? el('span', { class: 'mono' }, where) : null),
    el('span', { class: `chip ${failed ? 'is-exposed failed' : 'is-ok'}` }, e.status === 'denied' ? 'Denegada' : e.status === 'error' ? 'Error' : 'Correcta'));
}

// [verb, target] of a use in the activity: «GET» «api.example.com», «SSH» «deploy@server», «psql» «».
function useSummary(e) {
  const detail = (e.detail || '').split('\n')[0];
  if (e.action === 'http_request') {
    const [method, url] = detail.split(' ');
    return [method, hostOf(url || '')];
  }
  if (e.action === 'ssh_exec') return ['SSH', detail.split('$')[0]];
  if (e.action === 'ssh_upload' || e.action === 'ssh_download') return [e.action === 'ssh_upload' ? 'Subir' : 'Descargar', (detail.match(/[^\s]+@[^\s:]+/) || [''])[0]];
  if (e.action === 'run_command') return [detail.split(' ')[0], ''];
  if (e.action === 'release_env') return ['sb run', ''];
  return [ACTION_LABELS[e.action] || e.action, ''];
}

// «ahora», «hace 5 min», «hace 3 h», «ayer 18:20», «12 oct 09:15».
function sinceText(iso) {
  const date = new Date(iso);
  const minutes = Math.round((Date.now() - date) / 60000);
  if (minutes < 1) return 'ahora';
  if (minutes < 60) return `hace ${minutes} min`;
  if (minutes < 6 * 60) return `hace ${Math.round(minutes / 60)} h`;
  const day = dayLabel(date);
  const time = date.toLocaleTimeString('es-ES', { hour: '2-digit', minute: '2-digit' });
  return day === 'Hoy' ? time : day === 'Ayer' ? `ayer ${time}` : formatTime(iso);
}

function describePermissions(entry) {
  const policy = entry.policy || {};
  const items = [];
  const http = policy.http || {};
  if (http.allowed_hosts && http.allowed_hosts.length) items.push(['globe', `Peticiones a ${http.allowed_hosts.join(', ')}`]);
  if (entry.template === 'ssh') items.push(['server', `Comandos y archivos en ${entry.fields.host}`]);
  const commands = policy.commands || {};
  if (commands.allowed && commands.allowed.length) items.push(['terminal', `Ejecutar ${commands.allowed.join(', ')} en este PC`]);
  if (!items.length) return [];
  const approval = policy.approval || 'session';
  items.push(['fingerprint', { session: 'Te pregunta una vez por sesión', always: 'Te pregunta cada vez', never: 'No te pregunta' }[approval]]);
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
  const select = el('select', { class: 'input' }, el('option', { value: '' }, 'Elige el proveedor…'),
    providers.map((p, i) => el('option', { value: String(i) }, p.provider)));
  const details = el('div', {});
  select.addEventListener('change', () => {
    const provider = providers[Number(select.value)];
    details.replaceChildren(provider ? el('div', { style: 'margin-top:6px' },
      provider.help ? el('p', { class: 'help' }, provider.help) : null, linkList(provider.links)) : '');
  });
  return el('div', { class: 'field' }, el('label', {}, '¿Dónde consigo la clave?', el('span', { class: 'req' }, ' · opcional')),
    select, details);
}

// ----------------------------------------------------------------------- rotation

function destinationLabel(d) {
  return `GitHub ${d.repo}${d.environment ? ` (${d.environment})` : ''} · ${d.name}`;
}

const ROTATE_EVERY = [[null, 'Ajuste general'], [30, '30 días'], [60, '2 meses'], [90, '3 meses'], [180, '6 meses'], [365, '1 año'], [0, 'Nunca']];

// «cada año», «cada 6 meses», «cada 30 días».
function everyLabel(days) {
  if (days % 365 === 0) return days === 365 ? 'cada año' : `cada ${days / 365} años`;
  if (days % 30 === 0 && days >= 60) return `cada ${days / 30} meses`;
  return days === 1 ? 'cada día' : `cada ${days} días`;
}

// Days between rotation reminders for this credential (0: never), and whether it is the general setting.
function rotateEvery(entry) {
  const own = entry.rotate_every_days;
  const general = own === null || own === undefined;
  return { days: general ? (state.status.rotate_reminder_days ?? 365) : own, general };
}

function cadenceText(entry) {
  const { days, general } = rotateEvery(entry);
  if (!days) return general ? 'Los recordatorios de rotación están desactivados en Ajustes.' : 'No te recuerda rotarla.';
  let text = `Te recuerda rotarla ${everyLabel(days)}${general ? ' (ajuste general)' : ''}`;
  if (entry.secret_since) {
    const due = new Date(new Date(entry.secret_since).getTime() + days * 86400000);
    text += `: la próxima vez, hacia el ${due.toLocaleDateString('es-ES', { day: 'numeric', month: 'long', year: 'numeric' })}`;
  }
  return `${text}. Puedes cambiarlo al editarla.`;
}

// «en 3 meses», «en 12 días», «en un año», «mañana».
function inTime(days) {
  if (days <= 1) return days === 1 ? 'mañana' : 'hoy';
  if (days < 45) return `en ${days} días`;
  if (days < 330) return `en ${Math.round(days / 30)} meses`;
  const years = Math.max(1, Math.round(days / 365));
  return years === 1 ? 'en un año' : `en ${years} años`;
}

// «hoy a las 10:02», «ayer a las 18:40», «el 3 oct a las 10:02».
function atText(iso) {
  const text = whenText(iso);
  const day = text.slice(0, -6);
  return `${['hoy', 'ayer'].includes(day) ? day : `el ${day}`} a las ${text.slice(-5)}`;
}

function capitalized(text) { return text.charAt(0).toUpperCase() + text.slice(1); }

// «hoy 10:02», «ayer 18:40», «3 oct 10:02».
function whenText(iso) {
  if (!iso) return '';
  const date = new Date(iso);
  const time = date.toLocaleTimeString('es-ES', { hour: '2-digit', minute: '2-digit' });
  const today = new Date();
  const yesterday = new Date(Date.now() - 86400000);
  if (date.toDateString() === today.toDateString()) return `hoy ${time}`;
  if (date.toDateString() === yesterday.toDateString()) return `ayer ${time}`;
  return `${date.toLocaleDateString('es-ES', { day: 'numeric', month: 'short' })} ${time}`;
}

// How often each key is tested with its provider: hours, -1 once per value, 0 never, null the general setting.
const CHECK_EVERY = [[1, 'Cada hora'], [6, 'Cada 6 horas'], [12, 'Cada 12 horas'], [24, 'Cada día'], [168, 'Cada semana'],
  [720, 'Cada mes'], [8760, 'Cada año'], [-1, 'Solo una vez (cada clave nueva)'], [0, 'Nunca']];

function checkLabel(hours) {
  const found = CHECK_EVERY.find(([h]) => h === hours);
  if (found) return found[1].toLowerCase();
  return hours % 24 === 0 ? `cada ${hours / 24} días` : `cada ${hours} horas`;
}

// A select with the usual intervals plus «Cada X horas…»; value() is the number (or null for the general setting).
function checkEveryControl(current, withGeneral, onChange) {
  const presets = CHECK_EVERY.map(([h]) => h);
  const custom = current !== null && current !== undefined && !presets.includes(current);
  const select = el('select', { class: 'input', style: 'width:auto' },
    withGeneral ? el('option', { value: '' }, 'Ajuste general') : null,
    CHECK_EVERY.map(([h, label]) => el('option', { value: String(h) }, label)),
    el('option', { value: 'custom' }, 'Cada X horas…'));
  select.value = custom ? 'custom' : current === null || current === undefined ? (withGeneral ? '' : '24') : String(current);
  const hours = el('input', { class: 'input', type: 'number', min: '1', max: '87600', step: '1', style: 'width:90px',
    value: custom ? String(current) : '48', title: 'Horas entre comprobaciones' });
  const hoursBox = el('span', { style: 'display:inline-flex;gap:6px;align-items:center' }, hours, el('span', { class: 'muted small' }, 'horas'));
  const sync = () => { hoursBox.style.display = select.value === 'custom' ? 'inline-flex' : 'none'; };
  const value = () => {
    if (select.value === '') return null;
    if (select.value !== 'custom') return Number(select.value);
    const n = Number(hours.value);
    if (!Number.isInteger(n) || n < 1 || n > 87600) throw new Error('Las horas entre comprobaciones deben ser un número entre 1 y 87600.');
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
  const general = own === null || own === undefined ? ' (ajuste general)' : '';
  if (hours === 0) return `No se prueba sola${general}. Puedes hacerlo con «Revisar ahora» en Salud.`;
  if (hours === -1) return `Se prueba solo una vez cada clave nueva${general}.`;
  return `Se prueba ${checkLabel(hours)}${general}.`;
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
    const text = { exposed: 'Expuesta', warning: item.found_before ? 'Estuvo expuesta' : 'Revisar', ok: 'Sin copias conocidas', unknown: 'Sin buscar copias' }[item.level];
    chip(item.level, text, item.reasons.map((r) => r.text).join(' ') || 'Ver las copias encontradas', () => openHealth(entry.id));
  }
  const writable = canWrite(entry);
  if (entry.pending_rotation) {
    chip('warning', 'Rotación a medias', 'Hay una contraseña nueva preparada que aún no se ha guardado como la actual', () => rotateWithHelp(entry));
  } else if (entry.retired) {
    chip('warning', 'Falta anular la anterior', 'Clave nueva activa · falta anular la anterior', () => document.querySelector('.retired-box')?.scrollIntoView({ block: 'center', behavior: 'smooth' }));
  } else if (entry.secret_since && (entry.rotation || canChangePassword(entry) || entry.guide)) {
    const reminder = state.reminders && state.reminders[entry.id];
    const { days } = rotateEvery(entry);
    const age = Math.floor((Date.now() - new Date(entry.secret_since).getTime()) / 86400000);
    const due = days ? days - age : null;
    const late = reminder && ['old', 'expired', 'expiring'].includes(reminder.kind);
    const text = late ? (reminder.kind === 'old' ? 'Toca rotarla' : reminderShort(reminder))
      : due !== null ? `Rotar ${inTime(due)}` : `Puesta ${ageText(age)}`;
    chip(late ? 'warning' : 'neutral', text, `${late ? reminderText(reminder) : `Valor puesto ${ageText(age)}.`} ${cadenceText(entry)}`,
      () => (writable ? rotateWithHelp(entry) : toast('La rota quien gestiona la colección del equipo')));
  }
  if (entry.rotation || entry.template === 'database' || (entry.used_in || []).length) {
    const n = (entry.used_in || []).length;
    chip(n ? 'neutral' : 'unknown', n ? `Usada en ${n} ${n === 1 ? 'sitio' : 'sitios'}` : 'Sin sitios apuntados',
      n ? entry.used_in.join(' · ') : 'Apunta dónde se usa: al rotarla, la app te pedirá cambiarla en cada sitio', () => usedInModal(entry));
  }
  if (item && item.checkable) {
    const alive = item.alive;
    const checked = alive && alive.checked;
    const level = !alive ? 'unknown' : alive.status === 'ok' ? 'ok' : alive.status === 'invalid' ? 'exposed' : 'warning';
    const text = !alive ? 'Sin probar' : alive.status === 'ok' ? `Funciona · ${whenText(checked)}`
      : alive.status === 'invalid' ? `No funciona · ${whenText(checked)}` : `Sin respuesta · ${whenText(checked)}`;
    chip(level, text, `${alive && alive.message ? `${alive.message}. ` : ''}${checkCadenceText(entry)} Pulsa para probarla ahora.`, (button) => checkOne(entry, button));
  } else if (['api_key', 'generic'].includes(entry.template) && writable) {
    chip('unknown', 'No se puede probar', 'La app no sabe cómo probar esta clave: dile qué petición la prueba', () => testRequestModal(entry));
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
  if (!alive) toast('No se pudo probar');
  else if (alive.status === 'ok') toast(`Funciona: ${alive.provider} la acepta`);
  else toast(alive.message || 'No se pudo probar', 'error');
}

function usedInModal(entry) {
  const places = entry.used_in || [];
  const modal = openModal({
    title: `Dónde se usa ${entry.name}`,
    body: [places.length ? el('ul', { class: 'used-in' }, places.map((p) => el('li', {}, p)))
      : el('p', { class: 'muted' }, 'No está apuntado dónde se usa.'),
    el('p', { class: 'help' }, 'Al rotarla, la app te pide cambiarla en cada uno de estos sitios. La IA también los apunta cuando configura uno.')],
    footer: [el('div', { class: 'spacer' }), el('button', { class: 'btn', onclick: () => modal.close() }, 'Cerrar'),
      canWrite(entry) ? el('button', { class: 'btn primary', onclick: () => { modal.close(); openEditor(entry); } }, places.length ? 'Cambiar' : 'Apuntarlos') : null],
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
  const save = el('button', { class: 'btn primary' }, 'Guardar y probar');
  const remove = entry.test_request ? el('button', { class: 'btn ghost' }, 'Quitar') : null;
  const ask = `Busca en la documentación de la API de «${entry.name}» una petición GET de solo lectura que necesite la clave y guárdala en SecretBroker como test_request de ${entry.id}`;
  const modal = openModal({
    title: `Cómo probar ${entry.name}`,
    body: [
      el('p', { class: 'muted' }, 'Una petición que solo lee (GET o HEAD) a su API, con la clave puesta como la pone la credencial. Si responde lo esperado, la clave funciona.'),
      el('div', { class: 'field' }, el('label', {}, 'Petición'),
        el('div', { style: 'display:flex;gap:8px' }, method, el('div', { style: 'flex:1' }, url)),
        el('div', { class: 'help' }, base ? `Una ruta de ${base} o una dirección completa de sus webs permitidas.` : 'Una dirección completa de sus webs permitidas.')),
      el('div', { class: 'field' }, el('label', {}, 'Respuesta de una clave que funciona'), el('div', { style: 'display:flex;gap:8px;align-items:center' }, el('span', { class: 'muted' }, 'HTTP'), status)),
      el('div', { class: 'help' }, '¿No sabes cuál? Pídeselo a la IA: ', el('button', { class: 'link small', onclick: async () => { await api().copy_text(ask); toast('Copiado: pégaselo a la IA'); } }, 'copiar la petición para la IA')),
      errorText,
    ],
    footer: [remove, el('div', { class: 'spacer' }), el('button', { class: 'btn', onclick: () => modal.close() }, 'Cancelar'), save],
  });
  const send = async (button, value) => {
    errorText.textContent = '';
    busy(button, true);
    const result = await withProof((p) => api().call('set_test_request', { id: entry.id, test: value, check: !!value }, p), `Para cambiar cómo se prueba ${entry.name}.`);
    busy(button, false);
    if (!result.ok) { if (result.code !== 'cancelled') errorText.textContent = result.error; return; }
    modal.close();
    await loadEntries();
    renderMain();
    const check = result.result.check;
    if (!value) toast('Prueba quitada');
    else if (check && check.status === 'ok') toast('Guardada: la clave funciona');
    else toast(`Guardada. ${check ? check.message : 'No se pudo probar'}`, 'error');
  };
  save.addEventListener('click', () => {
    if (!url.value.trim()) { errorText.textContent = 'Escribe la ruta o la dirección que hay que pedir.'; return; }
    send(save, { method: method.value, url: url.value.trim(), status: Number(status.value) || 200 });
  });
  if (remove) remove.addEventListener('click', () => send(remove, {}));
  setTimeout(() => url.focus(), 50);
}

function rotationSection(entry) {
  const rotation = entry.rotation;
  if (!rotation) return null;
  if (!canWrite(entry)) {
    return el('div', { class: 'section' }, el('h3', {}, 'Rotación'),
      el('p', { class: 'help' }, `Es del equipo y tu permiso es «${PERMISSION_LABELS[entry.shared.permission]}»: la rota quien la gestiona, y la nueva te llega sola.`));
  }
  const destinations = entry.destinations || [];
  const guide = entry.guide || {};
  const apply = guide.apply || {};
  const apiButton = rotation.supported
    ? el('button', { class: 'btn', onclick: () => rotateEntry(entry) }, icon('rotate', 'sm'), 'Rotar clave') : null;
  const guidedButton = el('button', { class: rotation.supported ? 'btn ghost' : 'btn', onclick: () => rotateGuided(entry) },
    rotation.supported ? null : icon('rotate', 'sm'), rotation.supported ? 'Rotar a mano' : 'Rotar con ayuda');
  const testButton = ['api_key', 'generic'].includes(entry.template) && !rotation.supported && guide.kind !== 'database'
    && (!guide.testable || entry.test_request)
    ? el('button', { class: 'btn ghost', onclick: () => testRequestModal(entry) }, entry.test_request ? 'Cambiar la prueba' : 'Cómo probarla') : null;
  const ask = `Busca en la documentación oficial cómo se rota la clave de «${entry.name}» y guarda la guía en SecretBroker`;
  // One line: what the app does for this one.
  const line = rotation.supported
    ? `${rotation.provider} da una clave nueva y anula la actual${destinations.length ? `; se vuelve a subir a ${destinations.length === 1 ? destinationLabel(destinations[0]) : `${destinations.length} sitios`}` : ''}.`
    : guide.kind === 'database'
      ? (apply.available ? `La app la cambia en la base de datos con ${apply.client} y comprueba que entra con la nueva.`
        : `La app genera la nueva y te da ${guide.command ? 'el comando' : 'los pasos'}${guide.links && guide.links.length ? ' o el panel' : ''}.`)
      : `Con ayuda: la creas en su web y la pegas aquí${guide.testable ? '; se prueba antes de guardarla' : ''}.`;
  return el('div', { class: 'section' },
    el('h3', {}, 'Rotación', guide.source === 'ai'
      ? el('span', { class: 'chip', title: `Guía escrita por la IA${guide.written ? ` el ${guide.written}` : ''}: comprueba los enlaces antes de seguirla.` }, 'Guía de la IA') : null),
    el('p', { class: 'help' }, line,
      guide.source === 'generic' ? [' ', el('button', { class: 'link small', title: ask, onclick: async () => { await api().copy_text(ask); toast('Copiado: pégaselo a la IA'); } }, 'Pedir una guía a la IA')] : null),
    el('div', { style: 'margin-top:8px;display:flex;gap:8px;flex-wrap:wrap' }, apiButton, guidedButton, testButton));
}

// A rotation left halfway: the new password is kept in the vault (it may already be set somewhere).
function pendingRotationBox(entry) {
  const pending = entry.pending_rotation;
  if (!pending || !canWrite(entry)) return null;
  return el('div', { class: 'draft-box' },
    el('div', { class: 'warning is-warning' }, icon('alert', 'sm'), el('span', {}, `Rotación a medias: ${atText(pending.since)} se preparó una ${entry.template === 'database' || canChangePassword(entry) ? 'contraseña' : 'clave'} nueva que aún no se ha guardado como la actual.`)),
    el('div', { style: 'margin-top:8px;display:flex;gap:8px' },
      el('button', { class: 'btn', onclick: () => rotateWithHelp(entry) }, 'Terminar la rotación')));
}

// Places a rotated secret could not be uploaded to: they still have the old one.
function failedUploadsBox(entry) {
  const failed = entry.failed_uploads || [];
  if (!failed.length) return null;
  const retry = el('button', { class: 'btn' }, 'Reintentar subida');
  retry.addEventListener('click', () => retryUploads(entry, retry));
  return el('div', { class: 'draft-box is-danger' },
    el('div', { class: 'warning' }, icon('alert', 'sm'), el('span', {}, `No se pudo subir la nueva a ${failed.map((u) => u.label).join(', ')}: ahí sigue la anterior.`)),
    el('p', { class: 'help' }, failed[0].error),
    el('div', { style: 'margin-top:8px;display:flex;gap:8px' }, retry));
}

async function retryUploads(entry, button) {
  busy(button, true);
  const result = await withProof((p) => api().call('retry_uploads', { id: entry.id }, p), `Para subir de nuevo ${entry.name}.`);
  busy(button, false);
  if (!result.ok) { if (result.code !== 'cancelled') toast(result.error, 'error'); return null; }
  await loadEntries();
  renderMain();
  const failed = result.result.uploads.filter((u) => !u.ok);
  if (failed.length) toast(`Sigue sin poder subirse a ${failed.map((u) => u.label).join(', ')}: ${failed[0].error}`, 'error');
  else toast('Subida de nuevo');
  return result.result;
}

// After a rotation by hand, the old key is kept until it is confirmed dead at the provider.
function retiredBox(entry) {
  const retired = entry.retired;
  const guide = entry.guide || {};
  const where = retired.provider || 'la web del proveedor';
  const refresh = async () => { await loadEntries(); renderMain(); };
  const checkButton = retired.checkable ? el('button', { class: 'btn', onclick: async () => {
    busy(checkButton, true);
    const result = await api().call('check_retired', { id: entry.id });
    busy(checkButton, false);
    if (!result.ok) { toast(result.error, 'error'); return; }
    if (result.result.status === 'done') { toast('La clave anterior ya no funciona: rotación completa'); refresh(); }
    else if (result.result.status === 'alive') toast(`La clave anterior sigue funcionando: anúlala en ${where}`, 'error');
    else toast(result.result.message || 'No se pudo comprobar', 'error');
  } }, 'Comprobar') : null;
  const forget = el('button', { class: 'btn ghost', onclick: async () => {
    const result = await api().call('forget_retired', { id: entry.id });
    if (!result.ok) { toast(result.error, 'error'); return; }
    toast('Rotación completa');
    refresh();
  } }, 'Ya la he anulado');
  return el('div', { class: 'draft-box retired-box' },
    el('div', { class: 'warning is-warning' }, icon('alert', 'sm'), el('span', {}, retired.status === 'alive'
      ? `Clave nueva activa, pero la anterior sigue funcionando: anúlala en ${where}.`
      : `Clave nueva activa · falta anular la anterior en ${where}.`)),
    el('p', { class: 'help' }, guide.revoke || 'Bórrala o revócala en la misma página donde creaste la nueva.',
      (entry.used_in || []).length ? ` Antes, comprueba que ya usan la nueva: ${entry.used_in.join('; ')}.` : ''),
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
  const provider = known || 'el proveedor';
  const site = known ? `la web de ${known}` : 'la web del servicio';
  const database = guide.kind === 'database';
  const apply = guide.apply || {};
  const exposureBefore = exposureOf(entry.id);  // its findings are for the old value: gone once it changes
  const suggested = `${entry.id}-${new Date().toISOString().slice(0, 7)}`;
  const env = Object.keys(((entry.policy || {}).commands || {}).env || {});
  const automatic = [
    ...(entry.destinations || []).map((d) => `${destinationLabel(d)} (se vuelve a subir sola)`),
    ...(env.length ? [`tus programas con sb run (${env.join(', ')}), al reiniciarlos`] : []),
  ];
  const titles = database
    ? ['Dónde se usa', 'Cambia la contraseña', 'Ponla en cada sitio']
    : ['Dónde se usa', 'Crea la clave nueva', guide.generate ? 'El secreto nuevo' : 'Pega la clave nueva', 'Ponla en cada sitio', 'Anula la clave anterior'];
  const body = el('div', {});
  const foot = el('div', { style: 'display:contents' });
  let places = [...(entry.used_in || [])];
  let pending = entry.pending_rotation;  // {since, generated}: a new one kept by the service, never its value
  let saved = false;  // the new one is the current one
  let finished = false;
  let current = 1;  // the step shown: from the second one on, something may already be done at the provider
  const modal = openModal({
    title: `Rotar ${entry.name}`, wide: true, body, footer: [foot],
    confirmClose: () => (finished || (current === 1 && !pending && !saved) ? null
      : pending ? `La ${database ? 'contraseña' : 'clave'} nueva queda guardada aquí como pendiente: cuando vuelvas a «Rotar con ayuda», podrás terminar.`
        : saved ? 'La nueva ya está guardada y funcionando. Si cierras ahora, la credencial te recordará lo que falta.'
          : database ? 'Aún no se ha cambiado nada.' : 'Si ya creaste la clave nueva en el proveedor, tendrás que pegarla otra vez.'),
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
      `Para preparar la ${database ? 'contraseña' : 'clave'} nueva de ${entry.name}.`);
    if (!result.ok) { if (result.code !== 'cancelled' && errorText) errorText.textContent = result.error; return false; }
    pending = result.result.pending_rotation;
    refresh();
    return true;
  };
  const copyPending = async (what) => {
    const result = await withProof((p) => api().copy_rotation_secret(entry.id, what, p), `Para copiar la ${database ? 'contraseña' : 'clave'} nueva de ${entry.name}.`);
    if (result.ok) toast(`Copiad${what === 'command' ? 'o' : 'a'} · se borra del portapapeles en ${result.result} s`);
    else if (result.code !== 'cancelled') toast(result.error, 'error');
  };
  const masked = '••••••••••••';
  const pendingBox = (label, what = 'value') => el('div', { class: 'prop' },
    el('div', { style: 'min-width:0' }, el('div', { class: 'k' }, label), what === 'command'
      ? el('div', { class: 'v mono', style: 'white-space:normal' }, guide.command.replace('{password}', masked))
      : el('div', { class: 'v secret' }, masked)),
    el('div', { class: 'actions' }, el('button', { class: 'btn icon-only', title: 'Copiar', onclick: () => copyPending(what) }, icon('copy', 'sm'))));

  // 0 · A rotation left halfway: did the new one get set where it lives?
  function resume() {
    const errorText = el('div', { class: 'error-text' });
    const yes = el('button', { class: 'btn primary' }, database || canChangePassword(entry) ? 'Sí, ya la cambié: guardar' : 'Guardarla como la actual');
    yes.addEventListener('click', () => save(yes, errorText, { pending: true }));
    const discard = el('button', { class: 'btn', onclick: async () => {
      const result = await withProof((p) => api().call('rotation_discard', { id: entry.id }, p), `Para descartar la nueva de ${entry.name}.`);
      if (!result.ok) { if (result.code !== 'cancelled') errorText.textContent = result.error; return; }
      pending = null;
      refresh();
      where();
    } }, 'No, descartarla');
    const applyButton = database && apply.available ? el('button', { class: 'btn', onclick: () => applyNow(applyButton, errorText) }, 'Aplicarla ahora') : null;
    show(0, [
      el('p', { class: 'muted' }, `${capitalized(atText(pending.since))} se preparó una ${database ? 'contraseña' : 'clave'} nueva y no se llegó a guardar como la actual. `
        + `Si ya la pusiste en ${database ? 'la base de datos' : 'su sitio'}, guárdala ahora: la que hay aquí ya no funcionaría.`),
      pendingBox(database ? 'Contraseña nueva' : 'Clave nueva', 'value'),
      database && guide.command ? pendingBox('Comando con la contraseña nueva', 'command') : null,
      errorText,
    ], [discard, applyButton, yes], 'Rotación a medias: ¿ya la cambiaste?');
  }

  // 1 · Every place that will need the new one: asked first, kept with the credential for next time.
  function where() {
    const list = el('div', { class: 'used-in-edit' });
    const input = el('input', { class: 'input', placeholder: 'p. ej. pro: servidor api.ejemplo.com, /srv/app/.env' });
    const render = () => list.replaceChildren(places.length
      ? places.map((place, i) => el('div', { class: 'perm' }, el('span', { class: 'muted' }, '•'), el('span', { style: 'flex:1' }, place),
        el('button', { class: 'btn icon-only', title: 'Quitar', onclick: () => { places.splice(i, 1); render(); } }, icon('x'))))
      : el('p', { class: 'help' }, 'Todavía no hay ningún sitio apuntado.'));
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
        ? 'En cuanto cambie la contraseña, la actual deja de funcionar en todos los sitios que la usan. Apúntalos todos: develop, pre, pro, cada servidor, Vercel, CI, otros proyectos…'
        : 'Cuando tengas la nueva, habrá que ponerla en cada sitio que la usa antes de anular la anterior. Apúntalos todos: develop, pre, pro, cada servidor, Vercel, CI, otros proyectos…'),
      list,
      el('div', { style: 'display:flex;gap:8px;margin-top:8px' }, input, el('button', { class: 'btn', onclick: add }, 'Añadir')),
      automatic.length ? el('p', { class: 'help', style: 'margin-top:10px' }, `De esto se encarga la app: ${automatic.join('; ')}.`) : null,
      el('p', { class: 'help' }, 'Se guarda en la credencial para la próxima vez. La IA también los apunta cuando configura un sitio.'),
    ], [el('button', { class: 'btn', onclick: () => modal.close() }, 'Cancelar'),
      el('button', { class: 'btn primary', onclick: () => { if (input.value.trim()) add(); (database ? change : create)(); } }, 'Siguiente')]);
    setTimeout(() => input.focus(), 50);
  }

  const save = async (button, errorText, params, aiApplies = false) => {
    busy(button, true);
    const result = await withProof((p) => api().call('replace_key', { id: entry.id, used_in: places, ...params }, p),
      `Para guardar la ${database ? 'contraseña' : 'clave'} nueva de ${entry.name}.`);
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
    const result = await withProof((p) => api().call('rotation_apply', { id: entry.id, used_in: places }, p), `Para cambiar la contraseña de ${entry.name}.`);
    busy(button, false);
    if (!result.ok) {
      if (result.code === 'cancelled') return;
      errorText.textContent = result.code === 'unverified'
        ? `${result.error} La nueva sigue guardada aquí como pendiente: prueba a conectarte con ella y, si entra, pulsa «Ya la he cambiado: guardar».`
        : `${result.error} No se ha cambiado nada: puedes hacerlo tú.`;
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
      if (!await begin({ generate: true }, errorText)) { show(2, [errorText], [el('button', { class: 'btn', onclick: where }, 'Atrás')]); return; }
    }
    const saveButton = el('button', { class: 'btn primary' }, 'Ya la he cambiado: guardar');
    const aiButton = guide.command ? el('button', { class: 'btn', title: 'Se guarda ya y la IA la aplica con sb run, sin verla' }, 'Guardar y que la aplique la IA') : null;
    // A managed database whose panel makes the password: the user pastes it, and it is kept at once.
    const pasted = guide.generate ? null : passwordInput({ placeholder: 'Pega la que te ha dado el panel' });
    if (pasted) pasted.input.addEventListener('change', () => { if (pasted.input.value) begin({ value: pasted.input.value }, errorText); });
    const submit = async (button, ai) => {
      errorText.textContent = '';
      if (pasted) {
        if (!pasted.input.value) { errorText.textContent = 'Pega la contraseña que te ha dado el panel.'; return; }
        save(button, errorText, { value: pasted.input.value }, ai);
      } else save(button, errorText, { pending: true }, ai);
    };
    saveButton.addEventListener('click', () => submit(saveButton, false));
    if (aiButton) aiButton.addEventListener('click', () => submit(aiButton, true));
    const own = el('button', { class: 'link small', onclick: () => {
      const typed = passwordInput({ placeholder: 'Tu contraseña nueva' });
      const use = el('button', { class: 'btn', onclick: async () => {
        if (!typed.input.value) return;
        if (await begin({ value: typed.input.value }, errorText)) { toast('Guardada como pendiente'); change(); }
      } }, 'Usar esta');
      own.replaceWith(el('div', { style: 'display:flex;gap:8px;margin-top:6px' }, el('div', { style: 'flex:1' }, typed), use));
      setTimeout(() => typed.input.focus(), 50);
    } }, 'Prefiero escribir la mía');
    const manualNodes = [
      guideSteps(guide.create || []),
      guide.command ? pendingBox('Comando (al copiarlo lleva la contraseña nueva)', 'command') : null,
      guide.command_note ? el('p', { class: 'help' }, guide.command_note) : null,
      guide.links && guide.links.length ? linkList(guide.links) : null,
    ];
    const manualBox = el('div', { class: 'manual-box' });
    const manualButtons = [el('button', { class: 'btn', onclick: where }, 'Atrás'), aiButton, saveButton];
    const showManual = () => {
      manualBox.replaceChildren(...manualNodes.filter(Boolean));
      foot.replaceChildren(el('div', { class: 'spacer' }), ...manualButtons.filter(Boolean));
    };
    const canApply = apply.available && guide.generate;
    const applyButton = canApply ? el('button', { class: 'btn primary' }, 'Aplicar ahora') : null;
    if (applyButton) applyButton.addEventListener('click', () => applyNow(applyButton, errorText, showManual));
    show(2, [
      guide.warning ? el('div', { class: 'warning' }, icon('alert', 'sm'), el('span', {}, guide.warning)) : null,
      pasted ? [guideSteps(guide.create || []), el('div', { class: 'field' }, el('label', {}, 'Contraseña nueva'), pasted,
        el('div', { class: 'help' }, 'Se guarda aquí como pendiente en cuanto la pegas: no se pierde aunque cierres.')),
      guide.links && guide.links.length ? linkList(guide.links) : null]
        : [pendingBox('Contraseña nueva · guardada aquí, aún sin aplicar'),
          el('div', { class: 'help' }, '32 letras y números aleatorios. La IA no la ve. ', own)],
      canApply ? el('p', { class: 'muted', style: 'margin-top:10px' }, `La app se conecta con la actual, la cambia con ${apply.client} y comprueba que entra con la nueva antes de guardarla.`)
        : !pasted && apply.reason ? el('p', { class: 'help', style: 'margin-top:10px' }, apply.reason) : null,
      pasted ? null : manualBox,
      errorText,
    ], canApply
      ? [el('button', { class: 'btn', onclick: where }, 'Atrás'), el('button', { class: 'btn', onclick: showManual }, 'Lo hago yo'), applyButton]
      : [el('button', { class: 'btn', onclick: where }, 'Atrás'), aiButton, saveButton]);
    if (!canApply && !pasted) manualBox.replaceChildren(...manualNodes.filter(Boolean));
  }

  // 2 · API keys: where to create the new one.
  const paired = guide.paired;
  let idChoice = null;  // 'same' | 'new': the user must say it, never assumed
  const oldId = paired ? paired.value : '';
  const create = () => show(2, [
    el('p', { class: 'muted' }, `Créala en ${site}. La actual sigue funcionando hasta que la anules, así que no se corta nada.`),
    guide.warning ? el('div', { class: 'warning' }, icon('alert', 'sm'), el('span', {}, guide.warning)) : null,
    guideSteps(guide.create || []),
    el('div', { class: 'prop' }, el('div', { style: 'min-width:0' }, el('div', { class: 'k' }, 'Nombre sugerido para la clave'),
      el('div', { class: 'v selectable' }, suggested)), el('div', { class: 'actions' }, copyButton(suggested))),
    guide.links && guide.links.length ? linkList(guide.links) : null,
    guide.source === 'ai' ? el('p', { class: 'help' }, icon('sparkles', 'sm'), ' Guía escrita por la IA. Fuentes: ',
      guide.sources.map((url, i) => [i ? ', ' : '', el('button', { class: 'link small', onclick: () => api().open_link(url) }, new URL(url).hostname)])) : null,
  ], [el('button', { class: 'btn', onclick: where }, 'Atrás'),
    el('button', { class: 'btn primary', onclick: paste }, 'Ya la tengo')]);

  // 3 · Paste it: tested before it replaces the current one (when it can be tested).
  function paste() {
    const group = passwordInput({ placeholder: 'Pega aquí la clave nueva' });
    const errorText = el('div', { class: 'error-text' });
    const saveButton = el('button', { class: 'btn primary' }, guide.testable ? 'Probar y guardar' : 'Guardar');
    const idInput = el('input', { class: 'input mono', placeholder: paired && paired.hint ? paired.hint : '', spellcheck: 'false' });
    saveButton.addEventListener('click', () => {
      errorText.textContent = '';
      const value = group.input.value.trim();
      if (!value && !pending) { errorText.textContent = 'Pega la clave nueva.'; return; }
      const params = value ? { value } : { pending: true };
      if (paired) {
        if (!idChoice) { errorText.textContent = `Indica si el ${paired.label} es el mismo o ha cambiado.`; return; }
        params.paired_id = idChoice === 'same' ? oldId : idInput.value.trim();
        if (idChoice === 'new' && (!params.paired_id || params.paired_id === oldId)) {
          errorText.textContent = `Pega el ${paired.label} nuevo.`; idInput.focus(); return;
        }
      }
      save(saveButton, errorText, params);
    });
    group.input.addEventListener('keydown', (event) => { if (event.key === 'Enter') saveButton.click(); });
    const idField = el('div', { class: 'field hidden' }, el('label', {}, `${paired ? paired.label : ''} nuevo`), idInput);
    const choice = (value, text) => el('label', { class: 'perm', style: 'cursor:pointer' },
      el('input', { type: 'radio', name: 'id-choice', value, checked: idChoice === value, onchange: () => {
        idChoice = value;
        errorText.textContent = '';
        idField.classList.toggle('hidden', value !== 'new');
        if (value === 'new') idInput.focus();
      } }), el('span', {}, text));
    const idQuestion = paired ? el('div', { class: 'field' },
      el('label', {}, `¿Y el ${paired.label}?`),
      choice('same', paired.value ? `Es el mismo (${paired.value}): solo he creado un secreto nuevo.` : 'Es el mismo: solo he creado un secreto nuevo.'),
      choice('new', `Ha cambiado: he creado ${guide.provider === 'Microsoft Entra' ? 'otra app' : 'otro cliente'} nuevo.`),
      idField) : null;
    // A secret of the user's own: generated and kept by the service, then copied to where it is used.
    const field = el('div', { class: 'field' });
    const renderField = () => field.replaceChildren(pending
      ? [pendingBox('Secreto nuevo · guardado aquí, aún sin aplicar'), el('div', { class: 'help' }, 'Cópialo a donde se usa y guárdalo. La IA no lo ve.')]
      : [el('label', {}, 'Clave nueva'), group,
        el('div', { class: 'help' }, guide.testable
          ? `Se prueba con ${known || 'su API'} antes de sustituir la actual: si no funciona, no se cambia nada. La IA no la ve.`
          : 'Esta clave no se puede probar desde aquí: comprueba que la has copiado entera. La IA no la ve.')]);
    renderField();
    const generate = guide.generate ? el('button', { class: 'btn', onclick: async () => {
      if (await begin({ generate: true }, errorText)) { renderField(); toast('Generado y guardado como pendiente: 48 bytes aleatorios'); }
    } }, pending ? 'Generar otro' : 'Generar uno aleatorio') : null;
    show(3, [field, generate, idQuestion, errorText], [el('button', { class: 'btn', onclick: create }, 'Atrás'), saveButton]);
    if (!pending) setTimeout(() => group.input.focus(), 50);
  }

  // Put it in every place: each one ticked before the old one is revoked (or, for a database, before finishing).
  // `how`: user (said it is changed), service (the app changed it and logged in with it) or ai (the AI will apply it).
  function update(result, how) {
    const check = result.check;
    const applyPrompt = `Aplica en la base de datos la contraseña nueva de «${entry.name}» (${entry.id}), que ya está guardada en SecretBroker: `
      + `${(guide.command || '').replace("'{password}'", '<la nueva>').replace('"{password}"', '<la nueva>').replace('{password}', '<la nueva>')} `
      + `Usa sb run o run_command con {{password}}, sin verla, y comprueba después que se conecta con ella.`;
    const step = database ? 3 : 4;
    const next = el('button', { class: 'btn primary', onclick: () => {
      if (!database) revoke(result.entry.retired, result.id_changed);
      else if (how === 'ai') done('Contraseña nueva guardada · falta que la IA la aplique en la base de datos');
      else done('Rotación completa');
    } }, database ? 'Terminar' : 'Siguiente');
    const left = el('div', { class: 'help' });
    const boxes = places.map(() => el('input', { type: 'checkbox' }));
    const sync = () => {
      const missing = boxes.filter((box) => !box.checked).length;
      next.disabled = missing > 0;
      left.textContent = missing ? `Falta${missing > 1 ? 'n' : ''} ${missing}. ${database ? 'Hasta que la pongas, esos sitios no pueden conectar.' : 'No anules la anterior hasta tenerlos todos.'}` : '';
    };
    boxes.forEach((box) => box.addEventListener('change', sync));
    sync();
    const uploads = el('div', {});
    const renderUploads = (list) => {
      const failed = list.filter((u) => !u.ok);
      const retry = failed.length ? el('button', { class: 'btn', onclick: async () => {
        const again = await retryUploads(entry, retry);
        if (again) renderUploads([...list.filter((u) => u.ok), ...again.uploads]);
      } }, 'Reintentar subida') : null;
      uploads.replaceChildren(...list.map((u) => line(u.ok, u.ok ? `Subida a ${u.label} como ${u.name}.` : `No se pudo subir a ${u.label}: ${u.error}. Ahí sigue la anterior.`)),
        retry ? el('div', { style: 'margin:4px 0 0 26px' }, retry) : '');
    };
    renderUploads(result.uploads);
    show(step, [
      how === 'ai' ? el('div', { class: 'warning' }, icon('alert', 'sm'), el('span', {},
        'Guardada aquí, pero la base de datos aún tiene la anterior. Pídele a la IA que la aplique (puede hacerlo con sb run sin verla; '
        + 'en un contenedor Docker no necesita la anterior):')) : null,
      how === 'ai' ? el('div', { class: 'prop' }, el('div', { class: 'v selectable', style: 'white-space:normal' }, applyPrompt),
        el('div', { class: 'actions' }, copyButton(applyPrompt))) : null,
      how === 'service' ? line(true, `Cambiada en la base de datos con ${apply.client} y comprobada: entra con la nueva.`) : null,
      database ? line(true, 'Guardada. La URL de conexión ya lleva la nueva.')
        : check && check.status === 'ok' ? line(true, `Funciona: ${check.provider} la acepta.`)
          : !guide.testable ? line(false, 'Esta clave no se puede probar desde aquí: comprueba en tu app que funciona.')
            : line(false, `No se pudo probar con ${provider}${check && check.message ? ` (${check.message})` : ''}; se ha guardado igualmente.`),
      line(true, 'La IA ya usa la nueva. Sus aprobaciones de esta credencial se han reiniciado.'),
      result.id_changed ? line(true, `${paired.label} nuevo guardado: ${result.entry.fields.username}.`) : null,
      (result.also_updated || []).map((o) => line(true, `También se ha cambiado el ID en «${o.name}».`)),
      uploads,
      env.length ? line(true, `Tus programas con sb run (${env.join(', ')}) la usarán al reiniciarlos.`) : null,
      exposureBefore && exposureBefore.found && !database ? line(false, `La clave anterior estaba en claro en ${exposureBefore.found} ${exposureBefore.found === 1 ? 'sitio' : 'sitios'}. En cuanto la anules, esas copias dejan de ser un riesgo.`) : null,
      places.length
        ? el('div', { class: 'field', style: 'margin-top:10px' },
          el('label', {}, `Ponla en cada sitio y márcalo${result.id_changed ? ` (y el ${paired.label} nuevo)` : ''}`),
          places.map((place, i) => el('label', { class: 'perm', style: 'cursor:pointer' }, boxes[i], el('span', {}, place))), left)
        : el('p', { class: 'help', style: 'margin-top:8px' }, `No hay sitios apuntados. Si la usas en otro sitio (un servidor, Vercel, otra app…), cámbiala allí también${database ? '' : ' antes de anular la anterior'}.`),
    ], [next]);
  }

  // Revoke the old key at the provider, and check it is dead. Only then is the rotation complete.
  function revoke(retired, idChanged) {
    const status = el('div', {});
    const checkable = retired && retired.checkable;
    const checkButton = el('button', { class: 'btn primary' }, 'Comprobar que ya no funciona');
    checkButton.addEventListener('click', async () => {
      busy(checkButton, true);
      const result = await api().call('check_retired', { id: entry.id });
      busy(checkButton, false);
      if (!result.ok) { status.replaceChildren(el('div', { class: 'error-text' }, result.error)); return; }
      const answer = result.result;
      refresh();
      if (answer.status === 'done') {
        finished = true;
        status.replaceChildren(el('div', { class: 'perm' }, icon('check', 'sm'), el('span', {}, 'La clave anterior ya no funciona. Rotación completa.')));
        foot.replaceChildren(el('div', { class: 'spacer' }), el('button', { class: 'btn primary', onclick: () => modal.close() }, 'Terminar'));
      } else {
        status.replaceChildren(el('div', { class: 'warning' }, icon('alert', 'sm'), el('span', {}, answer.status === 'alive'
          ? `Sigue funcionando. Anúlala en ${provider} y vuelve a comprobarlo (a veces tarda unos minutos).`
          : answer.message || 'No se pudo comprobar.')));
      }
    });
    const forget = el('button', { class: checkable ? 'btn ghost' : 'btn primary', onclick: async () => {
      const result = await api().call('forget_retired', { id: entry.id });
      if (!result.ok) { toast(result.error, 'error'); return; }
      refresh();
      done('Rotación completa');
    } }, 'Ya la he anulado');
    show(5, [
      el('p', { class: 'muted' }, idChanged
        ? `Como has creado ${guide.provider === 'Microsoft Entra' ? 'otra app' : 'otro cliente'}, borra el anterior (${oldId}) en ${provider}.`
        : guide.revoke || `Borra o revoca la clave anterior en ${provider}.`),
      guide.links && guide.links.length ? linkList(guide.links.slice(0, 1)) : null,
      el('p', { class: 'help' }, checkable
        ? 'Después, la app comprueba con el proveedor que ya no funciona. Si lo dejas para luego, te lo recordará.'
        : 'Esta clave no se puede comprobar desde aquí: avísame cuando la hayas anulado.'),
      status,
    ], [el('button', { class: 'btn', onclick: () => done('Clave nueva activa · falta anular la anterior') }, 'Más tarde'),
      forget, checkable ? checkButton : null]);
  }

  if (pending) resume();
  else where();
}

async function rotateEntry(entry) {
  const destinations = entry.destinations || [];
  const modal = openModal({
    title: `¿Rotar ${entry.name}?`,
    body: el('div', {},
      el('p', { class: 'muted' }, `${entry.rotation.provider} creará una clave nueva y la actual dejará de funcionar al momento. `,
        'Las apps que ya estén en marcha con la clave vieja fallarán hasta que las reinicies.'),
      destinations.length ? el('p', { class: 'muted' }, 'La nueva se subirá también a: ', destinations.map(destinationLabel).join(', '), '.') : null),
    footer: [
      el('button', { class: 'btn', onclick: () => modal.close() }, 'Cancelar'),
      el('button', { class: 'btn primary', onclick: async () => {
        modal.close();
        const result = await withProof((p) => api().call('rotate', { id: entry.id }, p), `Para rotar ${entry.name}.`);
        if (!result.ok) { if (result.code !== 'cancelled') toast(result.error, 'error'); return; }
        await loadEntries();
        renderMain();
        const failed = result.result.uploads.filter((u) => !u.ok);
        const check = result.result.check;
        if (failed.length) toast(`Rotada, pero no se pudo subir a ${failed.map((u) => u.label).join(', ')}: puedes reintentarlo desde la credencial`, 'error');
        else if (check && check.status === 'invalid') toast(`Rotada, pero ${check.message}`, 'error');
        else toast(destinations.length ? 'Rotación completa: la anterior ya no funciona y la nueva está subida' : 'Rotación completa: la anterior ya no funciona');
      } }, 'Rotar'),
    ],
  });
}

async function deleteEntry(entry) {
  const modal = openModal({
    title: `¿Eliminar ${entry.name}?`,
    body: [el('p', { class: 'muted' }, 'Se borrará de la bóveda y la IA dejará de poder usarla. No se puede deshacer.'),
      entry.shared ? el('div', { class: 'warning' }, icon('alert', 'sm'), el('span', {},
        `Es del equipo: se borrará para todos los de «${entry.shared.collection_name}». Si solo quieres dejar de compartirla, usa «Dejar de compartir».`)) : null],
    footer: [
      el('button', { class: 'btn', onclick: () => modal.close() }, 'Cancelar'),
      el('button', { class: 'btn solid-danger', onclick: async () => {
        modal.close();
        const result = await withProof((p) => api().call('delete_entry', { id: entry.id }, p), `Para eliminar ${entry.name}.`);
        if (!result.ok) { if (result.code !== 'cancelled') toast(result.error, 'error'); return; }
        state.selected = null;
        await loadEntries();
        renderMain();
        toast('Eliminada');
      } }, 'Eliminar'),
    ],
  });
}

// ----------------------------------------------------------------------- editor

function openEditor(entry) {
  if (entry) { showForm(entry.template, entry); return; }
  const modal = openModal({
    title: 'Nueva credencial',
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

  const namePlaceholders = { web_login: 'Panel de Hostinger', api_key: 'OpenAI producción', ssh: 'VPS producción', database: 'Base de datos de la tienda', aws: 'AWS personal', generic: 'Token de despliegue' };
  const nameInput = el('input', { class: 'input', value: isNew ? '' : entry.name, placeholder: namePlaceholders[templateId] });
  const idInput = el('input', { class: 'input mono', value: isNew ? '' : entry.id, spellcheck: 'false' });
  nameInput.addEventListener('input', () => { if (!touched.id) idInput.value = slugify(nameInput.value); });
  idInput.addEventListener('input', () => { touched.id = true; });

  const fieldsBox = el('div', { class: 'form-grid' });
  const labelFor = (spec) => spec.name === 'notes'
    ? el('label', { class: 'with-icon' }, icon('lock', 'sm'), 'Notas privadas', el('span', { class: 'req' }, ' (solo tú, cifradas)'))
    : el('label', {}, editorLabel(templateId, spec), !spec.required ? el('span', { class: 'req' }, ' · opcional') : null);

  const buildField = (spec) => {
    const existingSecret = spec.secret && secretsSet.includes(spec.name);
    const placeholder = existingSecret ? 'Guardada · escribe para cambiarla' : (spec.hint || '');
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
          : el('div', {}, el('button', { class: 'link small', type: 'button', onclick: () => file.click() }, 'Cargar desde un archivo'), file));
    } else if (spec.kind === 'secret') {
      const group = passwordInput({ placeholder });
      control = group.input;
      control.addEventListener('input', onFieldChange);
      const wide = ['value', 'secret_access_key'].includes(spec.name) || (templateId === 'ssh' && spec.name === 'password');
      const generate = generatorButtons(templateId, spec.name, control);  // personal.js; null where it makes no sense
      const withGenerate = generate ? el('div', { style: 'display:flex;gap:8px' }, el('div', { style: 'flex:1' }, group), generate) : group;
      if (templateId === 'database' && spec.name === 'password') {
        const note = el('div', { class: 'warning hidden' }, icon('alert', 'sm'), el('span', {}, existingSecret
          ? 'Guardarla aquí no cambia la contraseña en el servidor: después hay que aplicarla en la base de datos (ALTER ROLE…), o pedírselo a la IA, que puede hacerlo con sb run sin verla. «Rotar con ayuda» te guía en todo.'
          : 'Si el usuario aún no existe, créalo en la base de datos con esta contraseña (o pídeselo a la IA).'));
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
    fieldsBox.replaceChildren(activeSpecs(templateId, snapshot).map(buildField));
    for (const [name, control] of Object.entries(inputs)) if (snapshot[name]) control.value = snapshot[name];
  };

  const notes = el('textarea', { class: 'input', rows: 3, placeholder: 'Ej.: cuenta de producción. Úsala solo para consultar pedidos, nunca para borrar.' }, isNew ? '' : entry.description);
  const tagsInput = el('input', { class: 'input', placeholder: 'tienda, produccion', value: isNew ? '' : (entry.tags || []).join(', ') });
  const expiresInput = el('input', { class: 'input', type: 'date', value: isNew ? '' : (entry.expires || '') });
  const currentEvery = isNew ? null : (entry.rotate_every_days ?? null);
  const everyInput = el('select', { class: 'input' }, ROTATE_EVERY.map(([days, label]) =>
    el('option', { value: days === null ? '' : String(days), selected: days === currentEvery }, label)));
  const checkEvery = checkEveryControl(isNew ? null : (entry.check_every_hours ?? null), true);
  const autofillBox = templateId === 'web_login' ? autofillEditor(entry) : null;
  const usedInput = el('textarea', { class: 'input', rows: 3, placeholder: 'develop: .env local (DATABASE_URL)\npro: servidor api.ejemplo.com, /srv/app/.env\nVercel: proyecto web' },
    isNew ? '' : (entry.used_in || []).join('\n'));

  const approval = el('div', { class: 'segmented' });
  const renderApproval = () => approval.replaceChildren(Object.entries(APPROVAL_LABELS).map(([k, label]) => el('button', {
    type: 'button', class: (policy.approval || 'session') === k ? 'active' : '', onclick: () => { policy.approval = k; renderApproval(); },
  }, label)));
  renderApproval();

  const hostsInput = el('input', { class: 'input mono', placeholder: 'api.ejemplo.com, *.ejemplo.com', spellcheck: 'false' });
  const authKind = el('select', { class: 'input' }, Object.entries(AUTH_LABELS).map(([k, v]) => el('option', { value: k }, v)));
  const authName = el('input', { class: 'input mono', placeholder: 'Authorization', spellcheck: 'false' });
  const authTemplate = el('input', { class: 'input mono', placeholder: 'Bearer {{value}}', spellcheck: 'false' });
  const authDetails = el('div', { class: 'form-grid' },
    el('div', { class: 'field' }, el('label', {}, 'Nombre'), authName),
    el('div', { class: 'field' }, el('label', {}, 'Valor'), authTemplate));
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
    el('summary', {}, el('span', { class: 'chev' }, icon('chevronRight', 'sm')), 'Permisos de la IA',
      el('span', { class: 'hint' }, 'qué puede hacer y cuándo te pregunta')),
    el('div', { class: 'inner' },
      el('div', { class: 'field' }, el('label', {}, 'Pedir tu aprobación'), approval),
      templateId !== 'ssh' ? el('div', { class: 'field' }, el('label', {}, 'Webs donde puede usarla'), hostsInput,
        el('div', { class: 'help' }, 'Dominios separados por comas. Nunca se enviará a otros sitios.')) : null,
      templateId !== 'ssh' ? el('div', { class: 'field' }, el('label', {}, 'Añadirla a las peticiones'), authKind, authDetails) : null,
      el('div', { class: 'field' }, el('label', {}, 'Programas que pueden usarla'), commandsInput,
        el('div', { class: 'help' }, 'Solo nombres, como gh o psql. La reciben en las variables de entorno de abajo.')),
      el('div', { class: 'field' }, el('label', {}, 'Variables de entorno'), envInput),
      templateId === 'web_login' ? el('div', { class: 'field' }, el('label', { class: 'check-row' }, totpForAi, 'Dejar que la IA escriba el código 2FA'),
        el('div', { class: 'help' }, 'Como ', el('code', {}, '{{totp_code}}'), ', sin verlo. Déjalo apagado salvo que un proceso automático lo necesite: por defecto la IA no tiene tus códigos 2FA.')) : null,
      el('div', { class: 'field' }, el('label', {}, 'Nombre para la IA'), idInput),
      el('div', { class: 'field' }, el('label', {}, 'Datos que la IA puede insertar sin verlos'), placeholderList)));

  const errorText = el('div', { class: 'error-text' });
  const saveButton = el('button', { class: 'btn primary' }, 'Guardar');
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
      if (index < 1) throw new Error(`A la variable «${line.trim()}» le falta el «=».`);
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
      el('div', {}, el('b', {}, 'Cambió mientras editabas'), changed.length ? `: ${listJoin(changed)}.` : '.'),
      el('div', { class: 'muted small' }, '«Recargar» descarta tus cambios y abre la versión nueva; «Sobrescribir» guarda la tuya encima.'),
      el('div', { class: 'conflict-actions' },
        el('button', { class: 'btn', onclick: () => { modal.close(); showForm(fresh.template, fresh); } }, 'Recargar'),
        el('button', { class: 'btn', onclick: () => { base = fresh.updated; baseVersion = fresh.version || null; conflictBox.classList.add('hidden'); save(); } }, 'Sobrescribir'))));
    conflictBox.classList.remove('hidden');
    conflictBox.scrollIntoView({ block: 'nearest' });
  };

  const save = async () => {
    errorText.textContent = '';
    let newEntry;
    try { newEntry = collect(); } catch (error) { errorText.textContent = error.message; return; }
    if (!newEntry.name) { errorText.textContent = 'Ponle un nombre.'; nameInput.focus(); return; }
    busy(saveButton, true);
    const result = await withProof((p) => api().call('save_entry', { entry: newEntry, replaces: isNew ? null : entry.id, base_updated: base, base_version: baseVersion }, p), `Para guardar «${newEntry.name}».`);
    busy(saveButton, false);
    if (!result.ok && result.code === 'conflict') {
      await loadEntries();
      const fresh = state.entries.find((e) => e.id === entry.id);
      if (fresh) showConflict(fresh);
      else errorText.textContent = 'Se ha eliminado mientras editabas.';
      return;
    }
    if (!result.ok) { if (result.code !== 'cancelled') errorText.textContent = friendlyError(result.error, templateId); return; }
    modal.close();
    state.selected = result.result.id;
    state.view = 'credentials';
    await loadEntries();
    renderMain();
    toast(isNew ? 'Guardada' : 'Cambios guardados');
  };
  saveButton.addEventListener('click', save);

  const modal = openModal({
    title: isNew ? template.label : entry.name,
    wide: true,
    lead: glyph(templateId),
    body: [
      readOnly ? el('div', { class: 'warning' }, icon('info', 'sm'), el('span', {},
        `Es del equipo y tu permiso es «${PERMISSION_LABELS[entry.shared.permission]}»: aquí solo puedes cambiar cuándo te pide aprobación la IA.`)) : null,
      conflictBox,
      el('div', { class: 'field' }, el('label', {}, 'Nombre'), nameInput),
      isNew && ['api_key', 'generic'].includes(templateId) ? keySourcePicker() : null,
      fieldsBox,
      el('div', { class: 'field' }, el('label', { class: 'with-icon' }, icon('bot', 'sm'), 'Instrucciones para la IA',
        el('span', { class: 'req' }, ' (la IA las lee) · opcional')), notes,
        el('div', { class: 'help' }, 'Qué es y cómo debe usarla. No pongas aquí nada secreto: para eso están las notas privadas.')),
      el('div', { style: 'display:flex;gap:12px' },
        el('div', { class: 'field', style: 'flex:2' }, el('label', {}, 'Etiquetas', el('span', { class: 'req' }, ' · opcional')), tagsInput,
          el('div', { class: 'help' }, 'Para agruparlas, por ejemplo por proyecto.')),
        el('div', { class: 'field', style: 'flex:1' }, el('label', {}, 'Caduca', el('span', { class: 'req' }, ' · opcional')), expiresInput),
        el('div', { class: 'field', style: 'flex:1' }, el('label', {}, 'Recordar rotarla'), everyInput)),
      el('div', { class: 'field' }, el('label', {}, 'Comprobar que funciona'), checkEvery.node,
        el('div', { class: 'help' }, 'Una llamada de solo lectura al proveedor (o entrar y salir del servidor SSH). «Ajuste general» sigue el de Ajustes.')),
      el('div', { class: 'field' }, el('label', {}, 'Dónde se usa', el('span', { class: 'req' }, ' · opcional')), usedInput,
        el('div', { class: 'help' }, 'Un sitio por línea: develop, pre, pro, cada servidor, Vercel, CI, otros proyectos… Al rotarla, la app te pedirá cambiarla en cada uno.')),
      advanced,
      autofillBox ? autofillBox.node : null,
      errorText,
    ],
    footer: [
      isNew ? el('button', { class: 'btn ghost', onclick: () => { changingType = true; modal.dismiss(); } }, icon('arrowLeft', 'sm'), 'Cambiar tipo') : null,
      el('div', { class: 'spacer' }),
      el('button', { class: 'btn', onclick: () => { changingType = false; modal.dismiss(); } }, 'Cancelar'),
      saveButton,
    ],
    // Esc, the X or «Cancelar» with changes: ask first. A click outside never closes it.
    confirmClose: () => (dirty ? { title: '¿Descartar cambios?', text: 'Lo que has cambiado en esta credencial no se guardará.' } : null),
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
  if (!same(before.name, after.name)) labels.push('Nombre');
  const specs = TEMPLATES[after.template] ? TEMPLATES[after.template].fields : [];
  for (const spec of specs) {
    const changed = spec.secret
      ? before.secrets_set.includes(spec.name) !== after.secrets_set.includes(spec.name) || (!spec.note && before.secret_since !== after.secret_since)
      : !same(before.fields[spec.name] || null, after.fields[spec.name] || null);
    if (changed) labels.push(spec.name === 'notes' ? 'Notas privadas' : fieldLabel(after.template, spec));
  }
  if (!same(before.description, after.description)) labels.push('Instrucciones para la IA');
  if (!same(before.tags, after.tags)) labels.push('Etiquetas');
  if (!same(before.expires, after.expires)) labels.push('Caduca');
  if (!same(before.rotate_every_days, after.rotate_every_days)) labels.push('Recordar rotarla');
  if (!same(before.check_every_hours, after.check_every_hours)) labels.push('Comprobar que funciona');
  if (!same(before.used_in, after.used_in)) labels.push('Dónde se usa');
  if (!same(before.policy, after.policy)) labels.push('Permisos de la IA');
  return [...new Set(labels)];
}

// ----------------------------------------------------------------------- exposure

const LEVELS = {
  exposed: { label: 'Expuesta', order: 0 },
  warning: { label: 'Revisar', order: 1 },
  unknown: { label: 'Sin comprobar', order: 2 },
  ok: { label: 'Sin copias conocidas', order: 3 },
};
const SOURCE_LABELS = {
  ai: 'Conversación con IA', history: 'Historial de terminal', config: 'Configuración', env: 'Variable de entorno',
  project: 'Archivo de proyecto', git: 'Historial de git',
};

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
  if (days < 1) return 'hoy';
  if (days < 45) return `hace ${days} ${days === 1 ? 'día' : 'días'}`;
  if (days < 365) return `hace ${Math.round(days / 30)} meses`;
  const years = Math.floor(days / 365);
  return `hace ${years} ${years === 1 ? 'año' : 'años'}`;
}

function exposureFacts(item) {
  const facts = [];
  const alive = item.alive;
  if (alive && alive.status === 'ok') facts.push(`Funciona en ${alive.provider} (${formatTime(alive.checked)})`);
  if (alive && alive.status === 'unknown') facts.push(`${alive.provider}: ${alive.message}`);
  if (item.pwned && !item.pwned.count) facts.push('No aparece en filtraciones conocidas');
  facts.push(item.age_days !== null ? `Valor puesto ${ageText(item.age_days)}` : 'Antigüedad desconocida');
  if (item.revealed) facts.push(`Mostrada o copiada ${item.revealed} ${item.revealed === 1 ? 'vez' : 'veces'}`);
  return el('div', { class: 'facts faint small' }, facts.join(' · '));
}

function scanProgress() {
  const scan = state.scan || {};
  const read = `${scan.files || 0} archivos leídos · ${Math.round((scan.bytes || 0) / 1e6)} MB`;
  return el('div', { class: 'scan-progress' }, el('div', { class: 'spinner' }),
    el('div', { class: 'meta' }, el('div', {}, scan.phase || 'Preparando'),
      el('div', { class: 'muted small' }, read, scan.skipped ? ` · ${scan.skipped} sin cambios` : '')),
    el('button', { class: 'btn ghost', onclick: () => api().cancel_scan() }, 'Cancelar'));
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
    if (exposed) toast(`Búsqueda terminada: ${exposed} ${exposed === 1 ? 'credencial expuesta' : 'credenciales expuestas'}`, 'error');
    else toast('Búsqueda terminada: no hay copias de tus claves');
  }
  if (state.screen === 'main') renderMain();
}

async function startScan(button) {
  busy(button, true);
  const result = await withProof((p) => api().start_scan(p), 'Para buscar copias de tus claves en los archivos de este PC.');
  busy(button, false);
  if (!result.ok) { if (result.code !== 'cancelled') toast(result.error, 'error'); return; }
  state.scan = { running: true };
  renderMain();
}

// «Revisar ahora»: search for copies and test every key with its provider, at once.
async function reviewNow(button) {
  busy(button, true);
  const [scan, check] = await Promise.all([
    withProof((p) => api().start_scan(p), 'Para buscar copias de tus claves en los archivos de este PC.'),
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
  const result = await withProof((p) => api().open_exposure_session(p), 'Para ver en qué archivos están tus claves.');
  if (!result.ok) { if (result.code !== 'cancelled') toast(result.error, 'error'); return; }
  await loadExposure();
  renderMain();
}

function renderExposure(content) {
  const report = state.exposure;
  const scanning = !!(state.scan && state.scan.running);
  const complete = !!(report && report.last_scan && report.last_check);
  const reviewButton = el('button', { class: `btn ${complete ? '' : 'primary'}`, disabled: scanning,
    title: 'Busca copias de tus claves en este PC y prueba cada una con su proveedor' }, icon('search', 'sm'), 'Revisar ahora');
  reviewButton.addEventListener('click', () => reviewNow(reviewButton));
  const header = el('div', { class: 'content-header' }, el('h1', {}, 'Salud'), reviewButton);
  if (!report) {
    content.replaceChildren(header, el('div', { class: 'content-body' }, el('div', { class: 'empty' }, el('p', {}, 'No se pudo cargar el estado.'))));
    return;
  }

  const entries = Object.fromEntries(state.entries.map((e) => [e.id, e]));
  const items = report.entries.filter((item) => entries[item.id])
    .sort((a, b) => LEVELS[a.level].order - LEVELS[b.level].order || entries[a.id].name.localeCompare(entries[b.id].name));
  const found = items.filter((item) => ['exposed', 'warning'].includes(item.level) || item.ignored);
  const hidden = !report.details && items.some((item) => item.found || item.found_before);
  const scanButton = el('button', { class: 'btn ghost', disabled: scanning }, 'Buscar copias');
  scanButton.addEventListener('click', () => startScan(scanButton));
  const body = el('div', { class: 'content-body' },
    offboardingPeople().map((person) => offboardingCard(person, true)),  // someone left the team: keys to change
    healthSection(),  // personal.js: score, weak / reused / old secrets, unfinished rotations
    el('div', { class: 'section-head' }, el('h2', { class: 'section-title' }, 'Copias encontradas'), scanButton),
    scanning ? scanProgress() : null,
    el('div', { class: 'exposure-summary' },
      el('p', { class: 'muted' }, 'Busca tus claves en las conversaciones con IA, los historiales de la terminal, la configuración de tus programas, las variables de entorno, tus proyectos y su historial de git. Todo ocurre en este PC.'),
      el('div', { class: 'faint small' },
        report.last_scan ? `Última búsqueda: ${whenText(report.last_scan.ts)} · ${report.last_scan.files} archivos` : 'Aún no se han buscado copias'),
      hidden ? el('div', { class: 'small' }, el('span', { class: 'muted' }, 'Las rutas solo se muestran tras verificar tu identidad. '),
        el('button', { class: 'link small', onclick: showWhere }, 'Ver en qué archivos')) : null),
    found.length ? el('div', { class: 'exposure-list' }, found.map((item) => exposureCard(item, entries[item.id])))
      : report.last_scan ? el('p', { class: 'muted small' }, 'Ninguna copia de tus claves en lo revisado.') : null);
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
    title: '¿Borrar la clave de este archivo?',
    text: `Se cambia por [REDACTED:${entry.id}] en ${place(f.location)}. Se guarda una copia del archivo al lado (.secretbroker.bak) por si algo fallara: bórrala cuando compruebes que todo va bien.`,
    warning: f.source === 'ai' ? 'La IA ya la vio y la envió a su proveedor: aunque la borres de aquí, rótala.' : null,
    action: 'Borrar de este archivo',
    onConfirm: async () => {
      act(button, () => api().redact_finding(entry.id, f.location), (r) => (r.count ? `Borrada del archivo (${r.count} ${r.count === 1 ? 'vez' : 'veces'})` : 'Ya no estaba en el archivo'));
      return true;
    },
  });
  const actions = (f) => {
    const buttons = [];
    if (f.ignored) {
      buttons.push(el('button', { class: 'btn ghost sm', onclick: (e) => act(e.currentTarget, () => api().ignore_finding(entry.id, f.location, false)) }, 'Volver a contar'));
      return buttons;
    }
    if (f.redacted && !f.present && redactable(f)) {
      // The copy left next to the file still has it: once the user is happy, delete it too.
      buttons.push(el('button', { class: 'btn ghost sm', onclick: async (e) => {
        const button = e.currentTarget;
        toast(await api().delete_redaction_backup(`${f.location}.secretbroker.bak`) ? 'Copia borrada' : 'Ya no había copia');
        button.remove();
      } }, 'Borrar la copia'));
    }
    if (!f.present) return buttons;
    if (backup(f.location)) {
      buttons.push(el('button', { class: 'btn ghost sm', onclick: async () => {
        if (await api().delete_redaction_backup(f.location)) { toast('Copia borrada. La próxima búsqueda dejará de encontrarla'); }
      } }, 'Borrar la copia'));
    } else if (redactable(f)) {
      buttons.push(el('button', { class: 'btn ghost sm', onclick: (e) => redact(f, e.currentTarget) }, 'Borrar de este archivo'));
    }
    buttons.push(el('button', { class: 'btn ghost sm', title: 'Un archivo de pruebas, una copia que quieres tener… Deja de contar como problema',
      onclick: (e) => act(e.currentTarget, () => api().ignore_finding(entry.id, f.location, true), 'Ignorada') }, 'Ignorar'));
    if (!f.location.startsWith('env:')) {
      buttons.push(el('button', { class: 'btn icon-only', title: 'Mostrar en su carpeta', onclick: () => api().show_location(f.location) }, icon('external', 'sm')));
    }
    return buttons;
  };
  const writable = canWrite(entry);
  return el('div', { class: `exposure-card is-${item.level}`, 'data-entry': entry.id },
    el('div', { class: 'exposure-head' },
      glyph(entry.template),
      el('div', { class: 'meta' }, el('div', { class: 'title' }, entry.name), el('div', { class: 'subtitle' }, subtitleOf(entry))),
      levelBadge(item.level),
      el('button', { class: 'btn ghost', onclick: () => { state.selected = entry.id; state.view = 'credentials'; renderMain(); } }, 'Abrir'),
      writable && ['exposed', 'warning'].includes(item.level)
        ? el('button', { class: 'btn primary', onclick: () => rotateWithHelp(entry) }, icon('rotate', 'sm'), 'Rotar con ayuda') : null),
    item.reasons.length ? el('ul', { class: 'reasons' }, item.reasons.map((r) => el('li', { class: `is-${r.level}` }, r.text))) : null,
    exposureFacts(item),
    findings.length ? el('details', { class: 'findings', open: item.level === 'exposed' || findings.some((f) => f.redacted || f.ignored) },
      el('summary', {}, `${findings.length} ${findings.length === 1 ? 'sitio' : 'sitios'}${item.ignored ? ` · ${item.ignored} ${item.ignored === 1 ? 'ignorado' : 'ignorados'}` : ''}`),
      findings.map((f) => el('div', { class: `finding ${f.present && !f.ignored ? '' : 'gone'}` },
        el('span', { class: 'source' }, backup(f.location) ? 'Copia de seguridad' : SOURCE_LABELS[f.source] || f.source),
        el('span', { class: 'path selectable', title: place(f.location) }, shortPath(place(f.location))),
        el('span', { class: 'faint' }, f.ignored ? 'ignorado' : f.redacted && !f.present ? 'borrada de aquí' : f.present ? `desde ${formatTime(f.first_seen)}` : 'ya no está'),
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
const ACTIVITY_FILTERS = [[null, 'Todo', null], ['ai', 'IA', 'bot'], ['browser', 'Navegador', 'globe'], ['denied', 'Denegadas', null], ['team', 'Equipo', 'users']];

// [kind, icon, label]: who did it.
function eventActor(e) {
  const actor = e.actor || (AI_EVENT_ACTIONS.has(e.action) ? 'ai' : e.action === 'team_conflict' ? 'team' : 'user');
  if (actor === 'ai') return ['ai', 'bot', 'IA'];
  if (actor === 'browser') return ['browser', 'globe', 'Navegador'];
  if (actor === 'team') return ['team', 'users', e.by || 'Equipo'];
  if (actor === 'system') return ['system', 'shield', 'SecretBroker'];
  return ['user', 'user', 'Tú'];
}

function isTeamEvent(e) {
  return e.actor === 'team' || e.action.startsWith('team_') || TEAM_EVENT_ACTIONS.has(e.action);
}

function dayLabel(date) {
  const today = new Date();
  const days = Math.round((new Date(today.getFullYear(), today.getMonth(), today.getDate())
    - new Date(date.getFullYear(), date.getMonth(), date.getDate())) / 86400000);
  if (days === 0) return 'Hoy';
  if (days === 1) return 'Ayer';
  const text = date.toLocaleDateString('es-ES', { weekday: 'long', day: 'numeric', month: 'long',
    year: date.getFullYear() === today.getFullYear() ? undefined : 'numeric' });
  return text.charAt(0).toUpperCase() + text.slice(1);
}

async function renderActivity(content) {
  const filter = state.activityFilter || (state.activityFilter = { kind: null, secret: '' });
  const body = el('div', { class: 'content-body' }, el('div', { class: 'spinner' }));
  const filters = el('div', { class: 'activity-filters' });
  content.replaceChildren(el('div', { class: 'content-header' }, el('h1', {}, 'Actividad'),
    el('button', { class: 'btn ghost', onclick: () => renderActivity(content) }, 'Actualizar')), filters, body);
  const result = await api().call('audit', { limit: ACTIVITY_PAGE });
  let events = result.ok ? result.result : [];
  let more = events.length === ACTIVITY_PAGE;
  if (!events.length) { filters.remove(); body.replaceChildren(el('div', { class: 'empty' }, el('p', {}, 'Aún no hay actividad.'))); return; }
  const names = Object.fromEntries(state.entries.map((e) => [e.id, e.name]));

  const credentials = el('select', { class: 'input compact', title: 'Solo una credencial' },
    el('option', { value: '' }, 'Todas las credenciales'),
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
    const detail = e.message || e.detail;
    return el('div', { class: 'event' },
      el('span', { class: 'time', title: date ? date.toLocaleString('es-ES') : '' },
        date ? date.toLocaleTimeString('es-ES', { hour: '2-digit', minute: '2-digit' }) : ''),
      el('span', { class: `actor is-${kind}` }, icon(actorIcon, 'sm'), el('span', {}, actorLabel)),
      el('div', { class: 'what' },
        el('div', {}, ACTION_LABELS[e.action] || e.action,
          e.secret && e.secret !== 'vault' ? el('span', { class: 'credential' }, ` · ${names[e.secret] || e.secret}`) : null),
        detail ? el('div', { class: `event-detail selectable ${MONO_EVENT_ACTIONS.has(e.action) && !e.message ? 'mono' : ''}`,
          title: [e.detail, e.message].filter(Boolean).join(' — ') }, detail) : null),
      failed ? el('span', { class: 'chip is-exposed failed' }, e.status === 'denied' ? 'Denegada' : 'Error') : el('span'));
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
      const label = e.ts ? dayLabel(new Date(e.ts)) : 'Sin fecha';
      if (label !== day) { day = label; list.append(el('div', { class: 'day-head' }, label)); }
      list.append(row(e));
    }
    if (!matching.length) list.append(el('p', { class: 'muted', style: 'padding:12px 0' }, more ? 'Nada así en lo más reciente.' : 'Nada así en la actividad.'));
    if (more) {
      const button = el('button', { class: 'btn' }, 'Cargar más');
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
  const result = paused ? await api().call('pause_ai') : await withProof((p) => api().call('resume_ai', {}, p), 'Para reanudar la IA.');
  if (!result.ok) { if (result.code !== 'cancelled') toast(result.error, 'error'); return; }
  toast(paused ? 'IA en pausa' : 'IA reanudada');
  await refreshStatus();
  renderMain();
}

async function renderAccess(content) {
  const paused = state.status.ai_paused;
  const body = el('div', { class: 'content-body' }, el('div', { class: 'spinner' }));
  content.replaceChildren(el('div', { class: 'content-header' }, el('h1', {}, 'Acceso de la IA')), body);
  const [result, permissions, clients] = await Promise.all([api().call('grants'), api().call('ai_permissions'), loadAiClients()]);
  const grants = result.ok ? result.result : [];
  const approved = grants.filter((g) => g.kind === 'approved');
  const free = grants.filter((g) => g.kind === 'never');
  const revoke = async (secretId) => {
    await api().call('revoke_sessions', secretId ? { secret_id: secretId } : {});
    toast(secretId ? 'Aprobación retirada' : 'Aprobaciones retiradas');
    await refreshStatus();
    renderAccess(content);
  };
  const row = (g, control) => el('div', { class: 'access-row' }, glyph(g.template),
    el('div', { class: 'meta' }, el('div', { class: 'title' }, g.name),
      el('div', { class: 'subtitle' }, g.kind === 'never' ? 'Nunca pregunta' : g.until ? `Hasta ${formatTime(g.until)}` : 'Hasta que bloquees')),
    control);
  body.replaceChildren(el('div', { class: 'settings' },
    aiClientsGroup(clients, () => renderAccess(content)),  // connect.js
    el('div', { class: `pause-card ${paused ? 'paused' : ''}` },
      el('div', { class: 'meta' },
        el('h3', {}, paused ? 'La IA está en pausa' : 'La IA puede trabajar'),
        el('p', {}, paused
          ? 'No puede usar, crear ni ver ninguna credencial. Tú sigues usando la bóveda con normalidad.'
          : 'Usa tus credenciales según sus permisos. Pausarla corta todo al instante, sin bloquear la bóveda.')),
      el('button', { class: `btn ${paused ? 'primary' : 'danger'}`, onclick: () => setPaused(!paused) }, icon('power', 'sm'), paused ? 'Reanudar' : 'Pausar la IA')),
    permissions.ok ? permissionsGroup(permissions.result, () => renderAccess(content)) : null,
    el('div', { class: 'settings-group' },
      el('div', { class: 'group-head' }, el('h3', { class: 'muted' }, 'Aprobadas ahora'),
        approved.length > 1 ? el('button', { class: 'btn ghost', onclick: () => revoke(null) }, 'Retirar todas') : null),
      approved.length
        ? approved.map((g) => row(g, el('button', { class: 'btn', onclick: () => revoke(g.secret_id) }, 'Retirar')))
        : el('p', { class: 'muted small' }, 'Ninguna. La próxima vez que la IA use una credencial te preguntará.')),
    el('div', { class: 'settings-group' }, el('h3', { class: 'muted' }, 'Nunca preguntan'),
      free.length
        ? free.map((g) => row(g, el('button', { class: 'btn', onclick: () => { state.view = 'credentials'; state.selected = g.secret_id; renderMain(); } }, 'Cambiar')))
        : el('p', { class: 'muted small' }, 'Todas las credenciales piden tu aprobación al menos una vez.'))));
}

const AI_LEVEL_LABELS = [['free', 'Libre'], ['notify', 'Avisarme'], ['ask', 'Preguntarme'], ['off', 'Nunca']];
const AI_LEVEL_HELP = {
  free: 'Libre: lo hace siguiendo los permisos de cada credencial.',
  notify: 'Avisarme: igual que Libre, y te llega un aviso de Windows.',
  ask: 'Preguntarme: te lo pide cada vez.',
  off: 'Nunca: se lo deniega.',
};
// The capabilities in three groups; one the app doesn't know yet goes with «Modificar».
const AI_CAPABILITY_GROUPS = [['Usar', ['local_env']], ['Modificar', ['create', 'edit_notes', 'edit_config', 'rotate']], ['Publicar', ['github']]];

function permissionsGroup(data, rerender) {
  const save = async (changes) => {
    const result = await withProof((p) => api().call('set_ai_permissions', changes, p), 'Para dar más permisos a la IA.');
    if (result.ok) toast('Guardado'); else if (result.code !== 'cancelled') toast(result.error, 'error');
    rerender();
  };
  const notify = el('input', { type: 'checkbox', checked: data.notify_uses });
  notify.addEventListener('change', () => save({ notify_uses: notify.checked }));
  const known = new Set(AI_CAPABILITY_GROUPS.flatMap(([, ids]) => ids));
  const groups = AI_CAPABILITY_GROUPS.map(([label, ids]) => [label, [
    ...ids.map((id) => data.capabilities.find((c) => c.id === id)).filter(Boolean),
    ...(label === 'Modificar' ? data.capabilities.filter((c) => !known.has(c.id)) : []),
  ]]).filter(([, caps]) => caps.length);
  const levelName = (level) => AI_LEVEL_LABELS.find(([l]) => l === level)[1];
  const row = (c) => el('div', { class: `ai-row ${c.level === 'off' ? 'is-off' : ''}`, role: 'radiogroup', 'aria-label': c.label },
    el('div', { class: 'meta' }, el('div', { class: 'title' }, c.label),
      c.level === c.default ? null : el('div', { class: 'changed' }, 'Cambiado · ',
        el('button', { class: 'link', title: `Volver al recomendado: ${levelName(c.default)}`,
          onclick: () => save({ permissions: { [c.id]: c.default } }) }, 'Restablecer'))),
    AI_LEVEL_LABELS.map(([level, label]) => {
      const radio = el('input', { type: 'radio', name: `ai-${c.id}`, value: level, checked: c.level === level, 'aria-label': label });
      radio.addEventListener('change', () => { if (radio.checked && c.level !== level) save({ permissions: { [c.id]: level } }); });
      return el('label', { title: AI_LEVEL_HELP[level] }, radio);
    }));
  return el('div', { class: 'settings-group' },
    el('h3', { class: 'muted' }, 'Qué puede hacer la IA'),
    el('p', { class: 'muted small', style: 'margin:2px 0 10px' }, 'Además de usar las credenciales. Pasa el ratón por cada columna para ver qué significa.'),
    el('div', { class: 'ai-grid' },
      el('div', { class: 'ai-grid-head' }, el('span'),
        AI_LEVEL_LABELS.map(([level, label]) => el('span', { title: AI_LEVEL_HELP[level] }, label))),
      groups.map(([label, caps]) => [el('div', { class: 'ai-group' }, label), caps.map(row)])),
    setting('Avisarme cuando use credenciales que no preguntan', 'Un aviso de Windows, como mucho uno cada 10 minutos por credencial.', notify));
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

const ROLE_LABELS = { owner: 'Propietario', admin: 'Administrador', member: 'Miembro' };
const PERMISSION_LABELS = { manage: 'Gestor', edit: 'Editor', view: 'Lector', use: 'Solo uso' };
const PERMISSION_HELP = {
  manage: 'Gestor: añade y quita personas, edita y cambia las claves.',
  edit: 'Editor: cambia las credenciales y rota sus claves.',
  view: 'Lector: la IA y tus programas pueden usarlas, y tú puedes verlas y copiarlas.',
  use: 'Solo uso: la IA y tus programas pueden usarla; tú no puedes verla ni copiarla.',
};
const USE_ONLY_NOTE = '«Solo uso» lo hace cumplir la app: alguien con una app modificada podría sacarla, como en otros gestores.';
const EVENT_LABELS = {
  'org.create': 'Creó la organización', invite: 'Invitó a', 'invite.delete': 'Retiró la invitación de',
  join: 'Aceptó la invitación', 'member.confirm': 'Confirmó a', 'member.remove': 'Quitó a', 'member.leave': 'Salió',
  'member.role': 'Cambió el rol de', 'collection.create': 'Creó la colección', 'collection.delete': 'Borró la colección',
  grant: 'Dio acceso a', revoke: 'Quitó el acceso a', rotate: 'Volvió a cifrar', 'item.put': 'Guardó una credencial en',
  'item.delete': 'Borró una credencial de',
};
const RELEASES_URL = 'https://github.com/xBofi/SecretBroker/releases/latest';

// «Bob», «Bob y Carol», «Bob, Carol e Inés».
function listJoin(names) {
  const list = (names || []).filter(Boolean).map(String);
  if (list.length < 2) return list[0] || '';
  const last = list[list.length - 1];
  return `${list.slice(0, -1).join(', ')} ${/^h?i(?![aeiouáéíóú])/i.test(last) ? 'e' : 'y'} ${last}`;
}

function plural(n, one, many) {
  return `${n} ${n === 1 ? one : many}`;
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

function sharedBadge(shared) {
  return el('span', { class: 'shared-badge', title: `Tu permiso: ${PERMISSION_LABELS[shared.permission]}. ${PERMISSION_HELP[shared.permission].split(': ')[1]}` },
    icon('users', 'sm'), `Compartida · ${shared.collection_name || 'Equipo'}`);
}

// Why a shared credential's edit has not reached the team yet (null: nothing waiting, or it goes out now).
function unsentText(entry) {
  const shared = entry.shared;
  if (!shared || !shared.unsent) return null;
  if (shared.unsent === 'rekey') {
    return `Tu cambio espera: «${shared.collection_name}» se tiene que volver a cifrar porque alguien salió. Se enviará cuando quien la gestiona sincronice.`;
  }
  const st = (state.team || {}).state;
  if (st === 'offline') return 'Tu cambio se enviará al equipo cuando vuelva la conexión.';
  if (st === 'reconnect') return 'Tu cambio se enviará cuando vuelvas a entrar en Equipo.';
  if (st === 'error') return 'Tu cambio aún no ha llegado al equipo; se reintentará solo.';
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
    reconnect: 'La sesión del equipo ha caducado: vuelve a entrar en Equipo.',
    offline: 'Sin conexión con el servidor del equipo. Todo funciona con lo que ya tienes.',
    error: 'Hay un problema al sincronizar con el equipo. Ábrelo para ver qué hacer.',
  }[state.status.team] || (held ? `${plural(held, 'cambio espera', 'cambios esperan')} a que su colección se vuelva a cifrar.` : null);
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
    footer: [el('button', { class: 'btn', onclick: () => modal.close() }, 'Cancelar'), button],
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
  return helpPopover('Qué permite cada permiso', 'Permisos en una colección', [
    el('div', { class: 'perm-legend' }, Object.keys(PERMISSION_LABELS).map((p) => {
      const [label, text] = PERMISSION_HELP[p].split(': ');
      return el('div', {}, el('b', {}, label), el('span', {}, text));
    })),
    el('p', { class: 'faint small', style: 'margin-top:8px' }, USE_ONLY_NOTE)]);
}

function permissionSelect(value) {
  const select = el('select', { class: 'input compact', title: PERMISSION_HELP[value] || 'Permiso', 'aria-label': 'Permiso' },
    Object.entries(PERMISSION_LABELS).map(([p, text]) => el('option', { value: p, title: PERMISSION_HELP[p] }, text)));
  select.value = value;
  select.addEventListener('change', () => { select.title = PERMISSION_HELP[select.value]; });
  return select;
}

// The sync state: a short line for the header, and the whole story for its tooltip.
function syncLine(team) {
  if (!team || !team.connected) return ['', '', ''];
  const every = 'Se sincroniza sola al desbloquear, cada 5 minutos y al guardar cambios.';
  if (state.teamRefreshing && team.state !== 'syncing') return ['', 'Actualizando…', 'Pidiendo al servidor lo último. Mientras, ves lo que ya había en este PC.'];
  switch (team.state) {
    case 'syncing': return ['', 'Sincronizando…', every];
    case 'offline': return ['warn', 'Sin conexión', team.error || 'No se llega al servidor. Se reintenta solo; mientras, todo funciona con lo que ya tienes.'];
    case 'reconnect': return ['warn', 'Sesión caducada', 'Vuelve a entrar para seguir sincronizando.'];
    case 'error': return ['warn', 'No se pudo sincronizar', team.error || 'Se reintentará solo.'];
    default: return ['', team.last_sync ? `Sincronizado ${formatTime(team.last_sync)}` : 'Sin sincronizar', every];
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
  const unshare = () => confirmModal({
    title: `¿Dejar de compartir ${entry.name}?`,
    text: `Se quita de «${shared.collection_name}» para todo el equipo. En este PC se queda como credencial tuya.`,
    warning: 'Quien la tuvo puede haberla visto o copiado. Si te preocupa, cámbiala.',
    action: 'Dejar de compartir',
    onConfirm: async (button) => {
      const result = await teamAct('team_unshare_entry', { id: entry.id }, `Para dejar de compartir ${entry.name}.`, button);
      if (!result.ok) return false;
      await loadEntries();
      renderMain();
      toast('Ya no se comparte');
      return true;
    },
  });
  return el('div', { class: 'section' },
    el('h3', {}, 'Equipo'),
    el('p', {}, 'Compartida en ', el('b', {}, shared.collection_name || 'una colección'), shared.org_name ? ` de ${shared.org_name}` : '',
      '. Tu permiso: ', el('b', {}, PERMISSION_LABELS[shared.permission]), '.'),
    el('p', { class: 'help' }, PERMISSION_HELP[shared.permission].split(': ')[1]),
    author ? el('p', { class: 'help' }, `Último cambio: ${author}${shared.changed ? ` · ${formatTime(shared.changed)}` : ''}.`) : null,
    unsent ? el('p', { class: 'help unsent-line' }, icon('clock', 'sm'), el('span', {}, el('b', {}, 'Sin enviar. '), unsent)) : null,
    canWrite(entry) ? el('div', { style: 'margin-top:6px' }, el('button', {
      class: 'btn ghost', onclick: unshare, disabled: teamOffline(), title: teamOffline() ? 'Sin conexión con el servidor del equipo' : null,
    }, 'Dejar de compartir')) : null);
}

// One line for a change waiting for review: new destinations, or new instructions for the AI.
function changeSummary(change) {
  const who = change.by || 'Un compañero';
  const hosts = change.only_hosts ? change.hosts || [] : [];
  const destinations = (change.changes || []).some((line) => !line.startsWith('Instrucciones'));
  if (hosts.length) return `${who} quiere que la IA pueda enviarla a ${listJoin(hosts)}`;
  if (change.texts && !destinations) return `${who} ha cambiado las instrucciones que lee la IA`;
  if (change.texts) return `${who} ha cambiado adónde puede ir esta clave y las instrucciones que lee la IA`;
  return `${who} ha cambiado adónde puede ir esta clave`;
}

// A teammate widened where the key can go, or rewrote the description the AI reads as instructions: it keeps
// working as before until this user decides.
function pendingChangeBox(entry) {
  const change = entry.shared.pending_change;
  const write = canWrite(entry);
  const who = change.by || 'Un compañero';
  const hosts = change.only_hosts ? change.hosts || [] : [];
  const destinations = (change.changes || []).filter((line) => !line.startsWith('Instrucciones'));
  const decide = async (accept, button) => {
    const result = await teamAct('team_accept_change', { id: entry.id, accept },
      accept ? `Para permitir el cambio en ${entry.name}.` : `Para mantener ${entry.name} como estaba.`, button);
    if (!result.ok) return;
    await loadEntries();
    renderMain();
    toast(accept ? 'Cambio permitido' : 'Rechazado: se mantiene como estaba para todo el equipo');
  };
  const reject = write ? el('button', { class: 'btn primary' }, 'Rechazar y mantener como estaba') : null;
  if (reject) reject.addEventListener('click', () => decide(false, reject));
  const allow = el('button', { class: write ? 'btn' : 'btn primary' }, hosts.length === 1 ? `Permitir ${hosts[0]}`
    : change.texts && !destinations.length ? 'Aceptar la descripción nueva' : 'Permitir los cambios');
  allow.addEventListener('click', () => decide(true, allow));
  return el('div', { class: 'section draft-box review-box' },
    hosts.length
      ? el('h3', {}, `${who} quiere que la IA pueda enviar esta clave a: `, hosts.map((h, i) => [i ? ', ' : '', el('code', { class: 'selectable' }, h)]))
      : el('h3', {}, changeSummary(change)),
    hosts.length || !destinations.length ? null : el('ul', { class: 'used-in' }, destinations.map((line) => el('li', { class: 'selectable' }, line))),
    change.texts ? el('div', { class: 'field' },
      el('div', { class: 'k small muted' }, 'Nueva descripción (la IA la lee como instrucciones)'),
      el('blockquote', { class: 'quote selectable' }, change.description || '')) : null,
    el('p', { class: 'help' }, change.texts && !destinations.length
      ? 'Mientras decides, la IA sigue leyendo la descripción anterior: un texto nuevo podría pedirle que haga otra cosa con tus claves. '
      : 'Mientras decides, la IA no puede usar los destinos nuevos: sigue usándola como estaba. ', write
      ? 'Rechazar deshace el cambio para todo el equipo.'
      : 'Solo quien puede editarla puede rechazarlo: si no te parece bien, habla con quien la gestiona.'),
    el('div', { style: 'margin-top:8px;display:flex;gap:8px;flex-wrap:wrap' }, reject, allow));
}

// ----- sharing one credential or several

async function shareEntry(entry) {
  return shareEntries([entry]);
}

async function shareEntries(entries, onDone) {
  const result = await api().call('team_collections');
  if (!result.ok) { toast(result.error, 'error'); return; }
  const writable = result.result.filter((c) => ['manage', 'edit'].includes(c.permission));
  if (!state.teamData) {  // Equipo not opened yet: what this PC knows of the organizations is enough here
    const known = await api().call('team_overview');
    if (known.ok) state.teamData = known.result;
  }
  const overview = state.teamData || {};
  const adminOrgs = (overview.orgs || []).filter((o) => ['owner', 'admin'].includes(o.role) && (!o.status || o.status === 'confirmed'));
  const what = entries.length === 1 ? entries[0].name : plural(entries.length, 'credencial', 'credenciales');
  if (!writable.length && !adminOrgs.length) {
    const modal = openModal({
      title: `Compartir ${what}`,
      body: el('p', { class: 'muted' }, 'Aún no tienes ninguna colección donde puedas añadir credenciales. Crea una en Equipo, o pide a quien gestiona una que te dé permiso de editor.'),
      footer: [el('button', { class: 'btn', onclick: () => modal.close() }, 'Cancelar'),
        el('button', { class: 'btn primary', onclick: () => { modal.close(); state.view = 'team'; renderMain(); } }, 'Ir a Equipo')],
    });
    return;
  }
  let chosen = writable.length === 1 ? writable[0].id : writable.length ? null : 'new';
  const errorText = el('div', { class: 'error-text' });
  const button = el('button', { class: 'btn primary' }, entries.length === 1 ? 'Compartir' : `Compartir ${entries.length}`);
  const newName = el('input', { class: 'input', placeholder: 'Nombre, p. ej. Producción' });
  const newOrg = el('select', { class: 'input compact' }, adminOrgs.map((o) => el('option', { value: o.id }, o.name)));
  if (adminOrgs.some((o) => o.id === state.teamOrg)) newOrg.value = state.teamOrg;
  const newForm = el('div', { class: `inline-form ${chosen === 'new' ? '' : 'hidden'}`, style: 'margin:4px 0 0 34px' },
    newName, adminOrgs.length > 1 ? newOrg : null);
  const pick = (id) => { chosen = id; errorText.textContent = ''; newForm.classList.toggle('hidden', id !== 'new'); if (id === 'new') newName.focus(); };
  const modal = openModal({
    title: `Compartir ${what}`,
    body: [
      el('p', { class: 'muted' }, 'Elige la colección. Les llegará cifrada a quienes estén en ella; el servidor no puede leerla.'),
      el('div', { class: 'choice-list' }, writable.map((c) => el('label', { class: 'choice' },
        el('input', { type: 'radio', name: 'share-collection', value: c.id, checked: chosen === c.id, onchange: () => pick(c.id) }),
        el('div', { class: 'meta' }, el('div', { class: 'title' }, c.name),
          el('div', { class: 'subtitle' }, `${c.org_name} · ${plural(c.entries, 'credencial', 'credenciales')}${c.needs_rekey ? ' · se volverá a cifrar' : ''}`)))),
      adminOrgs.length ? el('label', { class: 'choice' },
        el('input', { type: 'radio', name: 'share-collection', value: 'new', checked: chosen === 'new', onchange: () => pick('new') }),
        el('div', { class: 'meta' }, el('div', { class: 'title' }, 'Nueva colección…'),
          el('div', { class: 'subtitle' }, 'Una carpeta compartida nueva; luego eliges quién entra.'))) : null),
      newForm,
      el('p', { class: 'help' }, 'Se comparte entera: la clave, las notas y adónde puede ir. Cuándo te pide aprobación la IA lo decide cada uno en su PC.'),
      errorText],
    footer: [el('button', { class: 'btn', onclick: () => modal.close() }, 'Cancelar'), button],
  });
  newName.addEventListener('keydown', (e) => { if (e.key === 'Enter') button.click(); });
  button.addEventListener('click', async () => {
    if (!chosen) { errorText.textContent = 'Elige una colección.'; return; }
    let cid = chosen;
    if (chosen === 'new') {
      if (!newName.value.trim()) { errorText.textContent = 'Ponle un nombre a la colección.'; newName.focus(); return; }
      const created = await teamAct('team_create_collection', { org: newOrg.value || adminOrgs[0].id, name: newName.value.trim() }, 'Para crear la colección.', button);
      if (!created.ok) return;
      cid = created.result.id;
      state.openCollection = cid;
    }
    if (entries.length === 1) {
      const shared = await teamAct('team_share_entry', { id: entries[0].id, collection: cid }, `Para compartir ${entries[0].name}.`, button);
      if (!shared.ok) return;
      modal.close();
      toast(`Compartida en ${shared.result.collection_name}`);
    } else {
      const shared = await teamAct('team_share_entries', { ids: entries.map((e) => e.id), collection: cid }, `Para compartir ${what}.`, button);
      if (!shared.ok) return;
      modal.close();
      const { shared: done, failed, collection_name: name } = shared.result;
      if (failed.length) toast(`${plural(done.length, 'compartida', 'compartidas')} en ${name}; ${plural(failed.length, 'no se pudo', 'no se pudieron')}: ${failed[0].error}`, 'error');
      else toast(`${plural(done.length, 'credencial compartida', 'credenciales compartidas')} en ${name}`);
    }
    if (onDone) onDone();
    await loadEntries();
    renderMain();
  });
}

// ----- after someone leaves: change, one after the other, what they could see

function offboardingPeople() {
  // From the reminders: who left and how many of their credentials are still to change (Salud, Equipo).
  const people = {};
  for (const r of Object.values(state.reminders || {})) {
    if (r.kind !== 'team_access') continue;
    for (const name of r.people || []) (people[name] = people[name] || []).push(r.id);
  }
  return Object.entries(people).map(([person, ids]) => ({ person, pending: ids }));
}

function offboardingSummary(person) {
  const total = person.total === undefined ? null : person.total;
  if (total === null) return `${person.person} ya no está: ${plural(person.pending.length, 'credencial', 'credenciales')} por cambiar`;
  return `${person.person} pudo ver ${plural(total, 'credencial', 'credenciales')} · ${plural(total - person.pending.length, 'cambiada', 'cambiadas')}`;
}

function offboardingCard(person, compact = false) {
  const total = person.total === undefined ? person.pending.length : person.total;
  const done = total - person.pending.length;
  return el('div', { class: 'offboard-card' },
    icon('rotate'),
    el('div', { class: 'meta' },
      el('div', { class: 'title' }, offboardingSummary(person)),
      compact ? null : el('div', { class: 'subtitle' }, total === 1
        ? 'Pudo verla o copiarla. Cámbiala; si no la gestionas tú, la cambia quien la gestiona.'
        : 'Pudo verlas o copiarlas. Cámbialas una tras otra; las que no gestionas las cambia quien las gestiona.'),
      el('div', { class: 'progress', title: `${done} de ${total}` }, el('span', { style: `width:${total ? Math.round(100 * done / total) : 100}%` }))),
    el('button', { class: 'btn primary', onclick: () => openOffboarding(person.person) }, done ? 'Seguir' : 'Empezar'));
}

async function openOffboarding(name) {
  const skipped = new Set();
  const body = el('div', { class: 'offboard' });
  const foot = el('div', { style: 'display:contents' });
  const modal = openModal({ title: `Cambiar lo que pudo ver ${name}`, wide: true, body, footer: [foot] });
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
      const change = el('button', { class: 'btn' }, 'Cambiar');
      change.addEventListener('click', () => { skipped.delete(entry.id); rotateGuided(entry, async () => { await draw(); }); });
      return el('div', { class: `access-row ${skipped.has(entry.id) ? 'skipped' : ''}` }, glyph(entry.template),
        el('div', { class: 'meta' }, el('div', { class: 'title' }, entry.name),
          el('div', { class: 'subtitle' }, [entry.shared ? entry.shared.collection_name : null,
            !mine ? 'La cambia quien la gestiona; te llegará sola' : skipped.has(entry.id) ? 'Saltada' : null].filter(Boolean).join(' · '))),
        mine ? [skipped.has(entry.id) ? null : el('button', { class: 'btn ghost', onclick: () => { skipped.add(entry.id); draw(); } }, 'Saltar'), change] : null);
    };
    body.replaceChildren(
      el('p', { class: 'muted' }, `${name} ya no está en el equipo, pero pudo ver o copiar estas claves. Cambiarlas es la única forma de que deje de poder usarlas.`),
      el('div', { class: 'offboard-progress' },
        el('div', { class: 'progress' }, el('span', { style: `width:${person.total ? Math.round(100 * done / person.total) : 100}%` })),
        el('span', { class: 'muted small' }, `${done} de ${person.total} ${person.total === 1 ? 'cambiada' : 'cambiadas'}`)),
      pending.length ? el('div', {}, pending.map(row))
        : el('p', { class: 'ok-text' }, icon('check', 'sm'), `Listo: ${name} ya no tiene ninguna clave que funcione.`));
    const following = next();
    foot.replaceChildren(el('div', { class: 'spacer' }),
      el('button', { class: 'btn', onclick: () => modal.close() }, pending.length ? 'Más tarde' : 'Cerrar'),
      following ? el('button', { class: 'btn primary', onclick: runNext }, done || skipped.size ? `Seguir con ${following.name}` : 'Empezar') : null);
  };
  await draw();
}

// ----- the Equipo view

async function renderTeam(content) {
  if (!content.querySelector('.team-view')) {
    content.replaceChildren(el('div', { class: 'content-header' }, el('h1', {}, 'Equipo')),
      el('div', { class: 'content-body team-view' }, el('div', { class: 'spinner' })));
  }
  const result = await api().call('team_overview');
  if (state.view !== 'team') return;
  if (!result.ok) {
    content.replaceChildren(el('div', { class: 'content-header' }, el('h1', {}, 'Equipo')),
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
    tabs.push(['collections', 'Colecciones', collections.length]);
    tabs.push(['people', 'Personas', members.filter((m) => m.status !== 'invited').length]);
    if (admin) tabs.push(['activity', 'Actividad', null]);
  }
  if (org) tabs.push(['account', 'Tu cuenta', null]);
  else tabs.push(['none', '', null]);  // no organization yet: no tabs, one page
  if (!tabs.some(([id]) => id === state.teamTab)) state.teamTab = tabs[0][0];

  const [kind, text, detail] = syncLine(state.team);
  const syncButton = el('button', { class: 'btn' }, icon('rotate', 'sm'), 'Sincronizar ahora');
  syncButton.addEventListener('click', async () => {
    busy(syncButton, true);
    const result = await api().call('team_sync');
    busy(syncButton, false);
    if (!result.ok) { toast(result.error, 'error'); return; }
    await loadEntries();
    rerender();
    if (result.result.state === 'ok') toast('Sincronizado');
    else toast(result.result.error || 'No se pudo sincronizar', 'error');
  });
  const orgPicker = data.orgs && data.orgs.length ? el('select', { class: 'input compact org-picker', title: 'Organización' },
    data.orgs.map((o) => el('option', { value: o.id }, o.name)), el('option', { value: '__new' }, 'Nueva organización…')) : null;
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
    el('div', { class: 'content-header' }, el('h1', {}, 'Equipo'), orgPicker,
      org ? el('span', { class: 'muted small' }, ROLE_LABELS[org.role] || org.role) : null,
      el('div', { class: 'spacer' }),
      el('span', { id: 'team-sync', class: `state-text ${kind}`, title: detail }, text), syncButton),
    org ? el('div', { class: 'team-tabs', role: 'tablist' }, tabs.map(([id, label, count]) => el('button', {
      class: state.teamTab === id ? 'active' : '', role: 'tab', 'aria-selected': state.teamTab === id ? 'true' : 'false',
      onclick: () => { state.teamTab = id; drawTeam(content); },
    }, label, count !== null && count !== undefined ? el('span', { class: 'tab-count' }, count) : null,
    id === 'people' && peopleAlert ? el('span', { class: 'tab-dot', title: `${plural(peopleAlert, 'persona', 'personas')} por verificar` }) : null))) : null);

  let panel;
  if (!org) panel = [teamNoOrg(data, rerender), el('div', { style: 'margin-top:28px' }, teamAccountPanel(null, rerender))];
  else if (!confirmed && state.teamTab !== 'account') panel = teamWaitingForAdmin(org);
  else if (state.teamTab === 'collections') panel = teamCollectionsPanel(org, collections, members, admin, content);
  else if (state.teamTab === 'people') panel = teamPeoplePanel(org, members, admin, rerender);
  else if (state.teamTab === 'activity') panel = teamEventsPanel((data.events || {})[org.id], members, collections);
  else panel = teamAccountPanel(org, rerender);

  const old = content.querySelector('.content-body.team-view');
  const scroll = old && state.teamTabShown === state.teamTab ? old.scrollTop : 0;
  state.teamTabShown = state.teamTab;
  const body = el('div', { class: 'content-body team-view' }, teamBanners(org, members, admin, rerender), panel);
  content.replaceChildren(top, body);
  body.scrollTop = scroll;
  const scrolled = () => top.classList.toggle('scrolled', body.scrollTop > 2);
  body.addEventListener('scroll', scrolled, { passive: true });
  scrolled();
  if (teamOffline()) {
    content.querySelectorAll('[data-mutates]').forEach((node) => {
      node.disabled = true;
      node.title = 'Sin conexión con el servidor del equipo: vuelve a intentarlo cuando se recupere.';
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
  const [, , detail] = syncLine(team);
  const verify = verificationsFor(org, members, admin);
  const reviews = state.entries.filter((e) => e.shared && e.shared.pending_change);
  const unsent = state.entries.filter((e) => unsentText(e));
  const leavers = (data.offboarding || []).filter((p) => p.pending.length);
  const open = (entry) => { state.view = 'credentials'; state.selected = entry.id; state.tag = null; state.collection = null; renderMain(); };
  return el('div', { class: 'team-banners' },
    team.state === 'reconnect' ? el('div', { class: 'pause-card paused' },
      el('div', { class: 'meta' }, el('h3', {}, 'La sesión del equipo ha caducado'),
        el('p', {}, 'Todo sigue funcionando con lo que ya tienes en este PC. Vuelve a entrar para recibir y enviar cambios.')),
      el('button', { class: 'btn primary', onclick: () => reconnectTeam(rerender) }, 'Volver a entrar')) : null,
    ['offline', 'error'].includes(team.state) ? el('div', { class: 'warning banner-line' }, icon('alert', 'sm'), el('span', {}, detail)) : null,
    state.teamReadError ? el('div', { class: 'warning banner-line' }, icon('alert', 'sm'), el('span', {}, state.teamReadError)) : null,
    team.verified === false ? verifyEmailCard(team, rerender) : null,
    (team.held_deletions || []).map((held) => heldDeletionsCard(held, rerender)),
    (data.invites || []).length ? teamInvitesGroup(data.invites, rerender) : null,
    verify.length ? el('div', { class: 'banner' },
      el('div', { class: 'banner-head' }, icon('fingerprint', 'sm'), el('h3', {}, `Por verificar (${verify.length})`),
        el('span', { class: 'muted small' }, 'Compara su código de seguridad por teléfono o en persona.')),
      verify.map((person) => verifyRow(person, rerender))) : null,
    leavers.map((person) => offboardingCard(person)),
    reviews.length || unsent.length ? el('div', { class: 'banner' },
      el('div', { class: 'banner-head' }, icon('alert', 'sm'), el('h3', {}, `Por revisar (${reviews.length + unsent.length})`)),
      reviews.map((entry) => el('div', { class: 'access-row' }, glyph(entry.template),
        el('div', { class: 'meta' }, el('div', { class: 'title' }, entry.name),
          el('div', { class: 'subtitle' }, changeSummary(entry.shared.pending_change))),
        el('button', { class: 'btn', onclick: () => open(entry) }, 'Revisar'))),
      unsent.map((entry) => el('div', { class: 'access-row' }, glyph(entry.template),
        el('div', { class: 'meta' }, el('div', { class: 'title' }, entry.name, el('span', { class: 'draft-badge', style: 'margin-left:8px' }, 'Sin enviar')),
          el('div', { class: 'subtitle' }, unsentText(entry))),
        el('button', { class: 'btn ghost', onclick: () => open(entry) }, 'Abrir')))) : null);
}

// The account has not proved it owns its e-mail: until then nobody's invites reach it (someone could have
// registered the address first). One code, typed once.
function verifyEmailCard(team, rerender) {
  const email = (team.user && team.user.email) || '';
  if (team.verification === 'admin') {
    return el('div', { class: 'banner' },
      el('div', { class: 'banner-head' }, icon('shield', 'sm'), el('h3', {}, 'Falta verificar tu e-mail')),
      el('p', { class: 'muted small' }, `Este servidor no envía correos. Pide a quien lo administra que verifique `,
        el('b', {}, email), ' (lo hace en el servidor con «secretbroker-server verify-email»). Hasta entonces no te llegan invitaciones.'));
  }
  const code = el('input', { class: 'input verify-code', placeholder: '12345678', inputmode: 'numeric', autocomplete: 'one-time-code',
    maxlength: '12', 'aria-label': 'Código del e-mail' });
  const verify = el('button', { class: 'btn primary', 'data-mutates': '1' }, 'Verificar');
  const resend = el('button', { class: 'link small muted-link', 'data-mutates': '1' }, 'Enviar otro código');
  const submit = async () => {
    if (!code.value.trim()) { code.focus(); return; }
    const result = await teamAct('team_verify_email', { code: code.value.trim() }, 'Para verificar tu e-mail.', verify);
    if (!result.ok) { code.select(); return; }
    state.team = { ...state.team, ...result.result };
    toast('E-mail verificado');
    rerender();
  };
  verify.addEventListener('click', submit);
  code.addEventListener('keydown', (event) => { if (event.key === 'Enter') submit(); });
  resend.addEventListener('click', async () => {
    const result = await teamAct('team_send_code', {}, 'Para enviarte otro código.', resend);
    if (result.ok) toast(result.result.sent ? `Te hemos enviado otro código a ${email}` : 'Este servidor no envía correos: pide a quien lo administra que te verifique');
  });
  return el('div', { class: 'banner' },
    el('div', { class: 'banner-head' }, icon('shield', 'sm'), el('h3', {}, 'Verifica tu e-mail')),
    el('p', { class: 'muted small' }, 'Te hemos enviado un código de 8 cifras a ', el('b', {}, email),
      '. Las invitaciones solo llegan a direcciones verificadas, así que nadie puede quedarse con las tuyas.'),
    el('div', { class: 'inline-form', style: 'margin-top:8px' }, code, verify, resend));
}

// Many credentials deleted for the team at once (or a collection that vanished): nothing was deleted here.
// One click either way.
function heldDeletionsCard(held, rerender) {
  const who = held.by && held.by.length ? listJoin(held.by) : null;
  const what = plural(held.count, 'credencial', 'credenciales');
  const decide = async (apply, button) => {
    const result = await teamAct('team_resolve_deletions', { collection: held.collection, apply },
      apply ? `Para borrar ${what} de este PC.` : `Para conservar ${what}.`, button);
    if (!result.ok) return;
    await loadEntries();
    toast(apply ? `${what} borradas de este PC` : held.can_restore ? `${what} recuperadas para todo el equipo` : `${what} conservadas en este PC`);
    rerender();
  };
  const remove = el('button', { class: 'btn danger', 'data-mutates': '1' }, 'Borrarlas también aquí');
  remove.addEventListener('click', () => decide(true, remove));
  const keep = el('button', { class: 'btn primary', 'data-mutates': '1' }, held.can_restore ? 'Recuperarlas para el equipo' : 'Conservarlas en este PC');
  keep.addEventListener('click', () => decide(false, keep));
  const reason = held.gone
    ? `La colección «${held.collection_name}» ya no aparece en el servidor (te han quitado el acceso, la han borrado o el servidor falla).`
    : `${who || 'Alguien'} ha borrado ${what} de «${held.collection_name}» a la vez.`;
  return el('div', { class: 'banner' },
    el('div', { class: 'banner-head' }, icon('trash', 'sm'), el('h3', {}, `${what} esperan tu decisión`)),
    el('p', { class: 'muted small' }, reason, ' Por si es un error o un ataque, no se ha borrado nada en este PC. ',
      held.can_restore ? 'Recuperarlas las vuelve a poner para todo el equipo.' : 'Si las conservas, quedan como credenciales personales.'),
    el('div', { style: 'margin-top:8px;display:flex;gap:8px;flex-wrap:wrap' }, keep, remove));
}

// One person to verify: their code to compare, and one click («Confirmar» lets them in, «Verificar» trusts
// them on this PC). A key that changed is only re-verified by typing the code the person reads out: the one
// shown comes from the server, so sending it back would prove nothing.
function verifyRow(person, rerender) {
  const label = person.name || person.email || 'Alguien';
  const pending = person.kind === 'confirm';
  const typed = person.kind === 'changed' ? el('input', { class: 'input mono', placeholder: 'El código que te lee esa persona', autocomplete: 'off', spellcheck: 'false' }) : null;
  const button = el('button', { class: 'btn primary', 'data-mutates': '1' }, pending ? 'Confirmar' : 'Verificar');
  button.addEventListener('click', async () => {
    if (typed && !typed.value.trim()) { typed.focus(); toast('Escribe el código que te lee esa persona', 'error'); return; }
    const params = { org: person.org, user_id: person.user_id };
    if (typed) params.fingerprint = typed.value.trim();
    const result = await teamAct('team_confirm_member', params, `Para verificar a ${label}.`, button);
    if (!result.ok) return;
    toast(pending ? `${label} confirmado` : `${label} verificado`);
    await api().call('team_sync');
    await loadEntries();
    rerender();
  });
  const subtitle = person.kind === 'waiting' && person.reason === 'recovery'
    ? 'Es propietario de la organización: verifícalo para que pueda recuperar tus colecciones si tú faltas.'
    : person.kind === 'waiting'
    ? `Te comparte ${person.collections === 1 ? 'una colección' : `${person.collections} colecciones`}: verifícalo para recibirlas.`
    : person.kind === 'changed' ? 'Su clave ha cambiado desde que lo verificaste. No le compartas nada hasta comparar el código.'
      : `${person.email ? `${person.email} · ` : ''}Pendiente de confirmar`;
  return el('div', { class: 'member' },
    el('div', { class: 'access-row' }, el('div', { class: 'meta' }, el('div', { class: 'title' }, label),
      el('div', { class: 'subtitle' }, subtitle)), button),
    el('div', { class: 'fingerprint-box' },
      el('div', { class: 'k' }, typed ? 'Pídele su código de seguridad y escríbelo aquí' : `Código de ${label}`),
      typed || el('div', { class: 'fingerprint selectable' }, person.fingerprint),
      typed ? null : el('p', { class: 'help' }, 'Pídele que te lea el suyo (lo ve en Equipo › Tu cuenta). Si no coincide, no lo verifiques: alguien podría hacerse pasar por esa persona.')));
}

function teamInvitesGroup(invites, rerender) {
  return el('div', { class: 'banner' },
    el('div', { class: 'banner-head' }, icon('users', 'sm'), el('h3', {}, invites.length === 1 ? 'Te han invitado' : `Te han invitado (${invites.length})`)),
    invites.map((invite) => {
      const button = el('button', { class: 'btn primary', 'data-mutates': '1' }, 'Aceptar');
      button.addEventListener('click', async () => {
        const result = await teamAct('team_accept_invite', { id: invite.id }, `Para unirte a ${invite.org_name}.`, button);
        if (!result.ok) return;
        state.teamOrg = invite.org_id;
        toast('Aceptada. Falta que un administrador te confirme.');
        rerender();
      });
      const by = invite.invited_by_name || invite.invited_by_email;
      return el('div', { class: 'access-row' }, el('div', { class: 'meta' }, el('div', { class: 'title' }, invite.org_name),
        el('div', { class: 'subtitle' }, `${by ? `${by} te invita` : 'Te invitan'} como ${(ROLE_LABELS[invite.role] || invite.role).toLowerCase()}. Al aceptar, confías en su código de seguridad.`)), button);
    }));
}

function createOrgForm(onCreated) {
  const nameInput = el('input', { class: 'input', placeholder: 'Nombre del equipo o la empresa' });
  const create = el('button', { class: 'btn primary', 'data-mutates': '1' }, 'Crear organización');
  const submit = async () => {
    if (!nameInput.value.trim()) { nameInput.focus(); return; }
    const result = await teamAct('team_create_org', { name: nameInput.value.trim() }, 'Para crear la organización.', create);
    if (!result.ok) return;
    state.teamOrg = result.result.id;
    state.teamTab = 'collections';
    toast('Organización creada');
    onCreated();
  };
  create.addEventListener('click', submit);
  nameInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });
  return el('div', { class: 'inline-form' }, nameInput, create);
}

function newOrgModal(rerender) {
  let modal = null;
  modal = openModal({ title: 'Nueva organización', body: [
    el('p', { class: 'muted' }, 'Una organización es un equipo: tiene sus personas y sus colecciones.'),
    createOrgForm(() => { modal.close(); rerender(); })] });
  setTimeout(() => modal.overlay.querySelector('input').focus(), 50);
}

function teamNoOrg(data, rerender) {
  return el('div', { class: 'settings-group team-panel' }, el('h3', { class: 'muted' }, 'Organización'),
    el('p', { class: 'muted small', style: 'margin-bottom:10px' },
      (data.invites || []).length ? 'Acepta la invitación de arriba, o crea una organización propia.'
        : `Crea una para tu equipo, o pide a alguien que te invite con ${state.team.user.email}: la invitación aparecerá aquí.`),
    createOrgForm(rerender));
}

function teamWaitingForAdmin(org) {
  return el('div', { class: 'settings-group team-panel' },
    el('p', { class: 'muted' }, `Has aceptado la invitación. Falta que un administrador de ${org.name} te confirme; si te pide tu código de seguridad, es este:`),
    el('p', { class: 'fingerprint selectable', style: 'margin:6px 0' }, state.team.fingerprint),
    el('p', { class: 'help' }, 'Después verás sus colecciones aquí.'));
}

function teamAccountPanel(org, rerender) {
  const team = state.team;
  const disconnect = () => confirmModal({
    title: '¿Desconectar la cuenta del equipo?',
    text: `Se ${team.shared === 1 ? 'quita' : 'quitan'} de este PC ${team.shared === 1 ? 'la credencial' : `las ${team.shared} credenciales`} del equipo; siguen en el servidor para los demás. Las que compartiste tú desde tu bóveda y los cambios sin enviar se quedan como personales.`,
    warning: 'Para volver a conectarte necesitarás la contraseña de la cuenta.',
    action: 'Desconectar',
    danger: true,
    onConfirm: async (button) => {
      const result = await teamAct('team_disconnect', {}, 'Para desconectar la cuenta del equipo.', button);
      if (!result.ok) return false;
      state.teamData = null;
      await loadEntries();
      renderMain();
      toast('Desconectado');
      return true;
    },
  });
  const user = team.user || {};
  const me = org ? ((state.teamData.members || {})[org.id] || []).find((m) => m.me) : null;
  const leave = me && org.role !== 'owner' ? el('button', { class: 'btn ghost', 'data-mutates': '1', onclick: () => removeMember(org, me, rerender) }, `Salir de ${org.name}`) : null;
  return el('div', { class: 'settings team-panel' }, el('div', { class: 'settings-group' }, org ? null : el('h3', { class: 'muted' }, 'Tu cuenta'),
    setting(user.name || user.email, `${user.email} · ${hostOf(team.server_url)}${team.device ? ` · este PC: ${team.device}` : ''}`,
      el('button', { class: 'btn danger', onclick: disconnect }, 'Desconectar')),
    el('div', { class: 'setting' }, el('div', { class: 'meta' }, el('h3', {}, 'Tu código de seguridad'),
      el('p', {}, el('span', { class: 'fingerprint big selectable' }, team.fingerprint)),
      el('p', {}, 'Quien te confirme o te verifique lo compara con el que ve en su pantalla. Díctaselo por teléfono o en persona, no por el mismo chat.')),
    copyButton(team.fingerprint)),
    org ? setting(org.name, `Tu rol: ${(ROLE_LABELS[org.role] || org.role).toLowerCase()}.`, leave) : null));
}

function teamPeoplePanel(org, members, admin, rerender) {
  const iAmOwner = org.role === 'owner';
  const verifying = new Set(verificationsFor(org, members, admin).map((p) => p.user_id));
  const row = (m) => {
    const label = m.name || m.email;
    const invited = m.status === 'invited';
    const status = invited ? 'Invitada · aún no ha entrado' : m.status === 'accepted' ? 'Pendiente de confirmar' : ROLE_LABELS[m.role] || m.role;
    const controls = [];
    // Someone already in the org not verified on this PC: one click, after comparing their code.
    const verify = !m.me && m.fingerprint && m.status === 'confirmed' && !m.trusted && !verifying.has(m.user_id);
    if (invited && admin) {
      controls.push(el('button', { class: 'btn', onclick: () => inviteInstructions(org, m.email, m.invite_id) }, icon('copy', 'sm'), 'Copiar instrucciones'));
    } else if (verify) {
      const button = el('button', { class: 'btn', 'data-mutates': '1' }, 'Verificar');
      button.addEventListener('click', async () => {
        const result = await teamAct('team_confirm_member', { org: org.id, user_id: m.user_id }, `Para verificar a ${label}.`, button);
        if (!result.ok) return;
        toast(`${label} verificado`);
        rerender();
      });
      controls.push(button);
    } else if (admin && !m.me && m.status === 'confirmed' && (iAmOwner || m.role !== 'owner')) {
      const roles = el('select', { class: 'input compact', 'data-mutates': '1', 'aria-label': `Rol de ${label}` }, Object.entries(ROLE_LABELS)
        .filter(([r]) => iAmOwner || r !== 'owner').map(([r, text]) => el('option', { value: r }, text)));
      roles.value = m.role;
      roles.addEventListener('change', async () => {
        const result = await teamAct('team_set_role', { org: org.id, user_id: m.user_id, role: roles.value }, `Para cambiar el rol de ${label}.`);
        if (!result.ok) { roles.value = m.role; return; }
        toast('Rol cambiado');
        rerender();
      });
      controls.push(roles);
    }
    if (admin && !m.me && m.user_id && (iAmOwner || m.role !== 'owner')) {
      controls.push(el('button', { class: 'btn icon-only', 'data-mutates': '1', title: 'Quitar de la organización', onclick: () => removeMember(org, m, rerender) }, icon('trash', 'sm')));
    }
    return el('div', { class: 'member' },
      el('div', { class: 'access-row' },
        el('div', { class: `avatar ${invited ? 'invited' : ''}` }, (label || '?').trim().charAt(0).toUpperCase()),
        el('div', { class: 'meta' }, el('div', { class: 'title' }, label, m.me ? el('span', { class: 'faint' }, ' · tú') : null,
          verifying.has(m.user_id) ? el('span', { class: 'draft-badge', style: 'margin-left:8px' }, 'Por verificar') : null),
          el('div', { class: 'subtitle' }, [m.name && !invited ? m.email : null, status].filter(Boolean).join(' · '))),
        controls),
      verify ? el('div', { class: 'fingerprint-box' }, el('div', { class: 'k' }, `Código de ${label}`),
        el('div', { class: 'fingerprint selectable' }, m.fingerprint),
        el('p', { class: 'help' }, 'Aún no lo has verificado en este PC: no le das acceso a nada ni se usan las claves que firme. Compáralo con el suyo (Equipo › Tu cuenta) por teléfono o en persona.')) : null);
  };

  const draft = state.teamDraft || (state.teamDraft = {});
  const email = el('input', { class: 'input', type: 'email', placeholder: 'e-mail de la persona', value: draft.email || '' });
  email.addEventListener('input', () => { draft.email = email.value; });
  const role = el('select', { class: 'input compact', 'aria-label': 'Rol' }, el('option', { value: 'member' }, 'Miembro'), el('option', { value: 'admin' }, 'Administrador'));
  const invite = el('button', { class: 'btn primary', 'data-mutates': '1' }, 'Invitar');
  const submit = async () => {
    if (!email.value.trim()) { email.focus(); return; }
    const address = email.value.trim();
    const result = await teamAct('team_invite', { org: org.id, email: address, role: role.value }, 'Para invitar a una persona.', invite);
    if (!result.ok) return;
    draft.email = '';
    rerender();
    inviteInstructions(org, address, result.result.id, true);
  };
  invite.addEventListener('click', submit);
  email.addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });
  const people = members.filter((m) => m.status !== 'invited');
  const invited = members.filter((m) => m.status === 'invited');
  return el('div', { class: 'settings-group team-panel' },
    admin ? el('div', { class: 'invite-box' }, el('div', { class: 'inline-form' }, email, role, invite),
      el('p', { class: 'help' }, 'SecretBroker no envía las invitaciones por e-mail: después te damos unas instrucciones y un enlace para que se los pases. Cuando entre, aparecerá aquí con su código de seguridad para que lo confirmes.')) : null,
    people.map(row),
    invited.length ? [el('h3', { class: 'muted sub-head' }, `Invitaciones (${invited.length})`), invited.map(row)] : null);
}

function joinLink(server, email, code) {
  const params = new URLSearchParams({ server, email });
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

// No e-mail is sent: the admin passes these on (chat, e-mail, in person).
function inviteInstructions(org, email, code, justInvited = false) {
  const server = state.team.server_url;
  const link = joinLink(server, email, code);
  const text = [
    `Te he invitado al equipo «${org.name}» en SecretBroker.`,
    '',
    `1. Instala SecretBroker: ${RELEASES_URL}`,
    `2. Abre este enlace: ${link}`,
    '   Si no se abre, en SecretBroker ve a Equipo y escribe:',
    `   · Servidor: ${server}`,
    `   · E-mail: ${email}`,
    code ? `   · Código de invitación (si te lo pide): ${code}` : null,
    '3. Crea tu cuenta y acepta la invitación.',
    '4. Te confirmaré comparando tu código de seguridad (Equipo › Tu cuenta) por teléfono o en persona.',
  ].filter((line) => line !== null).join('\n');
  const copy = el('button', { class: 'btn primary' }, icon('copy', 'sm'), 'Copiar instrucciones');
  copy.addEventListener('click', async () => { await api().copy_text(text); toast('Instrucciones copiadas'); });
  const copyLink = el('button', { class: 'btn' }, 'Copiar solo el enlace');
  copyLink.addEventListener('click', async () => { await api().copy_text(link); toast('Enlace copiado'); });
  const modal = openModal({
    title: justInvited ? `Invitación creada para ${email}` : `Instrucciones para ${email}`,
    wide: true,
    body: [
      el('p', { class: 'muted' }, 'SecretBroker no envía las invitaciones por e-mail. Pásale esto por el canal que uséis; el enlace solo rellena su formulario, sin contraseñas.'),
      el('pre', { class: 'instructions selectable' }, text)],
    footer: [copyLink, el('div', { class: 'spacer' }), el('button', { class: 'btn', onclick: () => modal.close() }, 'Cerrar'), copy],
  });
}

function removeMember(org, member, rerender) {
  const label = member.name || member.email;
  const self = member.me;
  confirmModal({
    title: self ? `¿Salir de ${org.name}?` : `¿Quitar a ${label}?`,
    text: self ? 'Las credenciales de sus colecciones se quitarán de este PC.' : `Dejará de tener acceso a ${org.name} y a sus colecciones.`,
    warning: self ? null : 'Las colecciones que podía abrir se volverán a cifrar, y después te guiamos para cambiar las claves que pudo ver o copiar.',
    action: self ? 'Salir' : 'Quitar',
    danger: true,
    onConfirm: async (button) => {
      const result = await teamAct('team_remove_member', { org: org.id, user_id: member.user_id },
        self ? `Para salir de ${org.name}.` : `Para quitar a ${label}.`, button);
      if (!result.ok) return false;
      await loadEntries();
      const { failed = [], pending = [], offline = false, credentials = 0, person = label } = result.result;
      if (self) {
        toast('Has salido');
        state.teamOrg = null;
      } else {
        toast(['Quitado.',
          failed.length ? `${failed.length === 1 ? '1 colección se volverá' : `${failed.length} colecciones se volverán`} a cifrar ${offline ? 'al reconectar' : 'en la próxima sincronización'}.` : '',
          pending.length ? `${pending.length === 1 ? 'Otra la vuelve' : `Otras ${pending.length} las vuelve`} a cifrar quien las gestiona.` : ''].filter(Boolean).join(' '));
      }
      renderMain();
      if (!self && credentials) setTimeout(() => openOffboarding(person), 50);
      return true;
    },
  });
}

function teamCollectionsPanel(org, collections, members, admin, content) {
  const draft = state.teamDraft || (state.teamDraft = {});
  const name = el('input', { class: 'input', placeholder: 'Nombre, p. ej. Producción', value: draft.collection || '' });
  name.addEventListener('input', () => { draft.collection = name.value; });
  const create = el('button', { class: 'btn', 'data-mutates': '1' }, icon('plus', 'sm'), 'Crear colección');
  const submit = async () => {
    if (!name.value.trim()) { name.focus(); return; }
    const result = await teamAct('team_create_collection', { org: org.id, name: name.value.trim() }, 'Para crear la colección.', create);
    if (!result.ok) return;
    draft.collection = '';
    state.openCollection = result.result.id;
    toast('Colección creada');
    renderTeam(content);
  };
  create.addEventListener('click', submit);
  name.addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });
  return el('div', { class: 'settings-group team-panel' },
    el('div', { class: 'panel-head' },
      el('p', { class: 'muted small' }, collections.length
        ? 'Cada colección es una carpeta compartida: tú eliges quién entra y con qué permiso.'
        : 'Una colección es una carpeta compartida: eliges quién entra y con qué permiso. Después, en cada credencial, «Compartir».'),
      permissionHelp()),
    collections.map((c) => collectionBlock(c, members, content)),
    admin ? el('div', { class: 'inline-form', style: 'margin-top:12px' }, name, create) : null);
}

const SINGLE_MANAGER_TEXT = 'Solo una persona la gestiona: si deja el equipo o pierde su cuenta, nadie podrá dar acceso ni volver a cifrarla. '
  + 'Da permiso de Gestor a otra persona (los propietarios de la organización lo reciben solos cuando los verificas).';

function collectionBlock(collection, orgMembers, content) {
  const manage = collection.permission === 'manage';
  const list = el('div', { class: 'collection-members' });
  const cached = ((state.teamData || {}).collection_members || {})[collection.id];
  // The count follows the member list each time it loads (the cached one may be from before a grant).
  const subtitle = el('div', { class: 'subtitle' });
  const describe = (members) => { subtitle.textContent = [plural(collection.entries, 'credencial', 'credenciales'),
    members ? plural(members.length, 'persona', 'personas') : null,
    `Tu permiso: ${PERMISSION_LABELS[collection.permission]}`].filter(Boolean).join(' · '); };
  describe(cached);
  const block = el('details', { class: 'collection', open: state.openCollection === collection.id },
    el('summary', {}, el('span', { class: 'chev' }, icon('chevronRight', 'sm')),
      el('div', { class: 'meta' }, el('div', { class: 'title' }, collection.name), subtitle),
      collection.needs_rekey ? el('span', { class: 'draft-badge', title: 'Alguien salió de ella. Quien la gestiona la vuelve a cifrar en su próxima sincronización; mientras, los cambios esperan en cada PC.' }, 'Se volverá a cifrar')
        : collection.single_manager ? el('span', { class: 'draft-badge', title: SINGLE_MANAGER_TEXT }, 'Un solo gestor') : null),
    collection.single_manager && manage ? el('div', { class: 'warning', style: 'margin:4px 0 8px' }, icon('alert', 'sm'), el('span', {}, SINGLE_MANAGER_TEXT)) : null,
    list);
  const draw = (inside) => {
    describe(inside);
    const mine = state.team.user.id;
    const row = (m) => {
      const label = m.name || m.email || 'Alguien';
      let control = el('span', { class: 'muted small', title: PERMISSION_HELP[m.permission] }, PERMISSION_LABELS[m.permission]);
      if (manage && m.user_id !== mine) {
        const select = permissionSelect(m.permission);
        select.setAttribute('data-mutates', '1');
        select.addEventListener('change', async () => {
          const changed = await teamAct('team_grant', { collection: collection.id, user_id: m.user_id, permission: select.value },
            `Para cambiar el permiso de ${label}.`);
          if (!changed.ok) { select.value = m.permission; return; }
          toast(`${label}: ${PERMISSION_LABELS[select.value]}`);
          load();
        });
        control = [select, el('button', { class: 'btn icon-only', 'data-mutates': '1', title: 'Quitar de la colección', onclick: () => confirmModal({
          title: `¿Quitar a ${label} de ${collection.name}?`,
          text: 'Dejará de recibir sus credenciales y los cambios.',
          warning: 'La colección se volverá a cifrar y sus credenciales quedarán marcadas para cambiarlas: pudo verlas o copiarlas.',
          action: 'Quitar', danger: true,
          onConfirm: async (button) => {
            const revoked = await teamAct('team_revoke', { collection: collection.id, user_id: m.user_id }, `Para quitar a ${label}.`, button);
            if (!revoked.ok) return false;
            await loadEntries();
            toast('Quitado. La colección se ha vuelto a cifrar');
            load();
            return true;
          },
        }) }, icon('x', 'sm'))];
      }
      return el('div', { class: 'access-row' }, el('div', { class: 'meta' },
        el('div', { class: 'title' }, label, m.user_id === mine ? el('span', { class: 'faint' }, ' · tú') : null),
        m.name && m.email ? el('div', { class: 'subtitle' }, m.email) : null), control);
    };
    let add = null;
    if (manage) {
      const candidates = orgMembers.filter((m) => m.status === 'confirmed' && m.user_id && !inside.some((i) => i.user_id === m.user_id));
      if (candidates.length) {
        const who = el('select', { class: 'input', 'aria-label': 'Persona' }, candidates.map((m) => el('option', { value: m.user_id }, m.name ? `${m.name} (${m.email})` : m.email)));
        const permission = permissionSelect('use');
        const button = el('button', { class: 'btn', 'data-mutates': '1' }, 'Añadir');
        button.addEventListener('click', async () => {
          const granted = await teamAct('team_grant', { collection: collection.id, user_id: who.value, permission: permission.value },
            'Para dar acceso a la colección.', button);
          if (!granted.ok) return;
          toast('Añadido');
          load();
        });
        add = el('div', { class: 'inline-form', style: 'margin-top:8px' }, who, permission, button);
      } else {
        add = el('p', { class: 'help', style: 'margin-top:6px' }, 'Para añadir a alguien, invítalo a la organización y confírmalo.');
      }
    }
    const leave = !manage ? el('button', { class: 'link small muted-link', 'data-mutates': '1', style: 'margin-top:8px', onclick: () => confirmModal({
      title: `¿Salir de ${collection.name}?`,
      text: 'Sus credenciales se quitarán de este PC.',
      action: 'Salir', danger: true,
      onConfirm: async (button) => {
        const left = await teamAct('team_revoke', { collection: collection.id, user_id: mine }, `Para salir de ${collection.name}.`, button);
        if (!left.ok) return false;
        await loadEntries();
        toast('Has salido de la colección');
        renderTeam(content);
        return true;
      },
    }) }, 'Salir de la colección') : null;
    const shown = state.entries.filter((e) => e.shared && e.shared.collection === collection.id);
    list.replaceChildren(inside.map(row), add,
      shown.length ? el('p', { class: 'help', style: 'margin-top:8px' }, 'Credenciales: ',
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
    const label = EVENT_LABELS[e.action] || 'Otra acción';
    const [left, extra] = String(e.target || '').split(':');
    const [cid, uid] = left.split('/');
    switch (e.action) {
      case 'invite': case 'invite.delete': return `${label} ${e.target}`;
      case 'member.confirm': case 'member.remove': return `${label} ${name(e.target, 'alguien')}`;
      case 'member.role': return `${label} ${name(left, 'alguien')}: ${(ROLE_LABELS[extra] || extra || '').toLowerCase()}`;
      case 'grant': return `${label} ${name(uid, 'alguien')} en ${name(cid, 'una colección')} (${PERMISSION_LABELS[extra] || extra})`;
      case 'revoke': return `${label} ${name(uid, 'alguien')} en ${name(cid, 'una colección')}`;
      case 'rotate': case 'item.put': case 'item.delete': return `${label} ${name(cid, 'una colección')}`;
      case 'collection.create': case 'collection.delete': return `${label} ${name(e.target, '')}`.trim();
      default: return label;
    }
  };
  return el('div', { class: 'settings-group team-panel' },
    el('p', { class: 'help', style: 'margin-bottom:8px' }, 'El servidor anota quién hizo qué, nunca el contenido: no lo conoce. Solo lo ven los administradores.'),
    events === undefined ? el('div', { class: 'spinner' })
      : !events.length ? el('p', { class: 'muted' }, 'Aún no hay actividad.')
        : el('table', { class: 'table' }, el('tbody', {}, events.slice(0, 50).map((e) => el('tr', {},
          el('td', { class: 'muted', style: 'white-space:nowrap' }, formatTime(e.time)),
          el('td', {}, name(e.actor, 'alguien')),
          el('td', {}, describe(e)))))));
}

// ----- linking the account (the only time its password is typed on this PC)

function teamConnectForm({ server = '', email = '', code = '', mode = 'register', lockMode = false, invited = false, onDone }) {
  let current = mode;
  const serverInput = el('input', { class: 'input', placeholder: 'https://equipo.tuempresa.com', value: server, spellcheck: 'false' });
  const nameInput = el('input', { class: 'input', placeholder: 'Cómo te verá tu equipo' });
  const emailInput = el('input', { class: 'input', type: 'email', value: email, spellcheck: 'false' });
  const pw = passwordInput({ autocomplete: current === 'register' ? 'new-password' : 'current-password' });
  const repeat = passwordInput();
  const tokenInput = el('input', { class: 'input mono', spellcheck: 'false', value: code });
  const errorText = el('div', { class: 'error-text' });
  const button = el('button', { class: 'btn primary lg' });
  const tabs = el('div', { class: 'segmented' });
  const linkNote = el('div', { class: `notice ${invited ? '' : 'hidden'}` }, icon('users', 'sm'), el('span', { class: 'notice-text' }));
  const registerOnly = [
    el('div', { class: 'field' }, el('label', {}, 'Tu nombre', el('span', { class: 'req' }, ' · opcional')), nameInput),
  ];
  const meter = strengthMeter(pw.input);
  const repeatField = el('div', { class: 'field' }, el('label', {}, 'Repítela'), repeat);
  const tokenField = el('div', { class: 'field' }, el('label', {}, 'Código de invitación', el('span', { class: 'req' }, ' · si tu servidor lo pide')), tokenInput);
  const render = () => {
    tabs.replaceChildren([['register', 'Crear cuenta'], ['login', 'Entrar']].map(([m, text]) => el('button', {
      type: 'button', class: m === current ? 'active' : '', onclick: () => { current = m; errorText.textContent = ''; render(); },
    }, text)));
    const register = current === 'register';
    registerOnly.forEach((n) => n.classList.toggle('hidden', !register));
    meter.forEach((n) => n.classList.toggle('hidden', !register));
    repeatField.classList.toggle('hidden', !register);
    tokenField.classList.toggle('hidden', !register);
    button.textContent = register ? 'Crear cuenta' : 'Entrar';
  };
  render();
  const showLink = (link) => {
    linkNote.classList.remove('hidden');
    linkNote.querySelector('.notice-text').textContent = `Invitación para ${link.email || 'ti'} en ${hostOf(link.server)}. Comprueba que es el servidor de tu equipo; si ya tienes cuenta en él, elige «Entrar».`;
  };
  if (invited) showLink({ server, email });
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
    const register = current === 'register';
    if (!serverInput.value.trim()) { errorText.textContent = 'Escribe la dirección del servidor.'; serverInput.focus(); return; }
    if (!emailInput.value.trim()) { errorText.textContent = 'Escribe tu e-mail.'; emailInput.focus(); return; }
    if (!pw.input.value) { errorText.textContent = 'Escribe la contraseña de la cuenta.'; pw.input.focus(); return; }
    if (register && pw.input.value.length < 12) { errorText.textContent = 'La contraseña de la cuenta necesita al menos 12 caracteres.'; return; }
    if (register && pw.input.value !== repeat.input.value) { errorText.textContent = 'Las dos contraseñas no coinciden.'; return; }
    busy(button, true);
    const params = { server_url: serverInput.value.trim(), email: emailInput.value.trim(), password: pw.input.value, mode: current };
    if (register && nameInput.value.trim()) params.name = nameInput.value.trim();
    if (register && tokenInput.value.trim()) params.invite_token = tokenInput.value.trim();
    const result = await withProof((p) => api().call('team_connect', params, p), 'Para conectar la cuenta del equipo.');
    busy(button, false);
    if (!result.ok) { if (result.code !== 'cancelled') errorText.textContent = result.error; return; }
    pw.input.value = '';
    repeat.input.value = '';
    toast(register ? 'Cuenta creada y conectada' : 'Conectado');
    onDone(result.result);
  };
  button.addEventListener('click', submit);
  [pw.input, repeat.input, tokenInput].forEach((i) => i.addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); }));
  return el('div', { class: 'team-form' },
    lockMode ? null : tabs,
    linkNote,
    el('div', { class: 'field' }, el('label', {}, 'Servidor'), serverInput,
      el('div', { class: 'help' }, 'La dirección de vuestro SecretBroker Server. También puedes pegar aquí el enlace de invitación.')),
    registerOnly,
    el('div', { class: 'field' }, el('label', {}, 'E-mail'), emailInput),
    el('div', { class: 'field' }, el('label', {}, 'Contraseña de la cuenta'), pw, meter),
    repeatField,
    tokenField,
    el('p', { class: 'help' }, 'Solo se pide esta vez en este PC; después, todo es un clic. La necesitarás para conectar otro PC, y nadie puede recuperarla: el servidor no la conoce.'),
    errorText,
    el('div', {}, button));
}

function renderTeamConnect(content) {
  const link = state.joinLink;
  state.joinLink = null;
  const form = teamConnectForm({ server: link ? link.server : '', email: link ? link.email : '', code: link ? link.code : '',
    invited: !!link, onDone: async () => { await loadEntries(); renderMain(); } });
  content.replaceChildren(el('div', { class: 'content-header' }, el('h1', {}, 'Equipo')),
    el('div', { class: 'content-body team-view' }, el('div', { class: 'team-connect' },
      el('div', { class: 'team-intro' },
        el('h2', {}, 'Comparte credenciales con tu equipo'),
        el('p', { class: 'muted' }, 'Crea colecciones y decide quién entra y con qué permiso. Cuando alguien rota una clave, a los demás les llega sola.'),
        el('div', { class: 'points' },
          el('div', {}, icon('lock'), el('div', {}, el('b', {}, 'El servidor no ve nada. '), el('span', { class: 'muted' }, 'Se cifra en este PC antes de salir: ni las claves ni sus nombres viajan en claro.'))),
          el('div', {}, icon('users'), el('div', {}, el('b', {}, 'Solo lo que eliges. '), el('span', { class: 'muted' }, 'Se comparte lo que pones en una colección. El resto sigue solo en este PC.'))),
          el('div', {}, icon('server'), el('div', {}, el('b', {}, 'En vuestro servidor. '), el('span', { class: 'muted' }, 'SecretBroker Server es de código abierto y se instala con Docker; pide la dirección a quien lo administra.'))),
          el('div', {}, icon('rotate'), el('div', {}, el('b', {}, 'Si alguien se va, '), el('span', { class: 'muted' }, 'sus colecciones se vuelven a cifrar y te guía para cambiar lo que pudo ver.'))))),
      form)));
  if (link) setTimeout(() => form.querySelector(link.email ? 'input[type=password]' : 'input[type=email]').focus(), 50);
}

function reconnectTeam(rerender) {
  const team = state.team;
  let modal = null;
  const form = teamConnectForm({ server: team.server_url, email: team.user.email, mode: 'login', lockMode: true,
    onDone: () => { modal.close(); rerender(); } });
  modal = openModal({ title: 'Volver a entrar', body: form });
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
    toast(`Este PC ya tiene una cuenta de equipo (${state.team.user.email}). La invitación era para ${link.email || 'otra cuenta'} en ${hostOf(link.server)}.`, 'error');
    return;
  }
  state.view = 'team';
  renderMain();
}

// ----------------------------------------------------------------------- settings

// ----------------------------------------------------------------------- browser extension (Ajustes › Navegador)

const EXTENSION_STEPS = {
  chromium: (name, folder) => [
    [`Abre la página de extensiones de ${name}.`, 'open'],
    [`Activa «Modo de desarrollador»${name === 'Edge' ? ' (en el menú de la izquierda)' : ' (arriba a la derecha)'}.`],
    ['Pulsa «Cargar descomprimida» y elige la carpeta de la extensión de SecretBroker:', 'folder'],
    [`Fija el icono de SecretBroker en la barra de ${name}, ábrelo y pulsa «Conectar». Aquí te pediremos confirmarlo con un clic.`],
  ],
  firefox: () => [
    ['Abre la página de complementos en depuración de Firefox.', 'open'],
    ['Pulsa «Cargar complemento temporal…» y elige el archivo manifest.json de esta carpeta:', 'folder'],
    ['En el botón de extensiones de la barra, abre SecretBroker y permite que acceda a todas las webs (Firefox lo pide aparte), y pulsa «Conectar». Aquí te pediremos confirmarlo con un clic.'],
  ],
};

function extensionInstallModal(info, initial) {
  const installed = info.browsers.filter((b) => b.installed);
  const choices = installed.length ? installed : info.browsers;
  let current = choices.find((b) => b.id === initial) || choices[0];
  const tabs = el('div', { class: 'segmented' });
  const steps = el('ol', { class: 'install-steps' });
  const folder = info.extension_dir;
  const draw = () => {
    tabs.replaceChildren(choices.map((b) => el('button', { type: 'button', class: b.id === current.id ? 'active' : '',
      onclick: () => { current = b; draw(); } }, b.name)));
    const recipe = current.id === 'firefox' ? EXTENSION_STEPS.firefox() : EXTENSION_STEPS.chromium(current.name, folder);
    steps.replaceChildren(recipe.map(([text, extra]) => el('li', {}, el('div', {}, text),
      extra === 'open' ? el('button', { class: 'btn', onclick: async () => {
        if (!await api().open_browser_page(current.id)) toast(`No se encontró ${current.name} en este PC`, 'error');
      } }, icon('external', 'sm'), current.id === 'firefox' ? 'Abrir Firefox' : `Abrir extensiones de ${current.name}`) : null,
      extra === 'folder' ? el('div', { class: 'install-folder' },
        el('code', { class: 'selectable', title: folder }, folder || 'No se encontró la carpeta de la extensión'),
        el('button', { class: 'btn', disabled: !folder, onclick: async () => { await api().copy_text(folder); toast('Ruta copiada'); } }, icon('copy', 'sm'), 'Copiar ruta'),
        el('button', { class: 'btn', disabled: !folder, onclick: () => api().show_extension_folder() }, icon('folder', 'sm'), 'Mostrar')) : null)));
    note.replaceChildren(icon('info', 'sm'), el('span', {}, current.id === 'firefox'
      ? 'Firefox quita los complementos temporales al cerrarse: hasta que SecretBroker esté en addons.mozilla.org hay que cargarlo de nuevo cada vez.'
      : `${current.name} puede avisar al arrancar de que hay extensiones en modo de desarrollador: es esta. Cuando esté en la tienda de ${current.name} bastará con un clic.`));
  };
  const note = el('div', { class: 'warning subtle' });
  draw();
  const modal = openModal({
    title: 'Instalar la extensión',
    lead: glyph('web_login'),
    body: [
      el('p', { class: 'muted' }, 'Rellena tus contraseñas en el navegador, solo en la web donde las guardaste y solo cuando tú lo pides. Habla con SecretBroker directamente, sin abrir ningún puerto.'),
      choices.length > 1 ? tabs : null, steps, note],
    footer: [el('div', { class: 'spacer' }), el('button', { class: 'btn primary', onclick: () => modal.close() }, 'Hecho')],
  });
}

function browserSettingsGroup() {
  const group = el('div', { class: 'settings-group' }, el('h3', { class: 'muted' }, 'Navegador'),
    setting('Extensión del navegador', 'Comprobando…', null));
  const draw = async () => {
    const response = await api().browser_info();
    if (!response.ok) return;
    const info = response.result;
    const paired = info.paired || [];
    const installButton = el('button', { class: `btn ${paired.length ? '' : 'primary'}`, onclick: () => extensionInstallModal(info) },
      paired.length ? 'Añadir otro navegador' : 'Instalar la extensión');
    const summary = paired.length
      ? `Conectada en ${listJoin([...new Set(paired.map((b) => b.name))])}. Rellena usuario, contraseña y códigos 2FA solo en la web de cada credencial.`
      : 'Rellena tus contraseñas en Chrome, Edge, Brave y Firefox, solo en la web donde las guardaste y solo cuando tú lo pides.';
    const rows = paired.map((b) => el('div', { class: 'setting browser-row' },
      el('div', { class: 'meta' }, el('h3', { class: 'with-icon' }, icon('globe', 'sm'), b.name),
        el('p', {}, b.last_seen ? `Conectado · usado ${whenText(b.last_seen)}` : `Conectado el ${new Date(b.created).toLocaleDateString('es-ES', { day: 'numeric', month: 'long' })}`)),
      el('div', { class: 'control' }, el('button', { class: 'btn', onclick: () => confirmModal({
        title: `¿Desconectar ${b.name}?`, text: 'Dejará de poder rellenar tus contraseñas hasta que vuelvas a pulsar «Conectar» en la extensión.',
        action: 'Desconectar', onConfirm: async () => {
          const result = await api().call('browser_forget', { id: b.id });
          if (!result.ok) { toast(result.error, 'error'); return false; }
          toast(`${b.name} desconectado`);
          draw();
          return true;
        } }) }, 'Desconectar'))));
    group.replaceChildren(el('h3', { class: 'muted' }, 'Navegador'),
      setting('Extensión del navegador', summary, paired.length
        ? el('div', { style: 'display:flex;gap:12px;align-items:center' }, el('span', { class: 'state-text ok' }, icon('check', 'sm'), 'Conectada'), installButton)
        : installButton),
      ...rows,
      setting('Atajo de teclado', 'Ctrl+Mayús+L rellena el inicio de sesión de la web abierta; Ctrl+Mayús+Y abre la extensión. Se cambian en la página de atajos de extensiones del navegador.', null));
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
  const connect = el('button', { class: 'btn primary' }, 'Conectar');
  const deny = el('button', { class: 'btn' }, 'Rechazar');
  const modal = openModal({
    title: `¿Conectar ${request.name}?`,
    lead: glyph('web_login'),
    body: [
      el('p', { class: 'muted' }, `${request.name} podrá rellenar tus contraseñas, solo en la web de cada una y cuando tú lo pidas.`),
      el('div', { class: 'pair-code' }, el('span', { class: 'muted small' }, 'Comprueba que la extensión muestra este código'),
        el('div', { class: 'code' }, `${request.code.slice(0, 3)} ${request.code.slice(3)}`)),
      el('div', { class: 'warning subtle' }, icon('info', 'sm'), el('span', {}, 'Si no acabas de pulsar «Conectar» en el navegador, recházalo.'))],
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
    const result = await withProof((p) => api().call('browser_pair_answer', { id: request.id, accept: true }, p), `Para conectar ${request.name}.`);
    busy(connect, false);
    if (result.ok) { modal.close(); toast(`${request.name} conectado`); if (state.view === 'settings') renderView(); }
    else if (result.code !== 'cancelled') toast(result.error, 'error');
  });
}

// The editor's «Navegador» section of a web login: more addresses, and how strictly they match.
const AUTOFILL_MATCH = [['domain', 'Esta web y sus subdominios'], ['host', 'Solo esta dirección exacta'], ['never', 'Nunca']];

function autofillEditor(entry) {
  const autofill = (entry && entry.autofill) || {};
  const sites = el('textarea', { class: 'input mono', rows: 2, spellcheck: 'false', placeholder: 'https://login.ejemplo.com\nejemplo.es' },
    (autofill.sites || []).join('\n'));
  const match = el('select', { class: 'input' }, AUTOFILL_MATCH.map(([value, label]) => el('option', { value }, label)));
  match.value = autofill.match || 'domain';
  const node = el('details', { class: 'advanced' },
    el('summary', {}, el('span', { class: 'chev' }, icon('chevronRight', 'sm')), 'Navegador',
      el('span', { class: 'hint' }, 'dónde se rellena')),
    el('div', { class: 'inner' },
      el('div', { class: 'field' }, el('label', {}, 'Rellenar en'), match,
        el('div', { class: 'help' }, 'Con «subdominios», la de ejemplo.com también se ofrece en cuentas.ejemplo.com. Nunca en webs parecidas (ejemplo.com.otra.net, ejemp1o.com).')),
      el('div', { class: 'field' }, el('label', {}, 'Otras direcciones', el('span', { class: 'req' }, ' · opcional')), sites,
        el('div', { class: 'help' }, 'Además de la dirección web de arriba, una por línea: si la misma cuenta sirve en otros dominios.'))));
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
    ? el('span', { class: 'state-text' }, 'No disponible en este PC')
    : status.hello_enrolled
      ? el('div', { style: 'display:flex;gap:12px;align-items:center' }, el('span', { class: 'state-text ok' }, icon('check', 'sm'), 'Activado'),
        el('button', { class: 'btn', onclick: async () => {
          const result = await withProof((p) => api().disable_hello(p), 'Para desactivar Windows Hello.');
          if (result.ok) { toast('Windows Hello desactivado'); await refreshStatus(); renderView(); } else if (result.code !== 'cancelled') toast(result.error, 'error');
        } }, 'Desactivar'))
      : el('button', { class: 'btn primary', onclick: async () => {
        const proof = await askProof('Para activar Windows Hello, confirma primero con una contraseña.');
        if (!proof || proof === 'hello') return;
        const result = await api().enroll_hello(proof);
        if (result.ok) { toast('Windows Hello activado'); await refreshStatus(); renderView(); } else if (result.code !== 'hello_cancelled') toast(result.error, 'error');
      } }, 'Activar');

  const lockSelect = el('select', { class: 'input' },
    [[15, '15 minutos'], [30, '30 minutos'], [60, '1 hora'], [240, '4 horas'], [0, 'Nunca']].map(([v, label]) => el('option', { value: v }, label)));
  lockSelect.value = String(status.auto_lock_minutes || 0);
  lockSelect.addEventListener('change', async () => {
    const minutes = Number(lockSelect.value);
    const result = await withProof((p) => api().call('set_settings', { settings: { auto_lock_minutes: minutes } }, p), 'Para cambiar el bloqueo automático.');
    if (result.ok) { toast('Guardado'); await refreshStatus(); } else { lockSelect.value = String(status.auto_lock_minutes || 0); if (result.code !== 'cancelled') toast(result.error, 'error'); }
  });

  const sessionToggle = el('input', { type: 'checkbox', checked: !!(status.session_unlock && state.info.session_unlock_here) });
  sessionToggle.addEventListener('change', async () => {
    const result = sessionToggle.checked
      ? await withProof((p) => api().enable_session_unlock(p), 'Para abrir la bóveda con tu sesión de Windows.')
      : await api().disable_session_unlock();
    if (result.ok) {
      state.info.session_unlock_here = sessionToggle.checked;
      toast(sessionToggle.checked ? 'Se abrirá al iniciar sesión en Windows' : 'Desactivado');
      await refreshStatus(); renderView();
    } else { sessionToggle.checked = !sessionToggle.checked; if (result.code !== 'cancelled') toast(result.error, 'error'); }
  });
  const backupSlot = el('div', { class: 'settings-group' }, el('h3', { class: 'muted' }, 'Copia de seguridad'));
  renderBackup(backupSlot);
  const startToggle = el('input', { type: 'checkbox', checked: !!state.info.start_with_windows });
  startToggle.addEventListener('change', async () => {
    await api().set_start_with_windows(startToggle.checked);
    state.info.start_with_windows = startToggle.checked;
    toast('Guardado');
  });

  const approvalSelect = el('select', { class: 'input' },
    [[24, '24 horas'], [8, '8 horas'], [0, 'Hasta que bloquee']].map(([v, label]) => el('option', { value: v }, label)));
  approvalSelect.value = String(status.approval_hours ?? 24);
  approvalSelect.addEventListener('change', async () => {
    const hours = Number(approvalSelect.value);
    const result = await withProof((p) => api().call('set_settings', { settings: { approval_hours: hours } }, p), 'Para cambiar cuánto duran las aprobaciones.');
    if (result.ok) { toast('Guardado'); await refreshStatus(); } else { approvalSelect.value = String(status.approval_hours ?? 24); if (result.code !== 'cancelled') toast(result.error, 'error'); }
  });

  const settingSelect = (key, options, fallback, reason) => {
    const select = el('select', { class: 'input' }, options.map(([v, label]) => el('option', { value: v }, label)));
    select.value = String(status[key] ?? fallback);
    select.addEventListener('change', async () => {
      const result = await withProof((p) => api().call('set_settings', { settings: { [key]: Number(select.value) } }, p), reason);
      if (result.ok) { toast('Guardado'); await refreshStatus(); } else { select.value = String(status[key] ?? fallback); if (result.code !== 'cancelled') toast(result.error, 'error'); }
    });
    return select;
  };
  const usesSelect = settingSelect('max_uses_per_hour', [[50, '50 usos en una hora'], [100, '100 usos en una hora'], [500, '500 usos en una hora'], [0, 'Nunca']], 100, 'Para cambiar el límite de usos.');
  const reminderSelect = settingSelect('rotate_reminder_days', [[90, '3 meses'], [180, '6 meses'], [365, '1 año'], [0, 'Nunca']], 365, 'Para cambiar el recordatorio.');
  const checkControl = checkEveryControl(status.check_every_hours ?? 24, false, async () => {
    let hours;
    try { hours = checkControl.value(); } catch (error) { toast(error.message, 'error'); return; }
    const result = await withProof((p) => api().call('set_settings', { settings: { check_every_hours: hours } }, p), 'Para cambiar cada cuánto se comprueban las claves.');
    if (result.ok) { toast('Guardado'); await refreshStatus(); } else if (result.code !== 'cancelled') toast(result.error, 'error');
  });
  checkControl.select.style.width = '';  // the same width as the other selects here

  const autoScan = el('input', { type: 'checkbox', checked: state.info.prefs.auto_scan !== false });
  autoScan.addEventListener('change', async () => {
    state.info.prefs.auto_scan = autoScan.checked;
    await api().set_pref('auto_scan', autoScan.checked);
    toast('Guardado');
  });
  const folderList = el('div', { class: 'folder-list' });
  const renderFolders = async () => {
    const folders = await api().scan_folders();
    folderList.replaceChildren(
      folders.detected.map((f) => el('div', { class: 'folder' }, el('span', { class: 'path', title: f }, f), el('span', { class: 'faint' }, 'Claude Code'))),
      folders.extra.map((f) => el('div', { class: 'folder' }, el('span', { class: 'path', title: f }, f),
        el('button', { class: 'btn icon-only', title: 'Quitar', onclick: async () => {
          await api().set_pref('scan_folders', folders.extra.filter((x) => x !== f));
          renderFolders();
        } }, icon('x', 'sm')))));
  };
  renderFolders();
  const addFolder = el('button', { class: 'btn', onclick: async () => { if (await api().add_scan_folder()) renderFolders(); } }, 'Añadir carpeta');

  const palettes = el('div', { class: 'segmented' }, PALETTES.map(([id, label, color]) => el('button', {
    class: (state.info.prefs.palette || DEFAULT_PALETTE) === id ? 'active' : '',
    onclick: async () => { state.info.prefs.palette = id; applyPalette(id); await api().set_pref('palette', id); renderView(); },
  }, el('span', { style: `display:inline-block;width:10px;height:10px;border-radius:50%;background:${color};margin-right:7px;vertical-align:-1px` }), label)));

  const ai = state.info.integrations || {};
  const claudeControl = ai.claude_code === 'connected'
    ? el('span', { class: 'state-text ok' }, icon('check', 'sm'), 'Conectado')
    : ai.claude_code === 'missing'
      ? el('span', { class: 'state-text' }, 'No instalado')
      : el('button', { class: 'btn', onclick: async () => {
        const result = await api().connect_claude_code();
        if (result.ok) { toast('Conectado. Reinicia Claude Code.'); state.info.integrations.claude_code = 'connected'; renderView(); } else toast(result.error, 'error');
      } }, 'Conectar');
  const desktopControl = ai.claude_desktop === 'connected'
    ? el('span', { class: 'state-text ok' }, icon('check', 'sm'), 'Conectado')
    : ai.claude_desktop === 'missing'
      ? el('span', { class: 'state-text' }, 'No instalado')
      : el('button', { class: 'btn', onclick: async () => {
        const result = await api().connect_claude_desktop();
        if (result.ok) { toast('Conectado. Reinicia Claude Desktop.'); state.info.integrations.claude_desktop = 'connected'; renderView(); } else toast(result.error, 'error');
      } }, 'Conectar');

  content.replaceChildren(
    el('div', { class: 'content-header' }, el('h1', {}, 'Ajustes')),
    el('div', { class: 'content-body' }, el('div', { class: 'settings' },
      el('div', { class: 'settings-group' }, el('h3', { class: 'muted' }, 'Seguridad'),
        ['windows', 'macos'].includes(state.info.os || 'windows') ? setting('Windows Hello', 'Desbloquea y muestra contraseñas con tu PIN, huella o cara.', helloControl) : null,
        setting('Contraseña maestra', 'Si la olvidas, puedes cambiarla aquí tras confirmar con Windows.',
          el('button', { class: 'btn', onclick: () => changeMasterPassword(false) }, 'Cambiar')),
        setting('Abrir con mi sesión de Windows', 'La bóveda se abre sola al entrar en Windows y se cierra al bloquearlo (Win+L), sin escribir contraseñas. Protege de errores de la IA, no de alguien que use tu sesión.', sessionToggle),
        setting('Bloqueo automático', status.session_unlock
          ? 'Bloquea la bóveda tras un tiempo sin uso. Con la sesión de Windows se vuelve a abrir sola cuando tú o la IA la necesitáis, sin escribir nada.'
          : 'Bloquea la bóveda tras un tiempo sin uso. Las aprobaciones de la IA siguen valiendo al desbloquear.', lockSelect),
        setting('Volver a preguntar si se usa mucho', 'Aunque hayas aprobado una credencial, si la IA la usa más de estas veces en una hora te vuelve a preguntar. Frena bucles y sustos.', usesSelect),
        setting('Recordar rotar las claves', 'Marca las claves con más antigüedad que esta y te avisa una vez al día. Las fechas de caducidad avisan 14 días antes.', reminderSelect),
        setting('Comprobar que las claves funcionan', 'Prueba cada clave con una llamada de solo lectura a su proveedor, entra y sale de los servidores SSH y busca las contraseñas en filtraciones conocidas. Cada credencial puede tener el suyo al editarla.', checkControl.node),
        setting('Recordar aprobaciones', 'Cuando permites una credencial, la IA puede usarla sin volver a preguntarte durante este tiempo. Bloquear a mano las olvida todas.', approvalSelect),
        setting('Aislamiento', status.isolated
          ? 'El servicio usa una cuenta de Windows propia: ningún programa puede leer su memoria ni sus archivos.'
          : 'El servicio usa tu cuenta de Windows. Instala SecretBroker para activar la protección completa.',
        el('span', { class: `state-text ${status.isolated ? 'ok' : 'warn'}` }, status.isolated ? 'Activo' : 'Desactivado'))),
      el('div', { class: 'settings-group' }, el('h3', { class: 'muted' }, 'IA'),
        setting('Claude Code', 'Permite que Claude Code use tus credenciales a través de SecretBroker.', claudeControl),
        setting('Claude Desktop', 'Permite que la app de escritorio de Claude use tus credenciales.', desktopControl),
        setting('Acceso de la IA', status.session_grants
          ? (status.session_grants === 1 ? 'Una credencial aprobada ahora mismo.' : `${status.session_grants} credenciales aprobadas ahora mismo.`)
          : 'Qué puede usar la IA sin preguntarte, y pausarla.',
        el('button', { class: 'btn', onclick: () => { state.view = 'access'; renderMain(); } }, 'Ver'))),
      el('div', { class: 'settings-group' }, el('h3', { class: 'muted' }, 'Aplicación'),
        setting('Arrancar con Windows', 'SecretBroker se queda junto al reloj, listo para la IA. Cerrar la ventana no lo cierra: usa «Salir» en ese icono.', startToggle)),
      backupSlot,
      importExportGroup(),  // personal.js
      browserSettingsGroup(),
      el('div', { class: 'settings-group' }, el('h3', { class: 'muted' }, 'Copias de tus claves'),
        setting('Buscar copias al desbloquear', 'Busca copias de tus claves en este PC al desbloquear, como mucho cada 12 horas.', autoScan),
        setting('Carpetas de proyectos', 'Se revisan junto con sus historiales de git. Las carpetas donde has usado Claude Code se añaden solas.', addFolder),
        folderList),
      el('div', { class: 'settings-group' }, el('h3', { class: 'muted' }, 'Apariencia'),
        setting('Color', 'El tema claro u oscuro sigue al de Windows.', palettes)),
      el('div', { class: 'settings-group' }, el('h3', { class: 'muted' }, 'Actualizaciones'),
        setting(`Versión ${state.info.version}`, updateSummary(), el('button', { class: 'btn', onclick: async (event) => {
          busy(event.currentTarget, true);
          await checkUpdate(true);
          renderView();
          if (state.update && state.update.available) openUpdate();
          else if (state.update && !state.update.error) toast('Ya tienes la última versión');
        } }, 'Buscar ahora'))),
      el('p', { class: 'faint small' }, `SecretBroker ${state.info.version} · ${status.owner}`))));
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
  const nowButton = el('button', { class: 'btn' }, 'Hacer copia ahora');
  nowButton.addEventListener('click', () => run(nowButton, () => api().backup_now(), 'Copia guardada'));
  const folderButton = el('button', { class: 'btn' }, info.folder ? 'Cambiar carpeta' : 'Elegir otra carpeta');
  folderButton.addEventListener('click', () => run(folderButton, () => api().choose_backup_folder(), 'Copia guardada'));
  const enableButton = el('button', { class: 'btn primary' }, 'Activar');
  enableButton.addEventListener('click', () => run(enableButton, () => api().set_backup_folder(info.suggested), 'Copias activadas'));
  slot.replaceChildren(title,
    info.folder
      ? setting('Copia diaria automática', `En ${info.folder}. ${info.last ? `Última: ${formatTime(info.last)}.` : ''} Se guardan las 10 últimas.`,
        el('div', { style: 'display:flex;gap:8px' }, nowButton, folderButton))
      : setting('Copia diaria automática', `Guarda cada día la bóveda cifrada en ${info.suggested}. Sin copia, si se estropea el disco pierdes todas las claves.`,
        el('div', { style: 'display:flex;gap:8px' }, enableButton, folderButton)),
    setting('Restaurar una copia', 'Sustituye la bóveda por una copia. Necesitas la contraseña maestra que tenía entonces. La bóveda actual se guarda aparte por si acaso.',
      el('button', { class: 'btn', onclick: () => restoreBackup(async () => { await loadEntries(); renderMain(); }) }, 'Restaurar…')));
}

async function restoreBackup(onDone) {
  const path = await api().pick_backup_file();
  if (!path) return;
  const pw = passwordInput({ placeholder: 'Contraseña maestra de la copia', autocomplete: 'current-password' });
  const errorText = el('div', { class: 'error-text' });
  const button = el('button', { class: 'btn primary' }, 'Restaurar');
  const modal = openModal({
    title: 'Restaurar una copia',
    body: [el('p', { class: 'muted small selectable' }, path), el('div', { class: 'field' }, el('label', {}, 'Contraseña maestra'), pw), errorText],
    footer: [el('button', { class: 'btn', onclick: () => modal.close() }, 'Cancelar'), button],
  });
  const submit = async () => {
    errorText.textContent = '';
    busy(button, true);
    const restoring = state.status.state === 'no_vault'
      ? await api().restore_backup(path, pw.input.value)
      : await withProof((p) => api().restore_backup(path, pw.input.value, p), 'Para sustituir la bóveda actual.');
    busy(button, false);
    if (!restoring.ok) { if (restoring.code !== 'cancelled') errorText.textContent = restoring.error; return; }
    modal.close();
    toast('Copia restaurada');
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
  if (!u) return 'La app busca versiones nuevas en GitHub cada pocas horas.';
  if (u.error) return `No se pudo comprobar: ${u.error}`;
  if (u.available) return `Hay una versión nueva: ${u.latest}.`;
  return 'Tienes la última versión.';
}

function renderUpdateSlot() {
  const slot = document.getElementById('update-slot');
  if (!slot) return;
  const u = state.update;
  slot.replaceChildren(u && u.available
    ? el('button', { class: 'update-pill', onclick: openUpdate }, icon('sparkles', 'sm'), `Actualizar a ${u.latest}`)
    : '');
}

function openUpdate() {
  const u = state.update;
  const install = el('button', { class: 'btn primary' }, 'Actualizar');
  const errorText = el('div', { class: 'error-text' });
  const modal = openModal({
    title: `SecretBroker ${u.latest}`,
    body: el('div', {},
      u.notes ? el('p', { class: 'notes selectable muted' }, u.notes) : null,
      el('p', { class: 'help' }, 'Se descarga de GitHub y solo se instala si está firmada por el autor. ',
        'Windows te pedirá permiso de administrador; la bóveda y tus ajustes se conservan y la app se reabre sola.'),
      errorText),
    footer: [
      el('button', { class: 'btn', onclick: () => api().open_link(u.url) }, 'Ver en GitHub'),
      el('button', { class: 'btn', onclick: () => modal.close() }, 'Más tarde'),
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
    toast('Instalando la actualización… la app se reabrirá sola');
  });
}

function changeMasterPassword(recovering) {
  const pw = passwordInput();
  const confirm = passwordInput();
  const errorText = el('div', { class: 'error-text' });
  const button = el('button', { class: 'btn primary' }, 'Cambiar');
  button.addEventListener('click', async () => {
    errorText.textContent = '';
    if (pw.input.value.length < 12) { errorText.textContent = 'Necesita al menos 12 caracteres.'; return; }
    if (pw.input.value !== confirm.input.value) { errorText.textContent = 'Las dos contraseñas no coinciden.'; return; }
    busy(button, true);
    const result = await withProof((p) => api().call('change_master_password', { new_password: pw.input.value }, p), 'Para cambiar la contraseña maestra.');
    busy(button, false);
    if (!result.ok) { if (result.code !== 'cancelled') errorText.textContent = result.error; return; }
    modal.close();
    toast('Contraseña maestra cambiada');
  });
  const modal = openModal({
    title: recovering ? 'Elige una contraseña maestra nueva' : 'Cambiar contraseña maestra',
    body: [
      recovering ? el('p', { class: 'muted' }, 'Has entrado con Windows. Elige una nueva para no perder el acceso desde copias de seguridad u otros equipos.') : null,
      el('div', { class: 'field' }, el('label', {}, 'Nueva contraseña maestra'), pw, strengthMeter(pw.input)),
      el('div', { class: 'field' }, el('label', {}, 'Repítela'), confirm),
      errorText],
    footer: [el('button', { class: 'btn', onclick: () => modal.close() }, 'Cancelar'), button],
  });
  setTimeout(() => pw.input.focus(), 50);
}

// ======================================================================= drafts (prepared by the AI)

// The secret fields still missing in a draft: the only thing the user has to add.
function draftInputs(entry) {
  return activeSpecs(entry.template, entry.fields).filter((s) => s.secret && s.required).map((spec) => {
    const group = spec.kind === 'multiline'
      ? { input: el('textarea', { class: 'input mono', rows: 5, spellcheck: 'false' }) }
      : passwordInput({ placeholder: 'Pega aquí la clave' });
    return { spec, input: group.input, node: el('div', { class: 'field' }, el('label', {}, spec.label), group.input.tagName === 'TEXTAREA' ? group.input : group) };
  });
}

async function saveDraftSecret(entry, inputs, button, errorText) {
  const fields = Object.fromEntries(inputs.map(({ spec, input }) => [spec.name, input.value.trim()]));
  if (Object.values(fields).some((v) => !v)) { errorText.textContent = 'Pega la clave.'; return false; }
  busy(button, true);
  const result = await withProof((p) => api().call('complete_draft', { id: entry.id, fields }, p), `Para guardar la clave de ${entry.name}.`);
  busy(button, false);
  if (!result.ok) { if (result.code !== 'cancelled') errorText.textContent = result.error; return false; }
  await loadEntries();
  toast('Clave guardada');
  return true;
}

function draftSection(entry, onSaved) {
  const inputs = draftInputs(entry);
  const errorText = el('div', { class: 'error-text' });
  const save = el('button', { class: 'btn primary' }, 'Guardar clave');
  save.addEventListener('click', async () => { if (await saveDraftSecret(entry, inputs, save, errorText)) onSaved(); });
  return el('div', { class: 'section draft-box' },
    el('h3', {}, 'Falta la clave'),
    el('p', { class: 'help' }, 'La IA ha preparado esta credencial. Pega la clave y ya se podrá usar.'),
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
  const save = el('button', { class: 'btn primary' }, 'Guardar clave');
  const provider = entry.provider;
  const modal = openModal({
    title: 'La IA ha preparado una credencial',
    body: el('div', { class: 'request' },
      el('div', { class: 'request-who' }, glyph(entry.template),
        el('div', {}, el('div', { style: 'font-weight:600' }, entry.name), el('div', { class: 'muted small' }, TEMPLATES[entry.template].label))),
      entry.description ? el('p', { class: 'notes muted' }, entry.description) : null,
      el('div', { class: 'section' }, el('h3', {}, 'La IA podrá'), describePermissions(entry)),
      inputs.map((i) => i.node),
      provider && provider.links.length ? el('div', { class: 'section' }, el('h3', {}, `¿Dónde consigo la clave? · ${provider.provider}`), linkList(provider.links)) : null,
      errorText),
    footer: [el('button', { class: 'btn', onclick: () => modal.close() }, 'Más tarde'), save],
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
// credential, exactly what it will do (the host stands out), and two equally weighted ways to say yes. Several
// requests queue ("1 de 3"); «Decidir luego» folds them into a banner instead of popping up again.

// approval_hours (Ajustes) → [button, how long, in a sentence].
const APPROVAL_SPANS = { 24: ['Permitir 24 horas', 'durante 24 horas'], 8: ['Permitir 8 horas', 'durante 8 horas'],
  0: ['Hasta que bloquee', 'hasta que bloquees la bóveda'] };
const APPROVAL_TITLES = { request_access: 'pide acceso para una tarea', delete: 'propone borrar una credencial', rotate: 'quiere rotar una clave',
  import_env: 'quiere importar claves de un .env', edit: 'quiere cambiar una credencial', draft: 'quiere cambiar una credencial' };
const EXPIRED_TEXT = 'La petición de la IA caducó; la IA recibió un error';

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
    if (late.length) toast(EXPIRED_TEXT, 'error');
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
  return (request.client && request.client.name) || 'La IA';
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
  const detail = request.detail || '';
  const host = request.host;
  const at = host ? detail.indexOf(host) : -1;
  const lineEnd = detail.indexOf('\n');
  const content = at >= 0 && (lineEnd < 0 || at < lineEnd)
    ? [detail.slice(0, at), el('mark', { class: 'host', title: 'Adónde va' }, host), detail.slice(at + host.length)]
    : [detail];
  return el('div', { class: 'request-detail selectable' }, content);
}

function usageLine(request) {
  if (['request_access', 'import_env', 'draft'].includes(request.action)) return null;
  const today = request.uses_today || 0;
  const last = request.last_used ? `Último uso por la IA: ${sinceText(request.last_used)}` : 'La IA aún no la ha usado';
  return el('div', { class: 'muted small' }, today ? `${last} · ${plural(today, 'vez', 'veces')} hoy` : last);
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
        ? 'Para aprobar que la IA borre, rote o cambie adónde puede ir una clave.' : 'Para aprobar el uso de la credencial.');
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
  const onceLabel = { edit: 'Aplicar el cambio', draft: 'Permitir', rotate: 'Rotar ahora', delete: 'Borrar', import_env: 'Importar' }[request.action] || 'Solo esta vez';
  // Two ways to say yes, side by side and alike: neither is pushed on the user.
  const both = allowOnce && request.allow_session;
  const onceButton = allowOnce ? el('button', { class: `btn ${both ? 'equal' : 'primary'}` }, onceLabel) : null;
  if (onceButton) onceButton.addEventListener('click', () => approve([request.id], () => 'once', onceButton));
  const sessionButton = request.allow_session ? el('button', { class: `btn ${both ? 'equal' : 'primary'}` }, spanLabel) : null;
  if (sessionButton) sessionButton.addEventListener('click', () => approve([request.id], () => 'session', sessionButton));
  const batchButton = el('button', { class: 'btn ghost batch hidden' });
  batchButton.addEventListener('click', () => {
    const ids = sameClient().map((a) => a.id);
    approve(ids, (a) => (a.allow_session ? 'session' : 'once'), batchButton);
  });
  const sameClient = () => (state.approvals || []).filter((a) => clientOf(a) === who);

  const explain = request.allow_session ? el('p', { class: 'approval-explain' },
    el('b', {}, `«${spanLabel}»`), `: ${who} podrá usar «${request.secret_name}» sin volver a preguntarte ${spanText}`,
    allowOnce ? ['; ', el('b', {}, `«${onceLabel}»`), ', solo para esta petición.'] : '. Bloquear a mano lo anula antes.') : null;

  const counter = el('span', { class: 'queue-count' });
  const countdown = el('span', { class: 'countdown' });
  const bar = el('div', { class: 'countdown-bar' }, el('span'));
  const folder = request.client && request.client.folder;
  const entry = state.entries.find((e) => e.id === request.secret_id);
  const category = (TEMPLATES[request.template] || {}).icon || 'lock';
  const destructive = looksDestructive(request.detail);

  const modal = openModal({
    title: `${who} ${APPROVAL_TITLES[request.action] || 'quiere usar una credencial'}`,
    lead: el('div', { class: 'client-mark', title: who }, icon('bot')),
    className: 'approval',
    closeLabel: 'Decidir luego',
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
      request.reason ? el('div', { class: 'request-reason' }, el('span', { class: 'small muted' }, 'Para qué, según la IA'), el('p', {}, request.reason))
        : el('p', { class: 'muted small' }, `${who} no ha dicho para qué.`),
      el('div', { class: `cred-card cat-${category}` }, glyph(request.template),
        el('div', { class: 'meta' }, el('div', { class: 'cred-name' }, request.secret_name),
          el('div', { class: 'muted small' }, ACTION_LABELS[request.action] || request.action,
            entry && subtitleOf(entry) ? ` · ${subtitleOf(entry)}` : '')),
        usageLine(request)),
      actionBlock(request),
      destructive ? el('div', { class: 'warning is-danger' }, icon('alert', 'sm'), 'Parece que borra, detiene o modifica datos. Revísalo antes de permitirlo.') : null,
      explain,
      errorText),
    footer: [
      el('button', { class: 'btn danger', onclick: deny }, 'Denegar'),
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
    counter.textContent = queue.length > 1 ? `${position + 1} de ${queue.length}` : '';
    counter.classList.toggle('hidden', queue.length < 2);
    const batch = sameClient();
    batchButton.textContent = `Permitir las ${batch.length} para esta tarea`;
    batchButton.classList.toggle('hidden', batch.length < 2);
  };
  const tickDown = () => {
    if (!modal.overlay.isConnected) { clearInterval(timer); return; }  // closed with all the others
    const left = secondsLeft(request);
    if (left === null) return;
    countdown.textContent = left ? `Caduca en ${clock(left)}` : 'Caducando…';
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
    time.textContent = left === null ? '' : `caduca en ${clock(left)}`;
    time.classList.toggle('urgent', left !== null && left <= 20);
  };
  banner.replaceChildren(icon('bot', 'sm'),
    el('span', { class: 'text' }, waiting.length === 1
      ? [el('b', {}, clientOf(first)), ` espera tu respuesta: «${first.secret_name}»`]
      : [el('b', {}, `${waiting.length} peticiones de la IA`), ' esperan tu respuesta']),
    time,
    el('button', { class: 'btn primary', onclick: () => {
      state.approvalDeferred = new Set();
      banner.remove();
      showApproval(first);
    } }, 'Revisar'));
  draw();
  clearInterval(state.bannerTimer);
  state.bannerTimer = setInterval(draw, 1000);
}
