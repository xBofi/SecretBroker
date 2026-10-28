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
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

function icon(name, size = '') {
  return el('span', { class: `icon ${size}`, html: `<svg viewBox="0 0 24 24" aria-hidden="true">${ICONS[name] || ''}</svg>` });
}

function glyph(templateId, size = '') {
  const t = TEMPLATES[templateId] || TEMPLATES.generic;
  return el('div', { class: `glyph ${t.icon} ${size}` }, icon(t.icon, size === 'lg' ? 'lg' : ''));
}

function toast(message, kind = '') {
  const node = el('div', { class: `toast ${kind}` }, kind === 'error' ? icon('alert', 'sm') : null, message);
  document.getElementById('toasts').append(node);
  setTimeout(() => node.remove(), kind === 'error' ? 6000 : 2800);
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
  unlock: 'Desbloqueo', lock: 'Bloqueo', save: 'Guardada', delete: 'Eliminada',
  reveal: 'Secreto mostrado', create: 'Bóveda creada', enroll_hello: 'Windows Hello activado',
  remove_hello: 'Windows Hello desactivado', change_master_password: 'Contraseña maestra cambiada',
};
const APPROVAL_LABELS = { session: 'Una vez por sesión', always: 'Siempre', never: 'Nunca' };
const AUTH_LABELS = { none: 'No añadir', header: 'En una cabecera', query: 'Como parámetro de la URL', basic: 'HTTP Basic (usuario y contraseña)' };

// ======================================================================= boot & polling

async function boot() {
  state.info = await api().info();
  applyPalette(state.info.prefs.palette);
  for (const t of state.info.templates.templates) TEMPLATES[t.id] = t;
  DB_ENGINES = state.info.templates.db_engines;
  document.addEventListener('keydown', onShortcut);
  await refreshStatus();
  setInterval(tick, 1500);
}

if (window.pywebview && window.pywebview.api) boot();
else window.addEventListener('pywebviewready', boot);

function applyPalette(name) {
  if (name && name !== DEFAULT_PALETTE) document.documentElement.dataset.palette = name;
  else delete document.documentElement.dataset.palette;
}

function onShortcut(event) {
  const modalRoot = document.getElementById('modal-root');
  if (event.key === 'Escape' && modalRoot.lastElementChild) {
    modalRoot.lastElementChild.dispatchEvent(new CustomEvent('dismiss'));
    return;
  }
  if (state.screen !== 'main' || modalRoot.lastElementChild || !event.ctrlKey) return;
  const key = event.key.toLowerCase();
  if (key === 'f') { event.preventDefault(); state.view = 'credentials'; renderMain(); document.querySelector('.search .input')?.focus(); }
  else if (key === 'n') { event.preventDefault(); openEditor(null); }
  else if (key === 'l') { event.preventDefault(); lockNow(); }
}

async function tick() {
  await refreshStatus();
  if (state.status && state.status.state === 'unlocked') await pollApprovals();
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
    else if (target === 'lock') renderLock();
    else await enterMain();
  } else if (target === 'main') {
    updateSidebarState();
  }
}

function renderUnavailable(message) {
  state.screen = 'unavailable';
  $app().replaceChildren(el('div', { class: 'center-screen' },
    el('div', { class: 'auth' },
      el('div', { class: 'auth-head' }, brand(), el('h2', {}, 'No se puede conectar con el servicio')),
      el('p', { class: 'lead' }, message || 'El servicio SecretBroker no responde.'),
      el('p', { class: 'help' }, state.info && state.info.installed
        ? 'El servicio arranca con Windows. Si acabas de instalar, espera unos segundos o reinicia el equipo.'
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
  state.approvalOpen = null;
}

function openModal({ title, body, footer, wide = false, onClose, lead }) {
  let closed = false;
  const close = () => {
    if (closed) return;
    closed = true;
    overlay.remove();
    if (onClose) onClose();
  };
  const overlay = el('div', { class: 'overlay' },
    el('div', { class: `modal ${wide ? 'wide' : ''}`, role: 'dialog', 'aria-label': title },
      el('div', { class: 'modal-head' }, lead || null, el('h2', {}, title),
        el('button', { class: 'btn icon-only', onclick: close, title: 'Cerrar (Esc)' }, icon('x'))),
      el('div', { class: 'modal-body' }, body),
      footer ? el('div', { class: 'modal-foot' }, footer) : null));
  overlay.addEventListener('mousedown', (event) => { if (event.target === overlay) close(); });
  overlay.addEventListener('dismiss', close);
  document.getElementById('modal-root').append(overlay);
  return { close, overlay };
}

// Ask for a password proof. Resolves {kind, value}, 'hello' (retry with Hello) or null.
function askProof(reason, error) {
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
  while (!result.ok && ['proof_required', 'hello_cancelled', 'hello_failed', 'proof_invalid'].includes(result.code)) {
    const choice = await askProof(reason, result.code === 'proof_required' ? null : result.error);
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
  const steps = (n) => el('div', { class: 'steps' }, [1, 2, 3].map((i) => el('span', { class: i <= n ? 'done' : '' })));

  const welcome = () => {
    box.replaceChildren(
      el('div', { class: 'auth-head' }, brand(true), el('h1', { style: 'margin-top:12px' }, 'Tus claves, usadas sin ser vistas')),
      el('p', { class: 'lead' }, 'Guarda contraseñas, API keys y accesos. La IA podrá usarlos para trabajar por ti, pero nunca leerlos.'),
      el('div', { class: 'points' },
        el('div', {}, icon('bot'), el('div', {}, el('b', {}, 'La IA usa, no ve. '), el('span', { class: 'muted' }, 'Las claves se insertan en cada petición y se borran de las respuestas.'))),
        el('div', {}, icon('fingerprint'), el('div', {}, el('b', {}, 'Tú decides. '), el('span', { class: 'muted' }, 'Apruebas cada uso con tu PIN, huella o cara.'))),
        el('div', {}, icon('lock'), el('div', {}, el('b', {}, 'Cifrado local. '), el('span', { class: 'muted' }, 'AES-256 en este equipo. Nada sale a la nube.')))),
      status.legacy_vault ? el('p', { class: 'help' }, 'Hemos encontrado tu bóveda anterior: podrás importarla en el siguiente paso.') : null,
      el('div', {}, el('button', { class: 'btn primary lg', onclick: passwordStep }, 'Empezar')));
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
      if (state.info.hello_supported) helloStep(); else finish();
    };
    button.addEventListener('click', submit);
    confirm.input.addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });

    box.replaceChildren(
      el('div', { class: 'auth-head' }, steps(2), el('h2', { style: 'margin-top:12px' }, 'Elige una contraseña maestra')),
      el('p', { class: 'lead' }, 'Cifra la bóveda. En el día a día usarás Windows Hello; esta la necesitarás para restaurar copias o en otro equipo.'),
      el('div', { class: 'field' }, el('label', {}, 'Contraseña maestra'), pw, strengthMeter(pw.input)),
      el('div', { class: 'field' }, el('label', {}, 'Repítela'), confirm),
      legacySection,
      errorText,
      el('div', {}, button));
    setTimeout(() => pw.input.focus(), 50);
  };

  const helloStep = () => {
    const errorText = el('div', { class: 'error-text' });
    const button = el('button', { class: 'btn primary lg' }, icon('fingerprint', 'sm'), 'Activar Windows Hello');
    button.addEventListener('click', async () => {
      busy(button, true);
      const result = await api().enroll_hello({ kind: 'master_password', value: masterPassword });
      busy(button, false);
      if (!result.ok) { if (result.code !== 'hello_cancelled') errorText.textContent = result.error; return; }
      finish();
    });
    box.replaceChildren(
      el('div', { class: 'auth-head' }, steps(3), el('h2', { style: 'margin-top:12px' }, 'Desbloquea con tu PIN o tu huella')),
      el('p', { class: 'lead' }, 'Como cuando el navegador te pide el PIN para rellenar una tarjeta. Lo usarás para desbloquear, aprobar usos de la IA y ver contraseñas.'),
      el('p', { class: 'help' }, 'Si olvidas la contraseña maestra, podrás entrar con Windows Hello y elegir otra.'),
      errorText,
      el('div', { style: 'display:flex;gap:8px' }, button, el('button', { class: 'btn ghost lg', onclick: finish }, 'Ahora no')));
  };

  const finish = () => {
    masterPassword = null;
    state.setupActive = false;
    state.screen = null;
    refreshStatus();
  };

  welcome();
}

// ======================================================================= lock screen

function renderLock() {
  const status = state.status;
  const canDevice = status.device_unlock;
  const helloAvailable = canDevice && status.hello_enrolled && state.info.hello_supported;
  const errorText = el('div', { class: 'error-text', style: 'text-align:center' });

  const master = passwordInput({ placeholder: 'Contraseña maestra', autocomplete: 'current-password' });
  const masterButton = el('button', { class: `btn ${helloAvailable ? '' : 'primary'}` }, 'Desbloquear');
  const unlockMaster = async () => {
    if (!master.input.value) { master.input.focus(); return; }
    busy(masterButton, true);
    const result = await api().call('unlock', {}, { kind: 'master_password', value: master.input.value });
    busy(masterButton, false);
    if (!result.ok) { errorText.textContent = result.error; master.input.select(); return; }
    master.input.value = '';
    refreshStatus();
  };
  masterButton.addEventListener('click', unlockMaster);
  master.input.addEventListener('keydown', (e) => { if (e.key === 'Enter') unlockMaster(); });

  const helloButton = el('button', { class: 'btn primary lg block' }, icon('fingerprint', 'sm'), 'Desbloquear con Windows Hello');
  const unlockHello = async () => {
    errorText.textContent = '';
    busy(helloButton, true);
    const result = await api().call('unlock', {});
    busy(helloButton, false);
    if (!result.ok) { if (result.code !== 'hello_cancelled') errorText.textContent = result.error; return; }
    refreshStatus();
  };
  helloButton.addEventListener('click', unlockHello);

  const unlockWindows = async () => {
    errorText.textContent = '';
    const proof = await askProof('Escribe la contraseña de tu cuenta de Windows.');
    if (!proof) return;
    if (proof === 'hello') return unlockHello();
    const result = await api().call('unlock', {}, proof);
    if (!result.ok) { errorText.textContent = result.error; return; }
    refreshStatus();
  };

  const forgot = () => {
    if (!canDevice) {
      openModal({ title: 'Recuperar el acceso', body: [
        el('p', {}, 'Este equipo aún no tiene el desbloqueo con Windows activado, así que solo la contraseña maestra puede abrir la bóveda.'),
        el('p', { class: 'muted' }, 'Por seguridad, no hay otra forma de descifrarla.')] });
      return;
    }
    const modal = openModal({
      title: 'Recuperar el acceso',
      body: el('p', {}, 'Entra con Windows Hello o con tu contraseña de Windows. Después podrás elegir una contraseña maestra nueva. Solo funciona en este equipo.'),
      footer: [
        status.windows_password ? el('button', { class: 'btn', onclick: () => { modal.close(); state.afterUnlock = 'change_master'; unlockWindows(); } }, 'Contraseña de Windows') : null,
        helloAvailable ? el('button', { class: 'btn primary', onclick: () => { modal.close(); state.afterUnlock = 'change_master'; unlockHello(); } }, 'Windows Hello') : null,
      ],
    });
  };

  $app().replaceChildren(el('div', { class: 'center-screen' },
    el('div', { class: 'auth' },
      el('div', { class: 'auth-head center' }, brand(true), el('h2', { style: 'margin-top:10px' }, 'SecretBroker está bloqueado')),
      helloAvailable ? helloButton : null,
      canDevice && status.windows_password ? el('div', { style: 'text-align:center' },
        el('button', { class: 'link muted-link', onclick: unlockWindows }, 'Usar la contraseña de Windows')) : null,
      canDevice ? el('div', { class: 'divider' }, 'o') : null,
      el('div', { style: 'display:flex;gap:8px' }, el('div', { style: 'flex:1' }, master), masterButton),
      errorText,
      el('div', { style: 'text-align:center' }, el('button', { class: 'link small', onclick: forgot }, '¿Has olvidado la contraseña maestra?')),
      el('p', { class: 'footnote', style: 'margin-top:24px' }, 'Desbloquea solo en esta ventana. SecretBroker nunca te pedirá la contraseña en otra.'))));
  if (!helloAvailable) setTimeout(() => master.input.focus(), 50);
}

// ======================================================================= main

async function enterMain() {
  await loadEntries();
  renderMain();
  if (state.afterUnlock === 'change_master') {
    state.afterUnlock = null;
    state.view = 'settings';
    renderMain();
    changeMasterPassword(true);
  }
}

async function loadEntries() {
  const result = await api().call('entries');
  state.entries = result.ok ? result.result : [];
  if (state.selected && !state.entries.some((e) => e.id === state.selected)) state.selected = null;
}

function renderMain() {
  const sidebar = el('aside', { class: 'sidebar' },
    brand(),
    el('nav', { class: 'nav' },
      navButton('credentials', 'key', 'Credenciales', state.entries.length),
      navButton('activity', 'activity', 'Actividad'),
      navButton('settings', 'settings', 'Ajustes')),
    el('div', { class: 'sidebar-footer' },
      el('div', { class: 'state', id: 'sidebar-state' }),
      el('button', { class: 'btn icon-only', title: 'Bloquear (Ctrl+L)', onclick: lockNow }, icon('lock', 'sm'))));
  $app().replaceChildren(el('div', { class: 'layout' }, sidebar, el('main', { class: 'content', id: 'content' })));
  updateSidebarState();
  renderView();
}

function navButton(view, iconName, label, count) {
  return el('button', {
    class: state.view === view ? 'active' : '',
    onclick: () => { state.view = view; renderMain(); },
  }, icon(iconName), label, count ? el('span', { class: 'count' }, count) : null);
}

function updateSidebarState() {
  const node = document.getElementById('sidebar-state');
  if (!node || !state.status) return;
  const minutes = state.status.auto_lock_minutes;
  node.replaceChildren(
    el('span', { class: `dot ${state.status.isolated ? '' : 'warn'}` }),
    el('span', {}, minutes ? `Desbloqueada · ${minutes >= 60 ? `${minutes / 60} h` : `${minutes} min`}` : 'Desbloqueada'));
  node.title = state.status.isolated ? 'Servicio aislado' : 'Modo sin aislamiento';
}

async function lockNow() {
  await api().call('lock');
  state.revealed = {};
  refreshStatus();
}

function renderView() {
  const content = document.getElementById('content');
  if (!content) return;
  if (state.view === 'credentials') renderCredentials(content);
  else if (state.view === 'activity') renderActivity(content);
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

function renderCredentials(content) {
  const search = el('input', { class: 'input', placeholder: 'Buscar', value: state.search });
  search.addEventListener('input', () => { state.search = search.value; renderList(); });
  search.addEventListener('keydown', (e) => { if (e.key === 'Escape') { search.value = ''; state.search = ''; renderList(); } });
  const header = el('div', { class: 'content-header' },
    el('h1', {}, 'Credenciales'),
    state.entries.length ? el('div', { class: 'search' }, icon('search', 'sm'), search) : null,
    el('button', { class: 'btn primary', title: 'Nueva (Ctrl+N)', onclick: () => openEditor(null) }, icon('plus', 'sm'), 'Nueva'));

  if (!state.entries.length) {
    content.replaceChildren(header, el('div', { class: 'content-body' }, el('div', { class: 'empty' },
      el('p', {}, 'Aún no hay credenciales.'),
      el('button', { class: 'btn primary', onclick: () => openEditor(null) }, 'Añadir la primera'))));
    return;
  }

  const list = el('div', { class: 'list' });
  const detail = el('div', { class: 'detail' });
  const renderList = () => {
    const query = state.search.trim().toLowerCase();
    const items = state.entries.filter((e) => !query
      || [e.name, e.id, e.description, subtitleOf(e), TEMPLATES[e.template].label].join(' ').toLowerCase().includes(query));
    list.replaceChildren(items.map((entry) => el('div', {
      class: `row ${state.selected === entry.id ? 'selected' : ''}`,
      onclick: () => { state.selected = entry.id; renderList(); renderDetail(detail); },
    }, glyph(entry.template), el('div', { class: 'meta' }, el('div', { class: 'title' }, entry.name), el('div', { class: 'subtitle' }, subtitleOf(entry))))));
    if (!items.length) list.append(el('p', { class: 'muted', style: 'padding:12px 10px' }, 'Ninguna coincide.'));
  };

  if (!state.selected) state.selected = state.entries[0].id;
  content.replaceChildren(header, el('div', { class: 'split', style: 'flex:1;min-height:0' }, list, el('div', { class: 'rule' }), detail));
  renderList();
  renderDetail(detail);
}

function activeSpecs(templateId, fields) {
  const specs = TEMPLATES[templateId].fields;
  const resolved = {};
  for (const s of specs) resolved[s.name] = s.default;
  for (const [k, v] of Object.entries(fields)) if (v) resolved[k] = v;
  return specs.filter((s) => !s.show_if || Object.entries(s.show_if).every(([k, v]) => resolved[k] === v));
}

function shortLabel(label) { return label.replace(/\s*\((opcional|si tiene)\)$/, ''); }

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
      el('div', { style: 'min-width:0' }, el('div', { class: 'k' }, shortLabel(spec.label)),
        el('div', { class: 'v selectable', title: raw }, displayValue(spec, raw))),
      el('div', { class: 'actions' }, spec.kind === 'select' ? null : copyButton(raw)));
  });

  const perms = describePermissions(entry);
  panel.replaceChildren(
    el('div', { class: 'detail-head' },
      glyph(entry.template, 'lg'),
      el('div', { class: 'meta' }, el('h2', {}, entry.name), el('div', { class: 'muted small' }, template.label)),
      el('button', { class: 'btn', onclick: () => openEditor(entry) }, 'Editar'),
      el('button', { class: 'btn icon-only', title: 'Eliminar', onclick: () => deleteEntry(entry) }, icon('trash', 'sm'))),
    el('div', { class: 'section' }, props),
    entry.description ? el('div', { class: 'section' }, el('h3', {}, 'Notas para la IA'), el('p', { class: 'notes selectable muted' }, entry.description)) : null,
    el('div', { class: 'section' },
      el('h3', {}, 'Qué puede hacer la IA'),
      perms.length ? perms : el('p', { class: 'muted' }, 'Nada todavía. Edita la credencial y abre «Permisos de la IA».'),
      el('p', { class: 'help', style: 'margin-top:6px' }, 'La IA la conoce como ', el('code', { class: 'selectable' }, entry.id))));
}

function describePermissions(entry) {
  const policy = entry.policy || {};
  const items = [];
  const http = policy.http || {};
  if (http.allowed_hosts && http.allowed_hosts.length) items.push(['globe', `Peticiones a ${http.allowed_hosts.join(', ')}`]);
  if (entry.template === 'ssh') items.push(['server', `Comandos y archivos en ${entry.fields.host}`]);
  const commands = policy.commands || {};
  if (commands.allowed && commands.allowed.length) items.push(['terminal', `Ejecutar ${commands.allowed.join(', ')} en este equipo`]);
  if (!items.length) return [];
  const approval = policy.approval || 'session';
  items.push(['fingerprint', { session: 'Te pregunta una vez por sesión', always: 'Te pregunta cada vez', never: 'No te pregunta' }[approval]]);
  return items.map(([i, text]) => el('div', { class: 'perm' }, icon(i, 'sm'), el('span', {}, text)));
}

async function deleteEntry(entry) {
  const modal = openModal({
    title: `¿Eliminar ${entry.name}?`,
    body: el('p', { class: 'muted' }, 'Se borrará de la bóveda y la IA dejará de poder usarla. No se puede deshacer.'),
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
  const labelFor = (spec) => el('label', {}, shortLabel(spec.label),
    !spec.required ? el('span', { class: 'req' }, ' · opcional') : null);

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
        el('div', {}, el('button', { class: 'link small', type: 'button', onclick: () => file.click() }, 'Cargar desde un archivo'), file));
    } else if (spec.kind === 'secret') {
      const group = passwordInput({ placeholder });
      control = group.input;
      control.addEventListener('input', onFieldChange);
      const wide = ['value', 'secret_access_key'].includes(spec.name) || (templateId === 'ssh' && spec.name === 'password');
      node = el('div', { class: `field ${wide ? 'full' : ''}` }, labelFor(spec, existingSecret), group, spec.help ? el('div', { class: 'help' }, spec.help) : null);
    } else {
      const dbPort = spec.name === 'port' && templateId === 'database' ? (DB_ENGINES[(inputs.engine || {}).value || 'postgresql'] || {}).port : null;
      control = el('input', { class: 'input', value: values[spec.name] || '', placeholder: dbPort || spec.hint || spec.default, spellcheck: 'false', inputmode: spec.kind === 'number' ? 'numeric' : null });
      if (spec.kind === 'number' && spec.default && !values[spec.name] && isNew) control.value = spec.default;
      control.addEventListener('input', onFieldChange);
      const wide = ['url', 'base_url'].includes(spec.name);
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
      el('div', { class: 'field' }, el('label', {}, 'Nombre para la IA'), idInput),
      el('div', { class: 'field' }, el('label', {}, 'Datos que la IA puede insertar sin verlos'), placeholderList)));

  const errorText = el('div', { class: 'error-text' });
  const saveButton = el('button', { class: 'btn primary' }, 'Guardar');

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
    return {
      id: idInput.value.trim() || slugify(nameInput.value), name: nameInput.value.trim(), template: templateId,
      description: notes.value.trim(), fields, policy: newPolicy,
    };
  };

  const save = async () => {
    errorText.textContent = '';
    let newEntry;
    try { newEntry = collect(); } catch (error) { errorText.textContent = error.message; return; }
    if (!newEntry.name) { errorText.textContent = 'Ponle un nombre.'; nameInput.focus(); return; }
    busy(saveButton, true);
    const result = await withProof((p) => api().call('save_entry', { entry: newEntry, replaces: isNew ? null : entry.id }, p), `Para guardar «${newEntry.name}».`);
    busy(saveButton, false);
    if (!result.ok) { if (result.code !== 'cancelled') errorText.textContent = result.error; return; }
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
      el('div', { class: 'field' }, el('label', {}, 'Nombre'), nameInput),
      fieldsBox,
      el('div', { class: 'field' }, el('label', {}, 'Notas para la IA', el('span', { class: 'req' }, ' · opcional')), notes,
        el('div', { class: 'help' }, 'La IA lee estas notas, nunca las contraseñas. Explica qué es y cómo debe usarla.')),
      advanced,
      errorText,
    ],
    footer: [
      isNew ? el('button', { class: 'btn ghost', onclick: () => { modal.close(); openEditor(null); } }, icon('arrowLeft', 'sm'), 'Cambiar tipo') : null,
      el('div', { class: 'spacer' }),
      el('button', { class: 'btn', onclick: () => modal.close() }, 'Cancelar'),
      saveButton,
    ],
  });
  setTimeout(() => nameInput.focus(), 50);
}

// ----------------------------------------------------------------------- activity

async function renderActivity(content) {
  const body = el('div', { class: 'content-body' }, el('div', { class: 'spinner' }));
  content.replaceChildren(el('div', { class: 'content-header' }, el('h1', {}, 'Actividad'),
    el('button', { class: 'btn ghost', onclick: () => renderActivity(content) }, 'Actualizar')), body);
  const result = await api().call('audit', { limit: 300 });
  const events = result.ok ? result.result : [];
  if (!events.length) { body.replaceChildren(el('div', { class: 'empty' }, el('p', {}, 'Aún no hay actividad.'))); return; }
  const names = Object.fromEntries(state.entries.map((e) => [e.id, e.name]));
  const statusLabel = { ok: 'Hecho', denied: 'Denegado', error: 'Error' };
  body.replaceChildren(el('table', { class: 'table' },
    el('thead', {}, el('tr', {}, el('th', {}, 'Cuándo'), el('th', {}, 'Credencial'), el('th', {}, 'Acción'), el('th', {}, 'Resultado'), el('th', {}, 'Detalle'))),
    el('tbody', {}, events.map((e) => el('tr', {},
      el('td', { class: 'muted', style: 'white-space:nowrap' }, formatTime(e.ts)),
      el('td', {}, e.secret === 'vault' ? el('span', { class: 'muted' }, 'Bóveda') : (names[e.secret] || e.secret)),
      el('td', {}, ACTION_LABELS[e.action] || e.action),
      el('td', {}, el('span', { class: `status ${e.status}` }, statusLabel[e.status] || e.status)),
      el('td', { class: 'detail-cell selectable', title: [e.detail, e.message].filter(Boolean).join(' — ') }, e.message || e.detail))))));
}

// ----------------------------------------------------------------------- settings

function setting(title, description, control) {
  return el('div', { class: 'setting' }, el('div', { class: 'meta' }, el('h3', {}, title), el('p', {}, description)), control);
}

function renderSettings(content) {
  const status = state.status;
  const helloSupported = state.info.hello_supported;

  const helloControl = !helloSupported
    ? el('span', { class: 'state-text' }, 'No disponible en este equipo')
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

  const lockSelect = el('select', { class: 'input', style: 'width:auto' },
    [[15, '15 minutos'], [30, '30 minutos'], [60, '1 hora'], [240, '4 horas'], [0, 'Nunca']].map(([v, label]) => el('option', { value: v }, label)));
  lockSelect.value = String(status.auto_lock_minutes || 0);
  lockSelect.addEventListener('change', async () => {
    const minutes = Number(lockSelect.value);
    const result = await withProof((p) => api().call('set_settings', { settings: { auto_lock_minutes: minutes } }, p), 'Para cambiar el bloqueo automático.');
    if (result.ok) { toast('Guardado'); await refreshStatus(); } else { lockSelect.value = String(status.auto_lock_minutes || 0); if (result.code !== 'cancelled') toast(result.error, 'error'); }
  });

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
        setting('Windows Hello', 'Desbloquea, aprueba y muestra contraseñas con tu PIN, huella o cara.', helloControl),
        setting('Contraseña maestra', 'Si la olvidas, puedes cambiarla aquí tras confirmar con Windows.',
          el('button', { class: 'btn', onclick: () => changeMasterPassword(false) }, 'Cambiar')),
        setting('Bloqueo automático', 'Bloquea la bóveda tras un tiempo sin uso.', lockSelect),
        setting('Aislamiento', status.isolated
          ? 'El servicio usa una cuenta de Windows propia: ningún programa puede leer su memoria ni sus archivos.'
          : 'El servicio usa tu cuenta de Windows. Instala SecretBroker para activar la protección completa.',
        el('span', { class: `state-text ${status.isolated ? 'ok' : 'warn'}` }, status.isolated ? 'Activo' : 'Desactivado'))),
      el('div', { class: 'settings-group' }, el('h3', { class: 'muted' }, 'IA'),
        setting('Claude Code', 'Permite que Claude Code use tus credenciales a través de SecretBroker.', claudeControl),
        setting('Claude Desktop', 'Permite que la app de escritorio de Claude use tus credenciales.', desktopControl),
        setting('Permisos de esta sesión', status.session_grants
          ? `${status.session_grants} permiso(s) aprobados hasta que se bloquee la bóveda.`
          : 'No hay permisos de sesión activos.',
        el('button', { class: 'btn', disabled: !status.session_grants, onclick: async () => {
          await api().call('revoke_sessions'); toast('Permisos revocados'); await refreshStatus(); renderView();
        } }, 'Revocar'))),
      el('div', { class: 'settings-group' }, el('h3', { class: 'muted' }, 'Apariencia'),
        setting('Color', 'El tema claro u oscuro sigue al de Windows.', palettes)),
      el('p', { class: 'faint small' }, `SecretBroker ${state.info.version} · ${status.owner}`))));
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

// ======================================================================= approvals

async function pollApprovals() {
  const result = await api().call('pending_approvals');
  if (!result.ok) return;
  const approvals = result.result;
  if (state.approvalOpen && !approvals.some((a) => a.id === state.approvalOpen.id)) state.approvalOpen.modal.close();
  if (!state.approvalOpen && approvals.length) showApproval(approvals[0]);
}

function looksDestructive(detail) {
  return /\b(rm\s+-[a-z]*[rf]|rmdir|del\s|drop\s+(table|database|schema)|truncate|delete\s+from|shutdown|reboot|mkfs|dd\s+if=|chmod\s+-R|chown\s+-R|kill(all)?\s|systemctl\s+(stop|disable)|git\s+push\s+.*--force|^DELETE\s)/im.test(detail);
}

function showApproval(request) {
  const errorText = el('div', { class: 'error-text' });
  const decide = async (scope, button) => {
    errorText.textContent = '';
    if (scope === 'deny') {
      await api().call('deny', { id: request.id });
      modal.close();
      return;
    }
    busy(button, true);
    const result = await withProof((p) => api().call('approve', { id: request.id, scope }, p), 'Para aprobar el uso de la credencial.');
    busy(button, false);
    if (!result.ok) { if (result.code !== 'cancelled') errorText.textContent = result.error; return; }
    modal.close();
  };
  const onceButton = el('button', { class: 'btn primary' }, icon('fingerprint', 'sm'), 'Permitir');
  onceButton.addEventListener('click', () => decide('once', onceButton));
  const sessionButton = request.allow_session ? el('button', { class: 'btn', title: 'No volver a preguntar por esta acción hasta que se bloquee la bóveda' }, 'Permitir en esta sesión') : null;
  if (sessionButton) sessionButton.addEventListener('click', () => decide('session', sessionButton));
  const destructive = looksDestructive(request.detail);

  const modal = openModal({
    title: 'La IA quiere usar una credencial',
    body: el('div', { class: 'request' },
      el('div', { class: 'request-who' }, glyph(request.template),
        el('div', {}, el('div', { style: 'font-weight:600' }, request.secret_name), el('div', { class: 'muted small' }, ACTION_LABELS[request.action] || request.action))),
      el('div', { class: 'request-detail selectable' }, request.detail),
      destructive ? el('div', { class: 'warning' }, icon('alert', 'sm'), 'Parece que borra, detiene o modifica datos. Revísalo antes de permitirlo.') : null,
      errorText),
    footer: [
      el('button', { class: 'btn danger', onclick: () => decide('deny') }, 'Denegar'),
      el('div', { class: 'spacer' }),
      sessionButton, onceButton],
    onClose: () => {
      if (state.approvalOpen && state.approvalOpen.id === request.id) state.approvalOpen = null;
    },
  });
  state.approvalOpen = { id: request.id, modal };
  api().focus();
}
