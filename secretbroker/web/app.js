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
  exposure: null,
  scan: null,
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
  if (state.status && state.status.state === 'unlocked') {
    await pollDrafts();
    await pollApprovals();
    await pollScan();
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
    else if (target === 'lock') { state.info.session_unlock_here = await api().has_session_unlock(); renderLock(); }
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
      el('div', { style: 'display:flex;gap:8px;align-items:center' },
        el('button', { class: 'btn primary lg', onclick: passwordStep }, 'Empezar'),
        el('button', { class: 'btn ghost lg', onclick: () => restoreBackup(() => { state.setupActive = false; state.screen = null; refreshStatus(); }) }, 'Restaurar una copia')));
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

  const sessionAvailable = status.session_unlock && state.info.session_unlock_here;
  const sessionButton = el('button', { class: 'btn primary lg block' }, icon('unlock', 'sm'), 'Abrir con mi sesión de Windows');
  sessionButton.addEventListener('click', async () => {
    errorText.textContent = '';
    busy(sessionButton, true);
    const ok = await api().session_unlock();
    busy(sessionButton, false);
    if (!ok) { errorText.textContent = 'No se ha podido abrir con la sesión de Windows. Usa la contraseña.'; state.info.session_unlock_here = false; return; }
    refreshStatus();
  });

  const helloButton = el('button', { class: `btn ${sessionAvailable ? '' : 'primary'} lg block` }, icon('fingerprint', 'sm'), 'Desbloquear con Windows Hello');
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
      sessionAvailable ? sessionButton : null,
      helloAvailable ? helloButton : null,
      canDevice && status.windows_password ? el('div', { style: 'text-align:center' },
        el('button', { class: 'link muted-link', onclick: unlockWindows }, 'Usar la contraseña de Windows')) : null,
      canDevice ? el('div', { class: 'divider' }, 'o') : null,
      el('div', { style: 'display:flex;gap:8px' }, el('div', { style: 'flex:1' }, master), masterButton),
      errorText,
      el('div', { style: 'text-align:center' }, el('button', { class: 'link small', onclick: forgot }, '¿Has olvidado la contraseña maestra?')),
      el('p', { class: 'footnote', style: 'margin-top:24px' }, 'Desbloquea solo en esta ventana. SecretBroker nunca te pedirá la contraseña en otra.'))));
  if (!helloAvailable && !sessionAvailable) setTimeout(() => master.input.focus(), 50);
}

// ======================================================================= main

async function enterMain() {
  await loadEntries();
  renderMain();
  if (await api().auto_scan()) { state.scan = { running: true }; renderMain(); }
  if (state.afterUnlock === 'change_master') {
    state.afterUnlock = null;
    state.view = 'settings';
    renderMain();
    changeMasterPassword(true);
  }
}

async function loadEntries() {
  const [result, reminders] = await Promise.all([api().call('entries'), api().call('reminders')]);
  state.entries = result.ok ? result.result : [];
  state.reminders = Object.fromEntries((reminders.ok ? reminders.result : []).map((r) => [r.id, r]));
  if (state.selected && !state.entries.some((e) => e.id === state.selected)) state.selected = null;
  await loadExposure();
}

async function loadExposure() {
  const result = await api().exposure_report();
  state.exposure = result.ok ? result.result : null;
}

function renderMain() {
  const sidebar = el('aside', { class: 'sidebar' },
    brand(),
    el('nav', { class: 'nav' },
      navButton('credentials', 'key', 'Credenciales', state.entries.length),
      navButton('exposure', 'shield', 'Exposición', exposedCount(), 'danger'),
      navButton('access', 'bot', 'Acceso de la IA', state.status.ai_paused ? '‖' : null, 'danger'),
      navButton('activity', 'activity', 'Actividad'),
      navButton('settings', 'settings', 'Ajustes')),
    el('div', { id: 'update-slot' }),
    el('div', { class: 'sidebar-footer' },
      el('div', { class: 'state', id: 'sidebar-state' }),
      el('button', { class: 'btn icon-only', title: 'Bloquear (Ctrl+L)', onclick: lockNow }, icon('lock', 'sm'))));
  $app().replaceChildren(el('div', { class: 'layout' }, sidebar, el('main', { class: 'content', id: 'content' })));
  updateSidebarState();
  renderUpdateSlot();
  renderView();
}

function navButton(view, iconName, label, count, countClass = '') {
  return el('button', {
    class: state.view === view ? 'active' : '',
    onclick: () => { state.view = view; renderMain(); },
  }, icon(iconName), label, count ? el('span', { class: `count ${countClass}` }, count) : null);
}

function updateSidebarState() {
  const node = document.getElementById('sidebar-state');
  if (!node || !state.status) return;
  const minutes = state.status.auto_lock_minutes;
  const until = state.status.session_unlock ? 'Desbloqueada · sigue a Windows'
    : minutes ? `Desbloqueada · ${minutes >= 60 ? `${minutes / 60} h` : `${minutes} min`}` : 'Desbloqueada';
  node.replaceChildren(
    el('span', { class: `dot ${state.status.ai_paused || !state.status.isolated ? 'warn' : ''}` }),
    el('span', {}, state.status.ai_paused ? 'IA en pausa' : until));
  if (state.paused !== state.status.ai_paused) {  // paused or resumed from the icon next to the clock
    const first = state.paused === undefined;
    state.paused = state.status.ai_paused;
    if (!first) renderMain();
  }
  node.title = state.status.isolated ? 'Servicio aislado' : 'Modo sin aislamiento';
}

async function lockNow() {
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
  const allTags = [...new Set(state.entries.flatMap((e) => e.tags || []))].sort();
  if (state.tag && !allTags.includes(state.tag)) state.tag = null;
  const tagBar = allTags.length ? el('div', { class: 'tag-bar' }) : null;
  const renderTags = () => tagBar && tagBar.replaceChildren(
    el('button', { class: `tag ${state.tag ? '' : 'active'}`, onclick: () => { state.tag = null; renderTags(); renderList(); } }, 'Todas'),
    allTags.map((t) => el('button', { class: `tag ${state.tag === t ? 'active' : ''}`, onclick: () => { state.tag = state.tag === t ? null : t; renderTags(); renderList(); } }, t)));
  const renderList = () => {
    const query = state.search.trim().toLowerCase();
    const items = state.entries.filter((e) => (!state.tag || (e.tags || []).includes(state.tag)) && (!query
      || [e.name, e.id, e.description, subtitleOf(e), TEMPLATES[e.template].label, ...(e.tags || [])].join(' ').toLowerCase().includes(query)));
    list.replaceChildren(items.map((entry) => el('div', {
      class: `row ${state.selected === entry.id ? 'selected' : ''}`,
      onclick: () => { state.selected = entry.id; renderList(); renderDetail(detail); },
    }, glyph(entry.template), el('div', { class: 'meta' }, el('div', { class: 'title' }, entry.name), el('div', { class: 'subtitle' }, subtitleOf(entry))),
    entry.draft ? el('span', { class: 'draft-badge' }, 'Falta la clave')
      : state.reminders && state.reminders[entry.id] ? el('span', { class: 'draft-badge', title: reminderText(state.reminders[entry.id]) }, reminderShort(state.reminders[entry.id]))
        : levelDot(entry.id))));
    if (!items.length) list.append(el('p', { class: 'muted', style: 'padding:12px 10px' }, 'Ninguna coincide.'));
  };

  if (!state.selected) state.selected = state.entries[0].id;
  content.replaceChildren(header, tagBar, el('div', { class: 'split', style: 'flex:1;min-height:0' }, list, el('div', { class: 'rule' }), detail));
  renderTags();
  renderList();
  renderDetail(detail);
}

function reminderShort(r) {
  return { expired: 'Caducada', expiring: `Caduca en ${r.days} d`, old: 'Clave antigua', old_alive: 'Borra la anterior' }[r.kind];
}

function reminderText(r) {
  if (r.kind === 'old_alive') return `Rotaste la clave, pero la anterior sigue funcionando. Bórrala en ${r.provider || 'la web del proveedor'}.`;
  if (r.kind === 'expired') return `Caducó hace ${r.days} día(s). Crea una clave nueva o rótala.`;
  if (r.kind === 'expiring') return `Caduca en ${r.days} día(s). Rótala antes de que deje de funcionar.`;
  return `La clave tiene ${r.days} días. Conviene rotarla de vez en cuando.`;
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
    entry.draft ? draftSection(entry, () => renderMain()) : null,
    state.reminders && state.reminders[entry.id] ? el('div', { class: 'warning' }, icon('clock', 'sm'), reminderText(state.reminders[entry.id])) : null,
    (entry.tags || []).length || entry.expires ? el('div', { class: 'tag-line' },
      (entry.tags || []).map((t) => el('span', { class: 'tag static' }, t)),
      entry.expires ? el('span', { class: 'muted small' }, `Caduca el ${entry.expires}`) : null) : null,
    el('div', { class: 'section' }, props),
    entry.description ? el('div', { class: 'section' }, el('h3', {}, 'Notas para la IA'), el('p', { class: 'notes selectable muted' }, entry.description)) : null,
    providerSection(entry),
    exposureSection(entry),
    rotationSection(entry),
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

function everyLabel(days) {
  const found = ROTATE_EVERY.find(([d]) => d === days);
  return found ? found[1].toLowerCase() : `${days} días`;
}

function cadenceText(entry) {
  const own = entry.rotate_every_days;
  const days = own === null || own === undefined ? (state.status.rotate_reminder_days ?? 365) : own;
  if (!days) return own === 0 ? 'No te recuerda rotarla.' : 'Los recordatorios de rotación están desactivados en Ajustes.';
  let text = `Te recuerda rotarla cada ${everyLabel(days)}${own === null || own === undefined ? ' (ajuste general)' : ''}`;
  if (entry.secret_since) {
    const due = new Date(new Date(entry.secret_since).getTime() + days * 86400000);
    text += `: la próxima vez, hacia el ${due.toLocaleDateString('es-ES', { day: 'numeric', month: 'long', year: 'numeric' })}`;
  }
  return `${text}. Puedes cambiarlo al editarla.`;
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
  if (hours === 0) return `No se comprueba sola${general}. Puedes hacerlo con «Comprobar claves».`;
  if (hours === -1) return `Se comprueba solo una vez cada clave nueva${general}.`;
  return `Se comprueba ${checkLabel(hours)}${general}.`;
}

function rotationSection(entry) {
  const rotation = entry.rotation;
  if (!rotation) return null;
  const destinations = entry.destinations || [];
  const guide = entry.guide || {};
  const apiButton = rotation.supported
    ? el('button', { class: 'btn', onclick: () => rotateEntry(entry) }, icon('rotate', 'sm'), 'Rotar clave') : null;
  const guidedButton = el('button', { class: rotation.supported ? 'btn ghost' : 'btn', onclick: () => rotateGuided(entry) },
    rotation.supported ? null : icon('rotate', 'sm'), rotation.supported ? 'Rotar a mano' : 'Rotar con ayuda');
  const ask = `Busca en la documentación oficial cómo se rota la clave de «${entry.name}» y guarda la guía en SecretBroker`;
  return el('div', { class: 'section' },
    el('h3', {}, 'Rotación'),
    entry.retired ? retiredBox(entry) : null,
    el('p', { class: 'help' }, rotation.supported
      ? `Pide a ${rotation.provider} una clave nueva y anula la actual, sin que nadie la vea.`
      : `${rotation.reason} La app te guía: creas la clave nueva en su web, la pegas aquí y se prueba, se guarda y se sube donde haga falta.`),
    rotation.supported && destinations.length
      ? el('p', { class: 'help' }, 'Después se vuelve a subir a: ', destinations.map(destinationLabel).join(', '))
      : null,
    el('p', { class: 'help' }, cadenceText(entry)),
    guide.source === 'ai' ? el('p', { class: 'help' }, icon('sparkles', 'sm'), ` Guía escrita por la IA${guide.written ? ` el ${guide.written}` : ''}: comprueba los enlaces antes de seguirla.`) : null,
    guide.source === 'generic' ? el('div', { class: 'help' },
      'No hay una guía para este proveedor. Puedes pedírsela a la IA: ',
      el('div', { class: 'prop' }, el('div', { class: 'v selectable', style: 'white-space:normal' }, ask), el('div', { class: 'actions' }, copyButton(ask)))) : null,
    el('div', { style: 'margin-top:8px;display:flex;gap:8px' }, apiButton, guidedButton));
}

// After a rotation by hand, the old key is kept until it is confirmed dead at the provider.
function retiredBox(entry) {
  const retired = entry.retired;
  const guide = entry.guide || {};
  const where = retired.provider || 'la web del proveedor';
  const status = el('span', {});
  const refresh = async () => { await loadEntries(); renderMain(); };
  const checkButton = retired.checkable ? el('button', { class: 'btn', onclick: async () => {
    busy(checkButton, true);
    const result = await api().call('check_retired', { id: entry.id });
    busy(checkButton, false);
    if (!result.ok) { toast(result.error, 'error'); return; }
    if (result.result.status === 'done') { toast('La clave anterior ya no funciona: rotación completa'); refresh(); }
    else if (result.result.status === 'alive') toast(`La clave anterior sigue funcionando: bórrala en ${where}`, 'error');
    else toast(result.result.message || 'No se pudo comprobar', 'error');
  } }, 'Comprobar') : null;
  const forget = el('button', { class: 'btn ghost', onclick: async () => {
    const result = await api().call('forget_retired', { id: entry.id });
    if (!result.ok) { toast(result.error, 'error'); return; }
    toast('Rotación completa');
    refresh();
  } }, 'Ya la he borrado');
  return el('div', { class: 'draft-box', style: 'margin-bottom:10px' },
    el('div', { class: 'warning' }, icon('alert', 'sm'), el('span', {}, retired.status === 'alive'
      ? `La clave anterior sigue funcionando. Bórrala en ${where} para terminar la rotación.`
      : `Falta borrar la clave anterior en ${where}.`)),
    guide.revoke ? el('p', { class: 'help' }, guide.revoke) : null,
    guide.links && guide.links.length ? linkList(guide.links.slice(0, 1)) : null,
    el('div', { style: 'margin-top:8px;display:flex;gap:8px' }, checkButton, forget, status));
}

function guideSteps(steps) {
  return el('ol', { class: 'guide-steps' }, steps.map((text) => el('li', {}, text)));
}

function rotateGuided(entry) {
  const guide = entry.guide || { create: [], links: [], sources: [] };
  const known = guide.provider || (entry.rotation && entry.rotation.provider);
  const provider = known || 'el proveedor';
  const site = known ? `la web de ${known}` : 'la web del servicio';
  const exposureBefore = exposureOf(entry.id);  // its findings are for the old value: gone once it changes
  const suggested = `${entry.id}-${new Date().toISOString().slice(0, 7)}`;
  const body = el('div', {});
  const foot = el('div', { style: 'display:contents' });
  let changed = false;
  const modal = openModal({
    title: `Rotar ${entry.name}`, wide: true, body, footer: [foot],
    onClose: async () => { if (changed) { await loadEntries(); renderMain(); } },
  });
  const progress = (step) => el('div', { class: 'steps', style: 'margin-bottom:14px' }, [1, 2, 3, 4].map((i) => el('span', { class: i <= step ? 'done' : '' })));
  const show = (step, nodes, buttons) => {
    body.replaceChildren(el('div', {}, progress(step), nodes));
    foot.replaceChildren(el('div', { class: 'spacer' }), ...buttons.filter(Boolean));
  };

  const create = () => show(1, [
    el('h3', {}, '1 · Crea la clave nueva'),
    el('p', { class: 'muted' }, `Créala en ${site}. La actual sigue funcionando hasta que la borres, así que no se corta nada.`),
    guideSteps(guide.create || []),
    el('div', { class: 'prop' }, el('div', { style: 'min-width:0' }, el('div', { class: 'k' }, 'Nombre sugerido para la clave'),
      el('div', { class: 'v selectable' }, suggested)), el('div', { class: 'actions' }, copyButton(suggested))),
    guide.links && guide.links.length ? linkList(guide.links) : null,
    guide.source === 'ai' ? el('p', { class: 'help' }, icon('sparkles', 'sm'), ' Guía escrita por la IA. Fuentes: ',
      guide.sources.map((url, i) => [i ? ', ' : '', el('button', { class: 'link small', onclick: () => api().open_link(url) }, new URL(url).hostname)])) : null,
  ], [el('button', { class: 'btn', onclick: () => modal.close() }, 'Cancelar'),
    el('button', { class: 'btn primary', onclick: paste }, 'Ya la tengo')]);

  function paste() {
    const group = passwordInput({ placeholder: 'Pega aquí la clave nueva' });
    const errorText = el('div', { class: 'error-text' });
    const save = el('button', { class: 'btn primary' }, 'Probar y guardar');
    save.addEventListener('click', async () => {
      errorText.textContent = '';
      const value = group.input.value.trim();
      if (!value) { errorText.textContent = 'Pega la clave nueva.'; return; }
      busy(save, true);
      const result = await withProof((p) => api().call('replace_key', { id: entry.id, value }, p), `Para guardar la clave nueva de ${entry.name}.`);
      busy(save, false);
      if (!result.ok) { if (result.code !== 'cancelled') errorText.textContent = result.error; return; }
      changed = true;
      done(result.result);
    });
    group.input.addEventListener('keydown', (event) => { if (event.key === 'Enter') save.click(); });
    const generate = guide.generate ? el('button', { class: 'btn', onclick: () => {
      const bytes = crypto.getRandomValues(new Uint8Array(48));
      group.input.value = btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
      toast('Generado: 48 bytes aleatorios');
    } }, 'Generar uno aleatorio') : null;
    show(2, [
      el('h3', {}, guide.generate ? '2 · El secreto nuevo' : '2 · Pega la clave nueva'),
      el('div', { class: 'field' }, el('label', {}, 'Clave nueva'), group,
        el('div', { class: 'help' }, known
          ? `Se prueba con ${known} antes de sustituir la actual: si no funciona, no se cambia nada. La IA no la ve.`
          : 'Esta clave no se puede probar desde aquí: comprueba que la has copiado entera. La IA no la ve.')),
      generate,
      errorText,
    ], [el('button', { class: 'btn', onclick: create }, 'Atrás'), save]);
    setTimeout(() => group.input.focus(), 50);
  }

  function done(result) {
    const line = (ok, text) => el('div', { class: 'perm' }, icon(ok ? 'check' : 'alert', 'sm'), el('span', {}, text));
    const check = result.check;
    const env = Object.keys(((entry.policy || {}).commands || {}).env || {});
    show(3, [
      el('h3', {}, '3 · Ya se usa la nueva'),
      check && check.status === 'ok' ? line(true, `Funciona: ${check.provider} la acepta.`)
        : line(false, `No se pudo probar con ${provider}${check && check.message ? ` (${check.message})` : ''}; se ha guardado igualmente.`),
      line(true, 'La IA ya usa la nueva. Sus aprobaciones de esta credencial se han reiniciado.'),
      result.uploads.map((u) => line(u.ok, u.ok ? `Subida a ${u.label} como ${u.name}.` : `No se pudo subir a ${u.label}: ${u.error}`)),
      env.length ? line(true, `Tus programas con sb run (${env.join(', ')}) la usarán al reiniciarlos.`) : null,
      exposureBefore && exposureBefore.found ? line(false, `La clave anterior estaba en claro en ${exposureBefore.found} sitio(s). En cuanto la borres, esas copias dejan de ser un riesgo.`) : null,
      el('p', { class: 'help', style: 'margin-top:8px' }, 'Si la tienes puesta en otros sitios (un servidor, Vercel, otra app…), cámbiala allí también antes de borrar la anterior.'),
    ], [el('button', { class: 'btn primary', onclick: () => revoke(result.entry.retired) }, 'Siguiente')]);
  }

  function revoke(retired) {
    const status = el('div', {});
    const checkable = retired && retired.checkable;
    const checkButton = el('button', { class: 'btn primary' }, 'Comprobar que ya no funciona');
    checkButton.addEventListener('click', async () => {
      busy(checkButton, true);
      const result = await api().call('check_retired', { id: entry.id });
      busy(checkButton, false);
      if (!result.ok) { status.replaceChildren(el('div', { class: 'error-text' }, result.error)); return; }
      const answer = result.result;
      if (answer.status === 'done') {
        status.replaceChildren(el('div', { class: 'perm' }, icon('check', 'sm'), el('span', {}, 'La clave anterior ya no funciona. Rotación completa.')));
        foot.replaceChildren(el('div', { class: 'spacer' }), el('button', { class: 'btn primary', onclick: () => modal.close() }, 'Terminar'));
      } else {
        status.replaceChildren(el('div', { class: 'warning' }, icon('alert', 'sm'), el('span', {}, answer.status === 'alive'
          ? `Sigue funcionando. Bórrala en ${provider} y vuelve a comprobarlo (a veces tarda unos minutos).`
          : answer.message || 'No se pudo comprobar.')));
      }
    });
    const forget = el('button', { class: checkable ? 'btn ghost' : 'btn primary', onclick: async () => {
      const result = await api().call('forget_retired', { id: entry.id });
      if (!result.ok) { toast(result.error, 'error'); return; }
      modal.close();
      toast('Rotación completa');
    } }, 'Ya la he borrado');
    show(4, [
      el('h3', {}, '4 · Borra la clave anterior'),
      el('p', { class: 'muted' }, guide.revoke || `Borra o revoca la clave anterior en ${provider}.`),
      guide.links && guide.links.length ? linkList(guide.links.slice(0, 1)) : null,
      el('p', { class: 'help' }, checkable
        ? 'Después, la app comprueba con el proveedor que ya no funciona. Si lo dejas para luego, te lo recordará.'
        : 'Esta clave no se puede comprobar desde aquí: avísame cuando la hayas borrado.'),
      status,
    ], [el('button', { class: 'btn', onclick: () => { modal.close(); toast('Te recordaré borrar la anterior'); } }, 'Más tarde'),
      forget, checkable ? checkButton : null]);
  }

  create();
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
        if (failed.length) toast(`Rotada, pero no se pudo subir a ${failed.map((u) => u.label).join(', ')}: ${failed[0].error}`, 'error');
        else if (check && check.status === 'invalid') toast(`Rotada, pero ${check.message}`, 'error');
        else toast(destinations.length ? 'Rotada y subida de nuevo' : 'Rotada');
      } }, 'Rotar'),
    ],
  });
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
  const tagsInput = el('input', { class: 'input', placeholder: 'tienda, produccion', value: isNew ? '' : (entry.tags || []).join(', ') });
  const expiresInput = el('input', { class: 'input', type: 'date', value: isNew ? '' : (entry.expires || '') });
  const currentEvery = isNew ? null : (entry.rotate_every_days ?? null);
  const everyInput = el('select', { class: 'input' }, ROTATE_EVERY.map(([days, label]) =>
    el('option', { value: days === null ? '' : String(days), selected: days === currentEvery }, label)));
  const checkEvery = checkEveryControl(isNew ? null : (entry.check_every_hours ?? null), true);

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
      tags: [...new Set(tagsInput.value.split(',').map((t) => slugify(t.trim())).filter(Boolean))],
      ...(expiresInput.value ? { expires: expiresInput.value } : {}),
      ...(everyInput.value !== '' ? { rotate_every_days: Number(everyInput.value) } : {}),
      ...(checkEvery.value() !== null ? { check_every_hours: checkEvery.value() } : {}),
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
      isNew && ['api_key', 'generic'].includes(templateId) ? keySourcePicker() : null,
      fieldsBox,
      el('div', { class: 'field' }, el('label', {}, 'Notas para la IA', el('span', { class: 'req' }, ' · opcional')), notes,
        el('div', { class: 'help' }, 'La IA lee estas notas, nunca las contraseñas. Explica qué es y cómo debe usarla.')),
      el('div', { style: 'display:flex;gap:12px' },
        el('div', { class: 'field', style: 'flex:2' }, el('label', {}, 'Etiquetas', el('span', { class: 'req' }, ' · opcional')), tagsInput,
          el('div', { class: 'help' }, 'Para agruparlas, por ejemplo por proyecto.')),
        el('div', { class: 'field', style: 'flex:1' }, el('label', {}, 'Caduca', el('span', { class: 'req' }, ' · opcional')), expiresInput),
        el('div', { class: 'field', style: 'flex:1' }, el('label', {}, 'Recordar rotarla'), everyInput)),
      el('div', { class: 'field' }, el('label', {}, 'Comprobar que funciona'), checkEvery.node,
        el('div', { class: 'help' }, 'Una llamada de solo lectura al proveedor (o entrar y salir del servidor SSH). «Ajuste general» sigue el de Ajustes.')),
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

function exposureSection(entry) {
  const item = exposureOf(entry.id);
  if (!item) return null;
  return el('div', { class: 'section' },
    el('h3', {}, 'Exposición'),
    el('div', {}, levelBadge(item.level)),
    item.reasons.map((r) => el('p', { class: `reason is-${r.level}` }, r.text)),
    exposureFacts(item),
    item.checkable ? el('div', { class: 'facts faint small' }, checkCadenceText(entry), ' Puedes cambiarlo al editarla.') : null,
    el('div', {}, el('button', { class: 'link small', onclick: () => { state.view = 'exposure'; renderMain(); } }, 'Ver detalles')));
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
    if (exposed) toast(`Análisis terminado: ${exposed} ${exposed === 1 ? 'credencial expuesta' : 'credenciales expuestas'}`, 'error');
    else toast('Análisis terminado: no hay copias de tus claves');
  }
  if (state.screen === 'main') renderMain();
}

async function startScan(button) {
  busy(button, true);
  const result = await withProof((p) => api().start_scan(p), 'Para buscar tus claves en los archivos de este equipo.');
  busy(button, false);
  if (!result.ok) { if (result.code !== 'cancelled') toast(result.error, 'error'); return; }
  state.scan = { running: true };
  renderMain();
}

async function checkKeys(button) {
  busy(button, true);
  const result = await api().check_exposure();
  busy(button, false);
  if (!result.ok) { toast(result.error, 'error'); return; }
  state.exposure = result.result;
  renderMain();
  toast('Comprobación terminada');
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
  const scanButton = el('button', { class: 'btn primary', disabled: scanning }, icon('search', 'sm'), 'Buscar copias');
  scanButton.addEventListener('click', () => startScan(scanButton));
  const checkButton = el('button', { class: 'btn', title: 'Prueba cada clave con su proveedor y las contraseñas contra filtraciones conocidas' }, 'Comprobar claves');
  checkButton.addEventListener('click', () => checkKeys(checkButton));
  const header = el('div', { class: 'content-header' }, el('h1', {}, 'Exposición'), checkButton, scanButton);
  if (!report) {
    content.replaceChildren(header, el('div', { class: 'content-body' }, el('div', { class: 'empty' }, el('p', {}, 'No se pudo cargar el estado.'))));
    return;
  }

  const entries = Object.fromEntries(state.entries.map((e) => [e.id, e]));
  const items = report.entries.filter((item) => entries[item.id])
    .sort((a, b) => LEVELS[a.level].order - LEVELS[b.level].order || entries[a.id].name.localeCompare(entries[b.id].name));
  const hidden = !report.details && items.some((item) => item.found || item.found_before);
  content.replaceChildren(header, el('div', { class: 'content-body' },
    scanning ? scanProgress() : null,
    el('div', { class: 'exposure-summary' },
      el('p', { class: 'muted' }, 'Busca tus claves en las conversaciones con IA, los historiales de la terminal, la configuración de tus programas, las variables de entorno, tus proyectos y su historial de git. Todo ocurre en este equipo.'),
      el('div', { class: 'faint small' },
        report.last_scan ? `Último análisis: ${formatTime(report.last_scan.ts)} · ${report.last_scan.files} archivos` : 'Aún no se ha hecho ningún análisis',
        ' · ',
        report.last_check ? `Última comprobación con los proveedores: ${formatTime(report.last_check)}` : 'Claves sin comprobar con sus proveedores'),
      hidden ? el('div', { class: 'small' }, el('span', { class: 'muted' }, 'Las rutas solo se muestran tras verificar tu identidad. '),
        el('button', { class: 'link small', onclick: showWhere }, 'Ver en qué archivos')) : null),
    el('div', { class: 'exposure-list' }, items.map((item) => exposureCard(item, entries[item.id])))));
}

function exposureCard(item, entry) {
  const findings = item.findings || [];
  const place = (location) => location.replace(/^(env|git):/, '');
  return el('div', { class: `exposure-card is-${item.level}` },
    el('div', { class: 'exposure-head' },
      glyph(entry.template),
      el('div', { class: 'meta' }, el('div', { class: 'title' }, entry.name), el('div', { class: 'subtitle' }, subtitleOf(entry))),
      levelBadge(item.level),
      el('button', { class: 'btn ghost', onclick: () => { state.selected = entry.id; state.view = 'credentials'; renderMain(); } }, 'Abrir')),
    item.reasons.length ? el('ul', { class: 'reasons' }, item.reasons.map((r) => el('li', { class: `is-${r.level}` }, r.text))) : null,
    exposureFacts(item),
    findings.length ? el('details', { class: 'findings', open: item.level === 'exposed' },
      el('summary', {}, `${findings.length} ${findings.length === 1 ? 'sitio' : 'sitios'}`),
      findings.map((f) => el('div', { class: `finding ${f.present ? '' : 'gone'}` },
        el('span', { class: 'source' }, SOURCE_LABELS[f.source] || f.source),
        el('span', { class: 'path selectable', title: place(f.location) }, place(f.location)),
        el('span', { class: 'faint' }, f.present ? `desde ${formatTime(f.first_seen)}` : 'ya no está'),
        f.present && !f.location.startsWith('env:')
          ? el('button', { class: 'btn icon-only', title: 'Mostrar en el Explorador', onclick: () => api().show_location(f.location) }, icon('search', 'sm'))
          : el('span')))) : null);
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
  const [result, permissions] = await Promise.all([api().call('grants'), api().call('ai_permissions')]);
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

function permissionsGroup(data, rerender) {
  const save = async (changes) => {
    const result = await withProof((p) => api().call('set_ai_permissions', changes, p), 'Para dar más permisos a la IA.');
    if (result.ok) toast('Guardado'); else if (result.code !== 'cancelled') toast(result.error, 'error');
    rerender();
  };
  const notify = el('input', { type: 'checkbox', checked: data.notify_uses });
  notify.addEventListener('change', () => save({ notify_uses: notify.checked }));
  return el('div', { class: 'settings-group' },
    el('h3', { class: 'muted' }, 'Qué puede hacer la IA'),
    el('p', { class: 'muted small' }, 'Libre: lo hace siguiendo los permisos de cada credencial. Avisarme: igual, y te llega un aviso. Preguntarme: te lo pide cada vez. Nunca: se lo deniega.'),
    data.capabilities.map((c) => setting(c.label, c.level === c.default ? 'Valor recomendado' : '',
      el('div', { class: 'segmented small' }, AI_LEVEL_LABELS.map(([level, label]) => el('button', {
        class: c.level === level ? 'active' : '',
        onclick: () => c.level !== level && save({ permissions: { [c.id]: level } }),
      }, label))))),
    setting('Avisarme cuando use credenciales que no preguntan', 'Un aviso de Windows, como mucho uno cada 10 minutos por credencial.', notify));
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

  const approvalSelect = el('select', { class: 'input', style: 'width:auto' },
    [[24, '24 horas'], [8, '8 horas'], [0, 'Hasta que bloquee']].map(([v, label]) => el('option', { value: v }, label)));
  approvalSelect.value = String(status.approval_hours ?? 24);
  approvalSelect.addEventListener('change', async () => {
    const hours = Number(approvalSelect.value);
    const result = await withProof((p) => api().call('set_settings', { settings: { approval_hours: hours } }, p), 'Para cambiar cuánto duran las aprobaciones.');
    if (result.ok) { toast('Guardado'); await refreshStatus(); } else { approvalSelect.value = String(status.approval_hours ?? 24); if (result.code !== 'cancelled') toast(result.error, 'error'); }
  });

  const settingSelect = (key, options, fallback, reason) => {
    const select = el('select', { class: 'input', style: 'width:auto' }, options.map(([v, label]) => el('option', { value: v }, label)));
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
        setting('Windows Hello', 'Desbloquea, aprueba y muestra contraseñas con tu PIN, huella o cara.', helloControl),
        setting('Contraseña maestra', 'Si la olvidas, puedes cambiarla aquí tras confirmar con Windows.',
          el('button', { class: 'btn', onclick: () => changeMasterPassword(false) }, 'Cambiar')),
        setting('Abrir con mi sesión de Windows', 'La bóveda se abre sola al entrar en Windows y se cierra al bloquearlo (Win+L), sin escribir contraseñas. Protege de errores de la IA, no de alguien que use tu sesión.', sessionToggle),
        status.session_unlock ? null : setting('Bloqueo automático', 'Bloquea la bóveda tras un tiempo sin uso. Las aprobaciones de la IA siguen valiendo al desbloquear.', lockSelect),
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
          ? `${status.session_grants} credencial(es) aprobadas ahora mismo.`
          : 'Qué puede usar la IA sin preguntarte, y pausarla.',
        el('button', { class: 'btn', onclick: () => { state.view = 'access'; renderMain(); } }, 'Ver'))),
      el('div', { class: 'settings-group' }, el('h3', { class: 'muted' }, 'Aplicación'),
        setting('Arrancar con Windows', 'SecretBroker se queda junto al reloj, listo para la IA. Cerrar la ventana no lo cierra: usa «Salir» en ese icono.', startToggle)),
      backupSlot,
      el('div', { class: 'settings-group' }, el('h3', { class: 'muted' }, 'Exposición'),
        setting('Analizar al desbloquear', 'Busca copias de tus claves en este equipo al desbloquear, como mucho cada 12 horas.', autoScan),
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
  await loadEntries();
  if (state.screen === 'main') renderMain();
  const drafts = state.entries.filter((e) => e.draft);
  const newest = drafts.sort((a, b) => String(b.updated).localeCompare(String(a.updated)))[0];
  if (newest && !state.approvalOpen && !document.getElementById('modal-root').lastElementChild) showDraft(newest);
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

async function pollApprovals() {
  const result = await api().call('pending_approvals');
  if (!result.ok) return;
  const approvals = result.result;
  if (state.approvalOpen && !approvals.some((a) => a.id === state.approvalOpen.id)) state.approvalOpen.modal.close();
  if (!state.approvalOpen && approvals.length) showApproval(approvals[0]);
}

function approvalLabel() {
  const hours = (state.status || {}).approval_hours;
  if (hours === 0) return 'Permitir hasta que bloquee';
  if (hours === 8) return 'Permitir 8 horas';
  return 'Permitir hoy';
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
  const allowOnce = request.allow_once !== false;
  const onceLabel = { edit: 'Aplicar el cambio', draft: 'Permitir', rotate: 'Rotar ahora', delete: 'Borrar', import_env: 'Importar' }[request.action] || 'Solo esta vez';
  const onceButton = allowOnce ? el('button', { class: request.allow_session ? 'btn' : 'btn primary' }, onceLabel) : null;
  if (onceButton) onceButton.addEventListener('click', () => decide('once', onceButton));
  const sessionButton = request.allow_session ? el('button', { class: 'btn primary', title: `La IA podrá usar ${request.secret_name} sin volver a preguntarte` }, approvalLabel()) : null;
  if (sessionButton) sessionButton.addEventListener('click', () => decide('session', sessionButton));
  const destructive = looksDestructive(request.detail);

  const modal = openModal({
    title: request.action === 'request_access' ? 'La IA pide acceso para una tarea'
      : request.action === 'delete' ? 'La IA propone borrar una credencial'
        : request.action === 'rotate' ? 'La IA quiere rotar una clave'
          : request.action === 'import_env' ? 'Importar claves de un .env'
            : request.action === 'edit' || request.action === 'draft' ? 'La IA quiere cambiar una credencial' : 'La IA quiere usar una credencial',
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
