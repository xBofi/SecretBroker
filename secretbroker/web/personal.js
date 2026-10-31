'use strict';

// Personal vault features: password generator, health, import from other managers and export.
// Loaded after app.js and built from its helpers (el, icon, openModal, withProof, state…).

// ======================================================================= generator

const GENERATOR_KEY = 'generatorOptions';
const GENERATOR_DEFAULTS = { mode: 'random', length: 20, lower: true, upper: true, digits: true, symbols: true,
  avoid_ambiguous: false, words: 5, separator: '-', capitalize: true, number: true };
const SEPARATOR_LABELS = [['-', 'Guion (-)'], ['.', 'Punto (.)'], ['_', 'Guion bajo (_)'], [' ', 'Espacio'], [',', 'Coma (,)'], ['', 'Ninguno']];
const STRENGTH_CLASS = ['is-exposed', 'is-exposed', 'is-warning', 'is-ok', 'is-ok'];

function savedGeneratorOptions() {
  try { return { ...GENERATOR_DEFAULTS, ...JSON.parse(localStorage.getItem(GENERATOR_KEY) || '{}') }; } catch { return { ...GENERATOR_DEFAULTS }; }
}

function saveGeneratorOptions(options) {
  try { localStorage.setItem(GENERATOR_KEY, JSON.stringify(options)); } catch { /* only a convenience */ }
}

// The generator itself: options, the password and its strength. onValue(value) runs on every new one.
// Options changed here are remembered, except when the caller imposes its own (a database password).
function generatorPanel(initial, onValue) {
  const options = { ...savedGeneratorOptions(), ...(initial || {}) };
  const remember = !initial;
  const output = el('div', { class: 'gen-output mono selectable' });
  const meta = el('div', { class: 'gen-meta small' });
  const controls = el('div', { class: 'gen-controls' });
  let current = '';

  const generate = async () => {
    const result = await api().generate_password(options);
    if (!result.ok) { meta.replaceChildren(el('span', { class: 'error-text' }, result.error)); return; }
    current = result.result.value;
    output.textContent = current;
    const level = result.result.strength;
    meta.replaceChildren(el('span', { class: `level ${STRENGTH_CLASS[level]}` }, el('span', { class: 'level-dot' }),
      ['Muy débil', 'Débil', 'Aceptable', 'Buena', 'Excelente'][level]),
    el('span', { class: 'faint' }, ` · ${current.length} caracteres · unos ${result.result.bits} bits de azar`));
    if (onValue) onValue(current);
  };
  const change = (key, value) => { options[key] = value; if (remember) saveGeneratorOptions(options); renderControls(); generate(); };
  const toggle = (key, label) => {
    const box = el('input', { type: 'checkbox', checked: !!options[key] });
    box.addEventListener('change', () => change(key, box.checked));
    return el('label', { class: 'check-row' }, box, label);
  };
  const slider = (key, min, max, label) => {
    const range = el('input', { type: 'range', min, max, value: options[key], class: 'gen-range' });
    const number = el('span', { class: 'gen-count' }, String(options[key]));
    range.addEventListener('input', () => { number.textContent = range.value; });
    range.addEventListener('change', () => change(key, Number(range.value)));
    return el('div', { class: 'gen-slider' }, el('span', { class: 'muted small' }, label), range, number);
  };

  function renderControls() {
    const mode = el('div', { class: 'segmented small' }, [['random', 'Aleatoria'], ['passphrase', 'Frase de palabras']].map(([value, label]) =>
      el('button', { type: 'button', class: options.mode === value ? 'active' : '', onclick: () => change('mode', value) }, label)));
    if (options.mode === 'random') {
      controls.replaceChildren(mode, slider('length', 12, 128, 'Longitud'),
        el('div', { class: 'gen-checks' }, toggle('lower', 'a-z'), toggle('upper', 'A-Z'), toggle('digits', '0-9'),
          toggle('symbols', 'Símbolos'), toggle('avoid_ambiguous', 'Sin caracteres confusos (Il1O0)')));
    } else {
      const separator = el('select', { class: 'input', style: 'width:auto' }, SEPARATOR_LABELS.map(([value, label]) =>
        el('option', { value, selected: options.separator === value }, label)));
      separator.addEventListener('change', () => change('separator', separator.value));
      controls.replaceChildren(mode, slider('words', 3, 12, 'Palabras'),
        el('div', { class: 'gen-checks' }, el('span', { class: 'muted small' }, 'Separador'), separator,
          toggle('capitalize', 'Mayúscula inicial'), toggle('number', 'Añadir un número')),
        el('p', { class: 'help' }, 'Palabras cortas en español e inglés, sin tildes. Fácil de teclear y de recordar.'));
    }
  }

  renderControls();
  generate();
  const node = el('div', { class: 'generator' },
    el('div', { class: 'gen-result' }, output,
      el('button', { class: 'btn icon-only', type: 'button', title: 'Otra', onclick: generate }, icon('rotate', 'sm'))),
    meta, controls);
  return { node, value: () => current, regenerate: generate };
}

async function copyGenerated(value) {
  if (!value) return;
  const seconds = await api().copy_generated(value);
  toast(`Copiada · se borra en ${seconds} s`);
}

// Standalone generator (sidebar, Ctrl+G): for passwords that go somewhere else first.
function openGenerator() {
  const panel = generatorPanel();
  const modal = openModal({
    title: 'Generador de contraseñas',
    body: [panel.node, el('p', { class: 'help' }, 'Se genera en este PC. Al copiarla, el portapapeles se borra a los 30 s y no pasa al historial.')],
    footer: [el('div', { class: 'spacer' }), el('button', { class: 'btn', onclick: () => modal.close() }, 'Cerrar'),
      el('button', { class: 'btn primary', onclick: () => copyGenerated(panel.value()) }, icon('copy', 'sm'), 'Copiar')],
  });
}

// What a field's «Generar» makes at once. A database password goes in a connection URL, SQL and shells:
// letters and digits only. A secret of your own (generic) is long and URL-safe too.
function generatorPresetFor(templateId, field) {
  if (templateId === 'database') return { preset: 'url_safe' };
  if (templateId === 'generic' && field === 'value') return { preset: 'url_safe', length: 40 };
  return savedGeneratorOptions();
}

function canGenerate(templateId, field) {
  return field === 'password' || (templateId === 'generic' && field === 'value');
}

// «Generar» next to a secret input of the editor, plus a button with the options.
function generatorButtons(templateId, field, input) {
  if (!canGenerate(templateId, field)) return null;
  const fill = (value, message) => {
    input.value = value;
    input.dispatchEvent(new Event('input'));
    toast(message);
  };
  const quick = el('button', { class: 'btn', type: 'button', onclick: async () => {
    const result = await api().generate_password(generatorPresetFor(templateId, field));
    if (!result.ok) { toast(result.error, 'error'); return; }
    const preset = generatorPresetFor(templateId, field);
    fill(result.result.value, preset.preset === 'url_safe'
      ? `Generada: ${result.result.value.length} letras y números aleatorios` : 'Generada');
  } }, 'Generar');
  const more = el('button', { class: 'btn icon-only', type: 'button', title: 'Opciones del generador', onclick: () => {
    const panel = generatorPanel(templateId === 'database' ? { mode: 'random', symbols: false } : null);
    const modal = openModal({
      title: 'Generar contraseña',
      body: panel.node,
      footer: [el('div', { class: 'spacer' }), el('button', { class: 'btn', onclick: () => modal.close() }, 'Cancelar'),
        el('button', { class: 'btn primary', onclick: () => { fill(panel.value(), 'Generada'); modal.close(); } }, 'Usar esta')],
    });
  } }, icon('settings', 'sm'));
  return el('div', { class: 'gen-buttons' }, quick, more);
}

// ======================================================================= health

const HEALTH_LABELS = { weak: 'débiles', reused: 'repetidas', old: 'antiguas', expired: 'caducadas', expiring: 'caducan pronto',
  exposed: 'expuestas', pwned: 'en filtraciones', old_alive: 'con la anterior viva', was_exposed: 'estuvieron expuestas',
  team_access: 'con acceso de alguien que se fue', upload_failed: 'sin subir', half_rotated: 'rotaciones a medias',
  retired_pending: 'falta anular la anterior', unchecked: 'sin probar' };
// The same with one: «1 expuesta», «1 rotación a medias».
const HEALTH_LABEL_ONE = { weak: 'débil', reused: 'repetida', old: 'antigua', expired: 'caducada', expiring: 'caduca pronto',
  exposed: 'expuesta', was_exposed: 'estuvo expuesta', half_rotated: 'rotación a medias' };
const HEALTH_DANGER = new Set(['exposed', 'pwned', 'reused', 'weak', 'expired', 'team_access', 'upload_failed']);

function healthLabel(score) {
  return score >= 90 ? 'Excelente' : score >= 75 ? 'Buena' : score >= 50 ? 'Mejorable' : 'Necesita atención';
}

function canChangePassword(entry) {
  return entry.template === 'web_login' || (entry.template === 'ssh' && (entry.fields.auth_method || 'password') === 'password');
}

// «Rotar con ayuda» for any credential: the rotation wizard for keys and databases, the password
// change for web logins and SSH, and the credential itself for the rest.
function rotateWithHelp(entry) {
  if (canChangePassword(entry)) changePasswordGuided(entry);
  else if (entry.guide) rotateGuided(entry);
  else openEntry(entry);
}

function openEntry(entry) {
  state.selected = entry.id;
  state.view = 'credentials';
  renderMain();
}

// What fixes a credential's worst problem, as one button.
function healthAction(entry, issue, reminder) {
  const button = (text, onclick, primary = false) => {
    const node = el('button', { class: `btn ${primary ? 'primary' : ''}` }, text);
    node.addEventListener('click', () => onclick(node));
    return node;
  };
  if (!canWrite(entry)) return button('Abrir', () => openEntry(entry));
  if (issue.kind === 'upload_failed') return button('Reintentar subida', (node) => retryUploads(entry, node));
  if (issue.kind === 'half_rotated') return button('Terminar la rotación', () => rotateWithHelp(entry));
  if (issue.kind === 'retired_pending' || issue.kind === 'old_alive') return button('Anular la anterior', () => openEntry(entry));
  if (issue.kind === 'unchecked') return button('Probar', (node) => checkOne(entry, node));
  if (issue.kind === 'team_access' && reminder && !reminder.can_rotate) return button('Abrir', () => openEntry(entry));
  return button('Rotar con ayuda', () => rotateWithHelp(entry));
}

function healthSection() {
  const box = el('div', { class: 'health' }, el('div', { class: 'spinner' }));
  let showAll = false;
  const render = (report) => {
    const entries = Object.fromEntries(state.entries.map((e) => [e.id, e]));
    const items = report.items.filter((item) => entries[item.id]);
    const counts = Object.entries(report.counts).filter(([, n]) => n);
    const shown = showAll ? items : items.slice(0, 6);
    // Without a search for copies and a test with the providers, «all fine» would be a guess.
    const known = report.complete;
    const when = [report.scanned ? `búsqueda: ${whenText(report.scanned)}` : 'sin buscar copias',
      report.checked ? `proveedores: ${whenText(report.checked)}` : 'sin probar con los proveedores'].join(' · ');
    const missing = [report.scanned ? null : 'buscar copias de tus claves', report.checked ? null : 'probarlas con sus proveedores'].filter(Boolean);
    const scoreClass = !known ? 'is-unknown' : report.score >= 75 ? 'is-ok' : report.score >= 50 ? 'is-warning' : 'is-exposed';
    box.replaceChildren(
      el('div', { class: 'health-head' },
        el('div', { class: `health-score ${scoreClass}`, title: known ? 'Puntuación de 0 a 100' : 'Sin datos aún' }, known ? String(report.score) : '—'),
        el('div', { class: 'meta' },
          el('div', { class: 'title' }, !report.total ? 'Aún no hay credenciales' : known ? healthLabel(report.score) : 'Sin datos aún'),
          el('div', { class: 'muted small' }, !report.total ? '' : !known
            ? `Falta ${missing.join(' y ')}. «Revisar ahora» hace ${missing.length > 1 ? 'las dos cosas' : 'lo que falta'}.`
            : items.length ? `${report.healthy} de ${report.total} credenciales sin problemas (${when})`
              : `Sin problemas en lo revisado (${when})`),
          counts.length ? el('div', { class: 'health-counts' }, counts.map(([kind, n]) =>
            el('span', { class: `chip ${HEALTH_DANGER.has(kind) ? 'is-exposed' : kind === 'unchecked' ? '' : 'is-warning'}` }, `${n} ${(n === 1 && HEALTH_LABEL_ONE[kind]) || HEALTH_LABELS[kind] || kind}`))) : null)),
      items.length ? el('div', { class: 'health-list' }, shown.map((item) => {
        const entry = entries[item.id];
        return el('div', { class: 'health-row' }, glyph(entry.template),
          el('div', { class: 'meta' }, el('div', { class: 'title' }, entry.name,
            item.issues.map((issue) => el('span', { class: `chip ${HEALTH_DANGER.has(issue.kind) ? 'is-exposed' : issue.kind === 'unchecked' ? '' : 'is-warning'}` }, issue.label))),
          el('div', { class: 'subtitle' }, item.issues[0].text)),
          healthAction(entry, item.issues[0], state.reminders && state.reminders[entry.id]));
      }), items.length > shown.length || showAll ? el('button', { class: 'link small', onclick: () => { showAll = !showAll; render(report); } },
        showAll ? 'Ver menos' : `Ver todas (${items.length})`) : null) : null);
  };
  api().call('health').then((result) => {
    if (result.ok) render(result.result);
    else box.replaceChildren(el('p', { class: 'error-text' }, result.error));
  });
  return box;
}

// Change the password of a web login or an SSH account: generate it, change it there, save it here.
// The one shown is kept by the service as pending, so closing (or locking) before saving never loses
// a password already set on the site; reopening offers to finish.
function changePasswordGuided(entry) {
  const ssh = entry.template === 'ssh';
  const url = entry.fields.url || '';
  const site = ssh ? `${entry.fields.username}@${entry.fields.host}` : hostOf(url) || entry.name;
  const errorText = el('div', { class: 'error-text' });
  const save = el('button', { class: 'btn primary' }, 'Ya la he cambiado: guardar');
  let pending = entry.pending_rotation;
  let kept = '';  // the value the service keeps as pending (from this dialog)
  let finished = false;
  let timer = null;
  const keep = (value) => {
    clearTimeout(timer);
    timer = setTimeout(async () => {
      const result = await api().call('rotation_begin', { id: entry.id, value });
      if (result.ok) { kept = value; pending = result.result.pending_rotation; }
    }, 300);
  };
  const body = el('div', {});
  const foot = el('div', { style: 'display:contents' });
  const modal = openModal({
    title: `Cambiar la contraseña de ${entry.name}`,
    wide: true,
    body,
    footer: [foot],
    confirmClose: () => (finished ? null : pending
      ? 'La contraseña nueva queda guardada aquí como pendiente: cuando vuelvas a «Rotar con ayuda», podrás terminar.'
      : 'Aún no se ha cambiado nada.'),
    onClose: () => { clearTimeout(timer); loadEntries().then(renderMain); },
  });
  const finish = async (params) => {
    errorText.textContent = '';
    busy(save, true);
    const result = await withProof((p) => api().call('replace_key', { id: entry.id, ...params }, p), `Para guardar la contraseña nueva de ${entry.name}.`);
    busy(save, false);
    if (!result.ok) { if (result.code !== 'cancelled') errorText.textContent = result.error; return; }
    finished = true;
    modal.close();
    toast('Contraseña nueva guardada');
  };
  const copyPending = async () => {
    const result = await withProof((p) => api().copy_rotation_secret(entry.id, 'value', p), `Para copiar la contraseña nueva de ${entry.name}.`);
    if (result.ok) toast(`Copiada · se borra del portapapeles en ${result.result} s`);
    else if (result.code !== 'cancelled') toast(result.error, 'error');
  };

  const fresh = () => {
    const panel = generatorPanel(null, keep);
    save.onclick = () => finish(kept && kept === panel.value() ? { pending: true } : { value: panel.value() });
    body.replaceChildren(
      el('ol', { class: 'guide-steps' },
        el('li', {}, ssh ? `Entra en ${site} y prepárate para cambiarla con passwd (o desde el panel del servidor).`
          : `Abre ${site} y ve a la página para cambiar la contraseña.`,
        !ssh && /^https:\/\//i.test(url) ? [' ', el('button', { class: 'link', onclick: () => api().open_link(url) }, `Abrir ${hostOf(url)}`)] : null),
        el('li', {}, 'Copia esta contraseña nueva y pégala allí:'),
        el('li', {}, 'Cuando la acepte, guárdala aquí.', ssh ? ' La app comprueba que entra con ella antes de guardarla.' : '')),
      panel.node,
      el('div', { style: 'display:flex;gap:8px' }, el('button', { class: 'btn', onclick: () => { keep(panel.value()); copyGenerated(panel.value()); } }, icon('copy', 'sm'), 'Copiar')),
      el('p', { class: 'help' }, 'Mientras la cambias, se guarda aquí como pendiente: si cierras antes de guardarla, no se pierde.'),
      (entry.used_in || []).length ? el('p', { class: 'help' }, `Después cámbiala también en: ${entry.used_in.join('; ')}.`) : null,
      errorText);
    foot.replaceChildren(el('div', { class: 'spacer' }), el('button', { class: 'btn', onclick: () => modal.close() }, 'Cancelar'), save);
  };

  // Halfway: a new password was prepared and not saved. Was it set on the site?
  const resume = () => {
    save.onclick = () => finish({ pending: true });
    save.textContent = 'Sí, ya la cambié: guardar';
    body.replaceChildren(
      el('h3', {}, 'Rotación a medias: ¿ya la cambiaste?'),
      el('p', { class: 'muted' }, `${capitalized(atText(pending.since))} se preparó una contraseña nueva para ${site} y no se llegó a guardar. `
        + 'Si ya la pusiste allí, guárdala ahora: la que hay aquí ya no funcionaría.'),
      el('div', { class: 'prop' }, el('div', { style: 'min-width:0' }, el('div', { class: 'k' }, 'Contraseña nueva'), el('div', { class: 'v secret' }, '••••••••••••')),
        el('div', { class: 'actions' }, el('button', { class: 'btn icon-only', title: 'Copiar', onclick: copyPending }, icon('copy', 'sm')))),
      errorText);
    foot.replaceChildren(el('div', { class: 'spacer' }), el('button', { class: 'btn', onclick: async () => {
      const result = await withProof((p) => api().call('rotation_discard', { id: entry.id }, p), `Para descartar la nueva de ${entry.name}.`);
      if (!result.ok) { if (result.code !== 'cancelled') errorText.textContent = result.error; return; }
      pending = null;
      save.textContent = 'Ya la he cambiado: guardar';
      fresh();
    } }, 'No, descartarla'), save);
  };
  if (pending) resume();
  else fresh();
}

// ======================================================================= import

const IMPORT_STATUS = { new: ['Nueva', 'is-ok'], duplicate: ['Ya está', ''], conflict: ['Otra contraseña', 'is-warning'] };
const IMPORT_BATCH = 100;  // credentials per call: the vault is saved once per batch, and the progress moves
// Where each manager keeps its export, menu by menu (the file format is detected from its content).
const IMPORT_SOURCES = [
  ['bitwarden', 'Bitwarden', [
    ['En la web o la app de escritorio: ', el('b', {}, 'Herramientas → Exportar caja fuerte'), ' (en la app: ', el('b', {}, 'Archivo → Exportar caja fuerte'), ').'],
    ['Formato de archivo: ', el('b', {}, '.json'), ' (no «.json (Encrypted)»). También vale .csv, pero el .json trae más: carpetas, notas, claves SSH y códigos 2FA.'],
    ['Escribe tu contraseña maestra de Bitwarden y guarda el archivo.']]],
  ['onepassword', '1Password', [
    ['En la app de escritorio de 1Password 8: ', el('b', {}, 'Archivo → Exportar'), ' y elige tu cuenta.'],
    ['Escribe tu contraseña de 1Password y elige el formato ', el('b', {}, 'CSV'), ' (el formato .1pux no se puede leer).'],
    ['Guarda el archivo.']]],
  ['keepass', 'KeePassXC / KeePass', [
    ['KeePassXC: ', el('b', {}, 'Base de datos → Exportar → Exportar a CSV…'), '.'],
    ['KeePass 2: ', el('b', {}, 'Archivo → Exportar → KeePass CSV (1.x)'), '.'],
    ['Los códigos 2FA de KeePassXC (columna TOTP) se importan como «Código 2FA».']]],
  ['chrome', 'Chrome / Edge', [
    ['Chrome: ', el('b', {}, 'Configuración → Autocompletar y contraseñas → Gestor de contraseñas de Google → Configuración → Exportar contraseñas → Descargar archivo'), '.'],
    ['Edge: ', el('b', {}, 'Configuración → Perfiles → Contraseñas → … (Más acciones) → Exportar contraseñas'), '.'],
    ['Windows te pedirá tu PIN o contraseña antes de guardar el .csv.']]],
  ['firefox', 'Firefox', [
    ['Menú ', el('b', {}, '☰ → Contraseñas'), ' (o escribe ', el('code', {}, 'about:logins'), ' en la barra de direcciones).'],
    ['En el menú ', el('b', {}, '…'), ' de arriba a la derecha: ', el('b', {}, 'Exportar contraseñas…'), '.'],
    ['Confirma con tu contraseña de Windows y guarda el .csv.']]],
  ['secretbroker', 'SecretBroker', [
    ['En el otro PC: ', el('b', {}, 'Credenciales → … → Exportar → Cifrada'), '.'],
    ['Aquí te pedirá la contraseña que elegiste para el archivo.']]],
];
const IMPORT_SOURCE_KEY = 'importSource';

// Step 1: which manager, with how to export from it; then pick the file.
function openImport() {
  let source = 'bitwarden';
  try { source = localStorage.getItem(IMPORT_SOURCE_KEY) || source; } catch { /* the first one */ }
  if (!IMPORT_SOURCES.some(([id]) => id === source)) source = 'bitwarden';
  const tabs = el('div', { class: 'source-tabs', role: 'tablist' });
  const steps = el('ol', { class: 'steps-list' });
  const render = () => {
    tabs.replaceChildren(IMPORT_SOURCES.map(([id, label]) => el('button', {
      type: 'button', role: 'tab', 'aria-selected': id === source ? 'true' : 'false', class: id === source ? 'active' : '',
      onclick: () => { source = id; try { localStorage.setItem(IMPORT_SOURCE_KEY, id); } catch { /* not remembered */ } render(); },
    }, label)));
    // The steps hold nodes: clone them, so each drawing gets its own.
    steps.replaceChildren(IMPORT_SOURCES.find(([id]) => id === source)[2].map((parts) =>
      el('li', {}, parts.map((p) => (p instanceof Node ? p.cloneNode(true) : p)))));
  };
  render();
  const pick = el('button', { class: 'btn primary' }, icon('upload', 'sm'), 'Elegir el archivo…');
  const modal = openModal({
    title: 'Importar de otro gestor',
    wide: true,
    body: [
      el('p', { class: 'muted' }, 'Exporta tus datos desde el otro gestor y elige aquí el archivo. Antes de importar verás la lista (solo nombres).'),
      tabs, steps,
      el('p', { class: 'help' }, '¿Las claves de un proyecto en un .env? ',
        el('button', { class: 'link', type: 'button', onclick: () => { modal.close(); openEnvImportHelp(); } }, 'Usa «sb import»'), '.'),
    ],
    footer: [el('div', { class: 'spacer' }), el('button', { class: 'btn', onclick: () => modal.close() }, 'Cancelar'), pick],
  });
  pick.addEventListener('click', async () => {
    const path = await api().pick_import_file();
    if (!path) return;
    modal.close();
    previewImport(path, null);
  });
}

async function previewImport(path, password) {
  const result = await withProof((p) => api().import_file(path, 'auto', null, password, p), 'Para importar credenciales.');
  if (result.code === 'password_required' || result.code === 'wrong_password') { askFilePassword(path, result.code === 'wrong_password' ? result.error : ''); return; }
  if (!result.ok) { if (result.code !== 'cancelled') toast(result.error, 'error'); return; }
  showImportPreview(path, password, result.result);
}

function askFilePassword(path, error) {
  const pw = passwordInput({ autocomplete: 'off' });
  const go = () => { modal.close(); previewImport(path, pw.input.value); };
  pw.input.addEventListener('keydown', (event) => { if (event.key === 'Enter') go(); });
  const modal = openModal({
    title: 'Exportación cifrada',
    body: [el('p', { class: 'muted' }, 'Escribe la contraseña que elegiste al exportarla.'), el('div', { class: 'field' }, pw),
      el('div', { class: 'error-text' }, error || '')],
    footer: [el('div', { class: 'spacer' }), el('button', { class: 'btn', onclick: () => modal.close() }, 'Cancelar'),
      el('button', { class: 'btn primary', onclick: go }, 'Abrir')],
  });
  setTimeout(() => pw.input.focus(), 50);
}

// Step 2: the list (names only), what happens to each one, and the «only development keys» filter.
function showImportPreview(path, password, preview) {
  const chosen = new Set(preview.items.filter((i) => i.selected).map((i) => i.key));
  const devCount = preview.items.filter((i) => i.dev).length;
  let devOnly = false;
  const button = el('button', { class: 'btn primary' });
  const all = el('input', { type: 'checkbox' });
  const shown = () => preview.items.filter((i) => !devOnly || i.dev);
  const sync = () => {
    button.textContent = chosen.size ? `Importar ${chosen.size}` : 'Importar';
    button.disabled = !chosen.size;
    const visible = shown();
    all.checked = visible.length > 0 && visible.every((i) => chosen.has(i.key));
  };
  const list = el('div', { class: 'import-list' });
  const boxes = new Map();
  const rows = new Map(preview.items.map((item) => {
    const box = el('input', { type: 'checkbox', checked: chosen.has(item.key) });
    boxes.set(item.key, box);
    box.addEventListener('change', () => { if (box.checked) chosen.add(item.key); else chosen.delete(item.key); sync(); });
    const [label, cls] = IMPORT_STATUS[item.status] || [item.status, ''];
    return [item.key, el('label', { class: 'import-row' }, box, glyph(item.template),
      el('div', { class: 'meta' }, el('div', { class: 'title' }, item.name),
        el('div', { class: 'subtitle' }, [item.subtitle, item.tags.join(', '), item.totp ? 'con código 2FA' : '',
          item.notes ? 'con notas privadas' : '', item.reason].filter(Boolean).join(' · '))),
      el('span', { class: `level ${cls}` }, label))];
  }));
  const drawList = () => list.replaceChildren(shown().map((i) => rows.get(i.key)));
  all.addEventListener('change', () => {
    for (const item of shown()) { boxes.get(item.key).checked = all.checked; if (all.checked) chosen.add(item.key); else chosen.delete(item.key); }
    sync();
  });
  const devToggle = el('input', { type: 'checkbox' });
  devToggle.addEventListener('change', () => {
    devOnly = devToggle.checked;
    // Only the development keys stay ticked; turning it off brings back the ones that are new.
    for (const item of preview.items) {
      const on = devOnly ? item.dev && (chosen.has(item.key) || item.selected) : item.selected;
      boxes.get(item.key).checked = on;
      if (on) chosen.add(item.key); else chosen.delete(item.key);
    }
    drawList();
    sync();
  });
  drawList();
  sync();
  const counts = ['new', 'duplicate', 'conflict'].map((s) => [s, preview.items.filter((i) => i.status === s).length]).filter(([, n]) => n);
  const modal = openModal({
    title: `Importar de ${preview.label}`,
    wide: true,
    body: [
      el('p', { class: 'muted' }, `${plural(preview.items.length, 'credencial', 'credenciales')} en el archivo: `,
        counts.map(([s, n]) => `${n} ${{ new: n === 1 ? 'nueva' : 'nuevas', duplicate: n === 1 ? 'ya está en la bóveda' : 'ya están en la bóveda', conflict: 'con otra contraseña' }[s]}`).join(', '),
        '. Solo ves nombres: los valores van directos a la bóveda cifrada.'),
      devCount && devCount < preview.items.length ? el('label', { class: 'check-row dev-filter' }, devToggle,
        el('span', {}, 'Solo claves de desarrollo (API keys, SSH, bases de datos)', el('span', { class: 'faint' }, ` · ${devCount}`))) : null,
      preview.items.length ? el('label', { class: 'check-row', style: 'margin:4px 0' }, all, 'Seleccionar todas') : null,
      list,
      preview.skipped.length ? el('details', { class: 'findings' },
        el('summary', {}, `${preview.skipped.length} no se ${preview.skipped.length === 1 ? 'importa' : 'importan'}`),
        preview.skipped.map((s) => el('div', { class: 'small muted' }, `${s.name}: ${s.reason}`))) : null,
      el('p', { class: 'help' }, 'Los códigos 2FA de las webs van a su campo «Código 2FA»; las notas y los campos extra, a «Notas privadas». La IA no ve ninguno. ',
        'Los permisos de la IA salen de la plantilla, como al crearlas a mano.'),
    ],
    footer: [el('div', { class: 'spacer' }), el('button', { class: 'btn', onclick: () => modal.close() }, 'Cancelar'), button],
  });
  button.addEventListener('click', () => {
    modal.close();
    runImport(path, password, preview, preview.items.filter((i) => chosen.has(i.key)).map((i) => i.key));
  });
}

// Step 3: in batches, with «312 de 1000», then an honest summary.
async function runImport(path, password, preview, keys) {
  const bar = el('span', { style: 'width:0%' });
  const count = el('div', { class: 'import-count' }, `0 de ${keys.length}`);
  const modal = openModal({
    title: `Importando de ${preview.label}`,
    body: [count, el('div', { class: 'progress import-progress' }, bar),
      el('p', { class: 'help' }, 'Se guardan cifradas a medida que avanzan. No cierres la app.')],
    footer: null,
    confirmClose: () => 'La importación sigue: si cierras esto, termina igual y al acabar verás el resumen.',
  });
  const created = [];
  const failed = [];
  let stopped = null;
  for (let start = 0; start < keys.length; start += IMPORT_BATCH) {
    const part = keys.slice(start, start + IMPORT_BATCH);
    const last = start + IMPORT_BATCH >= keys.length;
    const result = preview.import_id
      ? await withProof((p) => api().import_batch(preview.import_id, part, last, p), 'Para importar credenciales.')
      : await withProof((p) => api().import_file(path, preview.format, part, password, p), 'Para importar credenciales.');
    if (!result.ok) { stopped = result; break; }
    created.push(...result.result.created);
    failed.push(...result.result.failed);
    const done = Math.min(start + IMPORT_BATCH, keys.length);
    count.textContent = `${done} de ${keys.length}`;
    bar.style.width = `${Math.round((done / keys.length) * 100)}%`;
  }
  modal.close();
  await loadEntries();
  renderMain();
  if (stopped && stopped.code === 'cancelled' && !created.length) return;
  importDone(path, { format: preview.format, created, failed, stopped, preview, keys });
}

// What happened to each one: created, skipped (with why) and failed (with why). The file holds every
// password in clear: strongly suggest deleting it.
function importDone(path, result) {
  const name = path.split(/[\\/]/).pop();
  const own = result.format === 'secretbroker_encrypted';
  const preview = result.preview || { items: [], skipped: [] };
  const picked = new Set(result.keys || []);
  const notImported = (result.stopped ? [] : preview.items.filter((i) => !picked.has(i.key)));
  const unpicked = (status) => notImported.filter((i) => i.status === status).length;
  const skippedLines = [
    unpicked('duplicate') ? `${unpicked('duplicate')} ya estaban en la bóveda` : null,
    unpicked('conflict') ? `${unpicked('conflict')} con otra contraseña que no elegiste` : null,
    unpicked('new') ? `${unpicked('new')} que dejaste sin marcar` : null,
    ...Object.entries(preview.skipped.reduce((acc, s) => ({ ...acc, [s.reason]: (acc[s.reason] || 0) + 1 }), {}))
      .map(([reason, n]) => `${n} · ${reason}`),
  ].filter(Boolean);
  const skippedTotal = notImported.length + preview.skipped.length;
  const remove = el('button', { class: 'btn solid-danger' }, icon('trash', 'sm'), 'Borrar el archivo');
  const stat = (n, label, cls) => el('div', { class: `import-stat ${n ? cls : ''}` }, el('div', { class: 'n' }, String(n)), el('div', { class: 'label' }, label));
  const modal = openModal({
    title: result.stopped ? 'Importación interrumpida'
      : `${result.created.length} ${result.created.length === 1 ? 'credencial importada' : 'credenciales importadas'}`,
    body: [
      el('div', { class: 'import-stats' },
        stat(result.created.length, result.created.length === 1 ? 'creada' : 'creadas', 'is-ok'),
        stat(skippedTotal, skippedTotal === 1 ? 'saltada' : 'saltadas', ''),
        stat(result.failed.length, result.failed.length === 1 ? 'con error' : 'con errores', 'is-danger')),
      result.stopped ? el('div', { class: 'warning is-danger' }, icon('alert', 'sm'), el('span', {},
        `Se paró en ${result.created.length + result.failed.length} de ${(result.keys || []).length}: ${result.stopped.error}. Las que ya estaban hechas se han guardado; vuelve a importar el archivo para seguir (las importadas saldrán como «Ya está»).`)) : null,
      skippedLines.length ? el('details', { class: 'findings' }, el('summary', {}, 'Saltadas'),
        skippedLines.map((line) => el('div', { class: 'small muted' }, line))) : null,
      result.failed.length ? el('details', { class: 'findings', open: true }, el('summary', {}, 'Con errores'),
        result.failed.map((f) => el('div', { class: 'small error-text' }, `${f.name}: ${f.reason}`))) : null,
      own ? el('p', { class: 'muted' }, 'El archivo está cifrado: puedes guardarlo como copia o borrarlo.')
        : el('div', { class: 'warning' }, icon('alert', 'sm'), el('span', {},
          el('b', {}, `${name} tiene todas tus contraseñas sin cifrar. `),
          'Cualquier programa o persona que lo lea las tiene. Bórralo ahora, y también las copias que haya en Descargas, el correo o la nube.')),
      el('p', { class: 'help' }, 'Mira ahora «Salud»: verás las contraseñas débiles o repetidas que traías, con un botón para cambiar cada una.'),
    ],
    footer: [
      el('button', { class: 'btn', onclick: () => { modal.close(); state.view = 'exposure'; renderMain(); } }, 'Ver la salud'),
      el('div', { class: 'spacer' }),
      el('button', { class: 'btn', onclick: () => modal.close() }, own ? 'Conservarlo' : 'Lo borraré yo'),
      remove,
    ],
  });
  remove.addEventListener('click', async () => {
    const deleted = await api().delete_import_source();
    if (!deleted.ok) { toast(deleted.error, 'error'); return; }
    modal.close();
    toast('Archivo borrado');
  });
}

// «…» next to «Nueva»: import and export, labelled.
function importExportMenu() {
  const menu = el('div', { class: 'menu hidden', role: 'menu' },
    el('button', { class: 'menu-item', role: 'menuitem', type: 'button', onclick: () => { close(); openImport(); } }, icon('upload', 'sm'), 'Importar…'),
    el('button', { class: 'menu-item', role: 'menuitem', type: 'button', onclick: () => { close(); openExport(); } }, icon('download', 'sm'), 'Exportar…'));
  const button = el('button', { class: 'btn icon-only', type: 'button', title: 'Más: importar y exportar', 'aria-label': 'Más acciones', 'aria-haspopup': 'menu' }, icon('more', 'sm'));
  const wrap = el('span', { class: 'popover-wrap' }, button, menu);
  const outside = (event) => { if (!wrap.contains(event.target)) close(); };
  const close = () => { menu.classList.add('hidden'); button.setAttribute('aria-expanded', 'false'); document.removeEventListener('mousedown', outside); };
  button.addEventListener('click', () => {
    if (!menu.classList.contains('hidden')) { close(); return; }
    menu.classList.remove('hidden');
    button.setAttribute('aria-expanded', 'true');
    document.addEventListener('mousedown', outside);
    menu.querySelector('button').focus();
  });
  menu.addEventListener('keydown', (event) => { if (event.key === 'Escape') { event.stopPropagation(); close(); button.focus(); } });
  return wrap;
}

// ======================================================================= 2FA codes

// The detail of a login with a 2FA seed: the current code with a ring counting down, and «Copiar». The code is
// computed by the service; the page asks for it only while this is on screen (and never keeps the seed).
const TOTP_RING = 2 * Math.PI * 9;

function totpProp(entry, spec) {
  const digits = el('div', { class: 'v totp-code secret' }, '••• •••');
  const arc = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
  arc.setAttribute('cx', '12'); arc.setAttribute('cy', '12'); arc.setAttribute('r', '9'); arc.setAttribute('class', 'arc');
  const ring = el('span', { class: 'totp-ring', title: 'Segundos hasta el código siguiente' });
  ring.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9" class="track"/></svg>';
  ring.firstChild.append(arc);
  const seconds = el('span', { class: 'totp-seconds' });
  ring.append(seconds);
  let shown = false;
  let remaining = 0;
  let period = 30;
  let timer = null;
  const reveal = el('button', { class: 'btn icon-only', title: 'Mostrar el código' }, icon('eye', 'sm'));
  const copy = el('button', { class: 'btn icon-only', title: 'Copiar el código' }, icon('copy', 'sm'));
  const node = el('div', { class: 'prop totp-prop' },
    el('div', { style: 'min-width:0' }, el('div', { class: 'k' }, shortLabel(spec.label)),
      el('div', { class: 'totp-line' }, ring, digits)),
    el('div', { class: 'actions' }, reveal, copy));
  const draw = (code) => {
    digits.textContent = code ? `${code.slice(0, Math.ceil(code.length / 2))} ${code.slice(Math.ceil(code.length / 2))}` : '••• •••';
    digits.className = `v totp-code ${code ? 'revealed selectable' : 'secret'}`;
    reveal.title = code ? 'Ocultar el código' : 'Mostrar el código';
    reveal.replaceChildren(icon(code ? 'eyeOff' : 'eye', 'sm'));
  };
  const tick = () => {
    if (!node.isConnected) { clearInterval(timer); return; }
    remaining -= 1;
    if (remaining <= 0) { fetchCode(true); return; }
    paint();
  };
  const paint = () => {
    seconds.textContent = shown ? String(remaining) : '';
    arc.style.strokeDasharray = `${TOTP_RING}`;
    arc.style.strokeDashoffset = `${TOTP_RING * (1 - (shown ? remaining / period : 1))}`;
    ring.classList.toggle('ending', shown && remaining <= 5);
  };
  // auto: refresh by itself, without ever asking for Hello or a password (then the eye does it).
  const fetchCode = async (auto) => {
    clearInterval(timer);
    const result = auto
      ? await api().totp_code(entry.id, false, true, null)
      : await withProof((p) => api().totp_code(entry.id, false, false, p), `Para ver el código 2FA de ${entry.name}.`);
    if (!node.isConnected) return;
    if (!result.ok) {
      shown = false; draw(null); paint();
      if (!auto && result.code !== 'cancelled') toast(result.error, 'error');
      return;
    }
    shown = true;
    ({ remaining, period } = result.result);
    draw(result.result.code);
    paint();
    timer = setInterval(tick, 1000);
  };
  reveal.addEventListener('click', () => {
    if (shown) { shown = false; clearInterval(timer); draw(null); paint(); return; }
    fetchCode(false);
  });
  copy.addEventListener('click', async () => {
    const result = await withProof((p) => api().totp_code(entry.id, true, false, p), `Para copiar el código 2FA de ${entry.name}.`);
    if (result.ok) toast(`Código 2FA copiado · válido ${result.result.remaining} s más`);
    else if (result.code !== 'cancelled') toast(result.error, 'error');
  });
  draw(null);
  paint();
  fetchCode(true);
  return node;
}

// ======================================================================= export

function openExport() {
  let format = 'encrypted';
  const pw = passwordInput();
  const confirm = passwordInput();
  const understood = el('input', { type: 'checkbox' });
  const errorText = el('div', { class: 'error-text' });
  const button = el('button', { class: 'btn primary' }, 'Exportar…');
  const details = el('div', {});
  const tabs = el('div', { class: 'segmented' });
  const render = () => {
    tabs.replaceChildren([['encrypted', 'Cifrada'], ['json', 'Sin cifrar (JSON)'], ['csv', 'Sin cifrar (CSV)']].map(([value, label]) =>
      el('button', { type: 'button', class: format === value ? 'active' : '', onclick: () => { format = value; errorText.textContent = ''; render(); } }, label)));
    details.replaceChildren(format === 'encrypted'
      ? [el('p', { class: 'muted' }, 'Todas las credenciales, con sus notas y permisos, en un archivo protegido con la contraseña que elijas (scrypt y AES-256-GCM). ',
        'Sirve para llevarlas a otro PC: se abre en «Ajustes → Importar».'),
      el('div', { class: 'field' }, el('label', {}, 'Contraseña del archivo'), pw, strengthMeter(pw.input)),
      el('div', { class: 'field' }, el('label', {}, 'Repítela'), confirm),
      el('p', { class: 'help' }, 'Si la olvidas, el archivo no se puede abrir.')]
      : [el('div', { class: 'warning' }, icon('alert', 'sm'), el('span', {}, el('b', {}, 'El archivo tendrá todas tus contraseñas a la vista. '),
        format === 'csv' ? 'El CSV (nombre, web, usuario, contraseña, nota) lo leen Bitwarden, 1Password, KeePassXC y los navegadores. Solo guarda la clave principal de cada credencial.'
          : 'El JSON lo tiene todo, en claro. Úsalo solo para pasar a otra herramienta.')),
      el('label', { class: 'check-row', style: 'margin-top:10px' }, understood, 'Lo entiendo: lo importaré enseguida y después lo borraré')]);
  };
  render();
  const modal = openModal({
    title: 'Exportar la bóveda',
    body: [tabs, details, errorText],
    footer: [el('div', { class: 'spacer' }), el('button', { class: 'btn', onclick: () => modal.close() }, 'Cancelar'), button],
  });
  button.addEventListener('click', async () => {
    errorText.textContent = '';
    if (format === 'encrypted') {
      if (pw.input.value.length < 12) { errorText.textContent = 'La contraseña del archivo necesita al menos 12 caracteres.'; return; }
      if (pw.input.value !== confirm.input.value) { errorText.textContent = 'Las dos contraseñas no coinciden.'; return; }
    } else if (!understood.checked) { errorText.textContent = 'Marca la casilla para exportar sin cifrar.'; return; }
    busy(button, true);
    const result = await withProof((p) => api().export_vault(format, format === 'encrypted' ? pw.input.value : null, p), 'Para exportar la bóveda.');
    busy(button, false);
    if (!result.ok) { if (result.code !== 'cancelled') errorText.textContent = result.error; return; }
    modal.close();
    toast(`${result.result.entries} credenciales exportadas a ${result.result.path}`);
  });
}

function importExportGroup() {
  return el('div', { class: 'settings-group' }, el('h3', { class: 'muted' }, 'Importar y exportar'),
    setting('Importar de otro gestor', 'Bitwarden, 1Password, KeePass / KeePassXC, Chrome, Edge, Firefox o una exportación de SecretBroker. Antes de importar ves la lista (solo nombres) y se saltan las que ya tienes.',
      el('button', { class: 'btn', onclick: openImport }, icon('upload', 'sm'), 'Importar…')),
    setting('Exportar', 'Un archivo cifrado para otro PC, o JSON / CSV sin cifrar para otra herramienta. Tus datos son tuyos.',
      el('button', { class: 'btn', onclick: openExport }, icon('download', 'sm'), 'Exportar…')));
}
