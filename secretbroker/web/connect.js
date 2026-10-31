'use strict';

// Connecting the AI apps the user already has (Claude Code, Claude Desktop, Cursor, VS Code, Windsurf, Codex):
// the «Conecta tu IA» step at the end of the first run, «Clientes conectados» in Acceso de la IA, and the
// first steps of an empty vault. Loaded after app.js and built from its helpers (el, icon, openModal, toast…).
//
// api().ai_clients() → {clients: [{id, label, status: connected | disconnected | missing, last, requests}], others}
// (when each one last made a request comes from the service, which records the MCP client's name).

const AI_TEST_PROMPT = 'Usa SecretBroker: llama a list_secrets y dime qué credenciales tengo guardadas, sin mostrar ningún valor.';
const AI_CLIENT_AFTER = {
  claude_code: 'Abre una sesión nueva de Claude Code para que lo vea.',
  claude_desktop: 'Cierra Claude Desktop del todo (también junto al reloj) y ábrelo otra vez.',
  cursor: 'Reinicia Cursor para que lo vea.',
  vscode: 'Recarga VS Code y usa Copilot Chat en modo Agente.',
  windsurf: 'Reinicia Windsurf para que lo vea.',
  codex: 'Abre una sesión nueva de Codex para que lo vea.',
};
const AI_CLIENT_POLL_MS = 1500;

async function loadAiClients() {
  const result = await api().ai_clients();
  return result.ok ? result.result : { clients: [], others: [] };
}

function anyAiConnected(data) {
  return data.clients.some((c) => c.status === 'connected' || c.last) || data.others.length > 0;
}

// «Última petición hoy 10:02 · 34 peticiones», «Conectado · aún sin peticiones».
function aiClientUse(c) {
  if (c.last) return `Última petición ${whenText(c.last)} · ${plural(c.requests || 0, 'petición', 'peticiones')}`;
  return c.status === 'connected' ? 'Conectado · aún sin peticiones' : c.status === 'missing' ? 'No instalado en este PC' : 'Sin conectar';
}

async function connectAiClient(c, button) {
  busy(button, true);
  const result = await api().connect_ai(c.id);
  busy(button, false);
  if (!result.ok) { toast(result.error, 'error'); return false; }
  toast(`${c.label} conectado. ${AI_CLIENT_AFTER[c.id] || ''}`.trim());
  return true;
}

// One row per AI app: its state and, when installed but not connected, «Conectar».
function aiClientRow(c, onChange, { showUse = true } = {}) {
  const connect = el('button', { class: 'btn' }, 'Conectar');
  connect.addEventListener('click', async () => { if (await connectAiClient(c, connect)) onChange(); });
  const connected = c.status === 'connected';
  const control = connected
    ? el('span', { class: 'level is-ok' }, icon('check', 'sm'), 'Conectado')
    : c.status === 'missing' ? el('span', { class: 'faint small' }, 'No instalado') : connect;
  return el('div', { class: `ai-client ${c.status}`, 'data-client': c.id },
    el('div', { class: 'ai-client-mark' }, (c.label || '?').charAt(0)),
    el('div', { class: 'meta' }, el('div', { class: 'title' }, c.label),
      showUse ? el('div', { class: 'subtitle' }, connected && !c.last ? AI_CLIENT_AFTER[c.id] || aiClientUse(c) : aiClientUse(c)) : null),
    control);
}

// The prompt to try it, with its own copy button.
function aiTestPrompt() {
  return el('div', { class: 'prompt-box' },
    el('div', { class: 'prompt-text selectable' }, AI_TEST_PROMPT),
    el('button', { class: 'btn', title: 'Copiar la frase', onclick: async () => { await api().copy_text(AI_TEST_PROMPT); toast('Copiada: pégala en tu IA'); } },
      icon('copy', 'sm'), 'Copiar'));
}

// Waits for the next request of any AI app and says which one: «✓ Recibida de Claude Code».
function aiFirstRequestWatcher(baseline, onReceived) {
  const line = el('div', { class: 'wait-line', role: 'status' }, el('div', { class: 'spinner' }), el('span', {}, 'Esperando la primera petición…'));
  const total = (data) => data.clients.reduce((n, c) => n + (c.requests || 0), 0) + data.others.reduce((n, c) => n + (c.requests || 0), 0);
  const start = total(baseline);
  const timer = setInterval(async () => {
    if (!line.isConnected) { clearInterval(timer); return; }
    const data = await loadAiClients();
    if (total(data) <= start) return;
    clearInterval(timer);
    const latest = [...data.clients, ...data.others].filter((c) => c.last).sort((a, b) => (a.last < b.last ? 1 : -1))[0];
    line.classList.add('received');
    line.replaceChildren(icon('check', 'sm'), el('span', {}, `Recibida de ${latest ? latest.label : 'tu IA'}`),
      el('span', { class: 'faint small' }, '· SecretBroker ya está trabajando con tu IA'));
    if (onReceived) onReceived(latest, data);
  }, AI_CLIENT_POLL_MS);
  return line;
}

// The list of AI apps, installed ones first; those not on this PC folded into one line.
function aiClientList(data, rerender) {
  const installed = data.clients.filter((c) => c.status !== 'missing');
  const missing = data.clients.filter((c) => c.status === 'missing');
  return el('div', { class: 'ai-client-list' },
    installed.map((c) => aiClientRow(c, rerender)),
    installed.length ? null : el('p', { class: 'muted small' }, 'No encontramos ninguna IA compatible instalada en este PC.'),
    missing.length ? el('p', { class: 'faint small ai-missing' }, `No instalados: ${listJoin(missing.map((c) => c.label))}.`) : null);
}

// ----------------------------------------------------------------------- first run: «Conecta tu IA»

// The last step of the first run, separate so it can follow any other: `box` is the setup card, `onDone` ends it,
// `progress` the setup's step marks (all lit: it is the last one).
async function renderConnectAi(box, onDone, progress) {
  box.classList.remove('centered');
  box.replaceChildren(el('div', { class: 'spinner' }));
  let data = await loadAiClients();
  const baseline = data;
  const finish = el('button', { class: 'btn primary lg' }, 'Continuar');
  finish.addEventListener('click', onDone);
  const later = el('button', { class: 'btn ghost lg', onclick: onDone }, 'Ahora no');
  const watcher = aiFirstRequestWatcher(baseline, () => {
    finish.textContent = 'Empezar a usar SecretBroker';
    later.remove();
  });
  const list = el('div', {});
  const draw = async (reload) => {
    if (reload) data = await loadAiClients();
    list.replaceChildren(aiClientList(data, () => draw(true)));
  };
  draw(false);
  box.replaceChildren(
    el('div', { class: 'auth-head' }, progress || el('div', { class: 'eyebrow' }, 'Último paso'),
      el('h2', { style: progress ? 'margin-top:12px' : null }, 'Conecta tu IA')),
    el('p', { class: 'lead' }, 'SecretBroker funciona con la IA que ya usas. Conéctala con un clic: podrá usar tus claves, nunca verlas.'),
    list,
    el('div', { class: 'field' }, el('label', {}, 'Pruébalo: pega esto en tu IA'), aiTestPrompt()),
    watcher,
    el('div', { style: 'display:flex;gap:8px' }, finish, later));
  setTimeout(() => finish.focus(), 50);
}

// ----------------------------------------------------------------------- Acceso de la IA: «Clientes conectados»

function aiClientsGroup(data, rerender) {
  const used = data.clients.filter((c) => c.status === 'connected' || c.last);
  const waiting = data.clients.filter((c) => c.status === 'disconnected' && !c.last);
  const others = data.others.map((o) => ({ ...o, id: '', status: 'connected' }));
  const rows = [...used, ...others];
  return el('div', { class: 'settings-group ai-clients-card' },
    el('div', { class: 'group-head' }, el('h3', { class: 'muted' }, 'Clientes conectados'),
      el('button', { class: 'btn ghost', onclick: () => openConnectAi(rerender) }, icon('plus', 'sm'), 'Conectar otra IA')),
    rows.length
      ? rows.map((c) => el('div', { class: 'access-row' },
        el('div', { class: 'ai-client-mark' }, (c.label || '?').charAt(0)),
        el('div', { class: 'meta' }, el('div', { class: 'title' }, c.label), el('div', { class: 'subtitle' }, aiClientUse(c))),
        // «Activo»: used in the last day. An app that hasn't asked for anything in a while just shows when it last did.
        c.last ? (Date.now() - new Date(c.last).getTime() < 86400000
          ? el('span', { class: 'level is-ok', title: formatTime(c.last) }, el('span', { class: 'level-dot' }), 'Activo') : null)
          : el('span', { class: 'faint small' }, 'Esperando su primera petición')))
      : el('div', { class: 'ai-clients-empty' },
        el('p', { class: 'muted small' }, waiting.length
          ? `Ninguna IA está conectada todavía. Tienes ${listJoin(waiting.map((c) => c.label))}: conéctalo con un clic.`
          : 'Ninguna IA está conectada todavía.'),
        waiting.slice(0, 3).map((c) => aiClientRow(c, rerender, { showUse: false }))));
}

function openConnectAi(onClose) {
  const body = el('div', {}, el('div', { class: 'spinner' }));
  const modal = openModal({
    title: 'Conecta tu IA',
    body: [el('p', { class: 'muted' }, 'Con un clic, la IA podrá usar tus claves a través de SecretBroker sin verlas.'), body],
    footer: [el('div', { class: 'spacer' }), el('button', { class: 'btn primary', onclick: () => modal.close() }, 'Hecho')],
    onClose: () => { if (onClose) onClose(); },
  });
  const draw = async () => {
    const data = await loadAiClients();
    body.replaceChildren(aiClientList(data, draw),
      el('div', { class: 'field', style: 'margin-top:14px' }, el('label', {}, 'Pruébalo: pega esto en tu IA'), aiTestPrompt()),
      aiFirstRequestWatcher(data));
  };
  draw();
}

// ----------------------------------------------------------------------- an empty vault: where to start

function emptyCredentials() {
  const start = (iconName, title, text, action) => el('button', { class: 'start-card', onclick: action },
    el('div', { class: 'start-icon' }, icon(iconName)),
    el('div', { class: 'meta' }, el('div', { class: 'title' }, title), el('div', { class: 'subtitle' }, text)),
    icon('chevronRight', 'sm'));
  const aiSlot = el('div', {});
  const node = el('div', { class: 'empty-start' },
    el('h2', {}, 'Empieza tu bóveda'),
    el('p', { class: 'muted' }, 'Guarda aquí tus claves de API, contraseñas y accesos: la IA podrá usarlos sin verlos.'),
    el('div', { class: 'start-list' },
      start('plus', 'Añadir una credencial', 'Una web, una API key, un servidor SSH, una base de datos… Con plantillas para OpenAI, GitHub, Stripe y más.', () => openEditor(null)),
      start('upload', 'Importar de otro gestor', 'Bitwarden, 1Password, KeePassXC, Chrome, Edge o Firefox. Ves la lista antes de importar.', openImport),
      start('terminal', 'Importar un .env de un proyecto', 'Pasa las claves de un proyecto a la bóveda con «sb import» y deja de tenerlas en claro.', openEnvImportHelp),
      aiSlot));
  loadAiClients().then((data) => {
    if (!anyAiConnected(data)) {
      aiSlot.replaceWith(start('bot', 'Conectar tu IA', 'Claude Code, Claude Desktop, Cursor, VS Code, Windsurf o Codex, con un clic.', () => openConnectAi(() => renderMain())));
    }
  });
  return node;
}

function openEnvImportHelp() {
  const command = (text) => el('div', { class: 'prompt-box' }, el('code', { class: 'prompt-text selectable' }, text),
    el('button', { class: 'btn icon-only', title: 'Copiar', onclick: async () => { await api().copy_text(text); toast('Copiado'); } }, icon('copy', 'sm')));
  const modal = openModal({
    title: 'Importar un .env de un proyecto',
    body: [
      el('p', { class: 'muted' }, 'En la carpeta del proyecto, abre una terminal y ejecuta:'),
      command('sb import .env --delete'),
      el('ol', { class: 'steps-list' },
        el('li', {}, 'SecretBroker te enseña aquí la lista de variables (solo nombres) para que la confirmes con un clic.'),
        el('li', {}, 'Guarda cada clave como una credencial y escribe un archivo ', el('code', {}, '.secretbroker'), ' sin valores, que puedes subir a git.'),
        el('li', {}, 'Con ', el('code', {}, '--delete'), ', borra el .env: las claves ya no quedan en claro en el disco.')),
      el('p', { class: 'muted' }, 'Después arranca tu app con las claves de la bóveda:'),
      command('sb run -- npm run dev'),
      el('p', { class: 'help' }, 'También puedes pedírselo a tu IA: «Pasa el .env de este proyecto a SecretBroker». Lo hace sin ver los valores.'),
    ],
    footer: [el('div', { class: 'spacer' }), el('button', { class: 'btn primary', onclick: () => modal.close() }, 'Entendido')],
  });
}
