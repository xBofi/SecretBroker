'use strict';

// Connecting the AI apps the user already has (Claude Code, Claude Desktop, Cursor, VS Code, Windsurf, Codex):
// the «Conecta tu IA» step at the end of the first run, «Clientes conectados» in Acceso de la IA, and the
// first steps of an empty vault. Loaded after app.js and built from its helpers (el, icon, openModal, toast…).
//
// api().ai_clients() → {clients: [{id, label, status: connected | disconnected | missing, last, requests}], others}
// (when each one last made a request comes from the service, which records the MCP client's name).

const AI_CLIENT_AFTER = localized(() => ({
  claude_code: t('connect_ai.open_new_claude_code_session'),
  claude_desktop: t('connect_ai.quit_claude_desktop_completely_next'),
  cursor: t('connect_ai.restart_cursor_so_sees'),
  vscode: t('connect_ai.reload_vs_code_and_use'),
  windsurf: t('connect_ai.restart_windsurf_so_sees'),
  codex: t('connect_ai.open_new_codex_session_so'),
}));
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
  if (c.last) return t('ai_client_use.last_request', { when: whenText(c.last), plural: tn('ai.requests_count', c.requests || 0) });
  return c.status === 'connected' ? t('ai_client_use.connected_no_requests_yet') : c.status === 'missing' ? t('ai_client_use.not_installed_on_this_pc') : t('ai_client_use.not_connected');
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
  const connect = el('button', { class: 'btn' }, t('common.connect'));
  connect.addEventListener('click', async () => { if (await connectAiClient(c, connect)) onChange(); });
  const connected = c.status === 'connected';
  const control = connected
    ? el('span', { class: 'level is-ok' }, icon('check', 'sm'), t('common.connected'))
    : c.status === 'missing' ? el('span', { class: 'faint small' }, t('common.not_installed')) : connect;
  return el('div', { class: `ai-client ${c.status}`, 'data-client': c.id },
    el('div', { class: 'ai-client-mark' }, (c.label || '?').charAt(0)),
    el('div', { class: 'meta' }, el('div', { class: 'title' }, c.label),
      showUse ? el('div', { class: 'subtitle' }, connected && !c.last ? AI_CLIENT_AFTER[c.id] || aiClientUse(c) : aiClientUse(c)) : null),
    control);
}

// The prompt to try it, with its own copy button.
function aiTestPrompt() {
  return el('div', { class: 'prompt-box' },
    el('div', { class: 'prompt-text selectable' }, t('connect_ai.use_secretbroker_call_list_secrets')),
    el('button', { class: 'btn', title: t('ai_test_prompt.copy_phrase'), onclick: async () => { await api().copy_text(t('connect_ai.use_secretbroker_call_list_secrets')); toast(t('ai_test_prompt.copied_paste_into_your_ai')); } },
      icon('copy', 'sm'), t('common.copy')));
}

// Waits for the next request of any AI app and says which one: «✓ Recibida de Claude Code».
function aiFirstRequestWatcher(baseline, onReceived) {
  const line = el('div', { class: 'wait-line', role: 'status' }, el('div', { class: 'spinner' }), el('span', {}, t('ai_first_request_watcher.waiting_for_first_request')));
  const total = (data) => data.clients.reduce((n, c) => n + (c.requests || 0), 0) + data.others.reduce((n, c) => n + (c.requests || 0), 0);
  const start = total(baseline);
  const timer = setInterval(async () => {
    if (!line.isConnected) { clearInterval(timer); return; }
    const data = await loadAiClients();
    if (total(data) <= start) return;
    clearInterval(timer);
    const latest = [...data.clients, ...data.others].filter((c) => c.last).sort((a, b) => (a.last < b.last ? 1 : -1))[0];
    line.classList.add('received');
    line.replaceChildren(icon('check', 'sm'), el('span', {}, t('ai_first_request_watcher.received_from', { value: latest ? latest.label : t('ai_first_request_watcher.your_ai') })),
      el('span', { class: 'faint small' }, t('ai_first_request_watcher.secretbroker_is_now_working_with')));
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
    installed.length ? null : el('p', { class: 'muted small' }, t('ai_client_list.we_didn_find_any_compatible')),
    missing.length ? el('p', { class: 'faint small ai-missing' }, t('ai_client_list.not_installed', { names: listJoin(missing.map((c) => c.label)) })) : null);
}

// ----------------------------------------------------------------------- first run: «Conecta tu IA»

// The last step of the first run, separate so it can follow any other: `box` is the setup card, `onDone` ends it,
// `progress` the setup's step marks (all lit: it is the last one).
async function renderConnectAi(box, onDone, progress) {
  box.classList.remove('centered');
  box.replaceChildren(el('div', { class: 'spinner' }));
  let data = await loadAiClients();
  const baseline = data;
  const finish = el('button', { class: 'btn primary lg' }, t('common.continue'));
  finish.addEventListener('click', onDone);
  const later = el('button', { class: 'btn ghost lg', onclick: onDone }, t('connect_ai.not_now'));
  const watcher = aiFirstRequestWatcher(baseline, () => {
    finish.textContent = t('connect_ai.start_using_secretbroker');
    later.remove();
  });
  const list = el('div', {});
  const draw = async (reload) => {
    if (reload) data = await loadAiClients();
    list.replaceChildren(aiClientList(data, () => draw(true)));
  };
  draw(false);
  box.replaceChildren(
    el('div', { class: 'auth-head' }, progress || el('div', { class: 'eyebrow' }, t('connect_ai.last_step')),
      el('h2', { style: progress ? 'margin-top:12px' : null }, t('common.connect_your_ai'))),
    el('p', { class: 'lead' }, t('connect_ai.secretbroker_works_with_ai_you')),
    list,
    el('div', { class: 'field' }, el('label', {}, t('common.try_paste_this_into_your')), aiTestPrompt()),
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
    el('div', { class: 'group-head' }, el('h3', { class: 'muted' }, t('ai_clients_group.connected_clients')),
      el('button', { class: 'btn ghost', onclick: () => openConnectAi(rerender) }, icon('plus', 'sm'), t('ai_clients_group.connect_another_ai'))),
    rows.length
      ? rows.map((c) => el('div', { class: 'access-row' },
        el('div', { class: 'ai-client-mark' }, (c.label || '?').charAt(0)),
        el('div', { class: 'meta' }, el('div', { class: 'title' }, c.label), el('div', { class: 'subtitle' }, aiClientUse(c))),
        // «Activo»: used in the last day. An app that hasn't asked for anything in a while just shows when it last did.
        c.last ? (Date.now() - new Date(c.last).getTime() < 86400000
          ? el('span', { class: 'level is-ok', title: formatTime(c.last) }, el('span', { class: 'level-dot' }), t('common.active')) : null)
          : el('span', { class: 'faint small' }, t('ai_clients_group.waiting_for_its_first_request'))))
      : el('div', { class: 'ai-clients-empty' },
        el('p', { class: 'muted small' }, waiting.length
          ? t('ai_clients_group.no_ai_is_connected_yet', { names: listJoin(waiting.map((c) => c.label)) })
          : t('ai_clients_group.no_ai_is_connected_yet_2')),
        waiting.slice(0, 3).map((c) => aiClientRow(c, rerender, { showUse: false }))));
}

function openConnectAi(onClose) {
  const body = el('div', {}, el('div', { class: 'spinner' }));
  const modal = openModal({
    title: t('common.connect_your_ai'),
    body: [el('p', { class: 'muted' }, t('open_connect_ai.with_one_click_ai_will')), body],
    footer: [el('div', { class: 'spacer' }), el('button', { class: 'btn primary', onclick: () => modal.close() }, t('common.done'))],
    onClose: () => { if (onClose) onClose(); },
  });
  const draw = async () => {
    const data = await loadAiClients();
    body.replaceChildren(aiClientList(data, draw),
      el('div', { class: 'field', style: 'margin-top:14px' }, el('label', {}, t('common.try_paste_this_into_your')), aiTestPrompt()),
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
    el('h2', {}, t('empty_credentials.start_your_vault')),
    el('p', { class: 'muted' }, t('empty_credentials.store_your_api_keys_passwords')),
    el('div', { class: 'start-list' },
      start('plus', t('empty_credentials.add_credential'), t('empty_credentials.website_api_key_ssh_server'), () => openEditor(null)),
      start('upload', t('common.import_from_another_manager'), t('empty_credentials.bitwarden_1password_keepassxc_chrome_edg'), openImport),
      start('terminal', t('common.import_project_env'), t('empty_credentials.move_project_keys_into_vault'), openEnvImportHelp),
      aiSlot));
  loadAiClients().then((data) => {
    if (!anyAiConnected(data)) {
      aiSlot.replaceWith(start('bot', t('empty_credentials.connect_your_ai'), t('empty_credentials.claude_code_claude_desktop_cursor'), () => openConnectAi(() => renderMain())));
    }
  });
  return node;
}

function openEnvImportHelp() {
  const command = (text) => el('div', { class: 'prompt-box' }, el('code', { class: 'prompt-text selectable' }, text),
    el('button', { class: 'btn icon-only', title: t('common.copy'), onclick: async () => { await api().copy_text(text); toast(t('common.copied')); } }, icon('copy', 'sm')));
  const modal = openModal({
    title: t('common.import_project_env'),
    body: [
      el('p', { class: 'muted' }, t('open_env_import_help.in_project_folder_open_terminal')),
      command('sb import .env --delete'),
      el('ol', { class: 'steps-list' },
        el('li', {}, t('open_env_import_help.secretbroker_shows_you_list_variables')),
        el('li', {}, t('open_env_import_help.saves_each_key_as_credential'), el('code', {}, '.secretbroker'), t('open_env_import_help.without_values_which_you_can')),
        el('li', {}, t('open_env_import_help.with'), el('code', {}, '--delete'), t('open_env_import_help.deletes_env_keys_no_longer'))),
      el('p', { class: 'muted' }, t('open_env_import_help.then_start_your_app_with')),
      command('sb run -- npm run dev'),
      el('p', { class: 'help' }, t('open_env_import_help.you_can_also_ask_your')),
    ],
    footer: [el('div', { class: 'spacer' }), el('button', { class: 'btn primary', onclick: () => modal.close() }, t('open_env_import_help.understood'))],
  });
}
