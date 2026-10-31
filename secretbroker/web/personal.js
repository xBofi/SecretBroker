'use strict';

// Personal vault features: password generator, health, import from other managers and export.
// Loaded after app.js and built from its helpers (el, icon, openModal, withProof, state…).

// ======================================================================= generator

const GENERATOR_KEY = 'generatorOptions';
const GENERATOR_DEFAULTS = { mode: 'random', length: 20, lower: true, upper: true, digits: true, symbols: true,
  avoid_ambiguous: false, words: 5, separator: '-', capitalize: true, number: true };
const SEPARATOR_LABELS = localized(() => ([['-', t('generator.hyphen')], ['.', t('generator.period')], ['_', t('generator.underscore')], [' ', t('generator.space')], [',', t('generator.comma')], ['', t('generator.none')]]));
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
      [t('generator_panel.very_weak'), t('common.weak'), t('common.fair'), t('common.good'), t('common.excellent')][level]),
    el('span', { class: 'faint' }, t('generator_panel.characters_about_bits_randomness', { length: current.length, bits: result.result.bits })));
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
    const mode = el('div', { class: 'segmented small' }, [['random', t('generator_panel.random')], ['passphrase', t('generator_panel.passphrase')]].map(([value, label]) =>
      el('button', { type: 'button', class: options.mode === value ? 'active' : '', onclick: () => change('mode', value) }, label)));
    if (options.mode === 'random') {
      controls.replaceChildren(mode, slider('length', 12, 128, t('generator_panel.length')),
        el('div', { class: 'gen-checks' }, toggle('lower', 'a-z'), toggle('upper', 'A-Z'), toggle('digits', '0-9'),
          toggle('symbols', t('generator_panel.symbols')), toggle('avoid_ambiguous', t('generator_panel.no_look_alike_characters_il1o0'))));
    } else {
      const separator = el('select', { class: 'input', style: 'width:auto' }, SEPARATOR_LABELS.map(([value, label]) =>
        el('option', { value, selected: options.separator === value }, label)));
      separator.addEventListener('change', () => change('separator', separator.value));
      controls.replaceChildren(mode, slider('words', 3, 12, t('generator_panel.words')),
        el('div', { class: 'gen-checks' }, el('span', { class: 'muted small' }, t('generator_panel.separator')), separator,
          toggle('capitalize', t('generator_panel.capitalize_first_letter')), toggle('number', t('generator_panel.add_number'))),
        el('p', { class: 'help' }, t('generator_panel.short_words_in_spanish_and')));
    }
  }

  renderControls();
  generate();
  const node = el('div', { class: 'generator' },
    el('div', { class: 'gen-result' }, output,
      el('button', { class: 'btn icon-only', type: 'button', title: t('generator_panel.another'), onclick: generate }, icon('rotate', 'sm'))),
    meta, controls);
  return { node, value: () => current, regenerate: generate };
}

async function copyGenerated(value) {
  if (!value) return;
  const seconds = await api().copy_generated(value);
  toast(t('copy_generated.copied_cleared_in', { seconds }));
}

// Standalone generator (sidebar, Ctrl+G): for passwords that go somewhere else first.
function openGenerator() {
  const panel = generatorPanel();
  const modal = openModal({
    title: t('open_generator.password_generator'),
    body: [panel.node, el('p', { class: 'help' }, t('open_generator.generated_on_this_pc_when'))],
    footer: [el('div', { class: 'spacer' }), el('button', { class: 'btn', onclick: () => modal.close() }, t('common.close')),
      el('button', { class: 'btn primary', onclick: () => copyGenerated(panel.value()) }, icon('copy', 'sm'), t('common.copy'))],
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
      ? t('generator_buttons.generated_random_letters_and_numbers', { length: result.result.value.length }) : t('generator_buttons.generated'));
  } }, t('generator_buttons.generate'));
  const more = el('button', { class: 'btn icon-only', type: 'button', title: t('generator_buttons.generator_options'), onclick: () => {
    const panel = generatorPanel(templateId === 'database' ? { mode: 'random', symbols: false } : null);
    const modal = openModal({
      title: t('generator_buttons.generate_password'),
      body: panel.node,
      footer: [el('div', { class: 'spacer' }), el('button', { class: 'btn', onclick: () => modal.close() }, t('common.cancel')),
        el('button', { class: 'btn primary', onclick: () => { fill(panel.value(), t('generator_buttons.generated')); modal.close(); } }, t('common.use_this_one'))],
    });
  } }, icon('settings', 'sm'));
  return el('div', { class: 'gen-buttons' }, quick, more);
}

// ======================================================================= health

// The counts under the score, as plural messages: «3 débiles», «1 rotación a medias».
const HEALTH_LABELS = Object.fromEntries(['weak', 'reused', 'old', 'expired', 'expiring', 'exposed', 'pwned', 'old_alive',
  'was_exposed', 'team_access', 'upload_failed', 'half_rotated', 'retired_pending', 'unchecked'].map((kind) => [kind, `health.count_${kind}`]));
const HEALTH_DANGER = new Set(['exposed', 'pwned', 'reused', 'weak', 'expired', 'team_access', 'upload_failed']);

function healthLabel(score) {
  return score >= 90 ? t('common.excellent') : score >= 75 ? t('common.good') : score >= 50 ? t('health_label.could_be_better') : t('health_label.needs_attention');
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
  if (!canWrite(entry)) return button(t('common.open'), () => openEntry(entry));
  if (issue.kind === 'upload_failed') return button(t('common.retry_upload'), (node) => retryUploads(entry, node));
  if (issue.kind === 'half_rotated') return button(t('common.finish_rotation'), () => rotateWithHelp(entry));
  if (issue.kind === 'retired_pending' || issue.kind === 'old_alive') return button(t('health_action.revoke_old_one'), () => openEntry(entry));
  if (issue.kind === 'unchecked') return button(t('health_action.test'), (node) => checkOne(entry, node));
  if (issue.kind === 'team_access' && reminder && !reminder.can_rotate) return button(t('common.open'), () => openEntry(entry));
  return button(t('common.rotate_with_help'), () => rotateWithHelp(entry));
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
    const when = [report.scanned ? t('health_section.search', { when: whenText(report.scanned) }) : t('health_section.not_searched_for_copies'),
      report.checked ? t('health.providers_when', { when: whenText(report.checked) }) : t('health_section.not_tested_with_providers')].join(' · ');
    const missing = [report.scanned ? null : t('health_section.search_for_copies_your_keys'), report.checked ? null : t('health_section.test_them_with_their_providers')].filter(Boolean);
    const scoreClass = !known ? 'is-unknown' : report.score >= 75 ? 'is-ok' : report.score >= 50 ? 'is-warning' : 'is-exposed';
    box.replaceChildren(
      el('div', { class: 'health-head' },
        el('div', { class: `health-score ${scoreClass}`, title: known ? t('health_section.score_from_0_100') : t('health_section.no_data_yet') }, known ? String(report.score) : '—'),
        el('div', { class: 'meta' },
          el('div', { class: 'title' }, !report.total ? t('health_section.no_credentials_yet') : known ? healthLabel(report.score) : t('health_section.no_data_yet')),
          el('div', { class: 'muted small' }, !report.total ? '' : !known
            ? t(missing.length > 1 ? 'health.missing_both' : 'health.missing_one', { what: listJoin(missing) })
            : items.length ? t('health_section.credentials_without_problems', { healthy: report.healthy, total: report.total, when })
              : t('health_section.no_problems_in_what_was', { when })),
          counts.length ? el('div', { class: 'health-counts' }, counts.map(([kind, n]) =>
            el('span', { class: `chip ${HEALTH_DANGER.has(kind) ? 'is-exposed' : kind === 'unchecked' ? '' : 'is-warning'}` }, HEALTH_LABELS[kind] ? tn(HEALTH_LABELS[kind], n) : `${n} ${kind}`))) : null)),
      items.length ? el('div', { class: 'health-list' }, shown.map((item) => {
        const entry = entries[item.id];
        return el('div', { class: 'health-row' }, glyph(entry.template),
          el('div', { class: 'meta' }, el('div', { class: 'title' }, entry.name,
            item.issues.map((issue) => el('span', { class: `chip ${HEALTH_DANGER.has(issue.kind) ? 'is-exposed' : issue.kind === 'unchecked' ? '' : 'is-warning'}` }, issue.label))),
          el('div', { class: 'subtitle' }, item.issues[0].text)),
          healthAction(entry, item.issues[0], state.reminders && state.reminders[entry.id]));
      }), items.length > shown.length || showAll ? el('button', { class: 'link small', onclick: () => { showAll = !showAll; render(report); } },
        showAll ? t('health_section.see_less') : t('health_section.see_all', { length: items.length })) : null) : null);
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
  const save = el('button', { class: 'btn primary' }, t('common.i_ve_changed_save'));
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
    title: t('change_password_guided.change_password', { name: entry.name }),
    wide: true,
    body,
    footer: [foot],
    confirmClose: () => (finished ? null : pending
      ? t('change_password_guided.new_password_stays_saved_here')
      : t('common.nothing_has_been_changed_yet')),
    onClose: () => { clearTimeout(timer); loadEntries().then(renderMain); },
  });
  const finish = async (params) => {
    errorText.textContent = '';
    busy(save, true);
    const result = await withProof((p) => api().call('replace_key', { id: entry.id, ...params }, p), t('change_password_guided.save_new_password', { name: entry.name }));
    busy(save, false);
    if (!result.ok) { if (result.code !== 'cancelled') errorText.textContent = result.error; return; }
    finished = true;
    modal.close();
    toast(t('change_password_guided.new_password_saved'));
  };
  const copyPending = async () => {
    const result = await withProof((p) => api().copy_rotation_secret(entry.id, 'value', p), t('change_password_guided.copy_new_password', { name: entry.name }));
    if (result.ok) toast(t('change_password_guided.copied_cleared_from_clipboard_in', { result: result.result }));
    else if (result.code !== 'cancelled') toast(result.error, 'error');
  };

  const fresh = () => {
    const panel = generatorPanel(null, keep);
    save.onclick = () => finish(kept && kept === panel.value() ? { pending: true } : { value: panel.value() });
    body.replaceChildren(
      el('ol', { class: 'guide-steps' },
        el('li', {}, ssh ? t('change_password_guided.sign_in_and_get_ready', { site })
          : t('change_password_guided.open_and_go_page_change', { site }),
        !ssh && /^https:\/\//i.test(url) ? [' ', el('button', { class: 'link', onclick: () => api().open_link(url) }, t('change_password_guided.open', { host: hostOf(url) }))] : null),
        el('li', {}, t('change_password_guided.copy_this_new_password_and')),
        el('li', {}, t('change_password_guided.once_accepted_save_here'), ssh ? t('change_password_guided.app_checks_that_can_sign') : '')),
      panel.node,
      el('div', { style: 'display:flex;gap:8px' }, el('button', { class: 'btn', onclick: () => { keep(panel.value()); copyGenerated(panel.value()); } }, icon('copy', 'sm'), t('common.copy'))),
      el('p', { class: 'help' }, t('change_password_guided.while_you_change_saved_here')),
      (entry.used_in || []).length ? el('p', { class: 'help' }, t('change_password_guided.then_change_in_these_places', { value: entry.used_in.join('; ') })) : null,
      errorText);
    foot.replaceChildren(el('div', { class: 'spacer' }), el('button', { class: 'btn', onclick: () => modal.close() }, t('common.cancel')), save);
  };

  // Halfway: a new password was prepared and not saved. Was it set on the site?
  const resume = () => {
    save.onclick = () => finish({ pending: true });
    save.textContent = t('common.yes_i_changed_save');
    body.replaceChildren(
      el('h3', {}, t('common.rotation_half_done_did_you')),
      el('p', { class: 'muted' }, t('change_password_guided.new_password_was_prepared_for', { capitalized: capitalized(atText(pending.since)), site })
        + t('change_password_guided.if_you_already_put_there')),
      el('div', { class: 'prop' }, el('div', { style: 'min-width:0' }, el('div', { class: 'k' }, t('common.new_password')), el('div', { class: 'v secret' }, '••••••••••••')),
        el('div', { class: 'actions' }, el('button', { class: 'btn icon-only', title: t('common.copy'), onclick: copyPending }, icon('copy', 'sm')))),
      errorText);
    foot.replaceChildren(el('div', { class: 'spacer' }), el('button', { class: 'btn', onclick: async () => {
      const result = await withProof((p) => api().call('rotation_discard', { id: entry.id }, p), t('common.discard_new_one', { name: entry.name }));
      if (!result.ok) { if (result.code !== 'cancelled') errorText.textContent = result.error; return; }
      pending = null;
      save.textContent = t('common.i_ve_changed_save');
      fresh();
    } }, t('common.no_discard')), save);
  };
  if (pending) resume();
  else fresh();
}

// ======================================================================= import

const IMPORT_STATUS = localized(() => ({ new: [t('common.new'), 'is-ok'], duplicate: [t('import.already_in'), ''], conflict: [t('import.different_password'), 'is-warning'] }));
const IMPORT_BATCH = 100;  // credentials per call: the vault is saved once per batch, and the progress moves
// Where each manager keeps its export, menu by menu (the file format is detected from its content).
const IMPORT_SOURCES = localized(() => ([
  ['bitwarden', t('import_source.bitwarden'), [
    [t('import_source.on_web_or_in_desktop'), el('b', {}, t('import_source.tools_export_vault')), t('import_source.in_app'), el('b', {}, t('import_source.file_export_vault')), ').'],
    [t('import_source.file_format'), el('b', {}, '.json'), t('import_source.not_json_encrypted_csv_works')],
    [t('import_source.type_your_bitwarden_master_password')]]],
  ['onepassword', '1Password', [
    [t('import_source.in_1password_8_desktop_app'), el('b', {}, t('import_source.file_export')), t('import_source.and_choose_your_account')],
    [t('import_source.type_your_1password_password_and'), el('b', {}, 'CSV'), t('import_source.1pux_format_can_be_read')],
    [t('import_source.save_file')]]],
  ['keepass', t('import_source.keepassxc_keepass'), [
    [t('import_source.keepassxc'), el('b', {}, t('import_source.database_export_export_csv')), '.'],
    [t('import_source.keepass_2'), el('b', {}, t('import_source.file_export_keepass_csv_1')), '.'],
    [t('import_source.keepassxc_2fa_codes_totp_column')]]],
  ['chrome', t('import_source.chrome_edge'), [
    [t('import_source.chrome'), el('b', {}, t('import_source.settings_autofill_and_passwords_google')), '.'],
    [t('import_source.edge'), el('b', {}, t('import_source.settings_profiles_passwords_more_actions')), '.'],
    [t('import_source.windows_will_ask_for_your')]]],
  ['firefox', t('import_source.firefox'), [
    [t('import_source.menu'), el('b', {}, t('import_source.passwords')), t('import_source.or_type'), el('code', {}, 'about:logins'), t('import_source.in_address_bar')],
    [t('import_source.in'), el('b', {}, '…'), t('import_source.menu_at_top_right'), el('b', {}, t('import_source.export_passwords')), '.'],
    [t('import_source.confirm_with_your_windows_password')]]],
  ['secretbroker', t('common.secretbroker'), [
    [t('import_source.on_other_pc'), el('b', {}, t('import_source.credentials_export_encrypted')), '.'],
    [t('import_source.here_will_ask_for_password')]]],
]));
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
  const pick = el('button', { class: 'btn primary' }, icon('upload', 'sm'), t('open_import.choose_file'));
  const modal = openModal({
    title: t('common.import_from_another_manager'),
    wide: true,
    body: [
      el('p', { class: 'muted' }, t('open_import.export_your_data_from_other')),
      tabs, steps,
      el('p', { class: 'help' }, t('open_import.project_keys_in_env'),
        el('button', { class: 'link', type: 'button', onclick: () => { modal.close(); openEnvImport(); } }, t('open_import.import_it_here')), '.'),
    ],
    footer: [el('div', { class: 'spacer' }), el('button', { class: 'btn', onclick: () => modal.close() }, t('common.cancel')), pick],
  });
  pick.addEventListener('click', async () => {
    const path = await api().pick_import_file();
    if (!path) return;
    modal.close();
    previewImport(path, null);
  });
}

async function previewImport(path, password) {
  const result = await withProof((p) => api().import_file(path, 'auto', null, password, p), t('common.import_credentials'));
  if (result.code === 'password_required' || result.code === 'wrong_password') { askFilePassword(path, result.code === 'wrong_password' ? result.error : ''); return; }
  if (!result.ok) { if (result.code !== 'cancelled') toast(result.error, 'error'); return; }
  showImportPreview(path, password, result.result);
}

function askFilePassword(path, error) {
  const pw = passwordInput({ autocomplete: 'off' });
  const go = () => { modal.close(); previewImport(path, pw.input.value); };
  pw.input.addEventListener('keydown', (event) => { if (event.key === 'Enter') go(); });
  const modal = openModal({
    title: t('ask_file_password.encrypted_export'),
    body: [el('p', { class: 'muted' }, t('ask_file_password.type_password_you_chose_when')), el('div', { class: 'field' }, pw),
      el('div', { class: 'error-text' }, error || '')],
    footer: [el('div', { class: 'spacer' }), el('button', { class: 'btn', onclick: () => modal.close() }, t('common.cancel')),
      el('button', { class: 'btn primary', onclick: go }, t('common.open'))],
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
    button.textContent = chosen.size ? t('show_import_preview.import', { size: chosen.size }) : t('common.import');
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
        el('div', { class: 'subtitle' }, [item.subtitle, item.tags.join(', '), item.totp ? t('show_import_preview.with_2fa_code') : '',
          item.notes ? t('show_import_preview.with_private_notes') : '', item.reason].filter(Boolean).join(' · '))),
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
    title: t('show_import_preview.import_from', { label: preview.label }),
    wide: true,
    body: [
      el('p', { class: 'muted' }, tn('import.in_file', preview.items.length),
        counts.map(([s, n]) => tn(`import.count_${s}`, n)).join(', '),
        t('show_import_preview.you_only_see_names_values')),
      devCount && devCount < preview.items.length ? el('label', { class: 'check-row dev-filter' }, devToggle,
        el('span', {}, t('show_import_preview.only_developer_keys_api_keys'), el('span', { class: 'faint' }, ` · ${devCount}`))) : null,
      preview.items.length ? el('label', { class: 'check-row', style: 'margin:4px 0' }, all, t('show_import_preview.select_all')) : null,
      list,
      preview.skipped.length ? el('details', { class: 'findings' },
        el('summary', {}, tn('import.skipped_summary', preview.skipped.length)),
        preview.skipped.map((s) => el('div', { class: 'small muted' }, `${s.name}: ${s.reason}`))) : null,
      el('p', { class: 'help' }, t('show_import_preview.websites_2fa_codes_go_into'),
        t('show_import_preview.ai_permissions_come_from_template')),
    ],
    footer: [el('div', { class: 'spacer' }), el('button', { class: 'btn', onclick: () => modal.close() }, t('common.cancel')), button],
  });
  button.addEventListener('click', () => {
    modal.close();
    runImport(path, password, preview, preview.items.filter((i) => chosen.has(i.key)).map((i) => i.key));
  });
}

// Step 3: in batches, with «312 de 1000», then an honest summary.
async function runImport(path, password, preview, keys) {
  const bar = el('span', { style: 'width:0%' });
  const count = el('div', { class: 'import-count' }, t('approval.position', { position: 0, total: keys.length }));
  const modal = openModal({
    title: t('run_import.importing_from', { label: preview.label }),
    body: [count, el('div', { class: 'progress import-progress' }, bar),
      el('p', { class: 'help' }, t('run_import.they_re_saved_encrypted_as'))],
    footer: null,
    confirmClose: () => t('run_import.import_keeps_going_if_you'),
  });
  const created = [];
  const failed = [];
  let stopped = null;
  for (let start = 0; start < keys.length; start += IMPORT_BATCH) {
    const part = keys.slice(start, start + IMPORT_BATCH);
    const last = start + IMPORT_BATCH >= keys.length;
    const result = preview.import_id
      ? await withProof((p) => api().import_batch(preview.import_id, part, last, p), t('common.import_credentials'))
      : await withProof((p) => api().import_file(path, preview.format, part, password, p), t('common.import_credentials'));
    if (!result.ok) { stopped = result; break; }
    created.push(...result.result.created);
    failed.push(...result.result.failed);
    const done = Math.min(start + IMPORT_BATCH, keys.length);
    count.textContent = t('approval.position', { position: done, total: keys.length });
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
    unpicked('duplicate') ? t('import_done.were_already_in_vault', { unpicked: unpicked('duplicate') }) : null,
    unpicked('conflict') ? t('import_done.with_different_password_you_didn', { unpicked: unpicked('conflict') }) : null,
    unpicked('new') ? t('import_done.you_left_unticked', { unpicked: unpicked('new') }) : null,
    ...Object.entries(preview.skipped.reduce((acc, s) => ({ ...acc, [s.reason]: (acc[s.reason] || 0) + 1 }), {}))
      .map(([reason, n]) => `${n} · ${reason}`),
  ].filter(Boolean);
  const skippedTotal = notImported.length + preview.skipped.length;
  const remove = el('button', { class: 'btn solid-danger' }, icon('trash', 'sm'), t('import_done.delete_file'));
  const stat = (n, label, cls) => el('div', { class: `import-stat ${n ? cls : ''}` }, el('div', { class: 'n' }, String(n)), el('div', { class: 'label' }, label));
  const modal = openModal({
    title: result.stopped ? t('import_done.import_interrupted')
      : tn('import.imported', result.created.length),
    body: [
      el('div', { class: 'import-stats' },
        stat(result.created.length, t('import.stat_created', { count: result.created.length }), 'is-ok'),
        stat(skippedTotal, t('import.stat_skipped', { count: skippedTotal }), ''),
        stat(result.failed.length, t('import.stat_failed', { count: result.failed.length }), 'is-danger')),
      result.stopped ? el('div', { class: 'warning is-danger' }, icon('alert', 'sm'), el('span', {},
        t('import_done.stopped_at_ones_already_done', { count: result.created.length + result.failed.length, count2: (result.keys || []).length, error: result.stopped.error }))) : null,
      skippedLines.length ? el('details', { class: 'findings' }, el('summary', {}, t('import_done.skipped')),
        skippedLines.map((line) => el('div', { class: 'small muted' }, line))) : null,
      result.failed.length ? el('details', { class: 'findings', open: true }, el('summary', {}, t('import_done.with_errors')),
        result.failed.map((f) => el('div', { class: 'small error-text' }, `${f.name}: ${f.reason}`))) : null,
      own ? el('p', { class: 'muted' }, t('import_done.file_is_encrypted_you_can'))
        : el('div', { class: 'warning' }, icon('alert', 'sm'), el('span', {},
          el('b', {}, t('import_done.has_all_your_passwords_unencrypted', { name })),
          t('import_done.any_program_or_person_who'))),
      el('p', { class: 'help' }, t('import_done.now_take_look_at_health')),
    ],
    footer: [
      el('button', { class: 'btn', onclick: () => { modal.close(); state.view = 'exposure'; renderMain(); } }, t('import_done.see_health')),
      el('div', { class: 'spacer' }),
      el('button', { class: 'btn', onclick: () => modal.close() }, own ? t('import_done.keep') : t('import_done.i_ll_delete_myself')),
      remove,
    ],
  });
  remove.addEventListener('click', async () => {
    const deleted = await api().delete_import_source();
    if (!deleted.ok) { toast(deleted.error, 'error'); return; }
    modal.close();
    toast(t('import_done.file_deleted'));
  });
}

// «…» next to «Nueva»: import and export, labelled.
function importExportMenu() {
  const menu = el('div', { class: 'menu hidden', role: 'menu' },
    el('button', { class: 'menu-item', role: 'menuitem', type: 'button', onclick: () => { close(); openImport(); } }, icon('upload', 'sm'), t('common.import_2')),
    el('button', { class: 'menu-item', role: 'menuitem', type: 'button', onclick: () => { close(); openEnvImport(); } }, icon('file', 'sm'), t('common.import_project_env')),
    el('button', { class: 'menu-item', role: 'menuitem', type: 'button', onclick: () => { close(); openExport(); } }, icon('download', 'sm'), t('common.export')));
  const button = el('button', { class: 'btn icon-only', type: 'button', title: t('import_export_menu.more_import_and_export'), 'aria-label': t('import_export_menu.more_actions'), 'aria-haspopup': 'menu' }, icon('more', 'sm'));
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
  const ring = el('span', { class: 'totp-ring', title: t('totp_prop.seconds_until_next_code') });
  ring.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9" class="track"/></svg>';
  ring.firstChild.append(arc);
  const seconds = el('span', { class: 'totp-seconds' });
  ring.append(seconds);
  let shown = false;
  let remaining = 0;
  let period = 30;
  let timer = null;
  const reveal = el('button', { class: 'btn icon-only', title: t('totp_prop.show_code') }, icon('eye', 'sm'));
  const copy = el('button', { class: 'btn icon-only', title: t('totp_prop.copy_code') }, icon('copy', 'sm'));
  const node = el('div', { class: 'prop totp-prop' },
    el('div', { style: 'min-width:0' }, el('div', { class: 'k' }, shortLabel(spec.label)),
      el('div', { class: 'totp-line' }, ring, digits)),
    el('div', { class: 'actions' }, reveal, copy));
  const draw = (code) => {
    digits.textContent = code ? `${code.slice(0, Math.ceil(code.length / 2))} ${code.slice(Math.ceil(code.length / 2))}` : '••• •••';
    digits.className = `v totp-code ${code ? 'revealed selectable' : 'secret'}`;
    reveal.title = code ? t('totp_prop.hide_code') : t('totp_prop.show_code');
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
      : await withProof((p) => api().totp_code(entry.id, false, false, p), t('totp_prop.see_2fa_code', { name: entry.name }));
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
    const result = await withProof((p) => api().totp_code(entry.id, true, false, p), t('totp_prop.copy_2fa_code', { name: entry.name }));
    if (result.ok) toast(t('totp_prop.2fa_code_copied_valid_for', { remaining: result.result.remaining }));
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
  const button = el('button', { class: 'btn primary' }, t('common.export'));
  const details = el('div', {});
  const tabs = el('div', { class: 'segmented' });
  const render = () => {
    tabs.replaceChildren([['encrypted', t('open_export.encrypted')], ['json', t('open_export.unencrypted_json')], ['csv', t('open_export.unencrypted_csv')]].map(([value, label]) =>
      el('button', { type: 'button', class: format === value ? 'active' : '', onclick: () => { format = value; errorText.textContent = ''; render(); } }, label)));
    details.replaceChildren(format === 'encrypted'
      ? [el('p', { class: 'muted' }, t('open_export.all_credentials_with_their_notes'),
        t('open_export.use_take_them_another_pc')),
      el('div', { class: 'field' }, el('label', {}, t('open_export.file_password')), pw, strengthMeter(pw.input)),
      el('div', { class: 'field' }, el('label', {}, t('common.repeat')), confirm),
      el('p', { class: 'help' }, t('open_export.if_you_forget_file_can'))]
      : [el('div', { class: 'warning' }, icon('alert', 'sm'), el('span', {}, el('b', {}, t('open_export.file_will_have_all_your')),
        format === 'csv' ? t('open_export.csv_name_website_username_password')
          : t('open_export.json_has_everything_in_plain'))),
      el('label', { class: 'check-row', style: 'margin-top:10px' }, understood, t('open_export.i_understand_i_ll_import'))]);
  };
  render();
  const modal = openModal({
    title: t('open_export.export_vault'),
    body: [tabs, details, errorText],
    footer: [el('div', { class: 'spacer' }), el('button', { class: 'btn', onclick: () => modal.close() }, t('common.cancel')), button],
  });
  button.addEventListener('click', async () => {
    errorText.textContent = '';
    if (format === 'encrypted') {
      if (pw.input.value.length < 12) { errorText.textContent = t('open_export.file_password_needs_at_least'); return; }
      if (pw.input.value !== confirm.input.value) { errorText.textContent = t('common.two_passwords_don_match'); return; }
    } else if (!understood.checked) { errorText.textContent = t('open_export.tick_box_export_unencrypted'); return; }
    busy(button, true);
    const result = await withProof((p) => api().export_vault(format, format === 'encrypted' ? pw.input.value : null, p), t('open_export.export_vault_2'));
    busy(button, false);
    if (!result.ok) { if (result.code !== 'cancelled') errorText.textContent = result.error; return; }
    modal.close();
    toast(tn('open_export.exported_to', result.result.entries, { path: result.result.path }));
  });
}

function importExportGroup() {
  return el('div', { class: 'settings-group' }, el('h3', { class: 'muted' }, t('import_export_group.import_and_export')),
    setting(t('common.import_from_another_manager'), t('import_export_group.bitwarden_1password_keepass_keepassxc_ch'),
      el('button', { class: 'btn', onclick: openImport }, icon('upload', 'sm'), t('common.import_2'))),
    setting(t('import_export_group.export'), t('import_export_group.encrypted_file_for_another_pc'),
      el('button', { class: 'btn', onclick: openExport }, icon('download', 'sm'), t('common.export'))));
}
