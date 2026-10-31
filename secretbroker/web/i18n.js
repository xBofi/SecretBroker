'use strict';

// ======================================================================= translations
//
// Every text the page shows comes from locales/<code>.json (es.json is the source, en.json the fallback). A message
// is a string with named placeholders («Rotar {name}»), or an object of plural forms chosen with Intl.PluralRules
// ({"one": "…", "other": "…"}, plus exact ones such as "=0"). See docs/I18N.md.

const I18N = {
  lang: 'en',
  locale: 'en',
  messages: {},
  fallback: {},
  version: 0,         // goes up on every change of language: localized() tables rebuild
  available: ['en'],  // the locale files found (app.py lists them)
};

const PLACEHOLDER = /\{(\w+)\}/g;

function lookup(key) {
  if (Object.prototype.hasOwnProperty.call(I18N.messages, key)) return I18N.messages[key];
  if (Object.prototype.hasOwnProperty.call(I18N.fallback, key)) return I18N.fallback[key];
  return null;
}

// «{{value}}» is shown as is: only {name} with a param of that name is replaced.
function fill(text, params) {
  if (!params) return text;
  return text.replace(PLACEHOLDER, (match, name, offset) => {
    if (text[offset - 1] === '{' && text[offset + match.length] === '}') return match;
    if (!Object.prototype.hasOwnProperty.call(params, name)) return match;
    const value = params[name];
    if (value === null || value === undefined) return '';
    return typeof value === 'number' ? fmtNumber(value) : String(value);
  });
}

function pluralForm(message, count) {
  if (Object.prototype.hasOwnProperty.call(message, `=${count}`)) return message[`=${count}`];
  let category = 'other';
  try { category = new Intl.PluralRules(I18N.locale).select(count); } catch { /* unknown locale */ }
  return message[category] ?? message.other ?? Object.values(message)[0] ?? '';
}

// t('lock.title') · t('detail.rotate', { name }) · a plural message takes params.count.
function t(key, params) {
  const message = lookup(key);
  if (message === null) return key;
  if (typeof message === 'object') return fill(pluralForm(message, Number(params?.count ?? 0)), params);
  return fill(message, params);
}

// tn('team.credentials', 3) → «3 credenciales». The count is also {count} in the text.
function tn(key, count, params = {}) {
  return t(key, { ...params, count });
}

function fmtNumber(n, options) {
  try { return new Intl.NumberFormat(I18N.locale, options).format(n); } catch { return String(n); }
}

function fmtDate(value, options) {
  const date = value instanceof Date ? value : new Date(value);
  try { return new Intl.DateTimeFormat(I18N.locale, options).format(date); } catch { return date.toISOString(); }
}

// «hace 5 minutos», «ayer», «en 3 días»: Intl.RelativeTimeFormat, numeric auto.
function fmtRelative(amount, unit, style = 'long') {
  try { return new Intl.RelativeTimeFormat(I18N.locale, { numeric: 'auto', style }).format(amount, unit); } catch { return `${amount} ${unit}`; }
}

// A list in the language's own way: «a, b y c», «a, b, and c».
function fmtList(items, type = 'conjunction') {
  try { return new Intl.ListFormat(I18N.locale, { style: 'long', type }).format(items.map(String)); } catch { return items.join(', '); }
}

// A label inside a sentence: «Cada día» → «cada día». Languages that capitalise nouns keep it.
function lowerFirst(text) {
  const value = String(text || '');
  if (['de', 'lb'].includes(I18N.lang.split('-')[0])) return value;
  return value.charAt(0).toLocaleLowerCase(I18N.locale) + value.slice(1);
}

function compareText(a, b) {
  return String(a).localeCompare(String(b), I18N.locale, { sensitivity: 'base' });
}

// A table of labels built with t(): rebuilt when the language changes, used like the object or array it returns.
function localized(build) {
  let cache;
  let version = -1;
  const current = () => {
    if (version !== I18N.version) { cache = build(); version = I18N.version; }
    return cache;
  };
  const sample = build();
  return new Proxy(Array.isArray(sample) ? [] : {}, {
    get(_, prop) {
      const value = current();
      const result = Reflect.get(value, prop);
      return typeof result === 'function' ? result.bind(value) : result;
    },
    has: (_, prop) => Reflect.has(current(), prop),
    ownKeys: () => Reflect.ownKeys(current()),
    getOwnPropertyDescriptor: (_, prop) => {
      const descriptor = Reflect.getOwnPropertyDescriptor(current(), prop);
      if (descriptor && prop !== 'length') descriptor.configurable = true;
      return descriptor;
    },
  });
}

// Names written out: WebView2 has no data for some languages and would name them in the system's («Gallego», «Maltés»).
const LANGUAGE_NAMES = {
  bg: 'Български', ca: 'Català', cs: 'Čeština', da: 'Dansk', de: 'Deutsch', el: 'Ελληνικά', en: 'English',
  es: 'Español', et: 'Eesti', eu: 'Euskara', fi: 'Suomi', fr: 'Français', ga: 'Gaeilge', gl: 'Galego', hr: 'Hrvatski',
  hu: 'Magyar', it: 'Italiano', lt: 'Lietuvių', lv: 'Latviešu', mt: 'Malti', nb: 'Norsk bokmål', nl: 'Nederlands',
  pl: 'Polski', pt: 'Português', ro: 'Română', ru: 'Русский', sk: 'Slovenčina', sl: 'Slovenščina', sv: 'Svenska',
  tr: 'Türkçe', uk: 'Українська', 'zh-CN': '简体中文',
};

// The language's own name, capitalised: «Deutsch», «Русский», «简体中文».
function languageName(code) {
  if (LANGUAGE_NAMES[code]) return LANGUAGE_NAMES[code];
  let name = code;
  try { name = new Intl.DisplayNames([code], { type: 'language' }).of(code) || code; } catch { /* old engine */ }
  return name.charAt(0).toLocaleUpperCase(code) + name.slice(1);
}

// Tags that mean a language we have under another code: Simplified Chinese in any of its spellings, Norwegian.
const LANGUAGE_ALIASES = { zh: 'zh-CN', 'zh-hans': 'zh-CN', 'zh-sg': 'zh-CN', 'zh-my': 'zh-CN', no: 'nb', nn: 'nb' };

// The best of the available locales for a list of wanted ones (navigator.languages): exact, then by language.
function matchLanguage(wanted, available) {
  for (const tag of wanted) {
    const lower = String(tag).toLowerCase();
    const exact = available.find((code) => code.toLowerCase() === lower);
    if (exact) return exact;
    const parts = lower.split('-');
    const traditional = /^zh-(hant|tw|hk|mo)/.test(lower);
    const alias = traditional ? null : LANGUAGE_ALIASES[parts.slice(0, 2).join('-')] || LANGUAGE_ALIASES[parts[0]];
    if (alias && available.includes(alias)) return alias;
    const base = available.find((code) => code.toLowerCase() === lower.split('-')[0]);
    if (base) return base;
  }
  return available.includes('en') ? 'en' : available[0];
}

// Loads `code` (and English as the fallback) through the app; `load(code)` returns the parsed file or null.
async function setLanguage(code, load) {
  const [messages, fallback] = await Promise.all([load(code), code === 'en' ? null : load('en')]);
  I18N.lang = messages ? code : 'en';
  I18N.messages = messages || fallback || {};
  I18N.fallback = (code === 'en' ? messages : fallback) || {};
  I18N.locale = I18N.lang;
  I18N.version += 1;
  document.documentElement.lang = I18N.lang;
  document.documentElement.dir = ['ar', 'he', 'fa', 'ur'].includes(I18N.lang.split('-')[0]) ? 'rtl' : 'ltr';
}
