'use strict';

// How the app looks (Ajustes › Apariencia): theme, colour, text size, density and motion.
//
// Loaded in <head>, before the styles: what the user chose is on the root element before the first frame, so the
// app never starts in the wrong theme. The choices are the user's preferences (prefs.json, through set_pref). They
// reach the page three times: in the address the app opens it with (app.py: index.html#theme=dark&palette=…),
// in this window's own copy after a reload, and in info().prefs, which boot() applies and which wins.
//
//   <html data-theme="system|light|dark" data-scheme="light|dark" data-palette="…" data-text-size="…"
//         data-density="…" data-motion="reduce">
//
// styles.css reads only those attributes. The colours of «Personalizado» are worked out here from the one colour the
// user picked and set inline on the root element.

const APPEARANCE = {
  themes: ['system', 'light', 'dark'],
  // [id, accent in light, accent in dark]: what the picker's swatches show. The tokens themselves are in styles.css
  // (and the page background of each, for the window, in secretbroker/appearance.py).
  palettes: [
    ['grafito', '#171717', '#f2f2f2'],
    ['cobalto', '#1f5fbf', '#5b9bf0'],
    ['violeta', '#6541c9', '#a48cf2'],
    ['frambuesa', '#b3245f', '#ee7aa6'],
    ['terracota', '#b5441b', '#ec8256'],
    ['oliva', '#586b14', '#b5c95a'],
    ['salvia', '#0f766e', '#3fb8a9'],
  ],
  textSizes: ['small', 'normal', 'large', 'xlarge'],
  densities: ['comfortable', 'compact'],
  defaults: { theme: 'system', palette: 'grafito', accent: '#7a5af5', text_size: 'normal', density: 'comfortable', reduce_motion: false },
  current: null,
  mirror: 'appearance',  // localStorage: this window's copy, for a reload
};

const DARK_SCHEME = window.matchMedia('(prefers-color-scheme: dark)');

// Only values the app knows: anything else (an older version's, a hand-edited file) is the default.
function cleanAppearance(raw) {
  const given = raw || {};
  const d = APPEARANCE.defaults;
  const one = (value, allowed, fallback) => (allowed.includes(value) ? value : fallback);
  const accent = typeof given.accent === 'string' && /^#[0-9a-f]{6}$/i.test(given.accent) ? given.accent.toLowerCase() : d.accent;
  return {
    theme: one(given.theme, APPEARANCE.themes, d.theme),
    palette: one(given.palette, [...APPEARANCE.palettes.map(([id]) => id), 'custom'], d.palette),
    accent,
    text_size: one(given.text_size, APPEARANCE.textSizes, d.text_size),
    density: one(given.density, APPEARANCE.densities, d.density),
    reduce_motion: given.reduce_motion === true || given.reduce_motion === '1',
  };
}

function schemeOf(theme) {
  return theme === 'system' ? (DARK_SCHEME.matches ? 'dark' : 'light') : theme;
}

function applyAppearance(raw) {
  const prefs = cleanAppearance(raw);
  const root = document.documentElement;
  const scheme = schemeOf(prefs.theme);
  APPEARANCE.current = prefs;
  root.dataset.theme = prefs.theme;
  root.dataset.scheme = scheme;
  root.dataset.palette = prefs.palette;
  root.dataset.textSize = prefs.text_size;
  root.dataset.density = prefs.density;
  if (prefs.reduce_motion) root.dataset.motion = 'reduce';
  else delete root.dataset.motion;
  const custom = prefs.palette === 'custom' ? customTokens(prefs.accent, scheme) : {};
  for (const name of CUSTOM_TOKENS) {
    if (custom[name]) root.style.setProperty(name, custom[name]);
    else root.style.removeProperty(name);
  }
  try { localStorage.setItem(APPEARANCE.mirror, JSON.stringify(prefs)); } catch { /* a reload starts from the address */ }
  return prefs;
}

// «Sistema» follows the system while the app is open.
DARK_SCHEME.addEventListener('change', () => applyAppearance(APPEARANCE.current));

// «Reducir animaciones», or the system's own setting (styles.css stops transitions for both).
function reducedMotion() {
  return document.documentElement.dataset.motion === 'reduce' || window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}

// ----------------------------------------------------------------------- «Personalizado»: tokens from one colour

// The colour the user picked is used as it is wherever it stays legible, and moved away from the page (darker in
// the light theme, lighter in the dark one) where it would not:
//   --accent        the fill of primary buttons: at least 1.5:1 against the surfaces it sits on (a plain button's
//                   fill has less), so a white or a black one never melts into the page.
//   --accent-text   its label, at least 4.5:1 on it (WCAG AA). White in the light theme and near black in the dark
//                   one, as in the other palettes, when the fill takes it as it is or a touch darker (lighter);
//                   otherwise the other one, on the colour exactly as picked: a yellow button keeps its yellow.
//   --interactive   links and selections, which are text: at least 4.5:1 on the page, the sidebar, dialogs and on its
//                   own soft background (selected tags). A grey has no hue to tell a link by: Grafito's blue instead.
const CUSTOM_TOKENS = ['--accent', '--accent-hover', '--accent-text', '--interactive', '--interactive-hover'];
// Grafito's surfaces (styles.css): «Personalizado» keeps them neutral, so any colour sits well on them.
const CUSTOM_SURFACES = {
  light: { on: ['#fbfbfb', '#f4f4f4', '#ffffff'], soft: 0.12, interactive: '#3963ae', labels: ['#ffffff', '#111111'] },
  dark: { on: ['#161616', '#1b1b1b', '#202020'], soft: 0.16, interactive: '#8eaee6', labels: ['#111111', '#ffffff'] },
};
const TEXT_CONTRAST = 4.5;
const FILL_CONTRAST = 1.5;
const LABEL_NUDGE = 0.12;  // how far (in lightness) the fill may move to keep the theme's usual label colour

function hexToRgb(hex) {
  const n = parseInt(hex.slice(1), 16);
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
}

function rgbToHex(rgb) {
  return `#${rgb.map((c) => Math.round(Math.min(255, Math.max(0, c))).toString(16).padStart(2, '0')).join('')}`;
}

function rgbToHsl([r, g, b]) {
  r /= 255; g /= 255; b /= 255;
  const max = Math.max(r, g, b), min = Math.min(r, g, b), l = (max + min) / 2, d = max - min;
  if (!d) return [0, 0, l];
  const s = d / (1 - Math.abs(2 * l - 1));
  const h = max === r ? ((g - b) / d) % 6 : max === g ? (b - r) / d + 2 : (r - g) / d + 4;
  return [(h * 60 + 360) % 360, s, l];
}

function hslToHex([h, s, l]) {
  const c = (1 - Math.abs(2 * l - 1)) * s, x = c * (1 - Math.abs(((h / 60) % 2) - 1)), m = l - c / 2;
  const [r, g, b] = h < 60 ? [c, x, 0] : h < 120 ? [x, c, 0] : h < 180 ? [0, c, x] : h < 240 ? [0, x, c] : h < 300 ? [x, 0, c] : [c, 0, x];
  return rgbToHex([(r + m) * 255, (g + m) * 255, (b + m) * 255]);
}

// WCAG 2 relative luminance and contrast ratio.
function luminance(hex) {
  const [r, g, b] = hexToRgb(hex).map((c) => { const v = c / 255; return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function contrast(a, b) {
  const la = luminance(a), lb = luminance(b);
  return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
}

function mixHex(a, b, share) {  // `share` of a over b, as color-mix(in srgb) does
  const x = hexToRgb(a), y = hexToRgb(b);
  return rgbToHex(x.map((c, i) => c * share + y[i] * (1 - share)));
}

// The colour with its lightness moved by `step` at a time until ok(colour): null if `limit` (of lightness) is not
// enough, black or white if nothing is.
function moveUntil(hex, step, ok, limit = 1) {
  const [h, s, start] = rgbToHsl(hexToRgb(hex));
  for (let l = start; l >= 0 && l <= 1 && Math.abs(l - start) <= limit; l += step) {
    const colour = hslToHex([h, s, l]);
    if (ok(colour)) return colour;
  }
  return limit < 1 ? null : step < 0 ? '#000000' : '#ffffff';
}

function lighter(hex, amount) {
  const [h, s, l] = rgbToHsl(hexToRgb(hex));
  return hslToHex([h, s, Math.min(1, Math.max(0, l + amount))]);
}

function customTokens(hex, scheme) {
  const surface = CUSTOM_SURFACES[scheme];
  const away = scheme === 'dark' ? 0.01 : -0.01;  // away from the page
  let accent = moveUntil(hex, away, (c) => surface.on.every((s) => contrast(c, s) >= FILL_CONTRAST));
  const [usual, other] = surface.labels;
  const nudged = moveUntil(accent, away, (c) => contrast(usual, c) >= TEXT_CONTRAST, LABEL_NUDGE);
  if (nudged) accent = nudged;
  const label = nudged ? usual : [other, '#000000', '#ffffff'].find((c) => contrast(c, accent) >= TEXT_CONTRAST);
  // Hovering moves the fill away from its label, so the label only gets clearer; a fill with no room left (black,
  // white) moves the other way while the label still reads.
  const from = luminance(label) > 0.5 ? -0.07 : 0.07;
  let hover = lighter(accent, from);
  if (hover === accent || contrast(hover, accent) < 1.08) hover = lighter(accent, -from);
  if (contrast(label, hover) < TEXT_CONTRAST) hover = accent;
  const grey = rgbToHsl(hexToRgb(hex))[1] < 0.08;
  const readable = (c) => surface.on.every((s) => contrast(c, s) >= TEXT_CONTRAST && contrast(c, mixHex(c, s, surface.soft)) >= TEXT_CONTRAST);
  const interactive = moveUntil(grey ? surface.interactive : hex, away, readable);
  return {
    '--accent': accent, '--accent-hover': hover, '--accent-text': label,
    '--interactive': interactive, '--interactive-hover': lighter(interactive, away * 8),
  };
}

// ----------------------------------------------------------------------- before the first frame

(function startAppearance() {
  let known = null;
  try { known = JSON.parse(localStorage.getItem(APPEARANCE.mirror)); } catch { /* the address, then */ }
  if (!known) known = Object.fromEntries(new URLSearchParams(window.location.hash.slice(1)));
  applyAppearance(known);
}());
