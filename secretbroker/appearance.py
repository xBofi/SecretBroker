"""What the app's Python side knows about Ajustes › Apariencia: which values of those preferences exist (set_pref
stores nothing else) and how the window looks before the page has drawn anything.

The page applies the choices itself (web/appearance.js, web/styles.css). Two things can't wait for it: the colour
of the empty window, and the choices themselves, which go in the address the page is opened with so its first frame
is already right.
"""

import re
from urllib.parse import urlencode

THEMES = ("system", "light", "dark")
# The page background of each palette, light and dark: --bg in web/styles.css (tests/test_gui.py compares them).
# «custom» is the user's own colour on Grafito's surfaces.
PALETTES = {
    "grafito": ("#fbfbfb", "#161616"),
    "cobalto": ("#fbfbfc", "#15171b"),
    "violeta": ("#fbfbfd", "#17161b"),
    "frambuesa": ("#fcfbfb", "#191617"),
    "terracota": ("#fcfbf9", "#191715"),
    "oliva": ("#fbfbf9", "#171814"),
    "salvia": ("#fbfbfa", "#161917"),
    "custom": ("#fbfbfb", "#161616"),
}
TEXT_SIZES = ("small", "normal", "large", "xlarge")
DENSITIES = ("comfortable", "compact")
_COLOR = re.compile(r"#[0-9a-f]{6}")

# Preference -> whether a value may be stored for it.
RULES = {
    "theme": lambda value: value in THEMES,
    "palette": lambda value: isinstance(value, str) and value in PALETTES,
    "accent": lambda value: isinstance(value, str) and _COLOR.fullmatch(value) is not None,
    "text_size": lambda value: value in TEXT_SIZES,
    "density": lambda value: value in DENSITIES,
    "reduce_motion": lambda value: isinstance(value, bool),
}


def chosen(prefs):
    """The appearance preferences in `prefs` that hold a value the app knows (a hand-edited or older file may not)."""
    return {key: prefs[key] for key, valid in RULES.items() if key in prefs and valid(prefs[key])}


def background(prefs, system_dark):
    """The colour of the window until the page draws: the page's own background, so starting shows no flash.
    `system_dark`: whether the desktop is dark (None: unknown, taken as dark)."""
    look = chosen(prefs)
    theme = look.get("theme", "system")
    dark = system_dark is not False if theme == "system" else theme == "dark"
    return PALETTES[look.get("palette", "grafito")][1 if dark else 0]


def fragment(prefs):
    """The choices as the fragment of the page's address (read by web/appearance.js before the first frame)."""
    look = chosen(prefs)
    return urlencode({key: ("1" if value else "") if isinstance(value, bool) else value for key, value in look.items()})
