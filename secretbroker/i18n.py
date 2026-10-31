"""The app's own texts in the user's language (see docs/I18N.md).

Messages live in secretbroker/locales/<code>.json: es.json is the source, en.json the fallback. A message is a text
with {named} placeholders, or an object of plural forms ({"one": …, "other": …}) chosen by params["count"]. The page
has its own files (web/locales); the languages offered are the ones it has a file for.

tr(key, **params) speaks the language of the request being answered (the app sends `lang` with every call to the
service), else the process's language (in the app, the one chosen; in the service, the last one the app used), else
Spanish, the source. Texts meant for the AI stay in English in mcp_server.py.
"""

import contextvars
import hashlib
import json
import re
import threading
import unicodedata
from pathlib import Path

LOCALES = Path(__file__).with_name("locales")
WEB_LOCALES = Path(__file__).with_name("web") / "locales"
SOURCE = "es"
FALLBACK = "en"
CODE = re.compile(r"^[a-z]{2,3}(-[A-Za-z0-9]{2,8})?$")
# Tags that mean a language we have under another code: Simplified Chinese in any of its spellings, Norwegian.
ALIASES = {"zh": "zh-CN", "zh-hans": "zh-CN", "zh-sg": "zh-CN", "zh-my": "zh-CN", "no": "nb", "nn": "nb"}
PLACEHOLDER = re.compile(r"\{(\w+)\}")

_request = contextvars.ContextVar("secretbroker_lang", default=None)
_default = [SOURCE]
_cache = {}
_lock = threading.Lock()


def available():
    """Language codes there is a page translation for (sorted)."""
    try:
        return sorted(p.stem for p in WEB_LOCALES.glob("*.json") if CODE.match(p.stem))
    except OSError:
        return [FALLBACK]


def valid(code):
    return isinstance(code, str) and bool(CODE.match(code)) and (WEB_LOCALES / f"{code}.json").is_file()


def catalog(code, folder=LOCALES):
    """The messages of one language ({} if there is no file or it is broken)."""
    if not isinstance(code, str) or not CODE.match(code):
        return {}
    path = folder / f"{code}.json"
    with _lock:
        if path not in _cache:
            try:
                _cache[path] = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                _cache[path] = {}
        return _cache[path]


def page_catalog(code):
    """The page's messages for `code` (web/locales), or None."""
    return catalog(code, WEB_LOCALES) or None if valid(code) else None


def set_default(code):
    if valid(code):
        _default[0] = code


def language():
    return _request.get() or _default[0]


class using:
    """with i18n.using(lang): … — the language of one request (ignored if unknown)."""

    def __init__(self, code):
        self.code = code if valid(code) else None
        self.token = None

    def __enter__(self):
        self.token = _request.set(self.code)
        return self

    def __exit__(self, *exc):
        _request.reset(self.token)


def plural_category(lang, n):
    """The CLDR cardinal category of a whole number in `lang` (the forms check_locales.py accepts)."""
    base = (lang or "").split("-")[0]
    n = abs(int(n))
    mod10, mod100 = n % 10, n % 100
    if base in ("zh", "ja", "ko", "vi", "th", "id", "ms"):
        return "other"
    if base in ("ru", "uk", "be"):
        return "one" if mod10 == 1 and mod100 != 11 else "few" if 2 <= mod10 <= 4 and not 12 <= mod100 <= 14 else "many"
    if base == "pl":
        return "one" if n == 1 else "few" if 2 <= mod10 <= 4 and not 12 <= mod100 <= 14 else "many"
    if base in ("cs", "sk"):
        return "one" if n == 1 else "few" if 2 <= n <= 4 else "other"
    if base in ("hr", "sr", "bs"):
        return "one" if mod10 == 1 and mod100 != 11 else "few" if 2 <= mod10 <= 4 and not 12 <= mod100 <= 14 else "other"
    if base == "lt":
        return "one" if mod10 == 1 and not 11 <= mod100 <= 19 else "few" if mod10 >= 2 and not 11 <= mod100 <= 19 else "other"
    if base == "lv":
        return "zero" if mod10 == 0 or 11 <= mod100 <= 19 else "one" if mod10 == 1 and mod100 != 11 else "other"
    if base == "ro":
        return "one" if n == 1 else "few" if n == 0 or 1 <= mod100 <= 19 else "other"
    if base == "sl":
        return {1: "one", 2: "two", 3: "few", 4: "few"}.get(mod100, "other")
    if base in ("fr", "pt"):
        return "one" if n in (0, 1) else "other"
    if base == "ga":
        return "one" if n == 1 else "two" if n == 2 else "few" if 3 <= n <= 6 else "many" if 7 <= n <= 10 else "other"
    if base == "mt":
        return ("one" if n == 1 else "two" if n == 2 else "few" if n == 0 or 3 <= mod100 <= 10
                else "many" if 11 <= mod100 <= 19 else "other")
    return "one" if n == 1 else "other"


def _fill(text, params):
    def replace(match):
        name = match.group(1)
        start, end = match.span()
        if text[start - 1:start] == "{" and text[end:end + 1] == "}":
            return match.group(0)  # «{{value}}» is shown as is
        if name not in params:
            return match.group(0)
        return "" if params[name] is None else str(params[name])
    return PLACEHOLDER.sub(replace, text)


def tr(key, **params):
    """The message `key` in the current language, with its {placeholders} filled."""
    lang = language()
    message = None
    for code in (lang, FALLBACK, SOURCE):
        message = catalog(code).get(key)
        if message is not None:
            lang = code
            break
    if message is None:
        return key
    if isinstance(message, dict):
        count = params.get("count", 0)
        exact = message.get(f"={count}")
        message = exact if exact is not None else message.get(plural_category(lang, count), message.get("other", ""))
    return _fill(message, params)


def alias(tag):
    """The code we keep `tag`'s language under, if it is spelt differently («zh-Hans-CN», «zh-SG» → «zh-CN»)."""
    lower = (tag or "").lower()
    if lower.startswith(("zh-hant", "zh-tw", "zh-hk", "zh-mo")):
        return None  # Traditional Chinese: not Simplified
    parts = lower.split("-")
    return ALIASES.get("-".join(parts[:2])) or ALIASES.get(parts[0])


def system_language():
    """The best available language for the system's own (Windows UI language, $LANG…), else English."""
    wanted = []
    try:
        import ctypes
        import locale
        lcid = ctypes.windll.kernel32.GetUserDefaultUILanguage()
        wanted.append(locale.windows_locale.get(lcid, ""))
    except Exception:
        pass
    try:
        import locale
        import os
        wanted += [os.environ.get(v, "") for v in ("LC_ALL", "LC_MESSAGES", "LANG")]
        wanted.append(locale.getlocale()[0] or "")
    except Exception:
        pass
    codes = available()
    for tag in wanted:
        tag = tag.split(".")[0].replace("_", "-")
        for code in (tag, alias(tag), tag.split("-")[0].lower()):
            if code in codes:
                return code
    return FALLBACK if FALLBACK in codes else SOURCE


# ----- texts written in Spanish in data (template labels, provider links): a message per text, keyed by it

TEXT_FIELDS = ("label", "hint", "help", "summary")


def source_key(prefix, text):
    """The message key of a Spanish text kept in data: «templates.direccion_web_1a2b3c»."""
    plain = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode().lower()
    slug = re.sub(r"[^a-z0-9]+", "_", plain).strip("_")[:32].strip("_") or "text"
    return f"{prefix}.{slug}_{hashlib.sha1(text.encode('utf-8')).hexdigest()[:6]}"


def phrase(prefix, text):
    """`text` (Spanish, from data) in the current language, if the catalog has it; else as is."""
    if not isinstance(text, str) or not text.strip():
        return text
    key = source_key(prefix, text)
    message = tr(key)
    return text if message == key else message


def localize(prefix, data, fields=TEXT_FIELDS):
    """A copy of `data` with the texts under `fields` keys in the current language."""
    if isinstance(data, list):
        return [localize(prefix, item, fields) for item in data]
    if isinstance(data, dict):
        return {k: phrase(prefix, v) if k in fields and isinstance(v, str) else localize(prefix, v, fields)
                for k, v in data.items()}
    return data
