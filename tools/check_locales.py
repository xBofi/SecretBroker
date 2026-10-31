"""Check SecretBroker's translations against English (see docs/I18N.md).

    python tools/check_locales.py          every language found
    python tools/check_locales.py de fr    only these

For each catalog (the app's page, the app's Python texts, the browser extension) a language must have exactly the
keys of English, the same placeholders, valid plural forms for that language and no empty texts. It also checks that
every key the page's code names exists in English. Exit code 1 if anything is wrong.
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WEB = ROOT / "secretbroker" / "web"
CATALOGS = (
    ("page", WEB / "locales"),
    ("app", ROOT / "secretbroker" / "locales"),
)
EXTENSION = ROOT / "extension" / "_locales"

# CLDR cardinal plural categories (https://www.unicode.org/cldr/charts/latest/supplemental/language_plural_rules.html).
# A language not listed may use any of them; "other" is always required.
CATEGORIES = ("zero", "one", "two", "few", "many", "other")
PLURALS = {
    **{code: ("one", "other") for code in "en de nl sv da nb nn no fi et el hu bg sq eu gl is tr ka lb mk az hy kk".split()},
    **{code: ("one", "many", "other") for code in "es fr it pt ca".split()},
    **{code: ("one", "few", "many", "other") for code in "ru uk be pl lt cs sk".split()},
    **{code: ("one", "few", "other") for code in "hr sr bs ro".split()},
    "sl": ("one", "two", "few", "other"),
    "lv": ("zero", "one", "other"),
    "he": ("one", "two", "other"),
    "mt": ("one", "two", "few", "many", "other"),
    "ga": ("one", "two", "few", "many", "other"),
    "cy": CATEGORIES,
    "ar": CATEGORIES,
    **{code: ("other",) for code in "zh ja ko vi th id ms".split()},
}
# Forms only used for huge round numbers («1 millón de…»): «other» is fine there, no warning.
RARE = {code: ("many",) for code in "es fr it pt ca".split()}
PLACEHOLDER = re.compile(r"(?<!\{)\{(\w+)\}(?!\})")
EXT_PLACEHOLDER = re.compile(r"\$(\w+)\$")
CODE_KEY = re.compile(r"\btn?\('([a-z0-9_]+(?:\.[a-z0-9_]+)+)'")


def placeholders(value):
    texts = value.values() if isinstance(value, dict) else [value]
    return set().union(*(set(PLACEHOLDER.findall(t)) for t in texts if isinstance(t, str)))


def check_message(lang, key, ref, value):
    """Problems with one message (a list of strings)."""
    problems = []
    if isinstance(ref, dict) != isinstance(value, dict):
        kind = "plural forms (an object)" if isinstance(ref, dict) else "a plain text"
        return [f"{key}: must be {kind}, like English"]
    if isinstance(value, dict):
        allowed = PLURALS.get(lang.split("-")[0].lower(), CATEGORIES)
        for form, text in value.items():
            if not (form in allowed or re.fullmatch(r"=\d+", form)):
                problems.append(f"{key}: plural form «{form}» does not exist in this language (use {', '.join(allowed)})")
            if not isinstance(text, str) or not text.strip():
                problems.append(f"{key}.{form}: empty")
        if "other" not in value:
            problems.append(f"{key}: the «other» plural form is missing")
        rare = RARE.get(lang.split("-")[0].lower(), ())
        missing = [f for f in allowed if f not in value and f != "other" and f not in rare]
        if missing and "other" in value:
            problems.append(f"warning: {key}: no «{'», «'.join(missing)}» form; «other» is used for those numbers")
    elif not isinstance(value, str) or not value.strip():
        if not (isinstance(ref, str) and not ref.strip()):
            problems.append(f"{key}: empty")
    if isinstance(ref, str) and isinstance(value, str) and value.strip() and (
            ref[:1].isspace() != value[:1].isspace() or ref[-1:].isspace() != value[-1:].isspace()):
        problems.append(f"{key}: keep the space at the start or end like English (it joins this text to the next)")
    want, got = placeholders(ref), placeholders(value)
    if want != got:
        extra, lost = sorted(got - want), sorted(want - got)
        problems.append(f"{key}: placeholders differ from English"
                        + (f"; missing {{{'}, {'.join(lost)}}}" if lost else "") + (f"; unknown {{{'}, {'.join(extra)}}}" if extra else ""))
    return problems


def load(path):
    try:
        return json.loads(path.read_text(encoding="utf-8")), None
    except (OSError, ValueError) as exc:
        return None, f"cannot read {path.relative_to(ROOT)}: {exc}"


def check_catalog(name, folder, langs):
    """{lang: [problems]} for one folder of <lang>.json files."""
    english, error = load(folder / "en.json")
    if error:
        return {"en": [error]}
    report = {}
    for path in sorted(folder.glob("*.json")):
        lang = path.stem
        if lang == "en" or (langs and lang not in langs):
            continue
        data, error = load(path)
        if error:
            report[lang] = [error]
            continue
        problems = [f"{key}: missing" for key in english if key not in data]
        problems += [f"{key}: not in English (remove it)" for key in data if key not in english]
        for key, ref in english.items():
            if key in data:
                problems += check_message(lang, key, ref, data[key])
        report[lang] = problems
    return report


def check_extension(langs):
    english, error = load(EXTENSION / "en" / "messages.json")
    if error:
        return {"en": [error]}
    report = {}
    for folder in sorted(p for p in EXTENSION.iterdir() if p.is_dir()):
        lang = folder.name.replace("_", "-")
        if folder.name == "en" or (langs and lang not in langs and folder.name not in langs):
            continue
        data, error = load(folder / "messages.json")
        if error:
            report[lang] = [error]
            continue
        problems = [f"{key}: missing" for key in english if key not in data]
        problems += [f"{key}: not in English (remove it)" for key in data if key not in english]
        for key, ref in english.items():
            if key not in data:
                continue
            message = (data[key] or {}).get("message", "")
            if not message.strip():
                problems.append(f"{key}: empty")
            if set(EXT_PLACEHOLDER.findall(message)) != set(EXT_PLACEHOLDER.findall(ref["message"])):
                problems.append(f"{key}: $placeholders$ differ from English")
            if set((data[key].get("placeholders") or {})) != set((ref.get("placeholders") or {})):
                problems.append(f"{key}: the «placeholders» block differs from English (copy it as is)")
        report[lang] = problems
    return report


def check_code():
    """Keys named in the page's code (t('…') / tn('…')) that English lacks."""
    english, error = load(WEB / "locales" / "en.json")
    if error:
        return [error]
    problems = []
    for path in sorted(p for p in WEB.glob("*.js") if p.name != "i18n.js"):  # i18n.js only names examples
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            for key in CODE_KEY.findall(line):
                if key not in english:
                    problems.append(f"{path.name}:{number}: «{key}» is not in locales/en.json")
    return problems


# On macOS the page swaps «Windows Hello (PIN, …)» and «your PIN, …» for Touch ID's wording (app.js, osText): these
# texts must contain the os.* phrases word for word, or the Mac would show Windows Hello's.
TOUCH_ID_PHRASES = (
    ("setup.windows_hello_pin_fingerprint_or", "Windows Hello ({os.hello_means})"),
    ("settings.unlock_and_show_passwords_with", "{os.your_hello_means}"),
)


def check_touch_id(langs):
    report = {}
    for path in sorted((WEB / "locales").glob("*.json")):
        lang = path.stem
        if langs and lang not in langs and lang != "en":
            continue
        data, error = load(path)
        if error:
            continue
        problems = []
        for key, pattern in TOUCH_ID_PHRASES:
            phrase = re.sub(r"\{(os\.\w+)\}", lambda m: str(data.get(m.group(1), m.group(0))), pattern)
            if key in data and phrase not in str(data[key]):
                problems.append(f"{key}: must contain «{phrase}» exactly as written (macOS replaces it with Touch ID's)")
        report[lang] = problems
    return report


def main(argv):
    langs = set(argv)
    failed = False
    sections = [(name, check_catalog(name, folder, langs)) for name, folder in CATALOGS if folder.is_dir()]
    if EXTENSION.is_dir():
        sections.append(("extension", check_extension(langs)))
    sections.append(("touch id", check_touch_id(langs)))
    for name, report in sections:
        for lang, problems in sorted(report.items()):
            errors = [p for p in problems if not p.startswith("warning:")]
            warnings = [p for p in problems if p.startswith("warning:")]
            state = "OK" if not errors else f"{len(errors)} problem(s)"
            print(f"[{name}] {lang}: {state}" + (f", {len(warnings)} warning(s)" if warnings else ""))
            for problem in errors + warnings:
                print(f"    {problem}")
            failed |= bool(errors)
    code = check_code()
    print(f"[code] keys used by the page: {'OK' if not code else f'{len(code)} missing'}")
    for problem in code:
        print(f"    {problem}")
    failed |= bool(code)
    print("FAILED" if failed else "All translations are consistent.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
