"""Write the Windows installer's languages: installer/SecretBroker.iss includes the result (see docs/I18N.md).

    python tools/installer_languages.py [output]     default: build/installer/languages.iss

One [Languages] entry for every language the app speaks (secretbroker/locales/<code>.json), with Inno Setup's own
translation of its wizard (compiler:Languages\\…) or ours (installer/languages/), and our texts, the installer.*
messages of those same files, as [Messages] and [CustomMessages]. tools/build_installer.ps1 runs it before compiling;
tools/check_locales.py runs problems().
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LOCALES = ROOT / "secretbroker" / "locales"
INSTALLER = ROOT / "installer"
DEFAULT_OUTPUT = ROOT / "build" / "installer" / "languages.iss"

# App language: Inno Setup messages file. «compiler:» files ship with Inno Setup 6; the others are in
# installer/languages (installer/languages/README.md says where each one comes from). English goes first: Setup uses
# the first language when none matches the system's.
MESSAGES_FILES = {
    "en": "compiler:Default.isl",
    "bg": "compiler:Languages\\Bulgarian.isl",
    "ca": "compiler:Languages\\Catalan.isl",
    "cs": "compiler:Languages\\Czech.isl",
    "da": "compiler:Languages\\Danish.isl",
    "de": "compiler:Languages\\German.isl",
    "el": "languages\\Greek.isl",
    "es": "compiler:Languages\\Spanish.isl",
    "et": "languages\\Estonian.isl",
    "eu": "languages\\Basque.isl",
    "fi": "compiler:Languages\\Finnish.isl",
    "fr": "compiler:Languages\\French.isl",
    "ga": "languages\\Irish.isl",
    "gl": "languages\\Galician.isl",
    "hr": "languages\\Croatian.isl",
    "hu": "compiler:Languages\\Hungarian.isl",
    "it": "compiler:Languages\\Italian.isl",
    "lt": "languages\\Lithuanian.isl",
    "lv": "languages\\Latvian.isl",
    "mt": "languages\\Maltese.isl",
    "nb": "compiler:Languages\\Norwegian.isl",
    "nl": "compiler:Languages\\Dutch.isl",
    "pl": "compiler:Languages\\Polish.isl",
    "pt": "compiler:Languages\\Portuguese.isl",
    "ro": "languages\\Romanian.isl",
    "ru": "compiler:Languages\\Russian.isl",
    "sk": "compiler:Languages\\Slovak.isl",
    "sl": "compiler:Languages\\Slovenian.isl",
    "sv": "compiler:Languages\\Swedish.isl",
    "tr": "compiler:Languages\\Turkish.isl",
    "uk": "compiler:Languages\\Ukrainian.isl",
    "zh-CN": "languages\\ChineseSimplified.isl",
}

# installer.<key> in the locale files: (section, Inno Setup name). The script uses them as {cm:Name} and
# CustomMessage('Name'); WelcomeLabel2 replaces the wizard's own welcome text.
MESSAGES = {
    "installer.welcome": ("Messages", "WelcomeLabel2"),
    "installer.desktop_icon": ("CustomMessages", "DesktopIcon"),
    "installer.app_comment": ("CustomMessages", "AppComment"),
    "installer.open_app": ("CustomMessages", "OpenApp"),
    "installer.owner_unknown": ("CustomMessages", "OwnerUnknown"),
    "installer.configuring_service": ("CustomMessages", "ConfiguringService"),
    "installer.service_failed": ("CustomMessages", "ServiceFailed"),
    "installer.details": ("CustomMessages", "Details"),
    "installer.connecting_claude": ("CustomMessages", "ConnectingClaude"),
    "installer.remove_vault": ("CustomMessages", "RemoveVault"),
    "installer.remove_failed": ("CustomMessages", "RemoveFailed"),
}
# Our placeholders, as Inno Setup writes them: [name/ver] is replaced by Setup, %1 by FmtMessage in the script.
PLACEHOLDERS = {"name_version": "[name/ver]", "folder": "%1"}
PLACEHOLDER = re.compile(r"\{(\w+)\}")


def inno_name(code):
    """The [Languages] name of an app language: zh-CN → zh_CN (the script turns it back for the app)."""
    return code.replace("-", "_")


def inno_text(text):
    """A message as Inno Setup reads it: one line, %n for line breaks, its placeholders."""
    return PLACEHOLDER.sub(lambda m: PLACEHOLDERS[m.group(1)], text.replace("\r\n", "\n")).replace("\n", "%n")


def _catalogs():
    return {p.stem: json.loads(p.read_text(encoding="utf-8")) for p in sorted(LOCALES.glob("*.json"))}


def problems(catalogs=None):
    """What would make the installer miss a language or show a broken text (a list of strings, empty if none)."""
    catalogs = _catalogs() if catalogs is None else catalogs
    found = []
    for code in sorted(set(catalogs) - set(MESSAGES_FILES)):
        found.append(f"{code}: the app speaks it but the installer doesn't (add it to MESSAGES_FILES in tools/installer_languages.py)")
    for code in sorted(set(MESSAGES_FILES) - set(catalogs)):
        found.append(f"{code}: in tools/installer_languages.py but there is no secretbroker/locales/{code}.json")
    for code, path in MESSAGES_FILES.items():
        if not path.startswith("compiler:") and not (INSTALLER / path.replace("\\", "/")).is_file():
            found.append(f"{code}: installer/{path} doesn't exist")
    for code, catalog in catalogs.items():
        for key in MESSAGES:
            text = catalog.get(key)
            if not isinstance(text, str) or not text.strip():
                found.append(f"[installer] {code}: {key} missing")
                continue
            unknown = set(PLACEHOLDER.findall(text)) - set(PLACEHOLDERS)
            if unknown:
                found.append(f"[installer] {code}: {key}: the installer has no placeholder {{{'}, {'.join(sorted(unknown))}}}")
            if "%" in text:
                found.append(f"[installer] {code}: {key}: «%» is a placeholder for Inno Setup, leave it out")
        for key in catalog:
            if key.startswith("installer.") and key not in MESSAGES:
                found.append(f"[installer] {code}: {key} isn't used by tools/installer_languages.py")
    return found


def render(catalogs=None):
    catalogs = _catalogs() if catalogs is None else catalogs
    codes = [code for code in MESSAGES_FILES if code in catalogs]
    lines = ["; Written by tools/installer_languages.py from secretbroker/locales/*.json: don't edit it.", "", "[Languages]"]
    lines += [f'Name: "{inno_name(code)}"; MessagesFile: "{MESSAGES_FILES[code]}"' for code in codes]
    for section in ("Messages", "CustomMessages"):
        lines += ["", f"[{section}]"]
        for key, (where, name) in MESSAGES.items():
            if where == section:
                lines += [f"{inno_name(code)}.{name}={inno_text(catalogs[code][key])}" for code in codes]
    return "\r\n".join(lines) + "\r\n"


def main(argv):
    found = problems()
    if found:
        print("\n".join(found), file=sys.stderr)
        return 1
    output = Path(argv[0]) if argv else DEFAULT_OUTPUT
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render(), encoding="utf-8-sig", newline="")
    print(f"{output}: {len(MESSAGES_FILES)} languages")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
