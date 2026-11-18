"""Build the browser extension's packages for the stores (docs/STORES.md).

    python tools/build_extension.py             dist/secretbroker-extension-<version>-chromium.zip
                                                dist/secretbroker-extension-<version>-firefox.zip
    python tools/build_extension.py --out DIR   somewhere else than dist/

extension/ is what users load unpacked from the app's folder, and it stays as it is: one manifest for every browser,
with the "key" that pins its id. A store takes the same files with a manifest of its own:

  chromium  Chrome Web Store and Microsoft Edge Add-ons (Brave installs from the Chrome Web Store). Without "key":
            each store gives the extension its own id (native_host.CHROME_EXTENSION_IDS lists them) and the Chrome
            Web Store may refuse a new item that carries one. Without Firefox's "browser_specific_settings" and
            "background.scripts": Chrome ignores the second from version 121 and refuses the whole manifest before,
            which is also the oldest Chrome the unpacked extension loads in (hence "minimum_chrome_version").
  firefox   addons.mozilla.org. Without "key" and "background.service_worker" (Firefox runs "background.scripts"),
            and with what Mozilla asks every new extension to declare: the data it hands over, to the SecretBroker
            app in this case (FIREFOX_DATA below). Firefox shows that when installing from version 140 on, hence
            "strict_min_version".

Files only for development (README.md, anything hidden) stay out. The zips are reproducible: the same source gives
the same bytes on any system and Python (a fixed order and date, no compression, text with LF line endings whatever
core.autocrlf checked out). Standard library only.
"""

import argparse
import copy
import hashlib
import io
import json
import re
import struct
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "extension"
STORES = ("chromium", "firefox")
DEV_ONLY = ("README.md",)
TEXT = (".js", ".json", ".css", ".html")
ZIP_DATE = (1980, 1, 1, 0, 0, 0)  # the oldest date a zip can hold

CHROME_MIN_VERSION = "121"
FIREFOX_MIN_VERSION = "140.0"
# Mozilla's Add-on Policies count what goes to a native application as data the extension transmits. Ours gets the
# address of the page (to find its logins) and the user and password typed in a login form (to offer to save them).
FIREFOX_DATA = {"required": ["authenticationInfo", "browsingActivity"]}

# What the stores refuse or cut when uploading.
MAX_NAME, MAX_SHORT_NAME, MAX_DESCRIPTION = 75, 12, 132
ICON_SIZES = ("16", "32", "48", "128")


def source_manifest():
    return json.loads((SOURCE / "manifest.json").read_text(encoding="utf-8"))


def store_manifest(store, manifest=None):
    """The manifest one store gets, from the one in extension/ (which is not changed)."""
    manifest = copy.deepcopy(manifest or source_manifest())
    manifest.pop("key", None)
    background = manifest["background"]
    if store == "chromium":
        manifest.pop("browser_specific_settings", None)
        manifest["background"] = {"service_worker": background["service_worker"]}
        manifest["minimum_chrome_version"] = CHROME_MIN_VERSION
    elif store == "firefox":
        manifest["background"] = {"scripts": list(background["scripts"])}
        gecko = manifest["browser_specific_settings"]["gecko"]
        gecko["strict_min_version"] = FIREFOX_MIN_VERSION
        gecko["data_collection_permissions"] = copy.deepcopy(FIREFOX_DATA)
    else:
        raise ValueError(f"unknown store: {store}")
    return manifest


def packaged_files():
    """{path inside the zip: bytes} of everything but the manifest, as every store gets it."""
    files = {}
    for path in sorted(SOURCE.rglob("*")):
        relative = path.relative_to(SOURCE)
        if not path.is_file() or relative.as_posix() == "manifest.json" or relative.as_posix() in DEV_ONLY:
            continue
        if any(part.startswith((".", "__")) for part in relative.parts) or path.name in ("Thumbs.db", "desktop.ini"):
            continue
        data = path.read_bytes()
        if path.suffix in TEXT:
            data = data.replace(b"\r\n", b"\n")
        files[relative.as_posix()] = data
    return files


def manifest_bytes(manifest):
    return (json.dumps(manifest, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def package(store):
    """The zip for one store, as bytes."""
    files = {"manifest.json": manifest_bytes(store_manifest(store)), **packaged_files()}
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
        for name in sorted(files):
            info = zipfile.ZipInfo(name, date_time=ZIP_DATE)
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3            # Unix, also when built on Windows
            info.external_attr = 0o644 << 16  # -rw-r--r--
            archive.writestr(info, files[name])
    return buffer.getvalue()


def _png_size(data):
    return struct.unpack(">II", data[16:24]) if data[:8] == b"\x89PNG\r\n\x1a\n" else None


def problems(manifest=None, files=None):
    """What a store would refuse in extension/: missing files or messages, texts over the limits, wrong icons."""
    manifest = manifest or source_manifest()
    files = packaged_files() if files is None else files
    found = []
    if not re.fullmatch(r"\d+(\.\d+){0,3}", manifest.get("version", "")):
        found.append(f"version {manifest.get('version')!r} is not 1 to 4 numbers separated by dots")
    if manifest.get("manifest_version") != 3:
        found.append("manifest_version must be 3")

    locales = {}
    for name, data in files.items():
        match = re.fullmatch(r"_locales/([^/]+)/messages\.json", name)
        if match:
            try:
                locales[match[1]] = json.loads(data.decode("utf-8"))
            except ValueError as exc:
                found.append(f"{name}: not valid JSON ({exc})")
    default = manifest.get("default_locale")
    if default not in locales:
        found.append(f"default_locale {default!r} has no _locales/{default}/messages.json")

    def texts(value):
        """A manifest text in every language: {locale: text} (one entry, "", for a text that is not translated)."""
        match = re.fullmatch(r"__MSG_(\w+)__", value or "")
        if not match:
            return {"": value or ""}
        result = {}
        for locale, messages in locales.items():
            message = (messages.get(match[1]) or {}).get("message")
            if not message:
                found.append(f"_locales/{locale}/messages.json: «{match[1]}» is missing (the manifest uses it)")
            result[locale] = message or ""
        return result

    for key, limit in (("name", MAX_NAME), ("short_name", MAX_SHORT_NAME), ("description", MAX_DESCRIPTION)):
        for locale, text in texts(manifest.get(key)).items():
            if not text.strip() and key != "short_name":
                found.append(f"{key} is empty" + (f" in {locale}" if locale else ""))
            if len(text) > limit:
                found.append(f"{key} has {len(text)} characters" + (f" in {locale}" if locale else "") + f": the limit is {limit}")
    for command in (manifest.get("commands") or {}).values():
        texts(command.get("description"))

    icons = manifest.get("icons") or {}
    for size in ICON_SIZES:
        data = files.get(icons.get(size, ""))
        if data is None:
            found.append(f"icons: no {size}x{size} icon")
        elif _png_size(data) != (int(size), int(size)):
            found.append(f"icons: {icons[size]} is not a {size}x{size} PNG")
    action = manifest.get("action") or {}
    background = manifest.get("background") or {}
    needed = [action.get("default_popup"), background.get("service_worker"), *(background.get("scripts") or []),
              *(action.get("default_icon") or {}).values(),
              *(script for entry in manifest.get("content_scripts") or [] for script in entry.get("js") or [])]
    for name in needed:
        if name and name not in files:
            found.append(f"the manifest names {name}, which is not in extension/")
    return found


def build(out):
    """Write both zips into `out`. Returns {store: path}."""
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    version = source_manifest()["version"]
    written = {}
    for store in STORES:
        path = out / f"secretbroker-extension-{version}-{store}.zip"
        path.write_bytes(package(store))
        written[store] = path
    return written


def main(argv=None):
    parser = argparse.ArgumentParser(description="Build the extension's zips for the Chrome Web Store, Edge Add-ons and addons.mozilla.org.")
    parser.add_argument("--out", default=str(ROOT / "dist"), help="folder to write the zips into (default: dist/)")
    args = parser.parse_args(argv)
    found = problems()
    for problem in found:
        print(f"  {problem}")
    if found:
        print(f"extension/ has {len(found)} problem(s) a store would refuse: nothing built.")
        return 1
    uses = {"chromium": "Chrome Web Store, Microsoft Edge Add-ons", "firefox": "addons.mozilla.org"}
    for store, path in build(args.out).items():
        data = path.read_bytes()
        print(f"{path}\n    {uses[store]} · {len(data):,} bytes · sha256 {hashlib.sha256(data).hexdigest()}")
    print("How to upload them, field by field: docs/STORES.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
