"""The extension's packages for the stores (tools/build_extension.py): what each zip holds, the manifest each store
gets, that nothing only for development goes in, and that the same source always gives the same bytes. Also that
the ids the native host answers are well formed, since a store's id is added there by hand (docs/STORES.md), and
that the listings' images (tools/store_images.py) have the sizes the stores ask for.

Builds into a temporary folder; extension/ and dist/ are not touched.
Run with:  .venv\\Scripts\\python.exe tests\\test_extension_build.py
"""

import base64
import hashlib
import importlib.util
import io
import json
import os
import re
import sys
import tempfile
import zipfile
from pathlib import Path

HOME = Path(tempfile.mkdtemp(prefix="secretbroker-extension-build-"))
os.environ["SECRETBROKER_HOME"] = str(HOME)  # must be set before importing secretbroker
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from secretbroker import native_host  # noqa: E402

spec = importlib.util.spec_from_file_location("build_extension", ROOT / "tools" / "build_extension.py")
build_extension = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build_extension)

EXTENSION = ROOT / "extension"
failures = 0


def check(condition, message):
    global failures
    print(("  OK   " if condition else "  FAIL ") + message)
    failures += not condition


def tree_digest(folder):
    digest = hashlib.sha256()
    for path in sorted(p for p in folder.rglob("*") if p.is_file()):
        digest.update(path.relative_to(folder).as_posix().encode() + b"\0" + path.read_bytes())
    return digest.hexdigest()


def chrome_id(key):
    """The id Chromium gives an extension with this public key: the first 16 bytes of its SHA-256, in letters a to p."""
    return "".join(chr(ord("a") + int(c, 16)) for c in hashlib.sha256(base64.b64decode(key)).hexdigest()[:32])


def check_source():
    print("extension/ as the stores take it")
    found = build_extension.problems()
    check(not found, "nothing a store refuses at upload (files, messages, lengths, icons)" + "".join(f"\n         {p}" for p in found))
    source = build_extension.source_manifest()
    broken = dict(source, description="x" * 133)
    check(any("description" in p for p in build_extension.problems(broken)), "a description over 132 characters is caught")
    files = build_extension.packaged_files()
    check(any("icon" in p for p in build_extension.problems(source, {k: v for k, v in files.items() if k != "icons/128.png"})),
          "and a missing 128x128 icon")
    lost = dict(files)
    lost["_locales/es/messages.json"] = b"{}"
    check(any("ext_description" in p for p in build_extension.problems(source, lost)), "and a language without the description")
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    check(re.search(r'^version = "(.+)"$', pyproject, re.M)[1] == source["version"],
          "the extension has the app's version (a store only takes a version higher than its last one)")
    code = "\n".join(data.decode("utf-8") for name, data in files.items() if name.endswith((".js", ".html")))
    check(not re.search(r"\beval\s*\(|new Function\b|importScripts\s*\(|document\.write\s*\(", code),
          "no eval, new Function, importScripts or document.write")
    check(not re.search(r"""<script[^>]+src=["']?(https?:)?//|\bimport\s*\(""", code), "no script loaded from the network")


def check_ids():
    print("The ids the native host answers")
    ids = native_host.CHROME_EXTENSION_IDS
    check(all(re.fullmatch(r"[a-p]{32}", i) for i in ids), "every Chromium id is 32 letters from a to p")
    check(len(set(ids)) == len(ids), "none is repeated")
    check(ids[0] == chrome_id(build_extension.source_manifest()["key"]), "the first is the unpacked extension's (the key in extension/manifest.json)")
    check(native_host.ALLOWED_ORIGINS == tuple(f"chrome-extension://{i}/" for i in ids)
          + tuple(f"moz-extension:{i}" for i in native_host.FIREFOX_EXTENSION_IDS), "and nothing else is allowed")
    check(all(re.fullmatch(r"[a-zA-Z0-9._-]*@[a-zA-Z0-9._-]+", i) and len(i) <= 80 for i in native_host.FIREFOX_EXTENSION_IDS),
          "Firefox's id has the form addons.mozilla.org takes")


def read_zip(data):
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        return archive.infolist(), {info.filename: archive.read(info) for info in archive.infolist()}


def check_package(store, path, source):
    print(f"The {store} zip")
    data = path.read_bytes()
    infos, files = read_zip(data)
    names = [info.filename for info in infos]
    manifest = json.loads(files["manifest.json"].decode("utf-8"))
    check(path.name == f"secretbroker-extension-{source['version']}-{store}.zip", f"is named after the version ({path.name})")
    check("manifest.json" in names and "popup.html" in names and "_locales/en/messages.json" in names,
          "manifest.json is at its root, next to the extension's files")

    wanted = {p.relative_to(EXTENSION).as_posix() for p in EXTENSION.rglob("*") if p.is_file()} - {"README.md"}
    check(set(names) == wanted, f"holds every file of extension/ but README.md ({len(names)} files)")
    dev = [n for n in names if n.lower().endswith((".md", ".py", ".pem", ".map", ".zip", ".crx", ".xpi", ".sh", ".ps1"))
           or any(part.startswith(".") for part in n.split("/"))]
    check(not dev, "nothing only for development (notes, scripts, keys, hidden files)" + (f": {dev}" if dev else ""))
    same = all(files[n] == (EXTENSION / n).read_bytes().replace(b"\r\n", b"\n") if n.endswith(build_extension.TEXT)
               else files[n] == (EXTENSION / n).read_bytes() for n in names if n != "manifest.json")
    check(same, "every file is the one in extension/, untouched")

    # The same on any system: order, dates, modes and bytes do not depend on where it was built.
    check(names == sorted(names), "files in alphabetical order")
    check(all(i.date_time == build_extension.ZIP_DATE and i.compress_type == zipfile.ZIP_STORED and i.create_system == 3
              and i.external_attr == 0o644 << 16 and not i.extra and not i.comment for i in infos),
          "a fixed date, no compression, the same mode and no extra fields")
    check(not any(b"\r" in files[n] for n in names if n.endswith(build_extension.TEXT)), "text files have LF line endings")
    check(build_extension.package(store) == data, "building it again gives the same bytes")

    check("key" not in manifest, "no «key» (the store gives the extension its id)")
    unchanged = ("manifest_version", "name", "short_name", "version", "description", "default_locale", "icons", "action",
                 "permissions", "host_permissions", "content_scripts", "commands")
    check(all(manifest[k] == source[k] for k in unchanged), "name, version, permissions, content script and shortcuts as in extension/")
    extra = set(manifest) - set(source)
    if store == "chromium":
        check("browser_specific_settings" not in manifest, "no «browser_specific_settings» (Firefox's)")
        check(manifest["background"] == {"service_worker": "background.js"}, "the background is the service worker alone")
        check(manifest.get("minimum_chrome_version") == "121" and extra == {"minimum_chrome_version"},
              "for Chrome 121 or newer, like the unpacked extension; nothing else added")
    else:
        gecko = manifest["browser_specific_settings"]["gecko"]
        check(manifest["background"] == {"scripts": ["background.js"]}, "the background is the event page alone (no service worker)")
        check(gecko["id"] == source["browser_specific_settings"]["gecko"]["id"] and gecko["id"] in native_host.FIREFOX_EXTENSION_IDS,
              f"the id is the one the native host answers ({gecko['id']})")
        data_types = gecko.get("data_collection_permissions") or {}
        known = {"none", "authenticationInfo", "bookmarksInfo", "browsingActivity", "financialAndPaymentInfo", "healthInfo",
                 "locationInfo", "personalCommunications", "personallyIdentifyingInfo", "searchTerms", "websiteActivity",
                 "websiteContent"}
        check(data_types.get("required") == ["authenticationInfo", "browsingActivity"] and set(data_types["required"]) <= known
              and set(data_types) == {"required"},
              "declares what goes to the SecretBroker app: logins and page addresses (data_collection_permissions)")
        check(int(gecko["strict_min_version"].split(".")[0]) >= 140, "for Firefox 140 or newer, which shows that declaration")
        check(not extra and "minimum_chrome_version" not in manifest and "gecko_android" not in manifest["browser_specific_settings"],
              "nothing else added; desktop only (Firefox for Android has no native messaging)")
    check(not build_extension.problems(manifest, {n: d for n, d in files.items() if n != "manifest.json"}),
          "and it still passes the upload checks")


def check_images():
    """tools/store_images.py: the sizes the stores ask for, exactly."""
    print("Images for the listings")
    spec = importlib.util.spec_from_file_location("store_images", ROOT / "tools" / "store_images.py")
    store_images = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(store_images)
    out = HOME / "store"
    check(store_images.main(["--out", str(out)]) == 0, "the logo and the promotional images are written")
    sizes = {p.name: build_extension._png_size(p.read_bytes()) for p in out.iterdir()}
    check(sizes == {"logo-300x300.png": (300, 300), "promo-small-440x280.png": (440, 280), "promo-marquee-1400x560.png": (1400, 560)},
          "300x300, 440x280 and 1400x560")
    # A screenshot of the test (the popup, a page, the app's window) becomes 1280x800 whatever its size.
    popup = store_images.plain(360, 315, (250, 250, 250))
    page = store_images.plain(1256, 808, (255, 255, 255))
    window = store_images.plain(1104, 701, (30, 30, 30))
    fitted = [store_images.store_screenshot(popup, "popup", None), store_images.store_screenshot(page, "page", (-640, 0)),
              store_images.store_screenshot(window, "window", None)]
    check(all((w, h) == (1280, 800) and len(rows) == 800 and all(len(r) == 3840 for r in rows) for w, h, rows in fitted),
          "screenshots are fitted to 1280x800")
    path = out / "roundtrip.png"
    store_images.write_png(path, fitted[0])
    again = store_images.read_png(path)
    check(again[:2] == (1280, 800) and again[2] == fitted[0][2], "and are written as PNGs that read back the same")


def main():
    before = tree_digest(EXTENSION)
    check_source()
    check_ids()
    source = build_extension.source_manifest()
    out = HOME / "dist"
    written = build_extension.build(out)
    check(sorted(written) == ["chromium", "firefox"] and sorted(p.name for p in out.iterdir()) == sorted(p.name for p in written.values()),
          "two zips are written: Chrome Web Store + Edge Add-ons, and addons.mozilla.org")
    for store, path in written.items():
        check_package(store, path, source)
    check_images()
    print("The source")
    check(tree_digest(EXTENSION) == before, "extension/ is as it was")
    check(chrome_id(source["key"]) == native_host.CHROME_EXTENSION_IDS[0] and source["background"] ==
          {"service_worker": "background.js", "scripts": ["background.js"]},
          "and still loads unpacked with its pinned id, in Chromium and Firefox")
    print(f"\n{'ALL PASSED' if not failures else f'{failures} FAILED'}  (zips: {out})")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
