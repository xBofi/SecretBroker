"""Check the website in site/ before it is published (run by .github/workflows/pages.yml).

    python tools/check_site.py            # the site/ next to this script's folder
    python tools/check_site.py <folder>

Standard library only. It fails when:
  * an internal link, or the #anchor it names, does not resolve;
  * an image, stylesheet or script a page uses does not exist, or an image has no alt text;
  * a language has a page another language lacks (English is site/, every other language its own folder);
  * a page's "other language" links (hreflang) do not point at the same page in each language;
  * anything is loaded from another server: scripts, styles, images, fonts, frames, CSS url(), fetch() in a script.
    The one allowed request is GitHub's public API for the download buttons (ALLOWED_FETCH). Links the reader clicks
    (<a href>) and the addresses in <meta>/<link rel="canonical|alternate"> load nothing and may point anywhere.
"""

import re
import sys
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
ALLOWED_FETCH = "https://api.github.com/repos/xBofi/SecretBroker/releases/latest"
# Tags whose address the browser fetches by itself, and the attribute that holds it.
LOADS = {"img": ("src", "srcset"), "script": ("src",), "iframe": ("src",), "embed": ("src",), "object": ("data",),
         "source": ("src", "srcset"), "video": ("src", "poster"), "audio": ("src",), "track": ("src",), "input": ("src",),
         "use": ("href", "xlink:href"), "image": ("href", "xlink:href")}
LOADING_RELS = {"stylesheet", "icon", "apple-touch-icon", "preload", "prefetch", "modulepreload", "manifest", "preconnect",
                "dns-prefetch", "mask-icon"}
REMOTE = re.compile(r"^(?:[a-z][a-z0-9+.-]*:)?//", re.I)


class Page(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.ids = set()
        self.links = []       # (href, line) of <a>
        self.loads = []       # (address, line, tag) of everything the browser fetches
        self.alternates = {}  # hreflang -> href
        self.problems = []
        self.lang = None
        self.inline_script = False
        self.csp = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        line = self.getpos()[0]
        if a.get("id"):
            if a["id"] in self.ids:
                self.problems.append(f"line {line}: the id \"{a['id']}\" is used twice")
            self.ids.add(a["id"])
        if tag == "html":
            self.lang = a.get("lang")
        if tag == "a" and a.get("href") is not None:
            self.links.append((a["href"], line))
        if tag == "link":
            rels = set((a.get("rel") or "").lower().split())
            if rels & LOADING_RELS and a.get("href"):
                self.loads.append((a["href"], line, "link"))
            if "alternate" in rels and a.get("hreflang"):
                self.alternates[a["hreflang"]] = a.get("href", "")
        if tag == "meta" and (a.get("http-equiv") or "").lower() == "content-security-policy":
            self.csp = a.get("content", "")
        for name in LOADS.get(tag, ()):
            if a.get(name):
                for part in a[name].split(",") if name == "srcset" else [a[name]]:
                    self.loads.append((part.strip().split(" ")[0], line, tag))
        if tag == "img" and a.get("alt") is None:
            self.problems.append(f"line {line}: an image has no alt text ({a.get('src')})")
        if tag == "script" and not a.get("src") and (a.get("type") or "text/javascript").lower() in ("text/javascript", "module"):
            self.inline_script = True
        if a.get("style"):
            self.problems.append(f"line {line}: a style attribute (the page's content security policy forbids it)")
        if tag == "style":
            self.problems.append(f"line {line}: a <style> block (the page's content security policy forbids it)")
        if tag == "base":
            self.problems.append(f"line {line}: <base> would break the relative links")


def target_of(page, address, site):
    """The file an internal address names, seen from `page`. Folders mean their index.html."""
    parts = urlsplit(address)
    path = unquote(parts.path)
    if not path:
        return page, parts.fragment
    if path.startswith("/"):
        return None, parts.fragment  # a root-absolute link breaks under https://<user>.github.io/<project>/
    target = (page.parent / path).resolve()
    if path.endswith("/") or target.is_dir():
        target = target / "index.html"
    return target, parts.fragment


def check(site):
    site = site.resolve()
    problems = []
    pages = {}
    for path in sorted(site.rglob("*.html")):
        parser = Page()
        parser.feed(path.read_text(encoding="utf-8"))
        pages[path] = parser

    # A language is a folder whose own index.html says so (<html lang="es"> in es/); guide/ is not one.
    languages = {"en": site}
    for folder in sorted(p for p in site.iterdir() if p.is_dir()):
        index = pages.get(folder / "index.html")
        if index is not None and index.lang == folder.name:
            languages[folder.name] = folder
    others = [folder for code, folder in languages.items() if code != "en"]

    def relative(path, base):
        return path.relative_to(base).as_posix()

    page_sets = {}
    for code, folder in languages.items():
        own = set()
        for path in pages:
            if folder not in path.parents and path.parent != folder:
                continue
            if code == "en" and any(other in path.parents or path.parent == other for other in others):
                continue
            own.add(relative(path, folder))
        page_sets[code] = own
    for code, own in page_sets.items():
        for missing in sorted(page_sets["en"] - own):
            problems.append(f"{code}: the page {missing} exists in English but not in this language")
        for extra in sorted(own - page_sets["en"]):
            problems.append(f"{code}: the page {extra} does not exist in English")

    for path, page in pages.items():
        name = relative(path, site)
        problems += [f"{name}: {text}" for text in page.problems]
        code = next((c for c, folder in languages.items() if c != "en" and (folder in path.parents)), "en")
        if page.lang != code:
            problems.append(f"{name}: <html lang=\"{page.lang}\"> in the folder of \"{code}\"")
        if page.inline_script:
            problems.append(f"{name}: an inline script (the page's content security policy forbids it)")
        if page.csp is None:
            problems.append(f"{name}: no content security policy")
        else:
            for source in re.findall(r"https?://[^\s;']+", page.csp):
                if source != "https://api.github.com":
                    problems.append(f"{name}: the content security policy allows {source}")

        for address, line, tag in page.loads:
            if REMOTE.match(address) or address.startswith(("data:", "blob:")):
                problems.append(f"{name}: line {line}: <{tag}> loads {address}: nothing may come from another server")
                continue
            target, _ = target_of(path, address, site)
            if target is None:
                problems.append(f"{name}: line {line}: <{tag}> uses the root-absolute address {address}")
            elif not target.is_file():
                problems.append(f"{name}: line {line}: <{tag}> names {address}, which does not exist")
            elif site not in target.parents:
                problems.append(f"{name}: line {line}: <{tag}> names {address}, outside the site")

        for address, line in page.links:
            if REMOTE.match(address) or address.startswith(("mailto:", "tel:")):
                if address.startswith("http://"):
                    problems.append(f"{name}: line {line}: a link without HTTPS: {address}")
                continue
            target, fragment = target_of(path, address, site)
            if target is None:
                problems.append(f"{name}: line {line}: the root-absolute link {address}")
                continue
            if not target.is_file():
                problems.append(f"{name}: line {line}: the link {address} leads nowhere")
                continue
            if fragment and target in pages and fragment not in pages[target].ids:
                problems.append(f"{name}: line {line}: the link {address} names an anchor that does not exist")

        # The same page in every language, by its hreflang links.
        own = relative(path, languages[code])
        public = own[:-len("index.html")] if own.endswith("index.html") else own
        for other in languages:
            href = page.alternates.get(other)
            if href is None:
                problems.append(f"{name}: no <link rel=\"alternate\" hreflang=\"{other}\">")
                continue
            expected = ("" if other == "en" else other + "/") + public
            if not href.endswith("/" + expected) and href != expected:
                problems.append(f"{name}: hreflang=\"{other}\" points at {href}, not at .../{expected}")

    for path in sorted(site.rglob("*.css")):
        name = relative(path, site)
        text = path.read_text(encoding="utf-8")
        if re.search(r"@import", text):
            problems.append(f"{name}: @import")
        for address in re.findall(r"url\(\s*['\"]?([^'\")]+)", text):
            if REMOTE.match(address):
                problems.append(f"{name}: url({address}) loads from another server")
            elif not address.startswith("data:") and not (path.parent / address.split("#")[0].split("?")[0]).is_file():
                problems.append(f"{name}: url({address}) does not exist")

    for path in sorted(site.rglob("*.js")):
        name = relative(path, site)
        text = path.read_text(encoding="utf-8")
        for address in set(re.findall(r"https?://[^\s'\"`<>)]+", text)):
            if address == ALLOWED_FETCH or address.startswith("https://github.com/xBofi/SecretBroker/"):
                continue  # the releases API, and the links the script writes into the download buttons
            problems.append(f"{name}: names {address}")
        if re.search(r"\b(XMLHttpRequest|sendBeacon|WebSocket|EventSource|importScripts)\b", text):
            problems.append(f"{name}: a network call other than fetch()")
        if len(re.findall(r"\bfetch\(", text)) > 1:
            problems.append(f"{name}: more than one fetch(): only the releases API may be asked")

    for path in sorted(p for p in site.rglob("*") if p.is_file() and p.name.startswith(".")):
        problems.append(f"{relative(path, site)}: hidden files are not published by GitHub Pages")

    return pages, languages, problems


def main():
    site = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "site"
    if not (site / "index.html").is_file():
        sys.exit(f"{site} has no index.html")
    pages, languages, problems = check(site)
    for problem in problems:
        print(problem)
    if problems:
        sys.exit(f"{len(problems)} problem(s) in {site}")
    print(f"site ok: {len(pages)} pages, {len(languages)} languages ({', '.join(languages)})")


if __name__ == "__main__":
    main()
