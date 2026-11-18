"""Writes site/**/*.html: wraps the content fragments of site-src/content/<language>/ in the shared page layout
(header, navigation, footer, language links). The site itself stays plain HTML, CSS and JS with nothing to build
on the server: run this after changing a fragment or the layout, and commit site/ with it.

    python site-src/build.py            # writes site/
    python site-src/build.py --check    # fails if site/ is not what the fragments give (pages.yml runs it)
"""
import html
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SITE = HERE.parent / "site"
BASE = "https://xbofi.github.io/SecretBroker/"
GH = "https://github.com/xBofi/SecretBroker"
UPDATED = "2026-11-18"


def png_size(path):
    """(width, height) of a PNG, from its header."""
    with open(path, "rb") as file:
        header = file.read(24)
    if header[:8] != bytes.fromhex("89504e470d0a1a0a"):
        raise ValueError(f"not a PNG: {path}")
    return int.from_bytes(header[16:20], "big"), int.from_bytes(header[20:24], "big")


ICONS = {
    "external": '<path d="M14 4h6v6"/><path d="M20 4 10 14"/><path d="M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5"/>',
    "rotate": '<path d="M21 12a9 9 0 1 1-2.6-6.4"/><path d="M21 4v5h-5"/>',
    "lock": '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
    "key": '<circle cx="7.5" cy="15.5" r="4"/><path d="m10.4 12.6 9.1-9.1"/><path d="m16 7 3 3"/><path d="m18.5 4.5 2 2"/>',
    "globe": '<circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3c2.5 2.5 3.8 5.5 3.8 9s-1.3 6.5-3.8 9c-2.5-2.5-3.8-5.5-3.8-9S9.5 5.5 12 3z"/>',
    "server": '<rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 7.5h.01M7 16.5h.01"/>',
    "database": '<ellipse cx="12" cy="5.5" rx="8" ry="3"/><path d="M4 5.5v13c0 1.7 3.6 3 8 3s8-1.3 8-3v-13"/><path d="M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/>',
    "cloud": '<path d="M7 19h10.5a4.5 4.5 0 0 0 .4-9A6.5 6.5 0 0 0 5.5 9.6 4.8 4.8 0 0 0 7 19z"/>',
    "shield": '<path d="M12 3 4.5 6v5.5c0 4.7 3.2 8.2 7.5 9.5 4.3-1.3 7.5-4.8 7.5-9.5V6z"/><path d="m9 12 2 2 4-4"/>',
    "search": '<circle cx="11" cy="11" r="7"/><path d="m20 20-4-4"/>',
    "activity": '<path d="M3 12h4l3-8 4 16 3-8h4"/>',
    "user": '<circle cx="12" cy="8" r="3.8"/><path d="M4.5 20a7.5 7.5 0 0 1 15 0"/>',
    "fingerprint": '<path d="M12 11v2.5a9 9 0 0 1-1.6 5"/><path d="M8.6 9.2A4 4 0 0 1 16 11.5v2"/><path d="M8 13.5a12 12 0 0 1-.9 4.5"/><path d="M5.4 7A8 8 0 0 1 20 11.5v1.5"/><path d="M4 11a8 8 0 0 1 .3-2"/><path d="M15.8 17.5a14 14 0 0 1-1.3 3"/><path d="M19.6 16.5c-.2.9-.5 1.8-.8 2.6"/>',
    "check": '<path d="m5 12.5 4.5 4.5L19 7.5"/>',
    "terminal": '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="m7 9 3 3-3 3"/><path d="M12.5 15H17"/>',
    "bot": '<rect x="4" y="8" width="16" height="12" rx="3"/><path d="M12 8V4.5"/><circle cx="12" cy="3.5" r="1"/><path d="M9 13.5h.01M15 13.5h.01"/><path d="M2 13v3M22 13v3"/>',
    "alert": '<path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><path d="M12 9v4M12 17h.01"/>',
    "upload": '<path d="M12 15V4M7 9l5-5 5 5"/><path d="M4 15v4a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-4"/>',
    "download": '<path d="M12 4v11M7 10l5 5 5-5"/><path d="M4 15v4a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-4"/>',
    "users": '<circle cx="9" cy="8" r="3.5"/><path d="M2.5 20a6.5 6.5 0 0 1 13 0"/><path d="M16 4.6a3.5 3.5 0 0 1 0 6.8"/><path d="M18.5 14a6.5 6.5 0 0 1 3 6"/>',
    "share": '<circle cx="18" cy="5" r="2.5"/><circle cx="6" cy="12" r="2.5"/><circle cx="18" cy="19" r="2.5"/><path d="m8.2 10.8 7.6-4.4M8.2 13.2l7.6 4.4"/>',
    "file": '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5"/>',
    "folder": '<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>',
    "power": '<path d="M12 3v9"/><path d="M6.3 6.3a8 8 0 1 0 11.4 0"/>',
    "sun": '<circle cx="12" cy="12" r="4"/><path d="M12 2.5V5M12 19v2.5M2.5 12H5M19 12h2.5M5.3 5.3l1.8 1.8M16.9 16.9l1.8 1.8M5.3 18.7l1.8-1.8M16.9 7.1l1.8-1.8"/>',
    "moon": '<path d="M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5z"/>',
    "menu": '<path d="M4 7h16M4 12h16M4 17h16"/>',
    "arrowRight": '<path d="M5 12h14M13 6l6 6-6 6"/>',
    "arrowLeft": '<path d="M19 12H5M11 6l-6 6 6 6"/>',
    "arrowDown": '<path d="M12 5v14M6 13l6 6 6-6"/>',
    "clock": '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
}

MARK = ('<svg class="mark" viewBox="0 0 100 100" aria-hidden="true"><rect class="mark-tile" x="4" y="4" width="92" height="92" rx="22"/>'
        '<path class="mark-shield" d="M50 17 77 27V49L73 62 64 73 50 83 36 73 27 62 23 49V27Z"/>'
        '<path class="mark-hole" d="M42.5 45a7.5 7.5 0 1 1 15 0 7.5 7.5 0 1 1-15 0ZM47 45h6l2.28 19H44.72Z"/></svg>')

T = {
    "en": {
        "skip": "Skip to content", "nav_label": "Main", "home": "SecretBroker home",
        "nav": [("guide/", "Guide", "guide"), ("guide/developers.html", "For developers", "developers"),
                ("guide/teams.html", "For teams", "teams"), ("security.html", "Security", "security")],
        "github": "GitHub", "download": "Download", "menu": "Menu",
        "other_lang": ("es", "Español", "Leer en español"), "theme": "Switch between light and dark",
        "toc": "On this page", "guide_crumb": "Guide", "updated": "Last updated: November 18, 2026",
        "subnav": [("guide/", "Getting started", "guide"), ("guide/developers.html", "For developers", "developers"),
                   ("guide/teams.html", "For teams", "teams")],
        "site_name": "SecretBroker", "locale": "en_US", "og": "img/og-en.png",
        "foot_blurb": "A free, open-source password and secrets manager for your computer. Windows and Ubuntu are supported; macOS is a preview.",
        "foot": [("Product", [("#download", "Download", "home"), ("guide/", "Guide", ""), ("guide/developers.html", "For developers", ""), ("guide/teams.html", "For teams", "")]),
                 ("Trust", [("security.html", "Security", ""), ("privacy.html", "Privacy", ""), (GH + "/blob/main/docs/THREAT_MODEL.md", "Threat model", "x"), (GH + "/blob/main/SECURITY.md", "Report a vulnerability", "x")]),
                 ("Project", [(GH, "Source code", "x"), (GH + "/blob/main/CHANGELOG.md", "Changelog", "x"), (GH + "/blob/main/docs/ROADMAP.md", "Roadmap", "x"), (GH + "/blob/main/LICENSE", "MIT License", "x")])],
        "fine": ["This site sets no cookies and runs no analytics, and loads nothing from other servers. One exception, on the home page only: the download buttons ask GitHub's public API which version is the latest. Your theme choice is kept in your browser.",
                 "SecretBroker is open source under the MIT License. © 2026 xBofi."],
    },
    "es": {
        "skip": "Saltar al contenido", "nav_label": "Principal", "home": "Inicio de SecretBroker",
        "nav": [("guide/", "Guía", "guide"), ("guide/developers.html", "Para desarrolladores", "developers"),
                ("guide/teams.html", "Para equipos", "teams"), ("security.html", "Seguridad", "security")],
        "github": "GitHub", "download": "Descargar", "menu": "Menú",
        "other_lang": ("en", "English", "Read in English"), "theme": "Cambiar entre tema claro y oscuro",
        "toc": "En esta página", "guide_crumb": "Guía", "updated": "Última actualización: 18 de noviembre de 2026",
        "subnav": [("guide/", "Primeros pasos", "guide"), ("guide/developers.html", "Para desarrolladores", "developers"),
                   ("guide/teams.html", "Para equipos", "teams")],
        "site_name": "SecretBroker", "locale": "es_ES", "og": "img/og-es.png",
        "foot_blurb": "Un gestor de contraseñas y secretos para tu ordenador, gratuito y de código abierto. Funciona en Windows y Ubuntu; en macOS es una vista previa.",
        "foot": [("Producto", [("#download", "Descargar", "home"), ("guide/", "Guía", ""), ("guide/developers.html", "Para desarrolladores", ""), ("guide/teams.html", "Para equipos", "")]),
                 ("Confianza", [("security.html", "Seguridad", ""), ("privacy.html", "Privacidad", ""), (GH + "/blob/main/docs/THREAT_MODEL.md", "Modelo de amenazas (en inglés)", "x"), (GH + "/blob/main/SECURITY.md", "Avisar de una vulnerabilidad", "x")]),
                 ("Proyecto", [(GH, "Código fuente", "x"), (GH + "/blob/main/CHANGELOG.md", "Cambios de cada versión", "x"), (GH + "/blob/main/docs/ROADMAP.md", "Hoja de ruta", "x"), (GH + "/blob/main/LICENSE", "Licencia MIT", "x")])],
        "fine": ["Esta web no usa cookies ni analítica y no carga nada de otros servidores. Una excepción, solo en la página de inicio: los botones de descarga preguntan a la API pública de GitHub cuál es la última versión. El tema que eliges se guarda en tu navegador.",
                 "SecretBroker es de código abierto, con licencia MIT. © 2026 xBofi."],
    },
}

# (path inside a language's folder, fragment name, layout)
PAGES = [
    ("index.html", "index", "landing"),
    ("guide/index.html", "guide", "article"),
    ("guide/developers.html", "developers", "article"),
    ("guide/teams.html", "teams", "article"),
    ("security.html", "security", "article"),
    ("privacy.html", "privacy", "article"),
]


def icon(name, cls=""):
    return f'<svg class="icon{(" " + cls) if cls else ""}" viewBox="0 0 24 24" aria-hidden="true">{ICONS[name]}</svg>'


def url_of(path):
    """The public address of a page: folders instead of index.html."""
    return path[:-len("index.html")] if path.endswith("index.html") else path


def parse(fragment):
    head, _, body = fragment.partition("\n---\n")
    meta = {}
    for line in head.splitlines():
        key, _, value = line.partition(":")
        meta[key.strip()] = value.strip()
    return meta, body


def shot(lang, asset, arguments):
    parts = [p.strip() for p in arguments.split("|")] + ["", "", ""]
    name, alt, caption, mode = parts[0], parts[1], parts[2], parts[3]
    folder = SITE / "img" / lang
    alt = html.escape(alt, quote=True)
    cap = f"\n  <figcaption>{caption}</figcaption>" if caption else ""
    if (folder / f"{name}-light.png").exists():
        w, h = png_size(folder / f"{name}-light.png")
        imgs = "".join(
            f'\n    <img class="only-{theme}" src="{asset}img/{lang}/{name}-{theme}.png" width="{w}" height="{h}" alt="{alt}" loading="lazy" decoding="async">'
            for theme in ("light", "dark"))
        cls = "shot window focus" if mode == "focus" else "shot window"
        if mode == "hero":
            cls = "shot window hero-shot"
        return f'<figure class="{cls}">\n  <div class="frame">{imgs}\n  </div>{cap}\n</figure>'
    w, h = png_size(folder / f"{name}.png")
    cls = "shot window" if w >= 1000 else "shot dialog"
    return (f'<figure class="{cls}">\n  <img src="{asset}img/{lang}/{name}.png" width="{w}" height="{h}" alt="{alt}" loading="lazy" decoding="async">{cap}\n</figure>')


def expand(text, lang, lroot, asset):
    text = re.sub(r"\[\[icon:([\w-]+)(?:\|([\w -]+))?\]\]", lambda m: icon(m[1], m[2] or ""), text)
    text = re.sub(r"\[\[shot:([^\]]+)\]\]", lambda m: shot(lang, asset, m[1]), text)
    return text.replace("[[HOME]]", lroot or "./").replace("[[L]]", lroot).replace("[[A]]", asset).replace("[[GH]]", GH).replace("[[MARK]]", MARK)


def toc_of(body):
    return [(m[1], re.sub(r"<[^>]+>", "", m[2])) for m in re.finditer(r'<h2 id="([^"]+)"[^>]*>(.*?)</h2>', body, re.S)]


def page_html(lang, path, name, layout):
    t = T[lang]
    depth = path.count("/")
    lroot = "../" * depth                       # to the language's folder
    asset = lroot + ("../" if lang != "en" else "")  # to the site's root
    home = lroot or "./"
    meta, body = parse((HERE / "content" / lang / f"{name}.html").read_text(encoding="utf-8"))
    body = expand(body, lang, lroot, asset)
    public = url_of(path)
    urls = {code: BASE + ("" if code == "en" else code + "/") + public for code in T}
    other, other_name, other_label = t["other_lang"]
    other_href = (asset + ("" if other == "en" else other + "/") + public) or "./"
    section = meta.get("section", name)

    def link(href, label, key, current=False):
        cur = ' aria-current="page"' if current else ""
        return f'<a href="{href}"{cur}>{label}</a>'

    nav = "".join(link(lroot + href, label, key, key == section) for href, label, key in t["nav"])
    nav += f'<a href="{GH}" rel="noopener">{t["github"]}</a>'
    privacy_current = ' aria-current="page"' if section == "privacy" else ""
    menu_nav = nav + f'<a href="{lroot}privacy.html"{privacy_current}>{t["foot"][1][1][1][1]}</a>' \
        + f'<a href="{home}#download">{t["download"]}</a>'

    alternates = "".join(f'\n<link rel="alternate" hreflang="{code}" href="{urls[code]}">' for code in T)
    alternates += f'\n<link rel="alternate" hreflang="x-default" href="{urls["en"]}">'
    og_alt = "".join(f'\n<meta property="og:locale:alternate" content="{T[c]["locale"]}">' for c in T if c != lang)
    title = html.escape(meta["title"], quote=True)
    desc = html.escape(meta["description"], quote=True)

    head = f"""<!doctype html>
<html lang="{lang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src https://api.github.com; base-uri 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer">
<title>{title}</title>
<meta name="description" content="{desc}">
<link rel="canonical" href="{urls[lang]}">{alternates}
<meta property="og:type" content="website">
<meta property="og:site_name" content="{t['site_name']}">
<meta property="og:title" content="{title}">
<meta property="og:description" content="{desc}">
<meta property="og:url" content="{urls[lang]}">
<meta property="og:image" content="{BASE}{t['og']}">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta property="og:locale" content="{t['locale']}">{og_alt}
<meta name="twitter:card" content="summary_large_image">
<meta name="color-scheme" content="light dark">
<meta name="theme-color" media="(prefers-color-scheme: light)" content="#fbfbfb">
<meta name="theme-color" media="(prefers-color-scheme: dark)" content="#161616">
<link rel="icon" href="{asset}favicon.ico" sizes="48x48">
<link rel="icon" href="{asset}img/icon.svg" type="image/svg+xml">
<link rel="apple-touch-icon" href="{asset}img/icon-180.png">
<link rel="stylesheet" href="{asset}css/site.css">
<script src="{asset}js/theme.js"></script>
</head>
<body>
<a class="skip" href="#main">{t['skip']}</a>
<header class="site-header">
  <div class="wrap">
    <a class="brand" href="{home}" aria-label="{t['home']}">{MARK}<span>SecretBroker</span></a>
    <nav class="nav" aria-label="{t['nav_label']}">{nav}</nav>
    <div class="tools">
      <a class="tool" href="{other_href}" hreflang="{other}" lang="{other}" aria-label="{other_label}">{other_name}</a>
      <button class="tool theme-toggle" type="button" aria-label="{t['theme']}" title="{t['theme']}">{icon('moon', 'to-dark')}{icon('sun', 'to-light')}</button>
      <a class="btn primary sm" href="{home}#download">{t['download']}</a>
      <details class="menu">
        <summary class="tool" aria-label="{t['menu']}">{icon('menu')}</summary>
        <nav class="menu-panel" aria-label="{t['menu']}">{menu_nav}</nav>
      </details>
    </div>
  </div>
</header>
"""

    if layout == "landing":
        main = f'<main id="main">\n{body}\n</main>\n'
    else:
        toc = "".join(f'<li><a href="#{i}">{label}</a></li>' for i, label in toc_of(body))
        crumbs = f'<a href="{home}">SecretBroker</a>'
        subnav = ""
        if section in ("guide", "developers", "teams"):
            if section != "guide":
                crumbs += f' / <a href="{lroot}guide/">{t["guide_crumb"]}</a>'
            subnav = '<nav class="subnav" aria-label="' + t["guide_crumb"] + '">' + "".join(
                link(lroot + href, label, key, key == section) for href, label, key in t["subnav"]) + "</nav>"
        main = f"""<main id="main" class="page wrap">
  <div class="page-grid">
    <header class="page-head">
      <p class="crumbs">{crumbs}</p>
      <h1>{meta['h1']}</h1>
      <p class="lede">{expand(meta['lede'], lang, lroot, asset)}</p>
      {subnav}
    </header>
    <nav class="toc" aria-label="{t['toc']}">
      <h2>{t['toc']}</h2>
      <ol>{toc}</ol>
    </nav>
    <article class="prose">
{body}
    <p class="updated">{t['updated']}</p>
    </article>
  </div>
</main>
"""

    cols = ""
    for heading, links in t["foot"]:
        items = ""
        for href, label, kind in links:
            if kind == "x":
                items += f'<li><a href="{href}" rel="noopener">{label}</a></li>'
            elif kind == "home":
                items += f'<li><a href="{home}{href}">{label}</a></li>'
            else:
                items += f'<li><a href="{lroot}{href}">{label}</a></li>'
        cols += f'\n      <div><h2>{heading}</h2><ul>{items}</ul></div>'
    fine = "".join(f"<p>{p}</p>" for p in t["fine"])
    foot = f"""<footer class="site-footer">
  <div class="wrap">
    <div class="foot">
      <div class="foot-brand">
        <a class="brand" href="{home}">{MARK}<span>SecretBroker</span></a>
        <p>{t['foot_blurb']}</p>
      </div>{cols}
    </div>
    <div class="fineprint">{fine}</div>
  </div>
</footer>
<script src="{asset}js/site.js" defer></script>
</body>
</html>
"""
    return head + main + foot


def main():
    check = "--check" in sys.argv[1:]
    stale = []
    for lang in T:
        for path, name, layout in PAGES:
            if not (HERE / "content" / lang / f"{name}.html").exists():
                print("MISSING", lang, name)
                stale.append(f"{lang}/{name}")
                continue
            target = SITE / ("" if lang == "en" else lang) / path
            text = page_html(lang, path, name, layout)
            if check:
                if not target.exists() or target.read_text(encoding="utf-8") != text:
                    stale.append(str(target.relative_to(SITE)))
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8", newline=chr(10))
            print("wrote", target.relative_to(SITE))
    if check:
        if stale:
            sys.exit("site/ is not what site-src gives (run python site-src/build.py): " + ", ".join(stale))
        print("site/ matches site-src")


if __name__ == "__main__":
    main()
