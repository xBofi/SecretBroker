"""Browser autofill: which saved logins belong to the page the browser is on.

Anti-phishing is decided here, in the service, never in the extension: a login is offered on a page only when
the page's *registrable domain* (the public-suffix rules, as browsers use them for cookies) is the one of an
address saved with the login. `accounts.example.com` matches a login saved for `example.com`; `example.com.evil.net`,
`examp1e.com`, `xn--exmple-cua.com` or another tenant of a shared suffix (`alice.github.io` for `bob.github.io`) do not.
A frame may only be filled if it is the top page or a frame of the same registrable domain.

Per credential (`entry.autofill`): `sites` (more addresses besides `fields.url`) and `match`:
    domain  the registrable domain and any of its subdomains (default)
    host    only the exact host (and port) saved
    never   never offered in the browser
"""

import ipaddress
import re
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

PSL_FILE = Path(__file__).with_name("data") / "public_suffix_list.dat"
MATCH_MODES = ("domain", "host", "never")
MAX_SITES = 20
MAX_SITE_LEN = 300
HOST_RE = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,62})(\.[a-z0-9_]([a-z0-9_-]{0,62}))*$")


class SiteError(ValueError):
    pass


@lru_cache(maxsize=1)
def _rules():
    """(normal, wildcard, exception) suffix sets from the Public Suffix List, ICANN and private sections alike
    (a private suffix such as github.io or blogspot.com separates its tenants just like a country code)."""
    normal, wildcard, exception = set(), set(), set()
    for line in PSL_FILE.read_text(encoding="utf-8").splitlines():
        rule = line.strip().split(" ")[0]
        if not rule or rule.startswith("//"):
            continue
        target = normal
        if rule.startswith("!"):
            target, rule = exception, rule[1:]
        elif rule.startswith("*."):
            target, rule = wildcard, rule[2:]
        try:
            rule = _ascii(rule)
        except SiteError:
            continue
        target.add(rule)
    return frozenset(normal), frozenset(wildcard), frozenset(exception)


def _ascii(host):
    """A host in the form browsers send it (lower case, punycode), or SiteError."""
    host = (host or "").strip().rstrip(".").lower()
    if not host:
        raise SiteError("Dirección vacía")
    if not host.isascii():
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            raise SiteError(f"Dirección no válida: {host}") from None
    return host


def is_ip(host):
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def public_suffix(host):
    """The public suffix of a host (`co.uk` for `shop.example.co.uk`). Unknown top-level domains count as one
    label, like browsers do."""
    labels = host.split(".")
    normal, wildcard, exception = _rules()
    for i in range(len(labels)):
        candidate = ".".join(labels[i:])
        if candidate in exception:
            return ".".join(labels[i + 1:])
        if candidate in normal:
            return candidate
        if i + 1 < len(labels) and ".".join(labels[i + 1:]) in wildcard:
            return candidate
    return labels[-1]


def registrable_domain(host):
    """`example.co.uk` for `www.shop.example.co.uk`. An IP address, `localhost`, a single-label intranet name or a
    public suffix itself has none of its own: the host is returned and only that exact host matches."""
    host = _ascii(host)
    if is_ip(host) or "." not in host:
        return host
    suffix = public_suffix(host)
    if suffix == host:
        return host
    labels = host[: -len(suffix) - 1].split(".")
    return labels[-1] + "." + suffix


def has_own_domain(host):
    """False for hosts that only match themselves (IP addresses, localhost, intranet names, public suffixes)."""
    host = _ascii(host)
    return not is_ip(host) and "." in host and public_suffix(host) != host


class Site:
    """A parsed address: scheme (`https` when not written), host, explicit port (None for the default one)."""

    def __init__(self, scheme, host, port):
        self.scheme, self.host, self.port = scheme, host, port

    @property
    def domain(self):
        return registrable_domain(self.host)

    @property
    def label(self):
        """How the user sees it: the host and a port if one is needed."""
        return self.host + (f":{self.port}" if self.port else "")

    def __repr__(self):
        return f"Site({self.scheme}://{self.label})"


DEFAULT_PORTS = {"http": 80, "https": 443}


def parse(address, page=False):
    """A site from a saved address (`example.com`, `https://login.example.com:8443/path`) or, with `page`, the URL of
    the page in the browser (only http and https pages are ever filled)."""
    text = str(address or "").strip()
    if not text or len(text) > 2048:
        raise SiteError("Dirección vacía o demasiado larga")
    if "://" not in text:
        if page:
            raise SiteError("Solo se rellenan páginas web (http o https)")
        text = "https://" + text
    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError:
        raise SiteError(f"Dirección no válida: {address}") from None
    scheme = parts.scheme.lower()
    if scheme not in DEFAULT_PORTS:
        raise SiteError("Solo se rellenan páginas web (http o https)")
    host = parts.hostname or ""
    if host.startswith("[") or ":" in host:
        host = host.strip("[]")
    host = _ascii(host)
    if not (is_ip(host) or HOST_RE.match(host)):
        raise SiteError(f"Dirección no válida: {address}")
    if port == DEFAULT_PORTS[scheme]:
        port = None
    return Site(scheme, host, port)


def clean_sites(sites):
    """The `autofill.sites` of a credential: one address per line, without duplicates."""
    if isinstance(sites, str):
        sites = sites.splitlines()
    if not isinstance(sites, list):
        raise SiteError("Direcciones para autorrellenar: una lista")
    cleaned = []
    for site in sites:
        site = str(site).strip()
        if not site:
            continue
        if len(site) > MAX_SITE_LEN:
            raise SiteError(f"Dirección demasiado larga: {site[:40]}…")
        parse(site)
        if site not in cleaned:
            cleaned.append(site)
    if len(cleaned) > MAX_SITES:
        raise SiteError(f"Como mucho {MAX_SITES} direcciones para autorrellenar")
    return cleaned


def validate(autofill):
    """Checks `entry.autofill` (raises SiteError)."""
    if not isinstance(autofill, dict) or set(autofill) - {"sites", "match"}:
        raise SiteError("Ajustes de autorrellenado no válidos")
    if autofill.get("match", "domain") not in MATCH_MODES:
        raise SiteError("Cómo comparar la dirección: domain, host o never")
    if clean_sites(autofill.get("sites") or []) != (autofill.get("sites") or []):
        raise SiteError("Direcciones para autorrellenar no válidas")


def saved_sites(entry):
    """Every address saved with a web login: its «Dirección web» and its autofill sites."""
    if entry.get("template") != "web_login":
        return []
    addresses = [entry.get("fields", {}).get("url")] + list((entry.get("autofill") or {}).get("sites") or [])
    result = []
    for address in addresses:
        if not address:
            continue
        try:
            site = parse(address)
        except SiteError:
            continue
        result.append((address, site))
    return result


def site_matches(saved, page, mode="domain"):
    """Whether a page may receive a login saved for `saved`. None if it may, else why not (a short code):
        insecure  the login was saved for https and the page is http
        port      a different port than the one saved
        host      another host, and the credential only fills its exact host
        domain    another registrable domain (or another tenant of a shared suffix): a lookalike, never filled"""
    if mode == "never":
        return "never"
    if saved.scheme == "https" and page.scheme == "http" and not _local(page.host):
        return "insecure"
    exact = mode == "host" or not has_own_domain(saved.host) or not has_own_domain(page.host)
    if exact:
        if page.host != saved.host:
            return "host" if registrable_domain(page.host) == registrable_domain(saved.host) else "domain"
    elif registrable_domain(page.host) != registrable_domain(saved.host):
        return "domain"
    if page.port != saved.port:
        return "port"
    return None


def _local(host):
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def match_entry(entry, page):
    """The saved address of `entry` that matches the page (a Site), with how: `(address, "host" | "domain")`, or None."""
    mode = (entry.get("autofill") or {}).get("match", "domain")
    best = None
    for address, site in saved_sites(entry):
        if site_matches(site, page, mode) is None:
            how = "host" if site.host == page.host else "domain"
            if best is None or (how == "host" and best[1] != "host"):
                best = (address, how)
    return best


def frame_allowed(top, frame):
    """A frame may be filled when it is the top page or of the same registrable domain (never a third-party
    frame: an ad or a widget the page embeds)."""
    if frame is None:
        return True
    if frame.scheme == "http" and top.scheme == "https":
        return False
    return registrable_domain(frame.host) == registrable_domain(top.host)


def page_sites(url, frame_url=None):
    """(top, frame) Sites from what the browser says. The frame is None when it is the top page itself."""
    top = parse(url, page=True)
    frame = parse(frame_url, page=True) if frame_url and frame_url != url else None
    if frame and frame.host == top.host and frame.port == top.port and frame.scheme == top.scheme:
        frame = None
    return top, frame
