"""Server settings, read once from the environment."""

import os
import re
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

SIGNUP_MODES = ("open", "invite", "closed")
VERIFICATION_MODES = ("required", "off")
SMTP_SECURITY = ("starttls", "ssl", "none")
VERSION_RE = re.compile(r"^\s*v?(\d{1,6})\.(\d{1,6})(?:\.(\d{1,6}))?")

# The protocol this server speaks (GET /info `api`): 1 = 0.16 (signed member lists and deletions, e-mail
# verification), 2 = invites that expire and are e-mailed, the client version header, /health. Additive: a client
# made for api 1 works unchanged.
API_VERSION = 2
# The oldest desktop app that works with this server: 0.16 is the first that signs member lists, which this server
# requires once a collection has one. Apps that don't send their version (before 0.17) are served as before.
MIN_CLIENT = "0.16.0"


class ConfigError(Exception):
    pass


def parse_version(text):
    """(major, minor, patch) from "0.17.0", "0.17.0-beta1" or "0.17"; None if it is not a version."""
    match = VERSION_RE.match(str(text or ""))
    return tuple(int(n or 0) for n in match.groups()) if match else None


@dataclass
class Settings:
    data_dir: Path
    public_url: str = ""
    signups: str = "invite"
    admin_emails: frozenset = field(default_factory=frozenset)
    session_days: int = 30
    allow_http: bool = False
    trust_proxy: bool = False
    name: str = "SecretBroker"
    max_body: int = 8 * 1024 * 1024
    # E-mail verification: "required" (invites only reach verified addresses) or "off" (explicit choice of a
    # self-hoster without e-mail). Without SMTP, "required" still works: the admin verifies from the command line.
    email_verification: str = "required"
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    smtp_security: str = "starttls"
    # Item deletions one account may make in an hour (a stolen session or a broken client wiping a team).
    max_deletes_per_hour: int = 100
    # Organization invites: how long one stays valid, and how many an organization (or an account) may create,
    # renew or re-send in an hour (each may send an e-mail: nobody uses the server to flood inboxes).
    invite_days: int = 14
    max_invites_per_hour: int = 30
    # The oldest desktop app this server serves (it says so with 426 client_too_old). Never below MIN_CLIENT.
    min_client: str = ""

    @property
    def db_path(self):
        return self.data_dir / "secretbroker.db"

    @property
    def oldest_client(self):
        """The minimum app version, as text: SB_MIN_CLIENT if it is newer than the built-in MIN_CLIENT."""
        mine = parse_version(self.min_client)
        return self.min_client if mine and mine > parse_version(MIN_CLIENT) else MIN_CLIENT

    @property
    def https(self):
        return self.public_url.startswith("https://")

    @property
    def smtp(self):
        return bool(self.smtp_host)

    @property
    def verification(self):
        """What /info tells clients: "email" (codes are e-mailed), "admin" (the admin verifies), "off"."""
        if self.email_verification == "off":
            return "off"
        return "email" if self.smtp else "admin"

    def check(self):
        """Refuse settings that would make the server unsafe to expose."""
        if self.signups not in SIGNUP_MODES:
            raise ConfigError(f"SB_SIGNUPS must be one of {', '.join(SIGNUP_MODES)}")
        if self.email_verification not in VERIFICATION_MODES:
            raise ConfigError(f"SB_EMAIL_VERIFICATION must be one of {', '.join(VERIFICATION_MODES)}")
        if self.smtp_security not in SMTP_SECURITY:
            raise ConfigError(f"SB_SMTP_SECURITY must be one of {', '.join(SMTP_SECURITY)}")
        if self.smtp and "@" not in self.smtp_from:
            raise ConfigError("SB_SMTP_FROM must be the sender address (for example secrets@example.com)")
        if self.max_deletes_per_hour < 1:
            raise ConfigError("SB_MAX_DELETES_PER_HOUR must be at least 1")
        if self.session_days < 1:
            raise ConfigError("SB_SESSION_DAYS must be at least 1")
        if not 1 <= self.invite_days <= 365:
            raise ConfigError("SB_INVITE_DAYS must be between 1 and 365")
        if self.max_invites_per_hour < 1:
            raise ConfigError("SB_MAX_INVITES_PER_HOUR must be at least 1")
        if self.min_client and parse_version(self.min_client) is None:
            raise ConfigError("SB_MIN_CLIENT must be a version such as 0.17.0")
        if self.public_url:
            parsed = urlparse(self.public_url)
            if parsed.scheme not in ("http", "https") or not parsed.netloc:
                raise ConfigError("SB_PUBLIC_URL must be a full URL such as https://secrets.example.com")
        if not self.https and not self.allow_http:
            raise ConfigError("SB_PUBLIC_URL must use https:// (set SB_ALLOW_HTTP=1 only for local tests)")
        return self


def _flag(value):
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def from_env(env=None):
    env = os.environ if env is None else env
    try:
        days = int(env.get("SB_SESSION_DAYS", "30"))
        max_body = int(env.get("SB_MAX_BODY", str(8 * 1024 * 1024)))
        smtp_port = int(env.get("SB_SMTP_PORT", "587"))
        max_deletes = int(env.get("SB_MAX_DELETES_PER_HOUR", "100"))
        invite_days = int(env.get("SB_INVITE_DAYS", "14"))
        max_invites = int(env.get("SB_MAX_INVITES_PER_HOUR", "30"))
    except ValueError as exc:
        raise ConfigError("SB_SESSION_DAYS, SB_MAX_BODY, SB_SMTP_PORT, SB_MAX_DELETES_PER_HOUR, SB_INVITE_DAYS and "
                          "SB_MAX_INVITES_PER_HOUR must be numbers") from exc
    emails = frozenset(e.strip().lower() for e in env.get("SB_ADMIN_EMAILS", "").split(",") if e.strip())
    return Settings(
        data_dir=Path(env.get("SB_DATA_DIR", "./data")).resolve(),
        public_url=env.get("SB_PUBLIC_URL", "").strip().rstrip("/"),
        signups=env.get("SB_SIGNUPS", "invite").strip().lower(),
        admin_emails=emails,
        session_days=days,
        allow_http=_flag(env.get("SB_ALLOW_HTTP", "")),
        trust_proxy=_flag(env.get("SB_TRUST_PROXY", "")),
        name=env.get("SB_SERVER_NAME", "SecretBroker").strip()[:64] or "SecretBroker",
        max_body=max_body,
        email_verification=env.get("SB_EMAIL_VERIFICATION", "required").strip().lower(),
        smtp_host=env.get("SB_SMTP_HOST", "").strip(),
        smtp_port=smtp_port,
        smtp_user=env.get("SB_SMTP_USER", "").strip(),
        smtp_password=env.get("SB_SMTP_PASSWORD", ""),
        smtp_from=env.get("SB_SMTP_FROM", "").strip(),
        smtp_security=env.get("SB_SMTP_SECURITY", "starttls").strip().lower(),
        max_deletes_per_hour=max_deletes,
        invite_days=invite_days,
        max_invites_per_hour=max_invites,
        min_client=env.get("SB_MIN_CLIENT", "").strip(),
    )


def server_secret(data_dir):
    """A random key that never leaves SB_DATA_DIR; it derives the fake prelogin salts.

    Created on first start. Losing it only changes the fake salts shown for unknown e-mails.
    """
    path = Path(data_dir) / "server_secret"
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:  # another worker created it first
            fd = None
        if fd is not None:
            with os.fdopen(fd, "w") as handle:
                handle.write(secrets.token_hex(32))
    return bytes.fromhex(path.read_text().strip())
