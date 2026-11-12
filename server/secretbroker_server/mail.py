"""E-mails over SMTP (SB_SMTP_*): verification codes and organization invites. Nothing else is ever e-mailed.

Codes are 8 digits, valid 30 minutes, at most 5 wrong tries each; only an HMAC of the code is stored.
An invite e-mail carries what the person needs to join: the server address, their e-mail and the invite id (a
sign-up code for that e-mail only, the same one the join link the admin can copy carries). Never a secret.
"""

import hashlib
import hmac
import logging
import secrets
import smtplib
import ssl
from datetime import datetime, timezone
from email.message import EmailMessage
from urllib.parse import urlencode

log = logging.getLogger("secretbroker_server")

CODE_SECONDS = 30 * 60
CODE_TRIES = 5
RESEND_SECONDS = 60  # one code a minute per account, so nobody uses the server to flood an inbox
INVITE_RESEND_SECONDS = 10 * 60  # the same invite e-mailed again at most every 10 minutes
DOWNLOAD_URL = "https://github.com/xBofi/SecretBroker/releases/latest"


def new_code():
    return f"{secrets.randbelow(10**8):08d}"


def code_hash(secret, user_id, code):
    return hmac.new(secret, f"secretbroker/email-code/v1|{user_id}|{code}".encode("utf-8"), hashlib.sha256).hexdigest()


def message(settings, to, code):
    msg = EmailMessage()
    msg["From"] = settings.smtp_from
    msg["To"] = to
    msg["Subject"] = f"Tu código de {settings.name}: {code}"
    msg.set_content(
        f"Tu código para verificar este e-mail en {settings.name} es:\n\n    {code}\n\n"
        "Escríbelo en SecretBroker › Equipo. Caduca en 30 minutos.\n"
        "Si no has creado una cuenta, ignora este mensaje: sin el código nadie puede usar tu dirección.\n\n"
        f"Your {settings.name} verification code is {code}. It expires in 30 minutes.\n")
    return msg


def join_link(server, email, code):
    return "secretbroker://join?" + urlencode({"server": server, "email": email, "code": code})


def invite_message(settings, to, code, org_name, inviter, expires):
    """The invite: the join link, and the same steps in plain words for someone without SecretBroker yet."""
    link = join_link(settings.public_url, to, code)
    until = datetime.fromtimestamp(expires, timezone.utc).strftime("%Y-%m-%d")
    msg = EmailMessage()
    msg["From"] = settings.smtp_from
    msg["To"] = to
    msg["Subject"] = f"{inviter} te invita a «{org_name}» en SecretBroker"
    lines = [
        f"{inviter} te ha invitado al equipo «{org_name}» en SecretBroker, para compartir credenciales cifradas de "
        "extremo a extremo.",
        "",
        "Si ya tienes SecretBroker, abre este enlace: rellena el formulario de Equipo (no lleva ninguna contraseña).",
        "",
        f"    {link}",
        "",
        "Si aún no lo tienes:",
        f"  1. Descárgalo e instálalo: {DOWNLOAD_URL}",
        "  2. Abre el enlace de arriba o, en SecretBroker, ve a Equipo y escribe:",
        f"       Servidor: {settings.public_url}",
        f"       E-mail: {to}",
        f"       Código de invitación: {code}",
        "  3. Crea tu cuenta (con una contraseña nueva, solo tuya) y acepta la invitación.",
        f"  4. {inviter} te confirmará comparando tu código de seguridad (Equipo › Tu cuenta) por teléfono o en "
        "persona.",
        "",
        f"La invitación caduca el {until} (UTC). Nadie te pedirá nunca tu contraseña por e-mail. Si no esperabas "
        "esta invitación, ignora este mensaje.",
        "",
        "---",
        "",
        f"{inviter} invited you to the team “{org_name}” on SecretBroker. If you have SecretBroker, open the link "
        f"above. If not, install it from {DOWNLOAD_URL}, then open the link, or go to Team and type the server, "
        f"your e-mail and the invitation code shown above. The invitation expires on {until} (UTC). Nobody will "
        "ever ask for your password by e-mail. If you did not expect it, ignore this message.",
    ]
    msg.set_content("\n".join(lines) + "\n")
    return msg


def send_invite(settings, to, code, org_name, inviter, expires):
    """True if the invite was handed to the SMTP server (False without SMTP or on failure, which is logged)."""
    if not settings.smtp or not settings.public_url:
        return False
    try:
        deliver(settings, invite_message(settings, to, code, org_name, inviter, expires))
        return True
    except (OSError, smtplib.SMTPException) as exc:
        log.warning("Could not send an invite e-mail: %s", type(exc).__name__)
        return False


def deliver(settings, msg):
    """Send one message. Kept apart so tests can capture what would be sent."""
    context = ssl.create_default_context()
    if settings.smtp_security == "ssl":
        client = smtplib.SMTP_SSL(settings.smtp_host, settings.smtp_port, timeout=20, context=context)
    else:
        client = smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=20)
    with client:
        if settings.smtp_security == "starttls":
            client.starttls(context=context)
        if settings.smtp_user:
            client.login(settings.smtp_user, settings.smtp_password)
        client.send_message(msg)


def send_code(settings, to, code):
    """True if the message was handed to the SMTP server. Failures are logged, never shown with details."""
    try:
        deliver(settings, message(settings, to, code))
        return True
    except (OSError, smtplib.SMTPException) as exc:
        log.warning("Could not send a verification e-mail: %s", type(exc).__name__)
        return False
