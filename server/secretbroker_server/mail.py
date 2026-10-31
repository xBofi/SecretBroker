"""Verification e-mails over SMTP (SB_SMTP_*). Nothing else is ever e-mailed: invites travel as links people pass on.

Codes are 8 digits, valid 30 minutes, at most 5 wrong tries each; only an HMAC of the code is stored.
"""

import hashlib
import hmac
import logging
import secrets
import smtplib
import ssl
from email.message import EmailMessage

log = logging.getLogger("secretbroker_server")

CODE_SECONDS = 30 * 60
CODE_TRIES = 5
RESEND_SECONDS = 60  # one code a minute per account, so nobody uses the server to flood an inbox


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
