"""Placeholder substitution and output redaction."""

import base64
import json
from urllib.parse import quote, quote_plus

from .templates import PLACEHOLDER_RE, placeholder_values, secret_values


class ActionError(Exception):
    pass


def substitute(text, entry, escape=None):
    """Replace {{field}} placeholders with values from the entry."""
    values = placeholder_values(entry)

    def replace(match):
        name = match.group(1)
        if name not in values:
            raise ActionError(f"El dato {{{{{name}}}}} no está disponible en '{entry['id']}'")
        return escape(values[name]) if escape else values[name]

    return PLACEHOLDER_RE.sub(replace, text)


def encodings(value):
    """The forms a value usually takes once embedded in text: raw, JSON, URL and base64."""
    yield value
    json_escaped = json.dumps(value)[1:-1]
    yield json_escaped
    yield json.dumps(json_escaped)[1:-1]  # JSON embedded inside JSON (e.g. echoed request bodies)
    yield base64.b64encode(value.encode()).decode()
    yield base64.b64encode(value.encode()).decode().rstrip("=")
    yield quote(value, safe="")
    yield quote_plus(value)


def _variants(value):
    yield from encodings(value)
    for line in value.splitlines():
        if len(line.strip()) >= 16:  # individual lines of a private key
            yield line.strip()


def redaction_forms(secrets):
    """Every form of these secrets worth removing from output, longest first."""
    values = {v for secret in secrets for v in _variants(secret) if len(v) >= 3}
    return sorted(values, key=len, reverse=True)


class Redactor:
    """Removes any known encoding of the entry's secrets from text returned to the agent."""

    def __init__(self, entry):
        self._values = redaction_forms(secret_values(entry))
        self._label = f"[REDACTED:{entry['id']}]"

    def __call__(self, text):
        for value in self._values:
            text = text.replace(value, self._label)
        return text
