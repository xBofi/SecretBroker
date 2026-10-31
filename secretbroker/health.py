"""Vault health: weak, reused, old, expired and exposed secrets, unfinished rotations, with a score.

Computed by the service, which alone has the values. The app gets names, reasons and counts, never a
value: reuse is found by comparing keyed fingerprints (vault.mac), so not even a hash of a password
leaves the service.

Without a search for copies and a check with the providers the report cannot say a secret is fine,
so it also says when each last ran (`scanned`, `checked`) and whether both have (`complete`).
"""

from . import exposure, generator, templates

# How much each problem takes away from a credential (1: as bad as it gets). A credential counts
# once, by its worst problem.
WEIGHTS = {"exposed": 1.0, "pwned": 1.0, "team_access": 1.0, "reused": 1.0, "weak": 1.0, "expired": 1.0,
           "old_alive": 0.7, "upload_failed": 0.6, "half_rotated": 0.6, "expiring": 0.5, "old": 0.5,
           "retired_pending": 0.4, "was_exposed": 0.3, "unchecked": 0.1}
ORDER = list(WEIGHTS)
LABELS = {"exposed": "Expuesta", "pwned": "En filtraciones", "team_access": "Alguien tenía acceso", "reused": "Repetida",
          "weak": "Débil", "expired": "Caducada", "old_alive": "La anterior sigue viva", "upload_failed": "Subida fallida",
          "half_rotated": "Rotación a medias", "expiring": "Caduca pronto", "old": "Antigua",
          "retired_pending": "Falta anular la anterior", "was_exposed": "Estuvo expuesta", "unchecked": "Sin probar"}


def _days(n):
    return f"{n} día" if n == 1 else f"{n} días"


def _people(names):
    names = [str(n) for n in names] or ["Una persona"]
    who = names[0] if len(names) == 1 else ", ".join(names[:-1]) + " y " + names[-1]
    return f"{who} {'tenía' if len(names) == 1 else 'tenían'} acceso"


def _left_team(reminder):
    """Someone with access left the team: the same words as the credential's own reminder."""
    many = len(reminder.get("people") or []) > 1
    return (f"{_people(reminder.get('people') or [])} y ya no {'están' if many else 'está'} en el equipo: "
            + (f"cámbiala por si la {'vieron' if many else 'vio'}." if reminder.get("can_rotate")
               else "pide a quien la gestiona que la cambie."))


def key_values(entry):
    """The secret values of an entry that should be unique (passwords, keys), by field."""
    return {name: str(entry["fields"][name]) for name in templates.key_field_names(entry["template"])
            if entry["fields"].get(name) and name not in ("passphrase",)}


def reuse_groups(entries, mac):
    """{entry id: [other entry ids with the same value]} for every value used by more than one entry."""
    owners = {}
    for entry in entries:
        for value in key_values(entry).values():
            if len(value.strip()) >= 4:
                owners.setdefault(mac(b"health/reuse\0" + value.encode("utf-8")), set()).add(entry["id"])
    reused = {}
    for ids in owners.values():
        if len(ids) > 1:
            for entry_id in ids:
                reused.setdefault(entry_id, set()).update(ids - {entry_id})
    return {k: sorted(v) for k, v in reused.items()}


def _issues(entry, reused, names, reminder, exposure_item, state):
    issues = []
    level = (exposure_item or {}).get("level")
    if (exposure_item or {}).get("found"):
        issues.append(("exposed", "Está en claro en algún archivo de este PC."))
    elif (exposure_item or {}).get("found_before"):
        issues.append(("was_exposed", "Estuvo en claro en algún archivo. Conviene rotarla."))
    alive = (exposure_item or {}).get("alive") or {}
    if level == "exposed" and alive.get("status") == "invalid" and alive.get("was_ok"):
        issues.append(("exposed", "Ha dejado de funcionar: puede que el proveedor la haya revocado por filtrada."))
    pwned = ((exposure_item or {}).get("pwned") or {}).get("count")
    if pwned:
        issues.append(("pwned", f"Aparece {pwned:,} veces en filtraciones públicas.".replace(",", ".")))
    if reused:
        others = ", ".join(names.get(i, i) for i in reused[:3]) + (f" y {len(reused) - 3} más" if len(reused) > 3 else "")
        issues.append(("reused", f"La misma contraseña o clave está en {others}."))
    password = exposure.password_of(entry)
    if password:
        rating = generator.strength(password)
        if rating["score"] <= 1:
            issues.append(("weak", f"Contraseña {rating['label'].lower()}: se adivinaría pronto."))
    if reminder:
        kind, days = reminder["kind"], reminder.get("days")
        text = {"expired": f"Caducó hace {_days(days or 0)}.", "expiring": f"Caduca en {_days(days or 0)}.",
                "old": f"La clave tiene {_days(days or 0)}.",
                "old_alive": "La rotaste, pero la anterior sigue funcionando: anúlala.",
                "team_access": _left_team(reminder)}.get(kind)
        if text:
            issues.append((kind, text))
    retired = state.get("retired")
    if retired and retired.get("status") != "alive":
        issues.append(("retired_pending", f"Clave nueva activa · falta anular la anterior en {retired.get('provider') or 'el proveedor'}."))
    failed = state.get("failed_uploads") or []
    if failed:
        issues.append(("upload_failed", f"No se pudo subir la nueva a {failed[0].get('label')}"
                                        + (f" ni a {len(failed) - 1} sitio{'s' if len(failed) > 2 else ''} más" if len(failed) > 1 else "")
                                        + ": ahí sigue la anterior."))
    if state.get("pending"):
        issues.append(("half_rotated", "Hay una contraseña nueva preparada que aún no se ha guardado como la actual: "
                                       "termina la rotación o descártala."))
    if state.get("testable") and exposure_item is not None and not (exposure_item.get("alive") or {}).get("checked"):
        issues.append(("unchecked", "Aún no se ha probado si funciona."))
    seen, unique = set(), []
    for kind, text in sorted(issues, key=lambda i: ORDER.index(i[0])):
        if kind not in seen:
            seen.add(kind)
            unique.append({"kind": kind, "label": LABELS[kind], "text": text})
    return unique


def report(entries, mac, reminders, exposure_items, states=None, scanned=None, checked=None):
    """{"score": 0-100, "total", "counts": {kind: n}, "items": [{id, name, template, issues}], "scanned", "checked",
    "complete"}, worst first. `states`: {entry id: {"retired", "failed_uploads", "pending", "testable"}}."""
    states = states or {}
    entries = [e for e in entries if not e.get("draft")]
    names = {e["id"]: e.get("name") or e["id"] for e in entries}
    reused = reuse_groups(entries, mac)
    reminders = {r["id"]: r for r in reminders}
    exposure_items = {item["id"]: item for item in exposure_items}
    items, penalty, counts = [], 0.0, {kind: 0 for kind in WEIGHTS}
    for entry in entries:
        issues = _issues(entry, reused.get(entry["id"]), names, reminders.get(entry["id"]), exposure_items.get(entry["id"]),
                         states.get(entry["id"]) or {})
        if not issues:
            continue
        for issue in issues:
            counts[issue["kind"]] += 1
        worst = max(WEIGHTS[i["kind"]] for i in issues)
        penalty += worst
        items.append({"id": entry["id"], "name": names[entry["id"]], "template": entry["template"],
                      "issues": issues, "weight": worst})
    items.sort(key=lambda i: (-i["weight"], ORDER.index(i["issues"][0]["kind"]), i["name"].lower()))
    score = 100 if not entries else round(100 * (1 - penalty / len(entries)))
    return {"score": score, "total": len(entries), "healthy": len(entries) - len(items), "counts": counts, "items": items,
            "scanned": scanned, "checked": checked, "complete": bool(scanned and checked)}
