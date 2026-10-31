"""Vault health: weak, reused, old, expired and exposed secrets, with a score.

Computed by the service, which alone has the values. The app gets names, reasons and counts, never a
value: reuse is found by comparing keyed fingerprints (vault.mac), so not even a hash of a password
leaves the service.
"""

from . import exposure, generator, templates

# How much each problem takes away from a credential (1: as bad as it gets). A credential counts
# once, by its worst problem.
WEIGHTS = {"exposed": 1.0, "pwned": 1.0, "reused": 1.0, "weak": 1.0, "expired": 1.0, "old_alive": 0.7,
           "expiring": 0.5, "old": 0.5, "was_exposed": 0.3}
ORDER = list(WEIGHTS)
LABELS = {"exposed": "Expuesta", "pwned": "En filtraciones", "reused": "Repetida", "weak": "Débil",
          "expired": "Caducada", "old_alive": "La anterior sigue viva", "expiring": "Caduca pronto", "old": "Antigua",
          "was_exposed": "Estuvo expuesta"}


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


def _issues(entry, reused, names, reminder, exposure_item):
    issues = []
    level = (exposure_item or {}).get("level")
    if (exposure_item or {}).get("found"):
        issues.append(("exposed", "Está en claro en algún archivo de este equipo."))
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
        text = {"expired": f"Caducó hace {days} día(s).", "expiring": f"Caduca en {days} día(s).",
                "old": f"La clave tiene {days} días.",
                "old_alive": "La rotaste, pero la anterior sigue funcionando: bórrala."}.get(kind)
        if text:
            issues.append((kind, text))
    seen, unique = set(), []
    for kind, text in sorted(issues, key=lambda i: ORDER.index(i[0])):
        if kind not in seen:
            seen.add(kind)
            unique.append({"kind": kind, "label": LABELS[kind], "text": text})
    return unique


def report(entries, mac, reminders, exposure_items):
    """{"score": 0-100, "total", "counts": {kind: n}, "items": [{id, name, template, issues}]}, worst first."""
    entries = [e for e in entries if not e.get("draft")]
    names = {e["id"]: e.get("name") or e["id"] for e in entries}
    reused = reuse_groups(entries, mac)
    reminders = {r["id"]: r for r in reminders}
    exposure_items = {item["id"]: item for item in exposure_items}
    items, penalty, counts = [], 0.0, {kind: 0 for kind in WEIGHTS}
    for entry in entries:
        issues = _issues(entry, reused.get(entry["id"]), names, reminders.get(entry["id"]), exposure_items.get(entry["id"]))
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
    return {"score": score, "total": len(entries), "healthy": len(entries) - len(items), "counts": counts, "items": items}
