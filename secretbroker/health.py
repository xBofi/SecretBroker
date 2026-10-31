"""Vault health: weak, reused, old, expired and exposed secrets, unfinished rotations, with a score.

Computed by the service, which alone has the values. The app gets names, reasons and counts, never a
value: reuse is found by comparing keyed fingerprints (vault.mac), so not even a hash of a password
leaves the service.

Without a search for copies and a check with the providers the report cannot say a secret is fine,
so it also says when each last ran (`scanned`, `checked`) and whether both have (`complete`).
"""

from . import exposure, generator, templates
from .i18n import tr

# How much each problem takes away from a credential (1: as bad as it gets). A credential counts
# once, by its worst problem.
WEIGHTS = {"exposed": 1.0, "pwned": 1.0, "team_access": 1.0, "reused": 1.0, "weak": 1.0, "expired": 1.0,
           "old_alive": 0.7, "upload_failed": 0.6, "half_rotated": 0.6, "expiring": 0.5, "old": 0.5,
           "retired_pending": 0.4, "was_exposed": 0.3, "unchecked": 0.1}
ORDER = list(WEIGHTS)
# The label of each problem: messages health.label_<kind>.
LABELS = {kind: f"health.label_{kind}" for kind in ORDER}


def _left_team(reminder):
    """Someone with access left the team: the same words as the credential's own reminder."""
    names = [str(n) for n in reminder.get("people") or []]
    who = (names[0] if len(names) == 1 else tr("health.list_and", names=", ".join(names[:-1]), last=names[-1])) if names \
        else tr("health.a_person")
    return tr("health.left_team_rotate" if reminder.get("can_rotate") else "health.left_team_ask", count=max(len(names), 1), who=who)


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
        issues.append(("exposed", tr("health.exposed")))
    elif (exposure_item or {}).get("found_before"):
        issues.append(("was_exposed", tr("health.was_exposed")))
    alive = (exposure_item or {}).get("alive") or {}
    if level == "exposed" and alive.get("status") == "invalid" and alive.get("was_ok"):
        issues.append(("exposed", tr("health.stopped_working")))
    pwned = ((exposure_item or {}).get("pwned") or {}).get("count")
    if pwned:
        issues.append(("pwned", tr("health.pwned", count=pwned, times=f"{pwned:,}".replace(",", tr("health.thousands_separator")))))
    if reused:
        others = ", ".join(names.get(i, i) for i in reused[:3])
        issues.append(("reused", tr("health.reused_more", names=others, count=len(reused) - 3) if len(reused) > 3
                       else tr("health.reused", names=others)))
    password = exposure.password_of(entry)
    if password:
        rating = generator.strength(password)
        if rating["score"] <= 1:
            issues.append(("weak", tr(f"health.weak_{rating['score']}")))
    if reminder:
        kind, days = reminder["kind"], reminder.get("days")
        text = {"expired": lambda: tr("health.expired", count=days or 0), "expiring": lambda: tr("health.expiring", count=days or 0),
                "old": lambda: tr("health.old", count=days or 0), "old_alive": lambda: tr("health.old_alive"),
                "team_access": lambda: _left_team(reminder)}.get(kind)
        text = text and text()
        if text:
            issues.append((kind, text))
    retired = state.get("retired")
    if retired and retired.get("status") != "alive":
        issues.append(("retired_pending", tr("health.retired_pending", provider=retired.get("provider") or tr("health.the_provider"))))
    failed = state.get("failed_uploads") or []
    if failed:
        issues.append(("upload_failed", tr("health.upload_failed_more", place=failed[0].get("label"), count=len(failed) - 1)
                        if len(failed) > 1 else tr("health.upload_failed", place=failed[0].get("label"))))
    if state.get("pending"):
        issues.append(("half_rotated", tr("health.half_rotated")))
    if state.get("testable") and exposure_item is not None and not (exposure_item.get("alive") or {}).get("checked"):
        issues.append(("unchecked", tr("health.unchecked")))
    seen, unique = set(), []
    for kind, text in sorted(issues, key=lambda i: ORDER.index(i[0])):
        if kind not in seen:
            seen.add(kind)
            unique.append({"kind": kind, "label": tr(LABELS[kind]), "text": text})
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
