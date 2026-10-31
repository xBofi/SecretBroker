"""Signed member lists of collections (docs/ARCHITECTURE.md 2.6).

Every change to who is in a collection (create, grant, permission change, removal, re-key) comes with the new list,
signed by the person making it and chained to the previous one by its hash. The server stores the chain as it got
it; clients verify the signatures and refuse a member list (or a key grant) the chain does not back. Here the server
only checks that each record is the next link and describes what it is about to store, so an honest server never
keeps a chain that disagrees with itself.
"""

import hashlib
import json

from .validate import ApiError, dump


def body_hash(body):
    """Must match the client's canonical form (secretbroker/teams.py _canonical)."""
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                          .encode("utf-8")).hexdigest()


def last(conn, cid):
    return conn.execute("SELECT seq, hash FROM collection_manifests WHERE collection_id = ? ORDER BY seq DESC "
                        "LIMIT 1", (cid,)).fetchone()


def members(conn, cid):
    return {r[0]: r[1] for r in conn.execute("SELECT user_id, permission FROM collection_members "
                                             "WHERE collection_id = ?", (cid,)).fetchall()}


def required(conn, cid):
    """Once a collection has a signed list, every membership change must carry the next one."""
    return last(conn, cid) is not None


def append(conn, cid, raw, record, caller, key_version):
    """Store `raw` (exactly what the client signed) as the next record, after checking it matches the table."""
    body = record["body"]
    previous = last(conn, cid)
    problems = []
    if body["cid"] != cid:
        problems.append("es de otra colección")
    if body["by"] != caller:
        problems.append("by debe ser tu usuario")
    if body["seq"] != (previous["seq"] + 1 if previous else 1):
        problems.append("no es la siguiente versión")
    if (body.get("prev") or None) != (previous["hash"] if previous else None):
        problems.append("no sigue a la anterior")
    if body["key_version"] != key_version:
        problems.append("tiene otra versión de clave")
    if body["members"] != members(conn, cid):
        problems.append("no coincide con los miembros")
    if problems:
        raise ApiError(409 if previous and body["seq"] <= previous["seq"] else 400, "members_record",
                       "La lista firmada de miembros no es válida: " + ", ".join(problems) + ". Sincroniza y repite.")
    conn.execute("INSERT INTO collection_manifests (collection_id, seq, record, hash) VALUES (?, ?, ?, ?)",
                 (cid, body["seq"], dump(raw), body_hash(raw["body"])))


def since(conn, cid, seq):
    rows = conn.execute("SELECT record FROM collection_manifests WHERE collection_id = ? AND seq > ? ORDER BY seq",
                        (cid, seq)).fetchall()
    return [json.loads(r[0]) for r in rows]
