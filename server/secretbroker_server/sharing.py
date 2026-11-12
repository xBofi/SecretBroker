"""Collections: members and key grants, atomic re-keying, and items with collection-wide revisions.

Every write to a collection bumps its `revision` by one and stamps the touched items with it, so a client only
asks for `?since=<last revision it saw>`. Deleted items stay as tombstones so other devices learn about them.
"""

import json

from . import manifests
from .accounts import rate_limited
from .db import event, now_iso
from .orgs import delete_collection_rows, forbidden, not_found
from .validate import (PERMISSIONS, ApiError, body, deletion, dump, grant, integer, mapping, members_record, one_of,
                       path_id, query_int, sealed, uuid_id)
from .web import route

ITEM_MAX = 256 * 1024
NAME_MAX = 1024
WRITE = ("manage", "edit")


def collection_quota(settings):
    """All of a collection's ciphertext must fit in one rotate request, with room left for the grants."""
    return settings.max_body // 2


def access(conn, cid, uid):
    """The collection as seen by a confirmed member; anyone else gets 404."""
    row = conn.execute(
        "SELECT c.*, cm.permission, cm.grant_json FROM collections c "
        "JOIN collection_members cm ON cm.collection_id = c.id AND cm.user_id = ? "
        "JOIN org_members om ON om.org_id = c.org_id AND om.user_id = cm.user_id AND om.status = 'confirmed' "
        "WHERE c.id = ?", (uid, cid)).fetchone()
    if row is None:
        raise not_found()
    return row


def need(row, permissions):
    if row["permission"] not in permissions:
        raise forbidden("Tu permiso en esta colección no permite hacer esto.")


def _collection(ctx, permissions=PERMISSIONS):
    cid = path_id(ctx.params["cid"])
    row = access(ctx.conn, cid, ctx.uid)
    need(row, permissions)
    return cid, row


def _bump(conn, cid):
    conn.execute("UPDATE collections SET revision = revision + 1 WHERE id = ?", (cid,))
    return conn.execute("SELECT revision FROM collections WHERE id = ?", (cid,)).fetchone()[0]


def _managers(conn, cid):
    return conn.execute("SELECT COUNT(*) FROM collection_members WHERE collection_id = ? AND permission = 'manage'",
                        (cid,)).fetchone()[0]


def _own_grant(ctx, value):
    """Grants are signed by whoever hands out the key; the server only lets you hand out grants in your name."""
    if value["granted_by"] != ctx.uid:
        raise ApiError(400, "invalid", "grant: granted_by debe ser tu usuario.")
    return dump(value)


def _record(ctx, data, cid, key_version):
    """Store the signed member list that came with a membership change; required once the collection has one."""
    if data.get("members_record"):
        manifests.append(ctx.conn, cid, ctx.body["members_record"], data["members_record"], ctx.uid, key_version)
    elif manifests.required(ctx.conn, cid):
        raise ApiError(400, "members_record", "Falta la lista firmada de miembros. Actualiza SecretBroker.")


def _summary(row):
    return {"id": row["id"], "org_id": row["org_id"], "encrypted_name": json.loads(row["encrypted_name"]),
            "key_version": row["key_version"], "permission": row["permission"], "grant": json.loads(row["grant_json"]),
            "needs_rekey": bool(row["needs_rekey"]), "revision": row["revision"], "direct": bool(row["direct"])}


@route("GET", "/collections")
def list_collections(ctx):
    rows = ctx.conn.execute(
        "SELECT c.*, cm.permission, cm.grant_json FROM collections c "
        "JOIN collection_members cm ON cm.collection_id = c.id AND cm.user_id = ? "
        "JOIN org_members om ON om.org_id = c.org_id AND om.user_id = cm.user_id AND om.status = 'confirmed' "
        "ORDER BY c.created, c.id", (ctx.uid,)).fetchall()
    return [_summary(r) for r in rows]


@route("DELETE", "/collections/{cid}")
def delete_collection(ctx):
    cid, row = _collection(ctx, ("manage",))
    delete_collection_rows(ctx.conn, cid)
    event(ctx.conn, row["org_id"], ctx.uid, "collection.delete", cid)
    return {}


@route("GET", "/collections/{cid}/members")
def list_collection_members(ctx):
    cid, _ = _collection(ctx)
    rows = ctx.conn.execute("SELECT u.id, u.email, u.name, cm.permission FROM collection_members cm JOIN users u "
                            "ON u.id = cm.user_id WHERE cm.collection_id = ? ORDER BY u.email", (cid,)).fetchall()
    return [{"user_id": r["id"], "email": r["email"], "name": r["name"], "permission": r["permission"]} for r in rows]


@route("GET", "/collections/{cid}/manifest")
def list_manifest(ctx):
    """The signed member lists after `since` (all of them with since=0), oldest first."""
    cid, _ = _collection(ctx)
    return {"records": manifests.since(ctx.conn, cid, query_int(ctx.query, "since", 0))}


@route("PUT", "/collections/{cid}/members/{uid}")
def put_collection_member(ctx):
    """Add someone with a key grant, change their permission, or replace their grant."""
    data = body(ctx.body, {"permission": one_of(*PERMISSIONS)}, {"grant": grant, "members_record": members_record})
    cid, row = _collection(ctx, ("manage",))
    uid = path_id(ctx.params["uid"])
    current = ctx.conn.execute("SELECT permission FROM collection_members WHERE collection_id = ? AND user_id = ?",
                               (cid, uid)).fetchone()
    if (current is None or data["grant"]) and row["needs_rekey"]:
        raise ApiError(409, "needs_rekey", "Hay que cambiar la clave de la colección antes de dar acceso.")
    if current is None:
        if not data["grant"]:
            raise ApiError(400, "invalid", "Falta el campo grant.")
        if not ctx.conn.execute("SELECT 1 FROM org_members WHERE org_id = ? AND user_id = ? AND status = 'confirmed'",
                                (row["org_id"], uid)).fetchone():
            raise ApiError(400, "not_confirmed", "Esa persona aún no está confirmada en la organización.")
        if row["direct"] and ctx.conn.execute("SELECT COUNT(*) FROM collection_members WHERE collection_id = ?",
                                              (cid,)).fetchone()[0] >= 2:
            raise ApiError(400, "direct_full", "Esta colección es para compartir con una sola persona.")
        ctx.conn.execute("INSERT INTO collection_members (collection_id, user_id, permission, grant_json, key_version) "
                         "VALUES (?, ?, ?, ?, ?)", (cid, uid, data["permission"], _own_grant(ctx, data["grant"]),
                                                    row["key_version"]))
        _record(ctx, data, cid, row["key_version"])
        event(ctx.conn, row["org_id"], ctx.uid, "grant", f"{cid}/{uid}:{data['permission']}")
        return {}
    if current["permission"] == "manage" and data["permission"] != "manage" and _managers(ctx.conn, cid) == 1:
        raise ApiError(400, "last_manager", "La colección necesita al menos una persona que la gestione.")
    ctx.conn.execute("UPDATE collection_members SET permission = ? WHERE collection_id = ? AND user_id = ?",
                     (data["permission"], cid, uid))
    if data["grant"]:
        ctx.conn.execute("UPDATE collection_members SET grant_json = ?, key_version = ? WHERE collection_id = ? "
                         "AND user_id = ?", (_own_grant(ctx, data["grant"]), row["key_version"], cid, uid))
    _record(ctx, data, cid, row["key_version"])
    event(ctx.conn, row["org_id"], ctx.uid, "grant", f"{cid}/{uid}:{data['permission']}")
    return {}


@route("DELETE", "/collections/{cid}/members/{uid}")
def remove_collection_member(ctx):
    """Take someone out (or leave). They may still hold the key, so the collection must be re-keyed."""
    data = body(ctx.body, {}, {"members_record": members_record})
    cid, row = _collection(ctx)
    uid = path_id(ctx.params["uid"])
    if uid != ctx.uid:
        need(row, ("manage",))
    current = ctx.conn.execute("SELECT permission FROM collection_members WHERE collection_id = ? AND user_id = ?",
                               (cid, uid)).fetchone()
    if current is None:
        raise not_found()
    if current["permission"] == "manage" and _managers(ctx.conn, cid) == 1:
        raise ApiError(400, "last_manager", "La colección necesita al menos una persona que la gestione.")
    ctx.conn.execute("DELETE FROM collection_members WHERE collection_id = ? AND user_id = ?", (cid, uid))
    ctx.conn.execute("UPDATE collections SET needs_rekey = 1 WHERE id = ?", (cid,))
    _record(ctx, data, cid, row["key_version"])
    event(ctx.conn, row["org_id"], ctx.uid, "revoke", f"{cid}/{uid}")
    return {}


@route("POST", "/collections/{cid}/rotate")
def rotate(ctx):
    """Replace the collection key in one step: new name, a grant per member and every live item re-encrypted."""
    data = body(ctx.body, {
        "key_version": integer(2, 2**31), "encrypted_name": sealed(NAME_MAX),
        "grants": mapping(uuid_id, grant, 10_000), "items": mapping(uuid_id, sealed(ITEM_MAX), 100_000),
    }, {"members_record": members_record})
    cid, row = _collection(ctx, ("manage",))
    if data["key_version"] != row["key_version"] + 1:
        raise ApiError(409, "key_version", "La colección cambió de clave mientras tanto. Sincroniza y repite.",
                       key_version=row["key_version"])
    members = {r[0] for r in ctx.conn.execute("SELECT user_id FROM collection_members WHERE collection_id = ?",
                                              (cid,)).fetchall()}
    live = {r[0] for r in ctx.conn.execute("SELECT id FROM items WHERE collection_id = ? AND deleted = 0",
                                           (cid,)).fetchall()}
    if set(data["grants"]) != members:
        raise ApiError(400, "incomplete", "La nueva clave debe darse exactamente a los miembros actuales.")
    if set(data["items"]) != live:
        raise ApiError(400, "incomplete", "Hay que volver a cifrar exactamente todos los elementos de la colección.")
    version, revision, now = data["key_version"], _bump(ctx.conn, cid), now_iso()
    ctx.conn.execute("UPDATE collections SET key_version = ?, encrypted_name = ?, needs_rekey = 0 WHERE id = ?",
                     (version, dump(data["encrypted_name"]), cid))
    for uid, value in data["grants"].items():
        ctx.conn.execute("UPDATE collection_members SET grant_json = ?, key_version = ? WHERE collection_id = ? "
                         "AND user_id = ?", (_own_grant(ctx, value), version, cid, uid))
    for iid, ciphertext in data["items"].items():
        ctx.conn.execute("UPDATE items SET ciphertext = ?, key_version = ?, revision = ?, updated_by = ?, updated = ? "
                         "WHERE collection_id = ? AND id = ?", (dump(ciphertext), version, revision, ctx.uid, now,
                                                                cid, iid))
    _record(ctx, data, cid, version)
    event(ctx.conn, row["org_id"], ctx.uid, "rotate", f"{cid}:{version}")
    return {"revision": revision}


@route("GET", "/collections/{cid}/items")
def list_items(ctx):
    cid, row = _collection(ctx)
    since = query_int(ctx.query, "since", 0)
    rows = ctx.conn.execute("SELECT * FROM items WHERE collection_id = ? AND revision > ? ORDER BY revision, id",
                            (cid, since)).fetchall()
    items = [{"id": r["id"], "revision": r["revision"], "key_version": r["key_version"],
              "ciphertext": json.loads(r["ciphertext"]) if r["ciphertext"] else None, "deleted": bool(r["deleted"]),
              "updated_by": r["updated_by"], "updated": r["updated"],
              **({"deletion": json.loads(r["deletion"])} if r["deleted"] and r["deletion"] else {})} for r in rows]
    return {"revision": row["revision"], "items": items}


def _item(ctx, cid):
    iid = path_id(ctx.params["iid"])
    return iid, ctx.conn.execute("SELECT revision, deleted FROM items WHERE collection_id = ? AND id = ?",
                                 (cid, iid)).fetchone()


def conflict(revision):
    return ApiError(409, "conflict", "Alguien cambió este elemento antes. Sincroniza para ver su versión.",
                    revision=revision)


@route("PUT", "/collections/{cid}/items/{iid}")
def put_item(ctx):
    """Create (base_revision 0) or update an item; a stale base_revision is a 409 with the current revision."""
    data = body(ctx.body, {"ciphertext": sealed(ITEM_MAX), "key_version": integer(1, 2**31),
                           "base_revision": integer(0, 2**62)})
    cid, row = _collection(ctx, WRITE)
    iid, item = _item(ctx, cid)
    if data["key_version"] != row["key_version"]:
        raise ApiError(409, "key_version", "La colección cambió de clave. Sincroniza y repite.",
                       key_version=row["key_version"])
    if row["needs_rekey"]:
        # Someone who left still holds this key: nothing new is written with it until a manager re-keys.
        raise ApiError(409, "needs_rekey", "Hay que cambiar la clave de la colección antes de guardar cambios. "
                       "Lo hace quien la gestiona al sincronizar.")
    current = item["revision"] if item else 0
    if data["base_revision"] != current:
        raise conflict(current)
    stored = ctx.conn.execute("SELECT COALESCE(SUM(LENGTH(ciphertext)), 0) FROM items WHERE collection_id = ? "
                              "AND id != ? AND deleted = 0", (cid, iid)).fetchone()[0]
    if stored + len(dump(data["ciphertext"])) > collection_quota(ctx.settings):
        raise ApiError(413, "collection_full", "La colección está llena: reparte sus credenciales en otra.")
    revision = _bump(ctx.conn, cid)
    ctx.conn.execute(
        "INSERT INTO items (collection_id, id, revision, key_version, ciphertext, deleted, updated_by, updated) "
        "VALUES (?, ?, ?, ?, ?, 0, ?, ?) ON CONFLICT (collection_id, id) DO UPDATE SET revision = excluded.revision, "
        "key_version = excluded.key_version, ciphertext = excluded.ciphertext, deleted = 0, deletion = NULL, "
        "updated_by = excluded.updated_by, updated = excluded.updated",
        (cid, iid, revision, data["key_version"], dump(data["ciphertext"]), ctx.uid, now_iso()))
    event(ctx.conn, row["org_id"], ctx.uid, "item.put", f"{cid}/{iid}")
    return {"revision": revision}


@route("DELETE", "/collections/{cid}/items/{iid}")
def delete_item(ctx):
    """Leave a tombstone (no ciphertext) so every device removes its copy. `deletion` is the deleter's signature:
    clients ignore a tombstone nobody with edit rights signed. Each account deletes at most SB_MAX_DELETES_PER_HOUR
    items an hour, so a stolen session or a broken client cannot wipe a team in one go."""
    data = body(ctx.body, {"base_revision": integer(0, 2**62)}, {"deletion": deletion})
    cid, row = _collection(ctx, WRITE)
    iid, item = _item(ctx, cid)
    if item is None:
        raise not_found()
    if data["base_revision"] != item["revision"]:
        raise conflict(item["revision"])
    if item["deleted"]:
        return {"revision": item["revision"]}
    if data["deletion"] and data["deletion"]["by"] != ctx.uid:
        raise ApiError(400, "invalid", "deletion: by debe ser tu usuario.")
    wait = ctx.server.delete_window.hit(ctx.uid)
    if wait:
        raise rate_limited(wait)
    revision = _bump(ctx.conn, cid)
    ctx.conn.execute("UPDATE items SET revision = ?, ciphertext = NULL, deleted = 1, updated_by = ?, updated = ?, "
                     "deletion = ? WHERE collection_id = ? AND id = ?",
                     (revision, ctx.uid, now_iso(), dump(ctx.body["deletion"]) if data["deletion"] else None, cid, iid))
    event(ctx.conn, row["org_id"], ctx.uid, "item.delete", f"{cid}/{iid}")
    return {"revision": revision}
