"""Administration: users, roles, OAuth clients and the audit log."""
from flask import Blueprint, g, jsonify, request

from . import int_arg, json_body
from .. import audit, clients, tokens, users, util
from ..db import get_db, transaction
from ..errors import ApiError
from ..policy import PERMISSIONS
from ..rbac import require_permissions

bp = Blueprint("admin", __name__, url_prefix="/admin")


def _target_user(user_id):
    user = users.get_user(user_id)
    if user is None:
        raise ApiError(404, "not_found", "User not found")
    return user


def _active_admins_excluding(user_id) -> int:
    return get_db().execute(
        "SELECT COUNT(*) FROM users u JOIN user_roles ur ON ur.user_id = u.id "
        "WHERE ur.role = 'admin' AND u.is_active = 1 AND u.id != ?", (user_id,)).fetchone()[0]


# ------------------------------------------------------------------- users
@bp.get("/users")
@require_permissions("users:read")
def list_users():
    limit, offset = int_arg("limit", 50, 1, 100), int_arg("offset", 0, 0, 10**9)
    q = (request.args.get("q") or "").strip().lower()
    where, args = ("WHERE email LIKE ? ESCAPE '\\'", [f"%{q.replace('%', '').replace('_', '')}%"]) if q else ("", [])
    db = get_db()
    total = db.execute(f"SELECT COUNT(*) FROM users {where}", args).fetchone()[0]
    rows = db.execute(f"SELECT * FROM users {where} ORDER BY created_at, id LIMIT ? OFFSET ?", args + [limit, offset])
    return jsonify({"items": [users.serialize(r) for r in rows], "total": total, "limit": limit, "offset": offset})


@bp.get("/users/<user_id>")
@require_permissions("users:read")
def get_user(user_id):
    return jsonify(users.serialize(_target_user(user_id), with_permissions=True))


@bp.put("/users/<user_id>/roles")
@require_permissions("roles:manage")
def set_roles(user_id):
    target = _target_user(user_id)
    roles = json_body().get("roles")
    if not isinstance(roles, list) or not roles or not all(isinstance(r, str) for r in roles):
        raise ApiError(400, "invalid_request", "roles must be a non-empty list of role names")
    roles = sorted(set(roles))
    known = {r["name"] for r in get_db().execute("SELECT name FROM roles")}
    if not set(roles) <= known:
        raise ApiError(400, "invalid_request", f"Unknown role(s): {', '.join(sorted(set(roles) - known))}")

    before = users.user_roles(target["id"])
    if "admin" in before and "admin" not in roles:
        if target["id"] == g.auth.subject:
            raise ApiError(400, "forbidden_change", "You cannot remove your own admin role")
        if target["is_active"] and _active_admins_excluding(target["id"]) == 0:
            raise ApiError(400, "forbidden_change", "Cannot remove the last active admin")

    db = get_db()
    with transaction(db):
        db.execute("DELETE FROM user_roles WHERE user_id = ?", (target["id"],))
        db.executemany("INSERT INTO user_roles(user_id, role) VALUES (?, ?)", [(target["id"], r) for r in roles])
    audit.log("user.roles_changed", actor_id=g.auth.subject, target=target["id"],
              details={"before": before, "after": roles})
    return jsonify(users.serialize(users.get_user(target["id"]), with_permissions=True))


@bp.post("/users/<user_id>/disable")
@require_permissions("users:write")
def disable_user(user_id):
    target = _target_user(user_id)
    if target["id"] == g.auth.subject:
        raise ApiError(400, "forbidden_change", "You cannot disable your own account")
    if "admin" in users.user_roles(target["id"]) and _active_admins_excluding(target["id"]) == 0:
        raise ApiError(400, "forbidden_change", "Cannot disable the last active admin")
    get_db().execute("UPDATE users SET is_active = 0, updated_at = ? WHERE id = ?", (util.now(), target["id"]))
    revoked = tokens.revoke_all_for_user(target["id"])
    users.bump_token_version(target["id"])
    audit.log("user.disabled", actor_id=g.auth.subject, target=target["id"], details={"sessions_revoked": revoked})
    return jsonify(users.serialize(users.get_user(target["id"])))


@bp.post("/users/<user_id>/enable")
@require_permissions("users:write")
def enable_user(user_id):
    target = _target_user(user_id)
    get_db().execute("UPDATE users SET is_active = 1, failed_attempts = 0, locked_until = 0, updated_at = ? WHERE id = ?",
                     (util.now(), target["id"]))
    audit.log("user.enabled", actor_id=g.auth.subject, target=target["id"])
    return jsonify(users.serialize(users.get_user(target["id"])))


# ------------------------------------------------------------------- roles
@bp.get("/roles")
@require_permissions("users:read")
def list_roles():
    db = get_db()
    out = []
    for r in db.execute("SELECT * FROM roles ORDER BY name"):
        perms = [p["permission"] for p in
                 db.execute("SELECT permission FROM role_permissions WHERE role = ? ORDER BY permission", (r["name"],))]
        out.append({"name": r["name"], "description": r["description"], "permissions": perms})
    return jsonify({"items": out, "available_permissions": PERMISSIONS})


@bp.post("/roles")
@require_permissions("roles:manage")
def create_role():
    data = json_body()
    name, perms = data.get("name"), data.get("permissions")
    if not isinstance(name, str) or not name.replace("-", "").replace("_", "").isalnum() or len(name) > 40:
        raise ApiError(400, "invalid_request", "name must be alphanumeric (with - or _), max 40 chars")
    if not isinstance(perms, list) or not perms or not set(perms) <= set(PERMISSIONS):
        raise ApiError(400, "invalid_request", f"permissions must be a non-empty subset of {sorted(PERMISSIONS)}")
    desc = data.get("description") if isinstance(data.get("description"), str) else ""
    db = get_db()
    if db.execute("SELECT 1 FROM roles WHERE name = ?", (name,)).fetchone():
        raise ApiError(409, "role_exists", "Role already exists")
    with transaction(db):
        db.execute("INSERT INTO roles(name, description) VALUES (?, ?)", (name, desc[:200]))
        db.executemany("INSERT INTO role_permissions(role, permission) VALUES (?, ?)", [(name, p) for p in set(perms)])
    audit.log("role.created", actor_id=g.auth.subject, target=name, details={"permissions": sorted(set(perms))})
    return jsonify({"name": name, "description": desc[:200], "permissions": sorted(set(perms))}), 201


# ----------------------------------------------------------------- clients
@bp.get("/clients")
@require_permissions("clients:manage")
def list_clients():
    return jsonify({"items": clients.list_clients()})


@bp.post("/clients")
@require_permissions("clients:manage")
def create_client():
    d = json_body()
    client_id, secret = clients.create_client(
        d.get("name"), d.get("redirect_uris", []), d.get("grant_types"), d.get("scopes"),
        public=bool(d.get("public", False)), created_by=g.auth.subject)
    audit.log("client.created", actor_id=g.auth.subject, target=client_id,
              details={"name": d.get("name"), "grant_types": d.get("grant_types"), "public": bool(d.get("public"))})
    out = clients.serialize(get_db().execute("SELECT * FROM oauth_clients WHERE client_id = ?", (client_id,)).fetchone())
    if secret:
        out["client_secret"] = secret       # shown exactly once
    return jsonify(out), 201


@bp.delete("/clients/<client_id>")
@require_permissions("clients:manage")
def delete_client(client_id):
    if not clients.delete_client(client_id):
        raise ApiError(404, "not_found", "Client not found")
    audit.log("client.deleted", actor_id=g.auth.subject, target=client_id)
    return "", 204


# --------------------------------------------------------------- audit log
@bp.get("/audit-logs")
@require_permissions("audit:read")
def audit_logs():
    limit, offset = int_arg("limit", 50, 1, 500), int_arg("offset", 0, 0, 10**9)
    clauses, args = [], []
    for param, column in (("event", "event"), ("actor_id", "actor_id"), ("target", "target"), ("ip", "ip")):
        if request.args.get(param):
            clauses.append(f"{column} = ?")
            args.append(request.args[param])
    if request.args.get("event_prefix"):
        clauses.append("event LIKE ?")
        args.append(request.args["event_prefix"].replace("%", "").replace("_", "") + "%")
    if request.args.get("success") in ("true", "false"):
        clauses.append("success = ?")
        args.append(1 if request.args["success"] == "true" else 0)
    if request.args.get("since"):
        clauses.append("ts >= ?")
        args.append(request.args["since"])
    if request.args.get("until"):
        clauses.append("ts <= ?")
        args.append(request.args["until"])
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    db = get_db()
    total = db.execute(f"SELECT COUNT(*) FROM audit_log {where}", args).fetchone()[0]
    rows = db.execute(f"SELECT * FROM audit_log {where} ORDER BY id DESC LIMIT ? OFFSET ?", args + [limit, offset])
    return jsonify({"items": [audit.serialize(r) for r in rows], "total": total, "limit": limit, "offset": offset})


@bp.get("/audit-logs/verify")
@require_permissions("audit:read")
def audit_verify():
    return jsonify(audit.verify_chain())
