"""User accounts, roles, permissions and password authentication."""
import sqlite3

from flask import current_app

from . import audit, security, util
from .db import get_db, transaction
from .errors import ApiError
from .policy import DEFAULT_ROLE


def normalize_email(email) -> str:
    return (email or "").strip().lower() if isinstance(email, str) else ""


def get_user(user_id):
    return get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def get_user_by_email(email):
    return get_db().execute("SELECT * FROM users WHERE email = ?", (normalize_email(email),)).fetchone()


def user_roles(user_id) -> list[str]:
    rows = get_db().execute("SELECT role FROM user_roles WHERE user_id = ? ORDER BY role", (user_id,))
    return [r["role"] for r in rows]


def user_permissions(user_id) -> set[str]:
    rows = get_db().execute(
        "SELECT DISTINCT rp.permission FROM user_roles ur "
        "JOIN role_permissions rp ON rp.role = ur.role WHERE ur.user_id = ?", (user_id,))
    return {r["permission"] for r in rows}


def serialize(row, with_permissions=False) -> dict:
    out = {"id": row["id"], "email": row["email"], "name": row["name"],
           "is_active": bool(row["is_active"]), "roles": user_roles(row["id"]),
           "created_at": util.iso(row["created_at"])}
    if with_permissions:
        out["permissions"] = sorted(user_permissions(row["id"]))
    return out


def create_user(email, password, name=None, roles=(DEFAULT_ROLE,)):
    email = normalize_email(email)
    if not util.EMAIL_RE.match(email):
        raise ApiError(400, "invalid_request", "A valid email address is required")
    problems = security.password_problems(password, email)
    if problems:
        raise ApiError(400, "weak_password", "Password needs: " + ", ".join(problems))
    if name is not None and (not isinstance(name, str) or len(name) > 100):
        raise ApiError(400, "invalid_request", "name must be a string of at most 100 characters")

    db = get_db()
    uid, ts = util.new_id(), util.now()
    try:
        with transaction(db):
            db.execute(
                "INSERT INTO users(id, email, name, password_hash, created_at, updated_at) VALUES (?,?,?,?,?,?)",
                (uid, email, name, security.hash_password(password), ts, ts))
            for role in roles:
                db.execute("INSERT INTO user_roles(user_id, role) VALUES (?, ?)", (uid, role))
    except sqlite3.IntegrityError:
        audit.log("user.register_failed", target=email, success=False, details={"reason": "email_exists"})
        raise ApiError(409, "email_exists", "An account with this email already exists")
    return get_user(uid)


def authenticate_password(email, password, via="login"):
    """Return the user row on success, None on any failure. Applies lockout and audits."""
    cfg = current_app.config
    email = normalize_email(email)
    password = password if isinstance(password, str) else ""
    user = get_user_by_email(email) if email else None
    db = get_db()

    if user is None:
        security.burn_password_check(password)
        audit.log("auth.login_failed", target=email or None, success=False,
                  details={"reason": "unknown_user", "via": via})
        return None

    if user["locked_until"] > util.now():
        security.burn_password_check(password)
        audit.log("auth.login_blocked", actor_id=user["id"], target=email, success=False,
                  details={"reason": "account_locked", "via": via})
        return None

    ok = security.verify_password(user["password_hash"], password)
    if not ok:
        db.execute("UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = ?", (user["id"],))
        attempts = db.execute("SELECT failed_attempts FROM users WHERE id = ?", (user["id"],)).fetchone()[0]
        audit.log("auth.login_failed", actor_id=user["id"], target=email, success=False,
                  details={"reason": "bad_password", "via": via, "attempts": attempts})
        if attempts >= cfg["MAX_FAILED_LOGINS"]:
            until = util.now() + cfg["LOCKOUT_SECONDS"]
            db.execute("UPDATE users SET locked_until = ?, failed_attempts = 0 WHERE id = ?", (until, user["id"]))
            audit.log("auth.account_locked", actor_id=user["id"], target=email, success=False,
                      details={"locked_until": util.iso(until)})
        return None

    if not user["is_active"]:
        audit.log("auth.login_failed", actor_id=user["id"], target=email, success=False,
                  details={"reason": "account_disabled", "via": via})
        return None

    if user["failed_attempts"]:
        db.execute("UPDATE users SET failed_attempts = 0 WHERE id = ?", (user["id"],))
    return user


def bump_token_version(user_id):
    """Invalidates every outstanding access token of the user."""
    get_db().execute("UPDATE users SET token_version = token_version + 1, updated_at = ? WHERE id = ?",
                     (util.now(), user_id))
