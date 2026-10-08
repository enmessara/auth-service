"""First-party authentication endpoints (JSON in, JSON out)."""
from flask import Blueprint, current_app, g, jsonify

from . import json_body
from .. import audit, security, tokens, users, util
from ..errors import ApiError
from ..db import get_db
from ..rbac import require_auth, require_permissions

bp = Blueprint("auth", __name__, url_prefix="/auth")


@bp.post("/register")
def register():
    if not current_app.config["REGISTRATION_ENABLED"]:
        raise ApiError(403, "registration_disabled", "Self-registration is disabled")
    data = json_body()
    user = users.create_user(data.get("email"), data.get("password"), data.get("name"))
    audit.log("user.registered", actor_id=user["id"], target=user["email"])
    return jsonify(users.serialize(user)), 201


@bp.post("/login")
def login():
    data = json_body()
    user = users.authenticate_password(data.get("email"), data.get("password"), via="login")
    if user is None:
        raise ApiError(401, "invalid_credentials", "Invalid email or password")
    scopes = sorted(users.user_permissions(user["id"]))
    if not scopes:
        raise ApiError(403, "no_permissions", "This account has no roles with permissions")
    return jsonify(tokens.issue_tokens(user=user, client_id=None, scopes=scopes, grant="login"))


@bp.post("/refresh")
def refresh():
    data = json_body()
    return jsonify(tokens.rotate_refresh_token(data.get("refresh_token"), client_id=None))


@bp.post("/logout")
@require_auth
def logout():
    """Ends the current session: revokes this access token and the whole refresh-token family."""
    claims = g.auth.claims
    tokens.revoke_jti(claims["jti"], claims["exp"])
    if claims.get("sid"):
        tokens.revoke_family(claims["sid"])
    audit.log("auth.logout", actor_id=g.auth.subject, details={"sid": claims.get("sid")})
    return "", 204


@bp.post("/logout-all")
@require_auth
def logout_all():
    if g.auth.is_service:
        raise ApiError(403, "forbidden", "Service tokens have no user sessions")
    tokens.revoke_all_for_user(g.auth.user["id"])
    users.bump_token_version(g.auth.user["id"])
    audit.log("auth.logout_all", actor_id=g.auth.subject)
    return "", 204


@bp.post("/change-password")
@require_permissions("profile:write")
def change_password():
    if g.auth.is_service:
        raise ApiError(403, "forbidden", "Service tokens have no user")
    data = json_body()
    user = g.auth.user
    if not security.verify_password(user["password_hash"], data.get("current_password") or ""):
        audit.log("user.password_change_failed", actor_id=user["id"], success=False,
                  details={"reason": "bad_current_password"})
        raise ApiError(400, "invalid_grant", "Current password is incorrect")
    problems = security.password_problems(data.get("new_password"), user["email"])
    if problems:
        raise ApiError(400, "weak_password", "Password needs: " + ", ".join(problems))
    get_db().execute("UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?",
                     (security.hash_password(data["new_password"]), util.now(), user["id"]))
    tokens.revoke_all_for_user(user["id"])
    users.bump_token_version(user["id"])
    audit.log("user.password_changed", actor_id=user["id"])
    return jsonify({"message": "Password changed. Please sign in again."})


@bp.get("/me")
@require_permissions("profile:read")
def me():
    if g.auth.is_service:
        raise ApiError(403, "forbidden", "Service tokens have no user profile")
    out = users.serialize(g.auth.user, with_permissions=True)
    out["token_permissions"] = sorted(g.auth.permissions)
    return jsonify(out)


@bp.patch("/me")
@require_permissions("profile:write")
def update_me():
    if g.auth.is_service:
        raise ApiError(403, "forbidden", "Service tokens have no user profile")
    name = json_body().get("name")
    if not isinstance(name, str) or not (1 <= len(name) <= 100):
        raise ApiError(400, "invalid_request", "name must be 1-100 characters")
    get_db().execute("UPDATE users SET name = ?, updated_at = ? WHERE id = ?",
                     (name, util.now(), g.auth.user["id"]))
    audit.log("user.updated", actor_id=g.auth.subject, details={"fields": ["name"]})
    return jsonify(users.serialize(users.get_user(g.auth.user["id"])))
