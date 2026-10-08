"""Access token / refresh token issuance, rotation with reuse detection, revocation.

* Access tokens are short-lived RS256 JWTs. User tokens carry a `sid` (session id).
* Refresh tokens are opaque random strings; only their SHA-256 is stored.
* Every refresh token belongs to a *family* (= session). Using a refresh token
  rotates it. Presenting an already-used token means it was stolen/replayed, so
  the whole family is revoked - and with it every access token with that `sid`.
"""
import hashlib
import secrets

from flask import current_app

from . import audit, users, util
from .db import get_db
from .errors import ApiError
from .policy import PERMISSIONS
from .security import keys


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


# ------------------------------------------------------------------- scopes
def parse_scope(scope) -> list[str]:
    if scope is None or scope == "":
        return []
    if not isinstance(scope, str):
        raise ApiError(400, "invalid_scope", "scope must be a space-separated string")
    requested = scope.split()
    unknown = [s for s in requested if s not in PERMISSIONS]
    if unknown:
        raise ApiError(400, "invalid_scope", f"Unknown scope(s): {' '.join(unknown)}")
    return requested


def resolve_user_scopes(user_id, requested, client_scopes=None) -> list[str]:
    """requested ∩ user's role permissions ∩ client's allowed scopes (default: everything allowed)."""
    allowed = users.user_permissions(user_id)
    if client_scopes is not None:
        allowed &= set(client_scopes)
    asked = parse_scope(requested)
    granted = (set(asked) & allowed) if asked else allowed
    if not granted:
        raise ApiError(400, "invalid_scope", "None of the requested scopes can be granted")
    return sorted(granted)


# ----------------------------------------------------------------- issuance
def issue_tokens(*, user, client_id, scopes, grant, family_id=None, rotated_from=None, with_refresh=True):
    cfg = current_app.config
    now = util.now()
    ttl = cfg["ACCESS_TOKEN_TTL"]
    sid = family_id or (util.new_id() if with_refresh else None)

    claims = {
        "iss": cfg["JWT_ISSUER"], "aud": cfg["JWT_AUDIENCE"],
        "sub": user["id"] if user else client_id,
        "iat": now, "nbf": now, "exp": now + ttl, "jti": util.new_id(),
        "scope": " ".join(scopes),
    }
    if user:
        claims["roles"] = users.user_roles(user["id"])
        claims["tv"] = user["token_version"]
    else:
        claims["gty"] = "client_credentials"
    if client_id:
        claims["client_id"] = client_id
    if sid:
        claims["sid"] = sid

    response = {"access_token": keys().encode(claims), "token_type": "Bearer",
                "expires_in": ttl, "scope": " ".join(scopes)}

    if with_refresh:
        db = get_db()
        raw, rid = secrets.token_urlsafe(48), util.new_id()
        db.execute(
            "INSERT INTO refresh_tokens(id, token_hash, family_id, user_id, client_id, scope, expires_at, created_at)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (rid, sha256_hex(raw), sid, user["id"], client_id, " ".join(scopes),
             now + cfg["REFRESH_TOKEN_TTL"], now))
        if rotated_from:
            db.execute("UPDATE refresh_tokens SET replaced_by = ? WHERE id = ?", (rid, rotated_from))
        response["refresh_token"] = raw

    event = {"login": "auth.login", "refresh_token": "token.refreshed"}.get(grant, "token.issued")
    audit.log(event, actor_id=claims["sub"],
              details={"grant": grant, "client_id": client_id, "sid": sid, "scope": claims["scope"]})
    return response


# ----------------------------------------------------------------- rotation
def rotate_refresh_token(raw, client_id, requested_scope=None):
    """Exchange a refresh token for a new pair. client_id=None means first-party."""
    db = get_db()
    invalid = ApiError(400, "invalid_grant", "Refresh token is invalid, expired or revoked")
    if not isinstance(raw, str) or not raw:
        raise ApiError(400, "invalid_request", "refresh_token is required")

    row = db.execute("SELECT * FROM refresh_tokens WHERE token_hash = ?", (sha256_hex(raw),)).fetchone()
    if row is None or row["client_id"] != client_id or row["revoked_at"] is not None:
        raise invalid
    if row["used_at"] is not None:
        return _reuse_detected(row, invalid)
    if row["expires_at"] <= util.now():
        raise invalid

    user = users.get_user(row["user_id"])
    if user is None or not user["is_active"]:
        revoke_family(row["family_id"])
        raise invalid

    # Validate the request fully *before* consuming the token.
    current = users.user_permissions(user["id"])
    scopes = [s for s in row["scope"].split() if s in current]      # roles may have shrunk since
    if requested_scope:
        asked = parse_scope(requested_scope)
        if not set(asked) <= set(scopes):
            raise ApiError(400, "invalid_scope", "Requested scope exceeds the originally granted scope")
        scopes = asked
    if not scopes:
        revoke_family(row["family_id"])
        raise invalid

    # Atomic claim: exactly one concurrent caller can flip used_at from NULL.
    cur = db.execute("UPDATE refresh_tokens SET used_at = ? WHERE id = ? AND used_at IS NULL AND revoked_at IS NULL",
                     (util.now(), row["id"]))
    if cur.rowcount != 1:
        return _reuse_detected(row, invalid)

    return issue_tokens(user=user, client_id=client_id, scopes=scopes, grant="refresh_token",
                        family_id=row["family_id"], rotated_from=row["id"])


def _reuse_detected(row, error):
    revoke_family(row["family_id"])
    audit.log("token.reuse_detected", actor_id=row["user_id"], success=False,
              details={"sid": row["family_id"], "client_id": row["client_id"],
                       "action": "session revoked"})
    raise error


# --------------------------------------------------------------- revocation
def revoke_family(family_id) -> int:
    cur = get_db().execute("UPDATE refresh_tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL",
                           (util.now(), family_id))
    return cur.rowcount


def revoke_all_for_user(user_id) -> int:
    cur = get_db().execute("UPDATE refresh_tokens SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
                           (util.now(), user_id))
    return cur.rowcount


def session_alive(sid) -> bool:
    row = get_db().execute("SELECT 1 FROM refresh_tokens WHERE family_id = ? AND revoked_at IS NULL LIMIT 1",
                           (sid,)).fetchone()
    return row is not None


def revoke_jti(jti, exp):
    get_db().execute("INSERT OR IGNORE INTO revoked_jtis(jti, expires_at) VALUES (?, ?)", (jti, int(exp)))


def jti_revoked(jti) -> bool:
    return get_db().execute("SELECT 1 FROM revoked_jtis WHERE jti = ?", (jti,)).fetchone() is not None


def purge_expired() -> dict:
    """Housekeeping: delete expired/consumed rows. Run periodically (see README)."""
    db, now = get_db(), util.now()
    out = {}
    out["revoked_jtis"] = db.execute("DELETE FROM revoked_jtis WHERE expires_at < ?", (now,)).rowcount
    out["auth_codes"] = db.execute("DELETE FROM auth_codes WHERE expires_at < ?", (now - 3600,)).rowcount
    out["refresh_tokens"] = db.execute("DELETE FROM refresh_tokens WHERE expires_at < ?", (now - 86400,)).rowcount
    return out
