"""OAuth2 authorization server: authorization-code + PKCE, client-credentials,
password (for trusted confidential clients), refresh-token, introspection (RFC 7662),
revocation (RFC 7009), JWKS and server metadata (RFC 8414)."""
import base64
import hashlib
import hmac
import re
import secrets
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import jwt
from flask import Blueprint, current_app, jsonify, make_response, redirect, render_template_string, request

from .. import audit, clients, tokens, users, util
from ..db import get_db
from ..errors import ApiError
from ..policy import PERMISSIONS
from ..rbac import resolve_token
from ..security import keys

bp = Blueprint("oauth", __name__)
_VERIFIER_RE = re.compile(r"^[A-Za-z0-9\-._~]{43,128}$")
_NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}


def _params() -> dict:
    if request.form:
        return request.form.to_dict()
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def _json(payload, status=200):
    return jsonify(payload), status, _NO_STORE


# ------------------------------------------------------------ discovery/JWKS
@bp.get("/.well-known/jwks.json")
def jwks():
    resp = jsonify({"keys": [keys().jwk()]})
    resp.headers["Cache-Control"] = "public, max-age=300"
    return resp


@bp.get("/.well-known/oauth-authorization-server")
def metadata():
    iss = current_app.config["JWT_ISSUER"].rstrip("/")
    return jsonify({
        "issuer": current_app.config["JWT_ISSUER"],
        "authorization_endpoint": f"{iss}/oauth/authorize",
        "token_endpoint": f"{iss}/oauth/token",
        "introspection_endpoint": f"{iss}/oauth/introspect",
        "revocation_endpoint": f"{iss}/oauth/revoke",
        "jwks_uri": f"{iss}/.well-known/jwks.json",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials", "password"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": sorted(PERMISSIONS),
    })


# ------------------------------------------------------------- authorization
class _Redirect(Exception):
    def __init__(self, uri, error, description, state):
        self.uri, self.error, self.description, self.state = uri, error, description, state


_FORM = """<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in</title>
<style>body{font:16px system-ui;max-width:380px;margin:12vh auto;padding:0 16px}
input,button{width:100%;padding:10px;margin:6px 0;box-sizing:border-box;font:inherit}
.err{color:#b00020}small{color:#555}</style>
<h2>Sign in</h2>
<p><b>{{ client_name }}</b> is requesting access to:<br><small>{{ scopes }}</small></p>
{% if error %}<p class="err">{{ error }}</p>{% endif %}
<form method="post" action="{{ action }}">
{% for k, v in hidden.items() %}<input type="hidden" name="{{ k }}" value="{{ v }}">{% endfor %}
<input name="email" type="email" placeholder="Email" required autofocus>
<input name="password" type="password" placeholder="Password" required>
<button type="submit">Sign in &amp; allow</button></form>"""


def _validate_authorize(src):
    client = clients.get_client(src.get("client_id"))
    if client is None or "authorization_code" not in client["grant_types"]:
        raise ApiError(400, "invalid_client", "Unknown client or authorization_code grant not allowed")
    uri = src.get("redirect_uri")
    if not uri and len(client["redirect_uris"]) == 1:
        uri = client["redirect_uris"][0]
    if uri not in client["redirect_uris"]:                       # exact match only
        raise ApiError(400, "invalid_request", "redirect_uri does not match a registered URI")
    state = src.get("state")

    if src.get("response_type") != "code":
        raise _Redirect(uri, "unsupported_response_type", "Only response_type=code is supported", state)
    challenge = src.get("code_challenge") or ""
    if src.get("code_challenge_method") != "S256" or not re.fullmatch(r"[A-Za-z0-9\-_]{43}", challenge):
        raise _Redirect(uri, "invalid_request", "PKCE with code_challenge_method=S256 is required", state)
    try:
        tokens.parse_scope(src.get("scope"))
    except ApiError as e:
        raise _Redirect(uri, "invalid_scope", e.description, state)
    return client, uri, state


def _with_query(uri, **extra):
    p = urlparse(uri)
    q = parse_qsl(p.query) + [(k, v) for k, v in extra.items() if v is not None]
    return urlunparse(p._replace(query=urlencode(q)))


_HIDDEN = ("client_id", "redirect_uri", "response_type", "scope", "state", "code_challenge", "code_challenge_method")


def _render_form(client, src, error=None, status=200):
    scope_text = src.get("scope") or "all permissions your roles allow"
    html = render_template_string(_FORM, client_name=client["name"], scopes=scope_text, error=error,
                                  action=request.path, hidden={k: src.get(k, "") for k in _HIDDEN})
    resp = make_response(html, status)
    resp.headers.update({"Cache-Control": "no-store", "X-Frame-Options": "DENY",
                         "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action *; frame-ancestors 'none'"})
    return resp


@bp.route("/oauth/authorize", methods=["GET", "POST"])
def authorize():
    src = request.values
    try:
        client, uri, state = _validate_authorize(src)
    except _Redirect as r:
        return redirect(_with_query(r.uri, error=r.error, error_description=r.description, state=r.state), 302)

    if request.method == "GET":
        return _render_form(client, src)

    user = users.authenticate_password(src.get("email"), src.get("password"), via="authorize")
    if user is None:
        return _render_form(client, src, error="Invalid email or password", status=401)
    try:
        scopes = tokens.resolve_user_scopes(user["id"], src.get("scope"), client["scopes"])
    except ApiError as e:
        return redirect(_with_query(uri, error=e.error, error_description=e.description, state=state), 302)

    code = secrets.token_urlsafe(32)
    get_db().execute(
        "INSERT INTO auth_codes(code_hash, client_id, user_id, redirect_uri, scope, code_challenge, expires_at)"
        " VALUES (?,?,?,?,?,?,?)",
        (tokens.sha256_hex(code), client["client_id"], user["id"], uri, " ".join(scopes),
         src["code_challenge"], util.now() + current_app.config["AUTH_CODE_TTL"]))
    audit.log("oauth.code_issued", actor_id=user["id"], target=client["client_id"],
              details={"scope": " ".join(scopes)})
    return redirect(_with_query(uri, code=code, state=state), 302)


# --------------------------------------------------------------------- token
@bp.post("/oauth/token")
def token():
    p = _params()
    grant = p.get("grant_type")
    if not grant:
        raise ApiError(400, "invalid_request", "grant_type is required")
    client = clients.authenticate_client(p)
    if grant not in clients.VALID_GRANTS:
        raise ApiError(400, "unsupported_grant_type", f"Unsupported grant_type: {str(grant)[:40]}")
    if grant not in client["grant_types"]:
        raise ApiError(400, "unauthorized_client", "This client may not use that grant type")
    handler = {"client_credentials": _grant_client_credentials, "password": _grant_password,
               "authorization_code": _grant_code, "refresh_token": _grant_refresh}[grant]
    return _json(handler(client, p))


def _grant_client_credentials(client, p):
    if client["public"]:
        raise ApiError(400, "unauthorized_client", "Public clients cannot use client_credentials")
    asked = tokens.parse_scope(p.get("scope"))
    allowed = set(client["scopes"])
    granted = sorted(set(asked) & allowed) if asked else sorted(allowed)
    if not granted or (asked and not set(asked) <= allowed):
        raise ApiError(400, "invalid_scope", "Requested scope exceeds what this client is allowed")
    return tokens.issue_tokens(user=None, client_id=client["client_id"], scopes=granted,
                               grant="client_credentials", with_refresh=False)


def _grant_password(client, p):
    if client["public"]:
        raise ApiError(400, "unauthorized_client", "Public clients cannot use the password grant")
    user = users.authenticate_password(p.get("username"), p.get("password"), via="oauth_password")
    if user is None:
        raise ApiError(400, "invalid_grant", "Invalid username or password")
    scopes = tokens.resolve_user_scopes(user["id"], p.get("scope"), client["scopes"])
    return tokens.issue_tokens(user=user, client_id=client["client_id"], scopes=scopes, grant="password")


def _pkce_ok(verifier, challenge) -> bool:
    if not isinstance(verifier, str) or not _VERIFIER_RE.match(verifier):
        return False
    digest = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return hmac.compare_digest(digest, challenge)


def _grant_code(client, p):
    db = get_db()
    bad = ApiError(400, "invalid_grant", "Authorization code is invalid, expired or already used")
    code = p.get("code")
    row = db.execute("SELECT * FROM auth_codes WHERE code_hash = ?",
                     (tokens.sha256_hex(code),)).fetchone() if isinstance(code, str) else None
    if row is None or row["client_id"] != client["client_id"]:
        raise bad
    if row["used_at"] is not None:
        if row["session_id"]:                                   # RFC 6749 s4.1.2: revoke what the code produced
            tokens.revoke_family(row["session_id"])
        audit.log("oauth.code_reuse", actor_id=row["user_id"], target=client["client_id"], success=False)
        raise bad
    if row["expires_at"] <= util.now() or p.get("redirect_uri", row["redirect_uri"]) != row["redirect_uri"]:
        raise bad
    if not _pkce_ok(p.get("code_verifier"), row["code_challenge"]):
        audit.log("oauth.pkce_failed", actor_id=row["user_id"], target=client["client_id"], success=False)
        raise bad

    sid = util.new_id()
    cur = db.execute("UPDATE auth_codes SET used_at = ?, session_id = ? WHERE code_hash = ? AND used_at IS NULL",
                     (util.now(), sid, row["code_hash"]))
    if cur.rowcount != 1:
        raise bad
    user = users.get_user(row["user_id"])
    if user is None or not user["is_active"]:
        raise bad
    scopes = [s for s in row["scope"].split() if s in users.user_permissions(user["id"])]
    if not scopes:
        raise bad
    return tokens.issue_tokens(user=user, client_id=client["client_id"], scopes=scopes,
                               grant="authorization_code", family_id=sid)


def _grant_refresh(client, p):
    return tokens.rotate_refresh_token(p.get("refresh_token"), client_id=client["client_id"],
                                       requested_scope=p.get("scope"))


# ------------------------------------------------------ introspect / revoke
@bp.post("/oauth/introspect")
def introspect():
    p = _params()
    client = clients.authenticate_client(p)
    raw = p.get("token")
    if not isinstance(raw, str) or not raw:
        raise ApiError(400, "invalid_request", "token is required")

    try:
        ctx = resolve_token(raw)
        c = ctx.claims
        return _json({"active": True, "scope": c.get("scope", ""), "client_id": c.get("client_id"),
                      "sub": c["sub"], "token_type": "Bearer", "exp": c["exp"], "iat": c["iat"],
                      "nbf": c["nbf"], "iss": c["iss"], "aud": c["aud"], "jti": c["jti"],
                      "roles": ctx.roles})
    except ApiError:
        pass

    row = get_db().execute("SELECT * FROM refresh_tokens WHERE token_hash = ?", (tokens.sha256_hex(raw),)).fetchone()
    if (row and row["client_id"] == client["client_id"] and row["used_at"] is None
            and row["revoked_at"] is None and row["expires_at"] > util.now()):
        return _json({"active": True, "scope": row["scope"], "client_id": row["client_id"],
                      "sub": row["user_id"], "token_type": "refresh_token", "exp": row["expires_at"]})
    return _json({"active": False})


@bp.post("/oauth/revoke")
def revoke():
    """Always answers 200, whether or not the token existed (RFC 7009)."""
    p = _params()
    client = clients.authenticate_client(p)
    raw = p.get("token")
    if isinstance(raw, str) and raw:
        if raw.count(".") == 2:                                  # looks like a JWT -> access token
            try:
                claims = keys().decode(raw)
                if claims.get("client_id") == client["client_id"]:
                    tokens.revoke_jti(claims["jti"], claims["exp"])
                    audit.log("token.revoked", actor_id=client["client_id"], target=claims["sub"],
                              details={"type": "access_token"})
            except jwt.PyJWTError:
                pass
        else:
            row = get_db().execute("SELECT * FROM refresh_tokens WHERE token_hash = ?",
                                   (tokens.sha256_hex(raw),)).fetchone()
            if row and row["client_id"] == client["client_id"]:
                tokens.revoke_family(row["family_id"])
                audit.log("token.revoked", actor_id=client["client_id"], target=row["user_id"],
                          details={"type": "refresh_token", "sid": row["family_id"]})
    return _json({})
