"""Bearer-token authentication + role/permission enforcement."""
from dataclasses import dataclass, field
from functools import wraps

import jwt
from flask import g, request

from . import audit, clients, tokens, users
from .errors import ApiError
from .security import keys


@dataclass
class AuthContext:
    claims: dict
    permissions: set = field(default_factory=set)
    roles: list = field(default_factory=list)
    user: object = None            # sqlite3.Row for user tokens, None for client-credentials tokens
    client_id: str | None = None

    @property
    def subject(self):
        return self.claims["sub"]

    @property
    def is_service(self):
        return self.user is None


def _fail(error, description, status=401):
    header = f'Bearer error="{error}"' if status == 401 else None
    raise ApiError(status, error, description, {"WWW-Authenticate": header} if header else {})


def resolve_token(token: str) -> AuthContext:
    """Fully validate an access token (signature, expiry, revocation, live user state)."""
    try:
        claims = keys().decode(token)
    except jwt.ExpiredSignatureError:
        _fail("invalid_token", "The access token expired")
    except jwt.PyJWTError:
        _fail("invalid_token", "The access token is invalid")

    if tokens.jti_revoked(claims["jti"]):
        _fail("invalid_token", "The access token was revoked")
    sid = claims.get("sid")
    if sid and not tokens.session_alive(sid):
        _fail("invalid_token", "The session was revoked")

    scope = set(claims.get("scope", "").split())

    if claims.get("gty") == "client_credentials":
        client = clients.get_client(claims.get("client_id"))
        if client is None or "client_credentials" not in client["grant_types"]:
            _fail("invalid_token", "The client no longer exists")
        return AuthContext(claims, permissions=scope & set(client["scopes"]), client_id=client["client_id"])

    user = users.get_user(claims["sub"])
    if user is None or not user["is_active"] or user["token_version"] != claims.get("tv"):
        _fail("invalid_token", "The access token is no longer valid")
    # Roles are read live, so role changes take effect immediately, not at token expiry.
    return AuthContext(claims, permissions=users.user_permissions(user["id"]) & scope,
                       roles=users.user_roles(user["id"]), user=user, client_id=claims.get("client_id"))


def authenticate_request() -> AuthContext:
    scheme, _, token = request.headers.get("Authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise ApiError(401, "missing_token", "Bearer token required", {"WWW-Authenticate": "Bearer"})
    ctx = resolve_token(token.strip())
    g.auth = ctx
    return ctx


def require_auth(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        authenticate_request()
        return fn(*a, **kw)
    return wrapper


def _deny(ctx, required_kind, required):
    audit.log("authz.denied", actor_id=ctx.subject, success=False,
              details={"path": request.path, "method": request.method, required_kind: sorted(required)})
    raise ApiError(403, "insufficient_permissions", f"Requires {required_kind[:-1]}: {', '.join(sorted(required))}")


def require_permissions(*needed):
    """Caller must hold ALL listed permissions (role-granted and within the token's scope)."""
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            ctx = authenticate_request()
            if not set(needed) <= ctx.permissions:
                _deny(ctx, "permissions", needed)
            return fn(*a, **kw)
        return wrapper
    return deco


def require_roles(*roles):
    """Caller must have ANY of the listed roles (user tokens only)."""
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            ctx = authenticate_request()
            if not set(roles) & set(ctx.roles):
                _deny(ctx, "roles", roles)
            return fn(*a, **kw)
        return wrapper
    return deco
