"""OAuth2 client registry and client authentication."""
import hashlib
import hmac
import json
import re
import secrets
from urllib.parse import urlparse

from flask import request

from . import audit, util
from .db import get_db
from .errors import ApiError
from .policy import PERMISSIONS

VALID_GRANTS = {"authorization_code", "refresh_token", "client_credentials", "password"}
_BAD_SCHEMES = {"javascript", "data", "file", "vbscript", "about"}
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "[::1]", "::1"}


def _hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()   # secrets are 256-bit random; fast hash is fine


def serialize(row) -> dict:
    return {"client_id": row["client_id"], "name": row["name"], "public": row["secret_hash"] is None,
            "redirect_uris": row["redirect_uris"], "grant_types": row["grant_types"],
            "scopes": row["scopes"], "created_at": util.iso(row["created_at"])}


def _load(row):
    if row is None:
        return None
    d = dict(row)
    d["redirect_uris"] = json.loads(d["redirect_uris"])
    d["grant_types"] = json.loads(d["grant_types"])
    d["scopes"] = json.loads(d["scopes"])
    d["public"] = d["secret_hash"] is None
    return d


def get_client(client_id):
    if not isinstance(client_id, str):
        return None
    row = get_db().execute("SELECT * FROM oauth_clients WHERE client_id = ?", (client_id,)).fetchone()
    return _load(row)


def list_clients():
    rows = get_db().execute("SELECT * FROM oauth_clients ORDER BY created_at").fetchall()
    out = []
    for r in rows:
        d = _load(r)
        out.append({"client_id": d["client_id"], "name": d["name"], "public": d["public"],
                    "redirect_uris": d["redirect_uris"], "grant_types": d["grant_types"],
                    "scopes": d["scopes"], "created_at": util.iso(d["created_at"])})
    return out


def _check_redirect_uri(uri):
    if not isinstance(uri, str) or len(uri) > 500:
        raise ApiError(400, "invalid_request", "redirect_uris must be strings")
    p = urlparse(uri)
    if not p.scheme or p.fragment or p.scheme in _BAD_SCHEMES:
        raise ApiError(400, "invalid_request", f"Invalid redirect URI: {uri}")
    if p.scheme == "http" and p.hostname not in {h.strip("[]") for h in _LOCAL_HOSTS}:
        raise ApiError(400, "invalid_request", "http redirect URIs are only allowed for localhost")
    if p.scheme in ("http", "https") and not p.hostname:
        raise ApiError(400, "invalid_request", f"Invalid redirect URI: {uri}")


def create_client(name, redirect_uris, grant_types, scopes, public, created_by):
    if not isinstance(name, str) or not (1 <= len(name) <= 100):
        raise ApiError(400, "invalid_request", "name is required (max 100 chars)")
    if not isinstance(grant_types, list) or not grant_types or not set(grant_types) <= VALID_GRANTS:
        raise ApiError(400, "invalid_request", f"grant_types must be a non-empty subset of {sorted(VALID_GRANTS)}")
    if not isinstance(scopes, list) or not scopes or not set(scopes) <= set(PERMISSIONS):
        raise ApiError(400, "invalid_scope", f"scopes must be a non-empty subset of {sorted(PERMISSIONS)}")
    if not isinstance(redirect_uris, list):
        raise ApiError(400, "invalid_request", "redirect_uris must be a list")
    for u in redirect_uris:
        _check_redirect_uri(u)
    if "authorization_code" in grant_types and not redirect_uris:
        raise ApiError(400, "invalid_request", "authorization_code requires at least one redirect URI")
    if public and ({"client_credentials", "password"} & set(grant_types)):
        raise ApiError(400, "invalid_request", "public clients cannot use client_credentials or password grants")

    client_id = "cl_" + secrets.token_urlsafe(12)
    secret = None if public else secrets.token_urlsafe(32)
    get_db().execute(
        "INSERT INTO oauth_clients(client_id, secret_hash, name, redirect_uris, grant_types, scopes, created_by, created_at)"
        " VALUES (?,?,?,?,?,?,?,?)",
        (client_id, _hash_secret(secret) if secret else None, name, json.dumps(redirect_uris),
         json.dumps(sorted(set(grant_types))), json.dumps(sorted(set(scopes))), created_by, util.now()))
    return client_id, secret


def delete_client(client_id) -> bool:
    cur = get_db().execute("DELETE FROM oauth_clients WHERE client_id = ?", (client_id,))
    return cur.rowcount == 1


_BASIC = {"WWW-Authenticate": 'Basic realm="oauth"'}


def authenticate_client(params: dict) -> dict:
    """Authenticate via HTTP Basic or client_id/client_secret body params (RFC 6749 s2.3)."""
    auth = request.authorization
    if auth is not None and auth.type == "basic" and auth.username:
        cid, secret = auth.username, auth.password or ""
    else:
        cid, secret = params.get("client_id"), params.get("client_secret")
    if not cid:
        raise ApiError(401, "invalid_client", "Client authentication required", _BASIC)

    client = get_client(cid)
    ok = client is not None
    if ok and not client["public"]:
        ok = bool(secret) and hmac.compare_digest(_hash_secret(secret), client["secret_hash"])
    if not ok:
        audit.log("oauth.client_auth_failed", target=str(cid)[:64], success=False)
        raise ApiError(401, "invalid_client", "Client authentication failed", _BASIC)
    return client
