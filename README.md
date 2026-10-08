# STILL ON DEVELOPMENT!!!👩🏿‍💻👩🏿‍💻👩🏿‍💻👩🏿‍💻👩🏿‍💻



# Auth Service

A self-contained **OAuth2 + JWT identity service** with **role-based access control**,
**rotating refresh tokens** and a **tamper-evident audit log**. Python 3.10+ (developed and tested on 3.12), Flask, SQLite.

**Tested:** 47 end-to-end tests (real Flask app, real SQLite, real RSA keys) plus a live
HTTP run of `scripts/demo.py` against a separately started server. See [Testing](#testing).

## Features

| Area | What you get |
|---|---|
| **Tokens** | RS256 JWT access tokens (RFC 9068 `at+jwt`), 15 min by default; public keys at `/.well-known/jwks.json` so other services verify tokens offline |
| **OAuth2** | Authorization Code + **PKCE (S256, mandatory)**, Client Credentials, Refresh Token, Password (confidential clients only), Introspection (RFC 7662), Revocation (RFC 7009), Server Metadata (RFC 8414) |
| **Refresh tokens** | Opaque, stored only as SHA-256, **rotated on every use**; replaying an old one is detected, **revokes the whole session** and every access token tied to it |
| **RBAC** | Users → roles → permissions. Permissions double as OAuth scopes: a request needs the permission from the user's role **and** in the token's scope. Role changes apply **immediately** to tokens already issued |
| **Audit log** | Append-only, SHA-256 hash-chained (edits/deletes in the middle are detectable via an API call). Secrets are redacted. Filterable via API |
| **Account safety** | scrypt password hashing, password policy, lockout after repeated failures, constant-time-ish handling of unknown users, per-IP rate limiting, no user enumeration on login |
| **Sessions** | Logout (current session), logout-all, change-password (kills all sessions), disable-user (kills all sessions) |

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

export BOOTSTRAP_ADMIN_EMAIL=admin@yourcompany.com
export BOOTSTRAP_ADMIN_PASSWORD='change-me-Please-1'
python wsgi.py                      # http://127.0.0.1:5000
```

On first start it creates `./data/auth.db` and an RSA signing key `./data/jwt_private.pem` (mode 0600).

```bash
curl -s localhost:5000/health
python scripts/demo.py              # walks through every feature against the running server
python -m unittest discover -s tests -t . -v   # run the test-suite
```

For production use a real WSGI server (e.g. `gunicorn -w 4 -b 0.0.0.0:5000 wsgi:app`), put it behind HTTPS,
and set `JWT_ISSUER` to the public URL. (gunicorn is not bundled; the service has been exercised with Flask's
threaded server and test client, not under multi-process gunicorn.)

## Configuration

All via environment variables (see `.env.example`).

| Variable | Default | Meaning |
|---|---|---|
| `DATA_DIR` | `./data` | SQLite DB + key location |
| `JWT_ISSUER` / `JWT_AUDIENCE` | `http://localhost:5000` / `auth-service-api` | `iss` / `aud` claims, enforced on every request |
| `ACCESS_TOKEN_TTL` / `REFRESH_TOKEN_TTL` | `900` / `604800` | seconds |
| `MAX_FAILED_LOGINS` / `LOCKOUT_SECONDS` | `5` / `900` | account lockout |
| `RATE_LIMIT_PER_MINUTE` | `60` | per IP, per sensitive POST endpoint; `0` disables |
| `REGISTRATION_ENABLED` | `true` | allow public `POST /auth/register` |
| `BOOTSTRAP_ADMIN_EMAIL` / `_PASSWORD` | – | create first admin on startup (password must satisfy the policy) |
| `TRUSTED_PROXY_COUNT` | `0` | trust `X-Forwarded-*` from N proxies (needed for correct client IPs in audit log) |
| `JWT_PRIVATE_KEY` | – | PEM text of the signing key (else a key file is generated) |
| `PASSWORD_HASH_METHOD` | `scrypt` | any Werkzeug method string |

Alternative to the bootstrap env vars: `flask --app auth_service:create_app create-admin you@example.com`.
Housekeeping (run from cron): `flask --app auth_service:create_app purge-expired`.

## RBAC model

Permissions (also the OAuth2 scopes): `profile:read`, `profile:write`, `users:read`, `users:write`,
`roles:manage`, `audit:read`, `clients:manage`.

| Role | Permissions |
|---|---|
| `user` (default for new accounts) | `profile:read`, `profile:write` |
| `auditor` | `profile:*`, `users:read`, `audit:read` |
| `admin` | everything |

Admins can create more roles (`POST /admin/roles`) and assign them (`PUT /admin/users/{id}/roles`).
Self-registration always yields `user` only. An admin cannot demote or disable themselves, nor the last active admin.

**Effective permissions** = *(permissions of the user's current roles)* ∩ *(scope in the token)*.
So a token obtained through the OAuth2 flow with `scope=profile:read` can never write, even if the user is an admin, and
demoting a user takes effect on their very next request rather than when the token expires.

Protect your own endpoints with `@require_permissions("x:y")` / `@require_roles("admin")` from `auth_service/rbac.py`,
or verify tokens in other services via the JWKS endpoint (check `iss`, `aud`, `exp`, header `typ == at+jwt`).
Note that a remote verifier checking only the signature will **not** see revocations; use `/oauth/introspect` when you need that.

## API overview

All errors are JSON: `{"error": "...", "error_description": "..."}`.

### First-party auth (JSON)
| Method & path | Auth | Purpose |
|---|---|---|
| `POST /auth/register` | – | `{email, password, name?}` → 201 |
| `POST /auth/login` | – | `{email, password}` → `{access_token, refresh_token, expires_in, scope}` |
| `POST /auth/refresh` | – | `{refresh_token}` → new pair (old token is now spent) |
| `POST /auth/logout` | Bearer | ends the current session |
| `POST /auth/logout-all` | Bearer | ends every session of the user |
| `POST /auth/change-password` | Bearer + `profile:write` | `{current_password, new_password}`; revokes all sessions |
| `GET` / `PATCH /auth/me` | Bearer + `profile:read` / `:write` | profile, roles, permissions |

### OAuth2 (form-encoded, per RFC)
| Endpoint | Purpose |
|---|---|
| `GET/POST /oauth/authorize` | Authorization Code flow with a minimal sign-in page. Requires `code_challenge` (S256). `redirect_uri` must **exactly** match a registered URI |
| `POST /oauth/token` | `authorization_code`, `refresh_token`, `client_credentials`, `password` grants. Client auth via HTTP Basic or body |
| `POST /oauth/introspect` | RFC 7662 (requires client auth) – reflects revocation, disabled users, etc. |
| `POST /oauth/revoke` | RFC 7009. Revoking a refresh token ends the whole session |
| `GET /.well-known/jwks.json` | public signing key(s) |
| `GET /.well-known/oauth-authorization-server` | server metadata |

### Administration (Bearer)
| Endpoint | Permission |
|---|---|
| `GET /admin/users?q=&limit=&offset=`, `GET /admin/users/{id}`, `GET /admin/roles` | `users:read` |
| `POST /admin/users/{id}/disable` · `/enable` | `users:write` |
| `PUT /admin/users/{id}/roles` `{"roles": [...]}`, `POST /admin/roles` | `roles:manage` |
| `GET/POST /admin/clients`, `DELETE /admin/clients/{id}` | `clients:manage` |
| `GET /admin/audit-logs`, `GET /admin/audit-logs/verify` | `audit:read` |

Audit filters: `event`, `event_prefix`, `actor_id`, `target`, `ip`, `success=true|false`, `since`, `until` (ISO-8601), `limit`, `offset`.

## Examples

```bash
B=http://localhost:5000

# register, log in
curl -s $B/auth/register -H 'content-type: application/json' \
     -d '{"email":"ann@example.com","password":"Sup3r-Secret-pw","name":"Ann"}'
TOKENS=$(curl -s $B/auth/login -H 'content-type: application/json' \
     -d '{"email":"ann@example.com","password":"Sup3r-Secret-pw"}')
AT=$(echo "$TOKENS" | python -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
curl -s $B/auth/me -H "authorization: Bearer $AT"

# service-to-service (as an admin: create the client once, secret is shown once)
curl -s $B/admin/clients -H "authorization: Bearer $ADMIN_AT" -H 'content-type: application/json' \
     -d '{"name":"billing","grant_types":["client_credentials"],"scopes":["users:read"]}'
curl -s $B/oauth/token -u "$CLIENT_ID:$CLIENT_SECRET" -d grant_type=client_credentials

# browser/mobile app: register a public client, then send the user to
#   $B/oauth/authorize?response_type=code&client_id=...&redirect_uri=...&scope=profile:read
#        &state=...&code_challenge=<S256(verifier)>&code_challenge_method=S256
# and exchange the returned ?code= at /oauth/token with grant_type=authorization_code & code_verifier.
# scripts/demo.py contains the complete, working version of this flow.
```

## Security design notes

* **Signature + claims**: only RS256 is accepted; `alg=none`, HS256 confusion, wrong `iss`/`aud`, wrong `typ` and
  foreign keys are all rejected (each has a test).
* **Session binding**: access tokens carry `sid`; the session is checked on each request, so logout / reuse
  detection / disabling a user invalidate access tokens immediately, not after 15 minutes.
* **Refresh rotation**: claiming a token is a single atomic `UPDATE ... WHERE used_at IS NULL`; with 8 concurrent
  requests presenting the same token exactly one wins (tested). Strictness trade-off: a client that double-submits a
  refresh will lose its session; add a short grace window if that matters for your clients.
* **Authorization codes**: single use, 60 s, bound to client + redirect URI + PKCE challenge; reuse revokes the tokens
  that were issued from it.
* **No enumeration on login**: unknown user, wrong password, locked and disabled accounts all return the same 401
  (the audit log records the real reason). `POST /auth/register` does reveal whether an email is taken – disable
  registration or add e-mail verification if that matters.
* **Audit log** records: registrations, logins (success/failure/blocked/lockout), token issue/refresh/revoke,
  reuse detection, logouts, password changes, role/user/client changes, permission denials, OAuth code issuance and
  failures. It never stores passwords, tokens, codes or secrets (keys with those names are redacted, and tests assert it).

## Known limitations (read before production)

* **SQLite, single node.** Fine for a small/medium deployment; use a client/server database for horizontal scaling.
* **Rate limiter is in-process.** Behind several workers/instances each has its own counters; use a gateway/Redis
  for a global limit. Account lockout *is* global (stored in the DB).
* **One signing key, no automatic rotation.** Replacing the key invalidates all outstanding access tokens
  (refresh tokens keep working, so clients recover transparently). Multi-key JWKS rotation is not implemented.
* **Audit chain detects modification/deletion in the middle, not truncation of the newest rows.** Forward the log to
  external storage (SIEM / WORM bucket) for that. Invalid-token attempts are intentionally *not* audited, to prevent
  unauthenticated clients from filling the log.
* **No MFA, e-mail verification or password reset flow**, and the authorization page has sign-in but no separate consent step.
* **Run behind HTTPS.** Tokens are bearer credentials.

## Project layout

```
auth_service/
  __init__.py      app factory, rate-limit hook, CLI
  config.py        env-based settings
  policy.py        permission catalogue + default roles
  db.py            SQLite schema & helpers
  security.py      password hashing, RSA key manager, JWT encode/decode
  users.py         accounts, roles, password auth + lockout
  tokens.py        issue / rotate / revoke tokens, scope resolution
  clients.py       OAuth2 client registry & client authentication
  rbac.py          bearer auth + @require_permissions / @require_roles
  audit.py         hash-chained audit log
  ratelimit.py     sliding-window limiter
  routes/          auth.py (first-party), oauth.py (OAuth2), admin.py
tests/             47 end-to-end tests
scripts/demo.py    live walkthrough over HTTP
wsgi.py            entrypoint
```

## Testing

```bash
python -m unittest discover -s tests -t . -v
```

Covers: registration/login validation, lockout, rate limiting, JWT verification via JWKS, forged/expired/tampered/
alg-confusion/wrong-type tokens, key persistence across restarts, refresh rotation, replay detection, concurrent
refresh race, logout / logout-all / change-password / disable, RBAC enforcement and live role changes, custom roles,
admin self-lockout protection, client management, client-credentials, password grant, client-bound refresh tokens,
authorization-code + PKCE (including redirect-URI and open-redirect protection, code reuse, XSS-escaped consent page),
introspection, revocation, audit events/filters/tamper detection/deletion detection/redaction, and concurrent audit writes.
As a check on the tests themselves, security-critical lines were deliberately broken one at a time (reuse detection, session
check, scope check, PKCE, redirect matching, lockout, audience, typ, hash chain, redaction, client-secret check, ...) and the
suite failed each time.
