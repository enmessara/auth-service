#!/usr/bin/env python3
"""Walk through the whole service over real HTTP.

    python scripts/demo.py [BASE_URL]

Needs a running server whose bootstrap admin matches ADMIN_EMAIL / ADMIN_PASSWORD
(env vars, defaults below). Exits non-zero if any step misbehaves.
"""
import base64
import hashlib
import os
import secrets
import sys
from urllib.parse import parse_qs, urlparse

import requests

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:5000").rstrip("/")
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "root@example.com")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "Str0ng-Bootstrap-Pw")
s = requests.Session()
step_no = 0


def step(title):
    global step_no
    step_no += 1
    print(f"\n[{step_no}] {title}")


def expect(resp, status, note=""):
    ok = resp.status_code == status
    print(f"    {'OK ' if ok else 'FAIL'} {resp.request.method} {urlparse(resp.url).path} -> {resp.status_code} {note}")
    if not ok:
        print("    body:", resp.text[:300])
        sys.exit(1)
    return resp


def bearer(tok):
    return {"Authorization": f"Bearer {tok['access_token']}"}


email = f"demo-{secrets.token_hex(3)}@example.com"
password = "Demo-Passw0rd-42"

step("Register and log in")
expect(s.post(f"{BASE}/auth/register", json={"email": email, "password": password, "name": "Demo"}), 201)
tok = expect(s.post(f"{BASE}/auth/login", json={"email": email, "password": password}), 200).json()
print("    access token expires in", tok["expires_in"], "s; scope:", tok["scope"])

step("Call a protected endpoint")
me = expect(s.get(f"{BASE}/auth/me", headers=bearer(tok)), 200).json()
print("    roles:", me["roles"], "| permissions:", me["permissions"])

step("RBAC: a normal user is blocked from admin APIs")
expect(s.get(f"{BASE}/admin/users", headers=bearer(tok)), 403)

step("Refresh-token rotation + reuse detection")
tok2 = expect(s.post(f"{BASE}/auth/refresh", json={"refresh_token": tok["refresh_token"]}), 200).json()
expect(s.post(f"{BASE}/auth/refresh", json={"refresh_token": tok["refresh_token"]}), 400, "(replayed old token)")
expect(s.get(f"{BASE}/auth/me", headers=bearer(tok2)), 401, "(whole session revoked after replay)")

step("Admin: promote the user to auditor, then read the audit log")
admin = expect(s.post(f"{BASE}/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}), 200).json()
expect(s.put(f"{BASE}/admin/users/{me['id']}/roles", json={"roles": ["auditor"]}, headers=bearer(admin)), 200)
tok3 = expect(s.post(f"{BASE}/auth/login", json={"email": email, "password": password}), 200).json()
logs = expect(s.get(f"{BASE}/admin/audit-logs", params={"actor_id": me["id"], "limit": 5}, headers=bearer(tok3)), 200).json()
for e in logs["items"]:
    print(f"    {e['ts']}  {e['event']:<24} success={e['success']}")

step("OAuth2 client_credentials for a service")
c = expect(s.post(f"{BASE}/admin/clients", headers=bearer(admin), json={
    "name": "billing-service", "grant_types": ["client_credentials"], "scopes": ["users:read"]}), 201).json()
svc = expect(s.post(f"{BASE}/oauth/token", data={"grant_type": "client_credentials"},
                    auth=(c["client_id"], c["client_secret"])), 200).json()
expect(s.get(f"{BASE}/admin/users", headers=bearer(svc)), 200, "(service token, scope users:read)")
expect(s.get(f"{BASE}/admin/audit-logs", headers=bearer(svc)), 403, "(outside its scope)")

step("OAuth2 authorization-code + PKCE for a public app")
app_client = expect(s.post(f"{BASE}/admin/clients", headers=bearer(admin), json={
    "name": "demo-spa", "public": True, "redirect_uris": ["http://localhost:3000/callback"],
    "grant_types": ["authorization_code", "refresh_token"], "scopes": ["profile:read"]}), 201).json()
verifier = secrets.token_urlsafe(48)
challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
r = expect(s.post(f"{BASE}/oauth/authorize", allow_redirects=False, data={
    "response_type": "code", "client_id": app_client["client_id"], "redirect_uri": "http://localhost:3000/callback",
    "scope": "profile:read", "state": "abc", "code_challenge": challenge, "code_challenge_method": "S256",
    "email": email, "password": password}), 302)
code = parse_qs(urlparse(r.headers["Location"]).query)["code"][0]
at = expect(s.post(f"{BASE}/oauth/token", data={
    "grant_type": "authorization_code", "code": code, "client_id": app_client["client_id"],
    "redirect_uri": "http://localhost:3000/callback", "code_verifier": verifier}), 200).json()
expect(s.get(f"{BASE}/auth/me", headers=bearer(at)), 200)

step("Logout, then the token stops working immediately")
expect(s.post(f"{BASE}/auth/logout", headers=bearer(tok3)), 204)
expect(s.get(f"{BASE}/auth/me", headers=bearer(tok3)), 401)

step("Audit-log integrity check")
v = expect(s.get(f"{BASE}/admin/audit-logs/verify", headers=bearer(admin)), 200).json()
print("    ", v)
assert v["valid"], "audit chain broken!"

print("\nAll steps passed.")
