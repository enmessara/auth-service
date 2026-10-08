"""End-to-end tests against the real Flask app + a real SQLite database.

Run:  python -m unittest discover -v        (or: pytest -v)
"""
import base64
import hashlib
import json
import secrets
import tempfile
import threading
import unittest
from urllib.parse import parse_qs, urlparse

import jwt
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

from auth_service import create_app, tokens
from auth_service.db import get_db

ADMIN_EMAIL, ADMIN_PW = "root@example.com", "Str0ng-Bootstrap-Pw"
USER_PW = "Sup3r-Secret-pw"


def b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def b64u_dec(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def pkce_pair():
    verifier = secrets.token_urlsafe(48)
    return verifier, b64u(hashlib.sha256(verifier.encode()).digest())


class Base(unittest.TestCase):
    config = {}

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.paths = {"DATABASE_PATH": f"{self.tmp.name}/auth.db", "PRIVATE_KEY_PATH": f"{self.tmp.name}/key.pem"}
        self.app = self.make_app()
        self.c = self.app.test_client()

    def tearDown(self):
        self.tmp.cleanup()

    def make_app(self, **extra):
        cfg = {"TESTING": True, "PASSWORD_HASH_METHOD": "pbkdf2:sha256:1000", "RATE_LIMIT_PER_MINUTE": 0,
               "BOOTSTRAP_ADMIN_EMAIL": ADMIN_EMAIL, "BOOTSTRAP_ADMIN_PASSWORD": ADMIN_PW,
               "JWT_ISSUER": "http://auth.test", **self.paths, **self.config, **extra}
        return create_app(cfg)

    # -- helpers
    def register(self, email, password=USER_PW, **extra):
        return self.c.post("/auth/register", json={"email": email, "password": password, **extra})

    def login(self, email, password=USER_PW, client=None):
        r = (client or self.c).post("/auth/login", json={"email": email, "password": password})
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        return r.json

    @staticmethod
    def hdr(tok):
        return {"Authorization": f"Bearer {tok['access_token'] if isinstance(tok, dict) else tok}"}

    def admin(self):
        return self.login(ADMIN_EMAIL, ADMIN_PW)

    def make_user(self, email, roles=None):
        r = self.register(email)
        self.assertEqual(r.status_code, 201, r.get_data(as_text=True))
        uid = r.json["id"]
        if roles:
            rr = self.c.put(f"/admin/users/{uid}/roles", json={"roles": roles}, headers=self.hdr(self.admin()))
            self.assertEqual(rr.status_code, 200, rr.get_data(as_text=True))
        return uid, self.login(email)

    def audit(self, **params):
        r = self.c.get("/admin/audit-logs", query_string={"limit": 500, **params}, headers=self.hdr(self.admin()))
        self.assertEqual(r.status_code, 200)
        return r.json["items"]

    def db_exec(self, sql, args=()):
        """Run raw SQL against the live DB (used to simulate time passing / tampering)."""
        with self.app.app_context():
            rows = get_db().execute(sql, args).fetchall()

        class Result(list):
            def fetchone(self):
                return self[0] if self else None

            def fetchall(self):
                return list(self)
        return Result(rows)

    def forge(self, **overrides):
        """Sign arbitrary claims with the server's real key (to test expiry etc.)."""
        import time
        now = int(time.time())
        claims = {"iss": "http://auth.test", "aud": "auth-service-api", "sub": "x", "iat": now, "nbf": now,
                  "exp": now + 600, "jti": secrets.token_hex(8), "scope": "profile:read"}
        claims.update(overrides)
        return self.app.extensions["keys"].encode(claims)

    def create_client(self, **body):
        r = self.c.post("/admin/clients", json=body, headers=self.hdr(self.admin()))
        self.assertEqual(r.status_code, 201, r.get_data(as_text=True))
        return r.json


class TestRegistrationAndLogin(Base):
    def test_register_ok_and_default_role_only(self):
        r = self.register("Alice@Example.com", name="Alice", roles=["admin"])   # mass-assignment attempt
        self.assertEqual(r.status_code, 201)
        self.assertEqual(r.json["email"], "alice@example.com")
        self.assertEqual(r.json["roles"], ["user"])
        self.assertNotIn("password", json.dumps(r.json))

    def test_register_validation(self):
        self.assertEqual(self.register("not-an-email").status_code, 400)
        for bad in ("short1A", "alllowercase123", "ALLUPPERCASE123", "NoDigitsHereAtAll"):
            r = self.register("bob@example.com", bad)
            self.assertEqual((r.status_code, r.json["error"]), (400, "weak_password"), bad)
        self.assertEqual(self.c.post("/auth/register", data="nope").status_code, 400)

    def test_duplicate_email_case_insensitive(self):
        self.assertEqual(self.register("dup@example.com").status_code, 201)
        r = self.register("DUP@example.com")
        self.assertEqual((r.status_code, r.json["error"]), (409, "email_exists"))

    def test_registration_can_be_disabled(self):
        app = self.make_app(REGISTRATION_ENABLED=False)
        r = app.test_client().post("/auth/register", json={"email": "z@example.com", "password": USER_PW})
        self.assertEqual(r.status_code, 403)

    def test_login_and_me(self):
        self.register("carol@example.com")
        tok = self.login("carol@example.com")
        self.assertEqual(tok["token_type"], "Bearer")
        self.assertEqual(tok["expires_in"], 900)
        me = self.c.get("/auth/me", headers=self.hdr(tok))
        self.assertEqual(me.status_code, 200)
        self.assertEqual(me.json["email"], "carol@example.com")
        self.assertEqual(me.json["permissions"], ["profile:read", "profile:write"])

    def test_wrong_password_and_unknown_user_are_indistinguishable(self):
        self.register("dave@example.com")
        a = self.c.post("/auth/login", json={"email": "dave@example.com", "password": "Wrong-pass-123"})
        b = self.c.post("/auth/login", json={"email": "ghost@example.com", "password": "Wrong-pass-123"})
        self.assertEqual((a.status_code, b.status_code), (401, 401))
        self.assertEqual(a.json, b.json)

    def test_login_response_not_cacheable(self):
        self.register("erin@example.com")
        r = self.c.post("/auth/login", json={"email": "erin@example.com", "password": USER_PW})
        self.assertEqual(r.headers["Cache-Control"], "no-store")

    def test_account_lockout_then_recovery(self):
        self.register("frank@example.com")
        for _ in range(5):
            r = self.c.post("/auth/login", json={"email": "frank@example.com", "password": "Wrong-pass-123"})
            self.assertEqual(r.status_code, 401)
        # Correct password is rejected while locked.
        r = self.c.post("/auth/login", json={"email": "frank@example.com", "password": USER_PW})
        self.assertEqual(r.status_code, 401)
        self.assertTrue(self.audit(event="auth.account_locked"))
        self.assertTrue(self.audit(event="auth.login_blocked"))
        self.db_exec("UPDATE users SET locked_until = 0 WHERE email = 'frank@example.com'")   # lock expires
        self.assertEqual(self.c.post("/auth/login", json={"email": "frank@example.com", "password": USER_PW}).status_code, 200)

    def test_rate_limiting(self):
        app = self.make_app(RATE_LIMIT_PER_MINUTE=3)
        c = app.test_client()
        codes = [c.post("/auth/login", json={"email": "a@b.co", "password": "x"}).status_code for _ in range(5)]
        self.assertEqual(codes, [401, 401, 401, 429, 429])
        r = c.post("/auth/login", json={"email": "a@b.co", "password": "x"})
        self.assertIn("Retry-After", r.headers)

    def test_misc_error_shapes(self):
        self.assertEqual(self.c.get("/nope").json["error"], "not_found")
        self.assertEqual(self.c.get("/auth/login").status_code, 405)
        big = self.c.post("/auth/register", data="x" * 100_000, content_type="application/json")
        self.assertEqual(big.status_code, 413)


class TestJwt(Base):
    def test_token_signature_verifiable_with_published_jwks(self):
        self.register("jwt@example.com")
        tok = self.login("jwt@example.com")
        jwk = self.c.get("/.well-known/jwks.json").json["keys"][0]
        pub = RSAPublicNumbers(int.from_bytes(b64u_dec(jwk["e"]), "big"),
                               int.from_bytes(b64u_dec(jwk["n"]), "big")).public_key()
        header = jwt.get_unverified_header(tok["access_token"])
        self.assertEqual((header["alg"], header["typ"], header["kid"]), ("RS256", "at+jwt", jwk["kid"]))
        claims = jwt.decode(tok["access_token"], pub, algorithms=["RS256"],
                            audience="auth-service-api", issuer="http://auth.test")
        self.assertEqual(claims["exp"] - claims["iat"], 900)
        self.assertEqual(claims["roles"], ["user"])
        self.assertEqual(claims["scope"], "profile:read profile:write")
        self.assertTrue(claims["jti"] and claims["sid"])

    def test_rejects_missing_tampered_expired_and_forged_tokens(self):
        self.register("t@example.com")
        tok = self.login("t@example.com")
        uid = self.c.get("/auth/me", headers=self.hdr(tok)).json["id"]
        me = lambda t: self.c.get("/auth/me", headers=self.hdr(t))

        self.assertEqual(self.c.get("/auth/me").status_code, 401)
        self.assertEqual(me("garbage").status_code, 401)
        # tampered payload (signature no longer matches)
        h, p, s = tok["access_token"].split(".")
        payload = json.loads(b64u_dec(p)); payload["roles"] = ["admin"]
        tampered = ".".join([h, b64u(json.dumps(payload).encode()), s])
        self.assertEqual(me(tampered).status_code, 401)
        # expired
        r = me(self.forge(sub=uid, tv=0, exp=1_000_000_000, iat=999_999_000, nbf=999_999_000))
        self.assertEqual((r.status_code, r.json["error_description"]), (401, "The access token expired"))
        # wrong audience / issuer
        self.assertEqual(me(self.forge(sub=uid, tv=0, aud="someone-else")).status_code, 401)
        self.assertEqual(me(self.forge(sub=uid, tv=0, iss="http://evil")).status_code, 401)
        # alg=none and HS256 signed with an arbitrary secret
        none_tok = jwt.encode({"sub": uid, "aud": "auth-service-api", "iss": "http://auth.test"}, None,
                              algorithm="none", headers={"typ": "at+jwt"})
        self.assertEqual(me(none_tok).status_code, 401)
        hs = jwt.encode({"sub": uid}, "secret", algorithm="HS256", headers={"typ": "at+jwt"})
        self.assertEqual(me(hs).status_code, 401)
        # token signed by a *different* RSA key
        from cryptography.hazmat.primitives.asymmetric import rsa
        other = rsa.generate_private_key(65537, 2048)
        foreign = jwt.encode({"sub": uid, "aud": "auth-service-api", "iss": "http://auth.test", "exp": 4_000_000_000,
                              "iat": 1, "nbf": 1, "jti": "j"}, other, algorithm="RS256", headers={"typ": "at+jwt"})
        self.assertEqual(me(foreign).status_code, 401)
        # a validly signed token with a stale token_version is rejected
        self.assertEqual(me(self.forge(sub=uid, tv=99)).status_code, 401)
        # sanity: a correctly-formed forged-by-server token works
        self.assertEqual(me(self.forge(sub=uid, tv=0)).status_code, 200)

    def test_server_signed_token_of_wrong_type_is_rejected(self):
        """Token-confusion: a JWT signed with our key but not typed at+jwt must not work as an access token."""
        self.register("typ@example.com")
        uid = self.login("typ@example.com") and self.c.get("/auth/me", headers=self.hdr(self.login("typ@example.com"))).json["id"]
        import time
        now = int(time.time())
        claims = {"iss": "http://auth.test", "aud": "auth-service-api", "sub": uid, "iat": now, "nbf": now,
                  "exp": now + 600, "jti": "j1", "scope": "profile:read", "tv": 0}
        key = self.app.extensions["keys"].private_key
        wrong_typ = jwt.encode(claims, key, algorithm="RS256", headers={"typ": "JWT"})
        self.assertEqual(self.c.get("/auth/me", headers=self.hdr(wrong_typ)).status_code, 401)
        right_typ = jwt.encode(claims, key, algorithm="RS256", headers={"typ": "at+jwt"})
        self.assertEqual(self.c.get("/auth/me", headers=self.hdr(right_typ)).status_code, 200)

    def test_signing_key_persists_across_restarts(self):
        self.register("p@example.com")
        tok = self.login("p@example.com")
        app2 = self.make_app()
        self.assertEqual(app2.extensions["keys"].kid, self.app.extensions["keys"].kid)
        self.assertEqual(app2.test_client().get("/auth/me", headers=self.hdr(tok)).status_code, 200)


class TestRefreshTokens(Base):
    def setUp(self):
        super().setUp()
        self.register("r@example.com")
        self.tok = self.login("r@example.com")

    def refresh(self, rt, client=None):
        return (client or self.c).post("/auth/refresh", json={"refresh_token": rt})

    def test_rotation_issues_new_pair_and_stores_only_hashes(self):
        r = self.refresh(self.tok["refresh_token"])
        self.assertEqual(r.status_code, 200)
        self.assertNotEqual(r.json["refresh_token"], self.tok["refresh_token"])
        self.assertEqual(self.c.get("/auth/me", headers=self.hdr(r.json)).status_code, 200)
        stored = [row[0] for row in self.db_exec("SELECT token_hash FROM refresh_tokens")]
        self.assertNotIn(self.tok["refresh_token"], stored)
        self.assertIn(hashlib.sha256(self.tok["refresh_token"].encode()).hexdigest(), stored)

    def test_reuse_of_rotated_token_revokes_entire_session(self):
        first = self.tok["refresh_token"]
        second = self.refresh(first).json
        self.assertEqual(self.c.get("/auth/me", headers=self.hdr(second)).status_code, 200)
        replay = self.refresh(first)                                   # attacker replays the stolen token
        self.assertEqual((replay.status_code, replay.json["error"]), (400, "invalid_grant"))
        self.assertEqual(self.refresh(second["refresh_token"]).status_code, 400)          # legit token now dead too
        self.assertEqual(self.c.get("/auth/me", headers=self.hdr(second)).status_code, 401)  # and its access token
        self.assertTrue(self.audit(event="token.reuse_detected"))

    def test_unknown_malformed_and_expired(self):
        self.assertEqual(self.refresh("nope").status_code, 400)
        self.assertEqual(self.c.post("/auth/refresh", json={}).status_code, 400)
        self.db_exec("UPDATE refresh_tokens SET expires_at = 1")
        self.assertEqual(self.refresh(self.tok["refresh_token"]).status_code, 400)

    def test_concurrent_use_of_one_refresh_token_only_succeeds_once(self):
        results, barrier = [], threading.Barrier(8)

        def worker():
            client = self.app.test_client()
            barrier.wait()
            results.append(self.refresh(self.tok["refresh_token"], client).status_code)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        [t.start() for t in threads]; [t.join() for t in threads]
        self.assertEqual(sorted(results), [200] + [400] * 7)

    def test_logout_kills_access_and_refresh_tokens(self):
        r = self.c.post("/auth/logout", headers=self.hdr(self.tok))
        self.assertEqual(r.status_code, 204)
        self.assertEqual(self.c.get("/auth/me", headers=self.hdr(self.tok)).status_code, 401)
        self.assertEqual(self.refresh(self.tok["refresh_token"]).status_code, 400)

    def test_logout_all_ends_every_session(self):
        other = self.login("r@example.com")
        self.assertEqual(self.c.post("/auth/logout-all", headers=self.hdr(self.tok)).status_code, 204)
        for t in (self.tok, other):
            self.assertEqual(self.c.get("/auth/me", headers=self.hdr(t)).status_code, 401)
            self.assertEqual(self.refresh(t["refresh_token"]).status_code, 400)

    def test_change_password_revokes_everything(self):
        r = self.c.post("/auth/change-password", headers=self.hdr(self.tok),
                        json={"current_password": "Wrong-pass-123", "new_password": "N3w-Password-ok"})
        self.assertEqual(r.status_code, 400)
        r = self.c.post("/auth/change-password", headers=self.hdr(self.tok),
                        json={"current_password": USER_PW, "new_password": "weak"})
        self.assertEqual(r.json["error"], "weak_password")
        r = self.c.post("/auth/change-password", headers=self.hdr(self.tok),
                        json={"current_password": USER_PW, "new_password": "N3w-Password-ok"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.c.get("/auth/me", headers=self.hdr(self.tok)).status_code, 401)
        self.assertEqual(self.refresh(self.tok["refresh_token"]).status_code, 400)
        self.assertEqual(self.c.post("/auth/login", json={"email": "r@example.com", "password": USER_PW}).status_code, 401)
        self.login("r@example.com", "N3w-Password-ok")

    def test_update_profile(self):
        r = self.c.patch("/auth/me", json={"name": "New Name"}, headers=self.hdr(self.tok))
        self.assertEqual((r.status_code, r.json["name"]), (200, "New Name"))
        self.assertEqual(self.c.patch("/auth/me", json={"name": ""}, headers=self.hdr(self.tok)).status_code, 400)


class TestRbac(Base):
    def test_plain_user_is_forbidden_from_admin_endpoints(self):
        _, tok = self.make_user("u@example.com")
        for method, url in (("get", "/admin/users"), ("get", "/admin/audit-logs"), ("get", "/admin/clients"),
                            ("post", "/admin/clients"), ("get", "/admin/roles")):
            r = getattr(self.c, method)(url, headers=self.hdr(tok), json={} if method == "post" else None)
            self.assertEqual((r.status_code, r.json["error"]), (403, "insufficient_permissions"), url)
        self.assertEqual(self.c.get("/admin/users").status_code, 401)        # anonymous

    def test_admin_can_list_users_with_pagination_and_search(self):
        for i in range(3):
            self.register(f"page{i}@example.com")
        adm = self.hdr(self.admin())
        r = self.c.get("/admin/users?limit=2", headers=adm)
        self.assertEqual((len(r.json["items"]), r.json["total"]), (2, 4))
        r = self.c.get("/admin/users?q=page1", headers=adm)
        self.assertEqual([u["email"] for u in r.json["items"]], ["page1@example.com"])
        self.assertEqual(self.c.get("/admin/users?limit=abc", headers=adm).status_code, 400)

    def test_role_change_takes_effect_immediately_on_existing_token(self):
        uid, tok = self.make_user("aud@example.com")
        self.assertEqual(self.c.get("/admin/users", headers=self.hdr(tok)).status_code, 403)
        adm = self.hdr(self.admin())
        # Token was issued while the user only had `user`; the scope claim limits it even after promotion:
        self.c.put(f"/admin/users/{uid}/roles", json={"roles": ["user", "auditor"]}, headers=adm)
        self.assertEqual(self.c.get("/admin/users", headers=self.hdr(tok)).status_code, 403)   # scope lacks users:read
        fresh = self.login("aud@example.com")                                                   # new token picks it up
        self.assertEqual(self.c.get("/admin/users", headers=self.hdr(fresh)).status_code, 200)
        self.assertEqual(self.c.get("/admin/audit-logs", headers=self.hdr(fresh)).status_code, 200)
        # auditor is read-only
        self.assertEqual(self.c.put(f"/admin/users/{uid}/roles", json={"roles": ["admin"]}, headers=self.hdr(fresh)).status_code, 403)
        self.assertEqual(self.c.post(f"/admin/users/{uid}/disable", headers=self.hdr(fresh)).status_code, 403)
        # demotion is immediate even though the token still carries the old scope
        self.c.put(f"/admin/users/{uid}/roles", json={"roles": ["user"]}, headers=adm)
        self.assertEqual(self.c.get("/admin/users", headers=self.hdr(fresh)).status_code, 403)

    def test_denials_are_audited(self):
        _, tok = self.make_user("denied@example.com")
        self.c.get("/admin/users", headers=self.hdr(tok))
        ev = self.audit(event="authz.denied")
        self.assertEqual(ev[0]["success"], False)
        self.assertEqual(ev[0]["details"]["permissions"], ["users:read"])

    def test_role_assignment_validation_and_custom_roles(self):
        uid, _ = self.make_user("v@example.com")
        adm = self.hdr(self.admin())
        self.assertEqual(self.c.put(f"/admin/users/{uid}/roles", json={"roles": ["nope"]}, headers=adm).status_code, 400)
        self.assertEqual(self.c.put(f"/admin/users/{uid}/roles", json={"roles": []}, headers=adm).status_code, 400)
        self.assertEqual(self.c.put("/admin/users/missing/roles", json={"roles": ["user"]}, headers=adm).status_code, 404)
        r = self.c.post("/admin/roles", json={"name": "support", "permissions": ["users:read", "profile:read"]}, headers=adm)
        self.assertEqual(r.status_code, 201)
        self.assertEqual(self.c.post("/admin/roles", json={"name": "support", "permissions": ["users:read"]}, headers=adm).status_code, 409)
        self.assertEqual(self.c.post("/admin/roles", json={"name": "bad", "permissions": ["root:all"]}, headers=adm).status_code, 400)
        self.c.put(f"/admin/users/{uid}/roles", json={"roles": ["support"]}, headers=adm)
        tok = self.login("v@example.com")
        self.assertEqual(self.c.get("/admin/users", headers=self.hdr(tok)).status_code, 200)
        self.assertEqual(self.c.get("/admin/audit-logs", headers=self.hdr(tok)).status_code, 403)

    def test_admin_cannot_lock_themselves_out(self):
        adm_tok = self.admin()
        adm_id = self.c.get("/auth/me", headers=self.hdr(adm_tok)).json["id"]
        r = self.c.put(f"/admin/users/{adm_id}/roles", json={"roles": ["user"]}, headers=self.hdr(adm_tok))
        self.assertEqual((r.status_code, r.json["error"]), (400, "forbidden_change"))
        self.assertEqual(self.c.post(f"/admin/users/{adm_id}/disable", headers=self.hdr(adm_tok)).status_code, 400)

    def test_last_active_admin_cannot_be_removed_or_disabled_by_someone_else(self):
        adm = self.hdr(self.admin())
        admin_id = self.c.get("/auth/me", headers=adm).json["id"]
        self.c.post("/admin/roles", json={"name": "hr", "permissions": ["roles:manage", "users:write", "profile:read"]}, headers=adm)
        hr_id, _ = self.make_user("hr@example.com", roles=["hr"])
        hr = self.hdr(self.login("hr@example.com"))
        r = self.c.put(f"/admin/users/{admin_id}/roles", json={"roles": ["user"]}, headers=hr)
        self.assertEqual((r.status_code, r.json["error"]), (400, "forbidden_change"))
        r = self.c.post(f"/admin/users/{admin_id}/disable", headers=hr)
        self.assertEqual((r.status_code, r.json["error"]), (400, "forbidden_change"))
        # with a second active admin, demotion is allowed
        other_id, _ = self.make_user("admin2@example.com", roles=["admin"])
        r = self.c.put(f"/admin/users/{admin_id}/roles", json={"roles": ["user"]}, headers=hr)
        self.assertEqual(r.status_code, 200)

    def test_disable_and_enable_user(self):
        uid, tok = self.make_user("dis@example.com")
        adm = self.hdr(self.admin())
        self.assertEqual(self.c.post(f"/admin/users/{uid}/disable", headers=adm).status_code, 200)
        self.assertEqual(self.c.get("/auth/me", headers=self.hdr(tok)).status_code, 401)
        self.assertEqual(self.c.post("/auth/refresh", json={"refresh_token": tok["refresh_token"]}).status_code, 400)
        self.assertEqual(self.c.post("/auth/login", json={"email": "dis@example.com", "password": USER_PW}).status_code, 401)
        self.assertEqual(self.c.post(f"/admin/users/{uid}/enable", headers=adm).status_code, 200)
        self.login("dis@example.com")


class TestOAuth2(Base):
    def test_metadata(self):
        m = self.c.get("/.well-known/oauth-authorization-server").json
        self.assertEqual(m["token_endpoint"], "http://auth.test/oauth/token")
        self.assertEqual(m["code_challenge_methods_supported"], ["S256"])

    def test_client_management_validation(self):
        adm = self.hdr(self.admin())
        bad = [
            {"name": "x", "grant_types": ["implicit"], "scopes": ["profile:read"]},
            {"name": "x", "grant_types": ["client_credentials"], "scopes": ["root"]},
            {"name": "x", "grant_types": ["authorization_code"], "scopes": ["profile:read"]},                       # no redirect
            {"name": "x", "grant_types": ["authorization_code"], "scopes": ["profile:read"], "redirect_uris": ["javascript:alert(1)"]},
            {"name": "x", "grant_types": ["authorization_code"], "scopes": ["profile:read"], "redirect_uris": ["http://evil.com/cb"]},
            {"name": "x", "grant_types": ["client_credentials"], "scopes": ["profile:read"], "public": True},
        ]
        for body in bad:
            self.assertEqual(self.c.post("/admin/clients", json=body, headers=adm).status_code, 400, body)
        c = self.create_client(name="svc", grant_types=["client_credentials"], scopes=["users:read"])
        self.assertIn("client_secret", c)
        listed = self.c.get("/admin/clients", headers=adm).json["items"]
        self.assertNotIn("client_secret", json.dumps(listed))
        self.assertNotIn("secret_hash", json.dumps(listed))
        self.assertEqual(self.c.delete(f"/admin/clients/{c['client_id']}", headers=adm).status_code, 204)
        self.assertEqual(self.c.delete(f"/admin/clients/{c['client_id']}", headers=adm).status_code, 404)

    def basic(self, cid, secret):
        return {"Authorization": "Basic " + base64.b64encode(f"{cid}:{secret}".encode()).decode()}

    def test_client_credentials_grant_scopes_introspection_and_revocation(self):
        c = self.create_client(name="svc", grant_types=["client_credentials"], scopes=["users:read"])
        auth = self.basic(c["client_id"], c["client_secret"])

        r = self.c.post("/oauth/token", data={"grant_type": "client_credentials"}, headers=auth)
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        self.assertNotIn("refresh_token", r.json)
        self.assertEqual(r.json["scope"], "users:read")
        self.assertEqual(r.headers["Cache-Control"], "no-store")
        svc = r.json
        # can do what its scope allows, nothing else
        self.assertEqual(self.c.get("/admin/users", headers=self.hdr(svc)).status_code, 200)
        self.assertEqual(self.c.get("/admin/audit-logs", headers=self.hdr(svc)).status_code, 403)
        self.assertEqual(self.c.get("/auth/me", headers=self.hdr(svc)).status_code, 403)
        # scope escalation / bad credentials
        r = self.c.post("/oauth/token", data={"grant_type": "client_credentials", "scope": "audit:read"}, headers=auth)
        self.assertEqual((r.status_code, r.json["error"]), (400, "invalid_scope"))
        r = self.c.post("/oauth/token", data={"grant_type": "client_credentials"}, headers=self.basic(c["client_id"], "wrong"))
        self.assertEqual((r.status_code, r.json["error"]), (401, "invalid_client"))
        self.assertIn("WWW-Authenticate", r.headers)
        r = self.c.post("/oauth/token", data={"grant_type": "client_credentials", "client_id": c["client_id"],
                                              "client_secret": c["client_secret"]})                      # body auth works too
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.c.post("/oauth/token", data={"grant_type": "password"}, headers=auth).json["error"],
                         "unauthorized_client")
        self.assertEqual(self.c.post("/oauth/token", data={"grant_type": "bogus"}, headers=auth).json["error"],
                         "unsupported_grant_type")
        # introspection
        i = self.c.post("/oauth/introspect", data={"token": svc["access_token"]}, headers=auth).json
        self.assertTrue(i["active"]); self.assertEqual(i["sub"], c["client_id"])
        self.assertEqual(self.c.post("/oauth/introspect", data={"token": "junk"}, headers=auth).json, {"active": False})
        self.assertEqual(self.c.post("/oauth/introspect", data={"token": svc["access_token"]}).status_code, 401)
        # revocation
        self.assertEqual(self.c.post("/oauth/revoke", data={"token": svc["access_token"]}, headers=auth).status_code, 200)
        self.assertFalse(self.c.post("/oauth/introspect", data={"token": svc["access_token"]}, headers=auth).json["active"])
        self.assertEqual(self.c.get("/admin/users", headers=self.hdr(svc)).status_code, 401)

    def test_deleting_client_invalidates_its_tokens(self):
        c = self.create_client(name="svc", grant_types=["client_credentials"], scopes=["users:read"])
        t = self.c.post("/oauth/token", data={"grant_type": "client_credentials"},
                        headers=self.basic(c["client_id"], c["client_secret"])).json
        self.c.delete(f"/admin/clients/{c['client_id']}", headers=self.hdr(self.admin()))
        self.assertEqual(self.c.get("/admin/users", headers=self.hdr(t)).status_code, 401)

    def test_password_grant_and_client_bound_refresh(self):
        self.register("pg@example.com")
        a = self.create_client(name="a", grant_types=["password", "refresh_token"], scopes=["profile:read", "profile:write"])
        b = self.create_client(name="b", grant_types=["password", "refresh_token"], scopes=["profile:read"])
        auth_a, auth_b = self.basic(a["client_id"], a["client_secret"]), self.basic(b["client_id"], b["client_secret"])
        form = {"grant_type": "password", "username": "pg@example.com", "password": USER_PW}
        bad = self.c.post("/oauth/token", data={**form, "password": "Wrong-pass-123"}, headers=auth_a)
        self.assertEqual((bad.status_code, bad.json["error"]), (400, "invalid_grant"))
        t = self.c.post("/oauth/token", data=form, headers=auth_a).json
        self.assertEqual(t["scope"], "profile:read profile:write")
        self.assertEqual(self.c.post("/oauth/token", data=form, headers=auth_b).json["scope"], "profile:read")
        # refresh token is bound to the client that received it
        r = self.c.post("/oauth/token", data={"grant_type": "refresh_token", "refresh_token": t["refresh_token"]}, headers=auth_b)
        self.assertEqual(r.json["error"], "invalid_grant")
        r = self.c.post("/auth/refresh", json={"refresh_token": t["refresh_token"]})
        self.assertEqual(r.json["error"], "invalid_grant")
        # scope escalation on refresh is refused (and does not burn the token)
        r = self.c.post("/oauth/token", data={"grant_type": "refresh_token", "refresh_token": t["refresh_token"],
                                              "scope": "users:read"}, headers=auth_a)
        self.assertEqual(r.json["error"], "invalid_scope")
        r = self.c.post("/oauth/token", data={"grant_type": "refresh_token", "refresh_token": t["refresh_token"],
                                              "scope": "profile:read"}, headers=auth_a)
        self.assertEqual((r.status_code, r.json["scope"]), (200, "profile:read"))
        # revoking the refresh token via /oauth/revoke kills the session
        t2 = r.json
        self.c.post("/oauth/revoke", data={"token": t2["refresh_token"]}, headers=auth_a)
        self.assertEqual(self.c.get("/auth/me", headers=self.hdr(t2)).status_code, 401)

    def _authorize_params(self, client, challenge, **over):
        p = {"response_type": "code", "client_id": client["client_id"], "redirect_uri": "http://localhost:3000/cb",
             "scope": "profile:read", "state": "xyz", "code_challenge": challenge, "code_challenge_method": "S256"}
        p.update(over)
        return {k: v for k, v in p.items() if v is not None}

    def test_authorization_code_flow_with_pkce(self):
        self.register("ac@example.com")
        client = self.create_client(name="<b>SPA</b>", public=True, redirect_uris=["http://localhost:3000/cb"],
                                    grant_types=["authorization_code", "refresh_token"], scopes=["profile:read", "profile:write"])
        verifier, challenge = pkce_pair()
        params = self._authorize_params(client, challenge)

        page = self.c.get("/oauth/authorize", query_string=params)
        html = page.get_data(as_text=True)
        self.assertEqual(page.status_code, 200)
        self.assertIn("&lt;b&gt;SPA&lt;/b&gt;", html)                         # output is escaped
        self.assertNotIn("<b>SPA</b>", html)
        self.assertEqual(page.headers["X-Frame-Options"], "DENY")

        # wrong password re-renders form, no redirect
        r = self.c.post("/oauth/authorize", data={**params, "email": "ac@example.com", "password": "Wrong-pass-123"})
        self.assertEqual(r.status_code, 401)

        r = self.c.post("/oauth/authorize", data={**params, "email": "ac@example.com", "password": USER_PW})
        self.assertEqual(r.status_code, 302)
        loc = urlparse(r.headers["Location"]); q = parse_qs(loc.query)
        self.assertEqual((loc.netloc, loc.path, q["state"]), ("localhost:3000", "/cb", ["xyz"]))
        code = q["code"][0]

        exch = {"grant_type": "authorization_code", "code": code, "client_id": client["client_id"],
                "redirect_uri": "http://localhost:3000/cb"}
        # wrong verifier is rejected and does not consume the code
        r = self.c.post("/oauth/token", data={**exch, "code_verifier": pkce_pair()[0]})
        self.assertEqual((r.status_code, r.json["error"]), (400, "invalid_grant"))
        # wrong redirect_uri rejected
        r = self.c.post("/oauth/token", data={**exch, "redirect_uri": "http://localhost:3000/other", "code_verifier": verifier})
        self.assertEqual(r.status_code, 400)

        r = self.c.post("/oauth/token", data={**exch, "code_verifier": verifier})
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        tok = r.json
        self.assertEqual(tok["scope"], "profile:read")

        # scope limits what the token can do although the user's role could do more
        self.assertEqual(self.c.get("/auth/me", headers=self.hdr(tok)).status_code, 200)
        r = self.c.patch("/auth/me", json={"name": "x"}, headers=self.hdr(tok))
        self.assertEqual((r.status_code, r.json["error"]), (403, "insufficient_permissions"))

        # public client can refresh without a secret
        rr = self.c.post("/oauth/token", data={"grant_type": "refresh_token", "client_id": client["client_id"],
                                               "refresh_token": tok["refresh_token"]})
        self.assertEqual(rr.status_code, 200)

        # replaying the code revokes everything that was issued from it
        r = self.c.post("/oauth/token", data={**exch, "code_verifier": verifier})
        self.assertEqual(r.status_code, 400)
        self.assertEqual(self.c.get("/auth/me", headers=self.hdr(tok)).status_code, 401)
        self.assertEqual(self.c.get("/auth/me", headers=self.hdr(rr.json)).status_code, 401)
        self.assertTrue(self.audit(event="oauth.code_reuse"))

    def test_authorize_request_validation(self):
        client = self.create_client(name="spa", public=True, redirect_uris=["http://localhost:3000/cb"],
                                    grant_types=["authorization_code"], scopes=["profile:read"])
        _, ch = pkce_pair()
        # unregistered redirect_uri or unknown client: never redirected (open-redirect protection)
        r = self.c.get("/oauth/authorize", query_string=self._authorize_params(client, ch, redirect_uri="http://localhost:3000/evil"))
        self.assertEqual((r.status_code, r.json["error"]), (400, "invalid_request"))
        r = self.c.get("/oauth/authorize", query_string=self._authorize_params(client, ch, client_id="nope"))
        self.assertEqual(r.status_code, 400)
        # PKCE is mandatory; error goes back to the registered redirect URI
        r = self.c.get("/oauth/authorize", query_string=self._authorize_params(client, None, code_challenge=None))
        self.assertEqual(r.status_code, 302)
        self.assertEqual(parse_qs(urlparse(r.headers["Location"]).query)["error"], ["invalid_request"])
        r = self.c.get("/oauth/authorize", query_string=self._authorize_params(client, ch, code_challenge_method="plain"))
        self.assertEqual(r.status_code, 302)
        r = self.c.get("/oauth/authorize", query_string=self._authorize_params(client, ch, scope="bogus"))
        self.assertEqual(parse_qs(urlparse(r.headers["Location"]).query)["error"], ["invalid_scope"])
        r = self.c.get("/oauth/authorize", query_string=self._authorize_params(client, ch, response_type="token"))
        self.assertEqual(parse_qs(urlparse(r.headers["Location"]).query)["error"], ["unsupported_response_type"])

    def test_code_cannot_be_redeemed_by_another_client_or_after_expiry(self):
        self.register("x@example.com")
        c1 = self.create_client(name="one", public=True, redirect_uris=["http://localhost:3000/cb"],
                                grant_types=["authorization_code"], scopes=["profile:read"])
        c2 = self.create_client(name="two", public=True, redirect_uris=["http://localhost:3000/cb"],
                                grant_types=["authorization_code"], scopes=["profile:read"])
        verifier, ch = pkce_pair()
        r = self.c.post("/oauth/authorize", data={**self._authorize_params(c1, ch), "email": "x@example.com", "password": USER_PW})
        code = parse_qs(urlparse(r.headers["Location"]).query)["code"][0]
        r = self.c.post("/oauth/token", data={"grant_type": "authorization_code", "code": code, "client_id": c2["client_id"],
                                              "redirect_uri": "http://localhost:3000/cb", "code_verifier": verifier})
        self.assertEqual(r.status_code, 400)
        self.db_exec("UPDATE auth_codes SET expires_at = 1")
        r = self.c.post("/oauth/token", data={"grant_type": "authorization_code", "code": code, "client_id": c1["client_id"],
                                              "redirect_uri": "http://localhost:3000/cb", "code_verifier": verifier})
        self.assertEqual(r.status_code, 400)


class TestAuditLog(Base):
    def test_events_are_recorded_with_context(self):
        self.register("log@example.com")
        self.c.post("/auth/login", json={"email": "log@example.com", "password": "Wrong-pass-123"},
                    headers={"User-Agent": "unit-test/1.0"})
        self.login("log@example.com")
        events = {e["event"] for e in self.audit()}
        self.assertTrue({"user.bootstrap_admin", "user.registered", "auth.login_failed", "auth.login"} <= events)
        failed = self.audit(event="auth.login_failed")[0]
        self.assertEqual((failed["success"], failed["user_agent"], failed["details"]["reason"]),
                         (False, "unit-test/1.0", "bad_password"))
        self.assertTrue(failed["ip"])

    def test_filters(self):
        self.register("f@example.com"); self.login("f@example.com")
        self.assertTrue(all(e["event"] == "auth.login" for e in self.audit(event="auth.login")))
        self.assertTrue(all(e["event"].startswith("user.") for e in self.audit(event_prefix="user.")))
        self.assertTrue(all(e["success"] for e in self.audit(success="true")))
        page = self.c.get("/admin/audit-logs?limit=2&offset=1", headers=self.hdr(self.admin())).json
        self.assertEqual((len(page["items"]), page["limit"], page["offset"]), (2, 2, 1))
        self.assertEqual(self.audit(since="2999-01-01"), [])

    def test_hash_chain_detects_tampering_and_deletion(self):
        self.register("chain@example.com"); self.login("chain@example.com")
        adm = self.hdr(self.admin())
        v = self.c.get("/admin/audit-logs/verify", headers=adm).json
        self.assertTrue(v["valid"]); self.assertGreater(v["checked"], 3)

        target = self.db_exec("SELECT id FROM audit_log WHERE event = 'user.registered'").fetchone()[0]
        self.db_exec("UPDATE audit_log SET actor_id = 'someone-else' WHERE id = ?", (target,))
        v = self.c.get("/admin/audit-logs/verify", headers=self.hdr(self.admin())).json
        self.assertEqual((v["valid"], v["first_invalid_id"]), (False, target))

    def test_hash_chain_detects_deleted_rows(self):
        self.register("chain2@example.com"); self.login("chain2@example.com")
        victim = self.db_exec("SELECT id FROM audit_log WHERE event = 'user.registered'").fetchone()[0]
        self.db_exec("DELETE FROM audit_log WHERE id = ?", (victim,))
        v = self.c.get("/admin/audit-logs/verify", headers=self.hdr(self.admin())).json
        self.assertFalse(v["valid"])

    def test_secrets_never_reach_the_audit_log(self):
        self.register("sec@example.com", "Very-Secret-Pw1")
        tok = self.login("sec@example.com", "Very-Secret-Pw1")
        self.c.post("/auth/login", json={"email": "sec@example.com", "password": "Another-Bad-Pw1"})
        self.c.post("/auth/refresh", json={"refresh_token": tok["refresh_token"]})
        dump = json.dumps([dict(r) for r in self.db_exec("SELECT * FROM audit_log").fetchall()])
        for secret in ("Very-Secret-Pw1", "Another-Bad-Pw1", ADMIN_PW, tok["refresh_token"], tok["access_token"]):
            self.assertNotIn(secret, dump)

    def test_sensitive_detail_keys_are_redacted(self):
        from auth_service import audit
        with self.app.app_context():
            audit.log("test.event", details={"password": "hunter2", "client_secret": "s3cr3t", "visible": "yes",
                                             "nested": {"refresh_token": "abc", "code_verifier": "v"}, "sid": "keep-me"})
        row = [e for e in self.audit(event="test.event")][0]
        self.assertEqual(row["details"]["visible"], "yes")
        self.assertEqual(row["details"]["sid"], "keep-me")
        self.assertEqual(row["details"]["password"], "[redacted]")
        self.assertEqual(row["details"]["client_secret"], "[redacted]")
        self.assertEqual(row["details"]["nested"], {"refresh_token": "[redacted]", "code_verifier": "[redacted]"})

    def test_concurrent_writes_keep_chain_valid(self):
        def worker(i):
            c = self.app.test_client()
            for _ in range(5):
                c.post("/auth/login", json={"email": f"nobody{i}@example.com", "password": "x"})
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(6)]
        [t.start() for t in threads]; [t.join() for t in threads]
        v = self.c.get("/admin/audit-logs/verify", headers=self.hdr(self.admin())).json
        self.assertTrue(v["valid"], v)
        self.assertGreaterEqual(v["checked"], 30)


class TestHousekeeping(Base):
    def test_purge_expired(self):
        self.register("h@example.com"); self.login("h@example.com")
        self.db_exec("UPDATE refresh_tokens SET expires_at = 1")
        with self.app.app_context():
            self.assertEqual(tokens.purge_expired()["refresh_tokens"], 1)

    def test_health(self):
        self.assertEqual(self.c.get("/health").json, {"status": "ok"})


if __name__ == "__main__":
    unittest.main()
