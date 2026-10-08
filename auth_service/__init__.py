"""Authentication service: OAuth2 + JWT + RBAC + refresh tokens + audit logging."""
import logging
import os

import click
from flask import Flask, jsonify, request
from werkzeug.middleware.proxy_fix import ProxyFix

from . import audit, db, tokens, users
from .config import load_config
from .errors import ApiError, register_error_handlers
from .policy import ROLE_DEFS
from .ratelimit import RateLimiter
from .security import KeyManager

_LIMITED_PATHS = {"/auth/login", "/auth/register", "/auth/refresh", "/oauth/token", "/oauth/authorize"}


def create_app(overrides: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.url_map.strict_slashes = False
    app.config.update(load_config())
    if overrides:
        app.config.update(overrides)
    cfg = app.config

    for path in (cfg["DATABASE_PATH"], cfg["PRIVATE_KEY_PATH"]):
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    if cfg["TRUSTED_PROXY_COUNT"] > 0:
        n = cfg["TRUSTED_PROXY_COUNT"]
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=n, x_proto=n, x_host=n)

    app.extensions["keys"] = KeyManager(cfg["PRIVATE_KEY_PATH"], cfg["JWT_PRIVATE_KEY"])
    app.extensions["limiter"] = RateLimiter(cfg["RATE_LIMIT_PER_MINUTE"]) if cfg["RATE_LIMIT_PER_MINUTE"] > 0 else None
    db.init_app(app)
    register_error_handlers(app)

    from .routes import admin, auth, oauth
    for module in (auth, admin, oauth):
        app.register_blueprint(module.bp)

    @app.before_request
    def _rate_limit():
        limiter = app.extensions["limiter"]
        if limiter and request.method == "POST" and request.path.rstrip("/") in _LIMITED_PATHS:
            retry = limiter.check((request.remote_addr, request.path))
            if retry:
                raise ApiError(429, "rate_limited", "Too many requests", {"Retry-After": str(retry)})

    @app.after_request
    def _headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        if request.path.startswith(("/auth", "/admin", "/oauth")):
            resp.headers.setdefault("Cache-Control", "no-store")
        return resp

    @app.get("/health")
    def health():
        db.get_db().execute("SELECT 1")
        return jsonify({"status": "ok"})

    _register_cli(app)
    _bootstrap_admin(app)
    return app


def _bootstrap_admin(app):
    email, password = app.config["BOOTSTRAP_ADMIN_EMAIL"], app.config["BOOTSTRAP_ADMIN_PASSWORD"]
    if not (email and password):
        return
    with app.app_context():
        if users.get_user_by_email(email) is None:
            try:
                user = users.create_user(email, password, name="Administrator", roles=("admin",))
            except ApiError as e:
                raise RuntimeError(f"Cannot create bootstrap admin: {e.description}") from None
            audit.log("user.bootstrap_admin", target=user["id"], ip="local")
            logging.getLogger(__name__).info("Bootstrap admin created: %s", user["email"])


def _register_cli(app):
    @app.cli.command("create-admin")
    @click.argument("email")
    @click.password_option()
    def create_admin(email, password):
        """Create an administrator account."""
        user = users.create_user(email, password, roles=("admin",))
        audit.log("user.bootstrap_admin", target=user["id"], ip="local")
        click.echo(f"Created admin {user['email']}")

    @app.cli.command("purge-expired")
    def purge_expired():
        """Delete expired tokens / codes. Run from cron."""
        click.echo(tokens.purge_expired())
