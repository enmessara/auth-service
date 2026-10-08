"""Configuration, loaded from environment variables (12-factor style)."""
import os
from pathlib import Path


def _get(name, default, cast=str):
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    if cast is bool:
        return raw.strip().lower() in ("1", "true", "yes", "on")
    return cast(raw)


def load_config() -> dict:
    data_dir = Path(_get("DATA_DIR", "./data"))
    return {
        "DATA_DIR": str(data_dir),
        "DATABASE_PATH": _get("DATABASE_PATH", str(data_dir / "auth.db")),
        # RSA signing key. Either a PEM file path (auto-generated on first run)
        # or the PEM text itself in JWT_PRIVATE_KEY (e.g. from a secret manager).
        "PRIVATE_KEY_PATH": _get("PRIVATE_KEY_PATH", str(data_dir / "jwt_private.pem")),
        "JWT_PRIVATE_KEY": _get("JWT_PRIVATE_KEY", None),
        "JWT_ISSUER": _get("JWT_ISSUER", "http://localhost:5000"),
        "JWT_AUDIENCE": _get("JWT_AUDIENCE", "auth-service-api"),
        "ACCESS_TOKEN_TTL": _get("ACCESS_TOKEN_TTL", 900, int),            # 15 min
        "REFRESH_TOKEN_TTL": _get("REFRESH_TOKEN_TTL", 7 * 86400, int),    # 7 days
        "AUTH_CODE_TTL": _get("AUTH_CODE_TTL", 60, int),
        "MAX_FAILED_LOGINS": _get("MAX_FAILED_LOGINS", 5, int),
        "LOCKOUT_SECONDS": _get("LOCKOUT_SECONDS", 900, int),
        "PASSWORD_HASH_METHOD": _get("PASSWORD_HASH_METHOD", "scrypt"),
        "REGISTRATION_ENABLED": _get("REGISTRATION_ENABLED", True, bool),
        "BOOTSTRAP_ADMIN_EMAIL": _get("BOOTSTRAP_ADMIN_EMAIL", None),
        "BOOTSTRAP_ADMIN_PASSWORD": _get("BOOTSTRAP_ADMIN_PASSWORD", None),
        "RATE_LIMIT_PER_MINUTE": _get("RATE_LIMIT_PER_MINUTE", 60, int),   # 0 = off
        "TRUSTED_PROXY_COUNT": _get("TRUSTED_PROXY_COUNT", 0, int),
        "MAX_CONTENT_LENGTH": 64 * 1024,
        "JSON_SORT_KEYS": False,
    }
