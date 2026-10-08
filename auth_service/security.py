"""Password hashing, RSA key management and JWT encode/decode."""
import base64
import hashlib
import os
import secrets

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import current_app
from werkzeug.security import check_password_hash, generate_password_hash

ALGORITHM = "RS256"
TOKEN_TYP = "at+jwt"           # RFC 9068 JWT access token
REQUIRED_CLAIMS = ["exp", "iat", "nbf", "sub", "jti", "iss", "aud"]


# ---------------------------------------------------------------- passwords
def hash_password(password: str) -> str:
    return generate_password_hash(password, method=current_app.config["PASSWORD_HASH_METHOD"])


def verify_password(stored_hash: str, password: str) -> bool:
    return check_password_hash(stored_hash, password)


_dummy_hash = None


def burn_password_check(password: str) -> None:
    """Spend the same time as a real check so unknown users aren't detectable by timing."""
    global _dummy_hash
    if _dummy_hash is None:
        _dummy_hash = hash_password(secrets.token_urlsafe(16))
    check_password_hash(_dummy_hash, password)


def password_problems(password, email=None) -> list[str]:
    problems = []
    if not isinstance(password, str):
        return ["password must be a string"]
    if len(password) < 10:
        problems.append("at least 10 characters")
    if len(password) > 128:
        problems.append("at most 128 characters")
    if not any(c.islower() for c in password):
        problems.append("a lowercase letter")
    if not any(c.isupper() for c in password):
        problems.append("an uppercase letter")
    if not any(c.isdigit() for c in password):
        problems.append("a digit")
    if email and email.split("@")[0].lower() in password.lower() and len(email.split("@")[0]) >= 4:
        problems.append("must not contain your email name")
    return problems


# --------------------------------------------------------------------- keys
def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _int_b64u(n: int) -> str:
    return _b64u(n.to_bytes((n.bit_length() + 7) // 8, "big"))


class KeyManager:
    """Holds the RS256 signing key. Generated on first start if no key exists."""

    def __init__(self, path=None, pem=None):
        if pem:
            self.private_key = serialization.load_pem_private_key(pem.encode(), password=None)
        else:
            if not os.path.exists(path):
                self._generate(path)
            with open(path, "rb") as fh:
                self.private_key = serialization.load_pem_private_key(fh.read(), password=None)
        self.public_key = self.private_key.public_key()
        der = self.public_key.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.kid = _b64u(hashlib.sha256(der).digest())[:22]

    @staticmethod
    def _generate(path):
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = key.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
        tmp = f"{path}.{secrets.token_hex(4)}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(pem)
        try:
            os.link(tmp, path)          # atomic; loses gracefully if another worker won the race
        except FileExistsError:
            pass
        finally:
            os.remove(tmp)

    def jwk(self) -> dict:
        nums = self.public_key.public_numbers()
        return {"kty": "RSA", "use": "sig", "alg": ALGORITHM, "kid": self.kid,
                "n": _int_b64u(nums.n), "e": _int_b64u(nums.e)}

    def encode(self, claims: dict) -> str:
        return jwt.encode(claims, self.private_key, algorithm=ALGORITHM,
                          headers={"kid": self.kid, "typ": TOKEN_TYP})

    def decode(self, token: str) -> dict:
        """Verify signature, exp/nbf, issuer, audience and token type. Raises jwt.PyJWTError."""
        header = jwt.get_unverified_header(token)
        if header.get("typ") != TOKEN_TYP:
            raise jwt.InvalidTokenError("wrong token type")
        if header.get("alg") != ALGORITHM:
            raise jwt.InvalidAlgorithmError("unexpected algorithm")
        cfg = current_app.config
        return jwt.decode(token, self.public_key, algorithms=[ALGORITHM],
                          audience=cfg["JWT_AUDIENCE"], issuer=cfg["JWT_ISSUER"],
                          options={"require": REQUIRED_CLAIMS})


def keys() -> KeyManager:
    return current_app.extensions["keys"]
