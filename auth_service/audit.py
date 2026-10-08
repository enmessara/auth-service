"""Append-only audit log with a SHA-256 hash chain.

Every row stores the hash of the previous row, so editing or deleting a row in
the middle of the log is detectable with verify_chain(). (Truncating the *tail*
is not detectable by the chain alone - ship the log to external storage as well.)
"""
import hashlib
import json
import threading

from flask import has_request_context, request

from . import util
from .db import get_db, transaction

GENESIS = "0" * 64
_lock = threading.Lock()
_SENSITIVE = ("password", "secret", "token", "code", "verifier", "authorization")


def _redact(value):
    if isinstance(value, dict):
        return {k: ("[redacted]" if any(s in k.lower() for s in _SENSITIVE) and k not in ("sid", "token_type")
                    else _redact(v)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact(v) for v in value]
    return value


def _digest(prev_hash: str, record: dict) -> str:
    canon = json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(f"{prev_hash}|{canon}".encode()).hexdigest()


def log(event, *, actor_id=None, target=None, success=True, details=None, ip=None, user_agent=None):
    if has_request_context():
        ip = ip or request.remote_addr
        user_agent = user_agent or request.headers.get("User-Agent")
    record = {
        "ts": util.iso(util.now()),
        "event": event,
        "actor_id": actor_id,
        "target": target,
        "ip": ip,
        "user_agent": (user_agent or "")[:200] or None,
        "success": bool(success),
        "details": _redact(details or {}),
    }
    db = get_db()
    with _lock, transaction(db):
        row = db.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
        prev = row["hash"] if row else GENESIS
        db.execute(
            "INSERT INTO audit_log(ts, event, actor_id, target, ip, user_agent, success, details, prev_hash, hash)"
            " VALUES (?,?,?,?,?,?,?,?,?,?)",
            (record["ts"], event, actor_id, target, record["ip"], record["user_agent"],
             int(record["success"]), json.dumps(record["details"], sort_keys=True),
             prev, _digest(prev, record)))


def _record_from_row(row) -> dict:
    return {"ts": row["ts"], "event": row["event"], "actor_id": row["actor_id"], "target": row["target"],
            "ip": row["ip"], "user_agent": row["user_agent"], "success": bool(row["success"]),
            "details": json.loads(row["details"])}


def verify_chain() -> dict:
    db = get_db()
    prev, checked = GENESIS, 0
    for row in db.execute("SELECT * FROM audit_log ORDER BY id ASC"):
        if row["prev_hash"] != prev or row["hash"] != _digest(prev, _record_from_row(row)):
            return {"valid": False, "checked": checked, "first_invalid_id": row["id"]}
        prev = row["hash"]
        checked += 1
    return {"valid": True, "checked": checked, "first_invalid_id": None}


def serialize(row) -> dict:
    return {"id": row["id"], "ts": row["ts"], "event": row["event"], "actor_id": row["actor_id"],
            "target": row["target"], "ip": row["ip"], "user_agent": row["user_agent"],
            "success": bool(row["success"]), "details": json.loads(row["details"]), "hash": row["hash"]}
