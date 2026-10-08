"""SQLite access. Connections run in autocommit mode; multi-statement units use
transaction() (BEGIN IMMEDIATE) so writers serialise cleanly."""
import sqlite3
from contextlib import contextmanager

from flask import current_app, g

from .policy import ROLE_DEFS

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  name TEXT,
  password_hash TEXT NOT NULL,
  is_active INTEGER NOT NULL DEFAULT 1,
  token_version INTEGER NOT NULL DEFAULT 0,
  failed_attempts INTEGER NOT NULL DEFAULT 0,
  locked_until INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS roles (
  name TEXT PRIMARY KEY,
  description TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS role_permissions (
  role TEXT NOT NULL REFERENCES roles(name) ON DELETE CASCADE,
  permission TEXT NOT NULL,
  PRIMARY KEY (role, permission)
);
CREATE TABLE IF NOT EXISTS user_roles (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role TEXT NOT NULL REFERENCES roles(name) ON DELETE RESTRICT,
  PRIMARY KEY (user_id, role)
);
CREATE TABLE IF NOT EXISTS oauth_clients (
  client_id TEXT PRIMARY KEY,
  secret_hash TEXT,                       -- NULL for public clients
  name TEXT NOT NULL,
  redirect_uris TEXT NOT NULL DEFAULT '[]',
  grant_types TEXT NOT NULL,
  scopes TEXT NOT NULL,
  created_by TEXT,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS auth_codes (
  code_hash TEXT PRIMARY KEY,
  client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  redirect_uri TEXT NOT NULL,
  scope TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  used_at INTEGER,
  session_id TEXT
);
CREATE TABLE IF NOT EXISTS refresh_tokens (
  id TEXT PRIMARY KEY,
  token_hash TEXT NOT NULL UNIQUE,        -- sha256 of the opaque token; raw token never stored
  family_id TEXT NOT NULL,                -- = session id (sid claim)
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  client_id TEXT REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
  scope TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  used_at INTEGER,
  revoked_at INTEGER,
  replaced_by TEXT
);
CREATE INDEX IF NOT EXISTS idx_refresh_family ON refresh_tokens(family_id);
CREATE INDEX IF NOT EXISTS idx_refresh_user ON refresh_tokens(user_id);
CREATE TABLE IF NOT EXISTS revoked_jtis (
  jti TEXT PRIMARY KEY,
  expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  event TEXT NOT NULL,
  actor_id TEXT,
  target TEXT,
  ip TEXT,
  user_agent TEXT,
  success INTEGER NOT NULL,
  details TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_event ON audit_log(event);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor_id);
"""


def connect(path):
    conn = sqlite3.connect(path, isolation_level=None, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=10000")
    return conn


def get_db():
    if "db" not in g:
        g.db = connect(current_app.config["DATABASE_PATH"])
    return g.db


def _close_db(_exc=None):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


@contextmanager
def transaction(conn):
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    else:
        conn.execute("COMMIT")


def init_app(app):
    app.teardown_appcontext(_close_db)
    conn = connect(app.config["DATABASE_PATH"])
    try:
        conn.executescript(SCHEMA)
        for role, (desc, perms) in ROLE_DEFS.items():
            conn.execute("INSERT OR IGNORE INTO roles(name, description) VALUES (?, ?)", (role, desc))
            for p in perms:
                conn.execute("INSERT OR IGNORE INTO role_permissions(role, permission) VALUES (?, ?)", (role, p))
    finally:
        conn.close()
