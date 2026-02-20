import sqlite3
import os
from app.config import DATABASE_PATH, DATA_DIR

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    last_login DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_seed INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL,
    asset_hostname TEXT NOT NULL,
    asset_ip TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    raw_log TEXT,
    assigned_to INTEGER REFERENCES users(id),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS secret_flags (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    flag_name TEXT NOT NULL,
    flag_value TEXT NOT NULL,
    hint TEXT
);

CREATE TABLE IF NOT EXISTS incident_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    alert_id INTEGER REFERENCES alerts(id),
    created_by INTEGER REFERENCES users(id),
    author_name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    event_type TEXT NOT NULL,
    candidate_email TEXT,
    session_id TEXT,
    method TEXT,
    path TEXT,
    detail TEXT,
    ip_address TEXT,
    user_agent TEXT
);
"""


def get_db(readonly=False):
    if readonly:
        conn = sqlite3.connect(f'file:{DATABASE_PATH}?mode=ro', uri=True)
    else:
        conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(DATABASE_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()


def query_db(query, args=(), one=False, readonly=True):
    conn = get_db(readonly=readonly)
    try:
        cur = conn.execute(query, args)
        rv = cur.fetchall()
        conn.commit()
        return (rv[0] if rv else None) if one else rv
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def execute_db(query, args=()):
    conn = get_db(readonly=False)
    try:
        cur = conn.execute(query, args)
        conn.commit()
        return cur
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def execute_vulnerable(query):
    """Execute a raw query string WITHOUT parameterization. Intentionally vulnerable.
    Uses execute() which does NOT support multiple statements — safe against '; DROP TABLE' etc."""
    conn = get_db(readonly=False)
    try:
        cur = conn.execute(query)
        rv = cur.fetchall()
        return rv
    except sqlite3.OperationalError as e:
        raise e
    finally:
        conn.close()
