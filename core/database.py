"""SQLite persistence with foreign keys, WAL and auditable transactions."""
from __future__ import annotations
import sqlite3
import json
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def connect(path: str | Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path), timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys=ON')
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA busy_timeout=15000')
    return conn


SCHEMA = '''
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
 display_name TEXT NOT NULL, business_role TEXT NOT NULL,
 system_role TEXT NOT NULL CHECK(system_role IN ('EMPLOYEE','APPROVER','ADMIN')),
 source_ip TEXT NOT NULL UNIQUE, active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
 created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS assets (
 id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, ip TEXT NOT NULL UNIQUE,
 department TEXT NOT NULL, sensitivity TEXT NOT NULL CHECK(sensitivity IN ('LOW','MEDIUM','HIGH')),
 owner TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1))
);
CREATE TABLE IF NOT EXISTS services (
 id INTEGER PRIMARY KEY, asset_id INTEGER NOT NULL REFERENCES assets(id),
 name TEXT NOT NULL, protocol TEXT NOT NULL CHECK(protocol IN ('TCP','UDP')),
 port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),
 active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
 UNIQUE(asset_id,protocol,port)
);
CREATE TABLE IF NOT EXISTS entitlements (
 id INTEGER PRIMARY KEY, business_role TEXT NOT NULL,
 service_id INTEGER NOT NULL REFERENCES services(id),
 UNIQUE(business_role, service_id)
);
CREATE TABLE IF NOT EXISTS requests (
 id INTEGER PRIMARY KEY, requester_id INTEGER NOT NULL REFERENCES users(id),
 service_id INTEGER NOT NULL REFERENCES services(id),
 purpose TEXT NOT NULL, status TEXT NOT NULL
 CHECK(status IN ('PENDING','APPROVED','REJECTED','REVOKED','EXPIRED')),
 requested_at TEXT NOT NULL, expires_at TEXT NOT NULL,
 decided_by INTEGER REFERENCES users(id), decided_at TEXT, decision_reason TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS traffic (
 id INTEGER PRIMARY KEY, dedup_key TEXT NOT NULL UNIQUE,
 occurred_at TEXT NOT NULL, src_ip TEXT NOT NULL, dst_ip TEXT NOT NULL,
 protocol TEXT NOT NULL CHECK(protocol IN ('TCP','UDP','ICMP')),
 dst_port INTEGER NOT NULL CHECK(dst_port BETWEEN 0 AND 65535),
 observed_action TEXT NOT NULL CHECK(observed_action IN ('ALLOW','DENY','UNKNOWN')),
 source_type TEXT NOT NULL, imported_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_events (
 id INTEGER PRIMARY KEY, occurred_at TEXT NOT NULL, actor_id INTEGER REFERENCES users(id),
 event TEXT NOT NULL, entity TEXT NOT NULL, entity_id INTEGER, detail_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_requests_user_status ON requests(requester_id,status);
CREATE INDEX IF NOT EXISTS idx_requests_expiry ON requests(status,expires_at);
CREATE INDEX IF NOT EXISTS idx_traffic_timestamp ON traffic(occurred_at);
'''


def initialize(path: str | Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    con=connect(path)
    try:
        con.executescript(SCHEMA)
    finally:
        con.close()


@contextmanager
def transaction(path: str | Path):
    c = connect(path)
    try:
        c.execute('BEGIN IMMEDIATE')
        yield c
        c.commit()
    except Exception:
        c.rollback()
        raise
    finally:
        c.close()


def event(c, actor_id, kind, entity, entity_id=None, detail=None):
    c.execute('INSERT INTO audit_events (occurred_at,actor_id,event,entity,entity_id,detail_json) VALUES (?,?,?,?,?,?)',
              (utc_now(),actor_id,kind,entity,entity_id,json.dumps(detail or {}, ensure_ascii=False,sort_keys=True)))


def query(path, sql, params=()):
    c=connect(path)
    try:
        return [dict(r) for r in c.execute(sql,params).fetchall()]
    finally:
        c.close()
