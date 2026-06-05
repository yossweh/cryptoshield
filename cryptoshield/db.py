"""SQLite cache for API results."""

import sqlite3
import json
import time
from pathlib import Path

DB_PATH = Path.home() / ".cryptoshield" / "cache.db"


def get_db() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cache (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            expires_at REAL NOT NULL
        )
    """)
    conn.commit()
    return conn


def cache_get(key: str) -> dict | None:
    conn = get_db()
    row = conn.execute(
        "SELECT value, expires_at FROM cache WHERE key = ?", (key,)
    ).fetchone()
    conn.close()
    if row and row[1] > time.time():
        return json.loads(row[0])
    return None


def cache_set(key: str, value: dict, ttl: int = 3600):
    conn = get_db()
    conn.execute(
        "INSERT OR REPLACE INTO cache (key, value, expires_at) VALUES (?, ?, ?)",
        (key, json.dumps(value), time.time() + ttl),
    )
    conn.commit()
    conn.close()


def cache_clear():
    conn = get_db()
    conn.execute("DELETE FROM cache")
    conn.commit()
    conn.close()
