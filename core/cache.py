"""Tiny SQLite key-value cache. Stores only public vulnerability data."""
import json
import sqlite3
import time
from contextlib import closing

from .config import DB_PATH


def _conn():
    c = sqlite3.connect(DB_PATH)
    c.execute("CREATE TABLE IF NOT EXISTS cache (key TEXT PRIMARY KEY, value TEXT, ts REAL)")
    return c


def get(key, ttl=None):
    """Return cached value if fresh (or any age when ttl is None), else None."""
    with closing(_conn()) as c:
        row = c.execute("SELECT value, ts FROM cache WHERE key=?", (key,)).fetchone()
    if row and (ttl is None or time.time() - row[1] < ttl):
        return json.loads(row[0])
    return None


def put(key, value):
    with closing(_conn()) as c:
        c.execute("REPLACE INTO cache (key, value, ts) VALUES (?, ?, ?)", (key, json.dumps(value), time.time()))
        c.commit()


def cached(key, ttl, fetch):
    """Fresh cache -> fetch() -> stale cache fallback if the fetch fails."""
    fresh = get(key, ttl)
    if fresh is not None:
        return fresh
    try:
        value = fetch()
    except Exception:
        stale = get(key, None)
        if stale is not None:
            return stale
        raise
    put(key, value)
    return value
