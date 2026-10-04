"""Durable SQLite state store for the safety state machine.

Approval token IDs are consumed with an atomic ``INSERT`` on a primary key, so
a restart or a second process sharing the same database file cannot replay an
approval.
"""

import json
import sqlite3
import threading


class SQLiteStateStore:
    """Persist machine state and single-use approval IDs in SQLite."""

    def __init__(self, path):
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS machine_state "
            "(id INTEGER PRIMARY KEY CHECK (id = 1), data TEXT NOT NULL)"
        )
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS consumed_approvals (token_id TEXT PRIMARY KEY)"
        )

    def consume_approval(self, token_id):
        """Atomically mark ``token_id`` consumed; return False if already used."""
        with self._lock:
            try:
                self._db.execute(
                    "INSERT INTO consumed_approvals (token_id) VALUES (?)", (token_id,)
                )
            except sqlite3.IntegrityError:
                return False
            return True

    def is_consumed(self, token_id):
        with self._lock:
            row = self._db.execute(
                "SELECT 1 FROM consumed_approvals WHERE token_id = ?", (token_id,)
            ).fetchone()
        return row is not None

    def consumed_approvals(self):
        with self._lock:
            rows = self._db.execute("SELECT token_id FROM consumed_approvals").fetchall()
        return {row[0] for row in rows}

    def save_state(self, data):
        payload = json.dumps(data, sort_keys=True)
        with self._lock:
            self._db.execute(
                "INSERT INTO machine_state (id, data) VALUES (1, ?) "
                "ON CONFLICT(id) DO UPDATE SET data = excluded.data",
                (payload,),
            )

    def load_state(self):
        with self._lock:
            row = self._db.execute("SELECT data FROM machine_state WHERE id = 1").fetchone()
        return json.loads(row[0]) if row else None

    def close(self):
        with self._lock:
            self._db.close()
