"""
GuardianAI - Audit log (Module 8)

Persistent SQLite log of every gateway decision. It stores categories,
tool names, decisions and reasons, never raw PII values (callers must
only pass tokenized or categorical data in `detail`).
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path


class AuditLog:
    def __init__(self, db_path: Path):
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        with self._lock:
            self._conn.execute(
                """CREATE TABLE IF NOT EXISTS audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL NOT NULL,
                    event TEXT NOT NULL,
                    agent TEXT,
                    decision TEXT,
                    detail TEXT NOT NULL)"""
            )
            self._conn.commit()

    def log(self, event: str, agent: str | None = None, decision: str | None = None, **detail) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO audit (ts, event, agent, decision, detail) VALUES (?,?,?,?,?)",
                (time.time(), event, agent, decision, json.dumps(detail, default=str)),
            )
            self._conn.commit()

    def recent(self, limit: int = 50, agent: str | None = None) -> list[dict]:
        query = "SELECT id, ts, event, agent, decision, detail FROM audit"
        params: list = []
        if agent:
            query += " WHERE agent = ?"
            params.append(agent)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(max(1, min(limit, 500)))
        with self._lock:
            rows = self._conn.execute(query, params).fetchall()
        return [
            {"id": r[0], "ts": r[1], "event": r[2], "agent": r[3], "decision": r[4],
             "detail": json.loads(r[5])}
            for r in rows
        ]

    def close(self) -> None:
        with self._lock:
            self._conn.close()
