"""
GuardianAI - Local Vault

Encrypted-at-rest key/value store on the user's disk (SQLite + Fernet).
The Fernet key lives in the OS keychain via `keyring`, never next to the
data. There is deliberately no hardcoded fallback key: if no keychain is
available, startup fails loudly instead of "securing" data with a key
that ships in the source code.

`key=` can be injected for automated tests only.
"""
from __future__ import annotations

import json
import secrets
import sqlite3
import threading
import time
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

_SERVICE_NAME = "guardianai"
_KEY_USERNAME = "vault-encryption-key"


class VaultError(RuntimeError):
    pass


def _get_or_create_keychain_key() -> bytes:
    import keyring  # imported lazily so tests can inject a key without a keychain

    existing = keyring.get_password(_SERVICE_NAME, _KEY_USERNAME)
    if existing:
        return existing.encode("utf-8")
    new_key = Fernet.generate_key()
    keyring.set_password(_SERVICE_NAME, _KEY_USERNAME, new_key.decode("utf-8"))
    return new_key


class Vault:
    def __init__(self, db_path: Path, key: bytes | None = None):
        self._fernet = Fernet(key if key is not None else _get_or_create_keychain_key())
        self._lock = threading.RLock()
        # FastAPI runs sync endpoints in a thread pool, so the connection must
        # be shareable; all access is serialized through self._lock.
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        with self._lock:
            self._conn.execute(
                """CREATE TABLE IF NOT EXISTS vault_entries (
                    key TEXT PRIMARY KEY,
                    ciphertext BLOB NOT NULL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL)"""
            )
            self._conn.commit()

    def set(self, key: str, value: dict) -> None:
        ciphertext = self._fernet.encrypt(json.dumps(value).encode("utf-8"))
        now = time.time()
        with self._lock:
            self._conn.execute(
                """INSERT INTO vault_entries (key, ciphertext, created_at, updated_at)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(key) DO UPDATE SET
                     ciphertext = excluded.ciphertext, updated_at = excluded.updated_at""",
                (key, ciphertext, now, now),
            )
            self._conn.commit()

    def get(self, key: str) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT ciphertext FROM vault_entries WHERE key = ?", (key,)
            ).fetchone()
        if row is None:
            return None
        try:
            return json.loads(self._fernet.decrypt(row[0]).decode("utf-8"))
        except InvalidToken as exc:
            raise VaultError(
                f"Could not decrypt vault entry '{key}': the keychain key may have "
                f"changed or the vault file may be corrupted."
            ) from exc

    def delete(self, key: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM vault_entries WHERE key = ?", (key,))
            self._conn.commit()

    def list_keys(self, prefix: str = "") -> list[str]:
        escaped = prefix.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        with self._lock:
            rows = self._conn.execute(
                "SELECT key FROM vault_entries WHERE key LIKE ? ESCAPE '\\' ORDER BY key",
                (f"{escaped}%",),
            ).fetchall()
        return [r[0] for r in rows]

    def get_or_create_secret(self, name: str) -> bytes:
        """A random per-install secret (e.g. the key used to derive stable tokens)."""
        with self._lock:
            entry = self.get(f"secret:{name}")
            if entry is None:
                entry = {"hex": secrets.token_hex(32)}
                self.set(f"secret:{name}", entry)
            return bytes.fromhex(entry["hex"])

    def close(self) -> None:
        with self._lock:
            self._conn.close()
