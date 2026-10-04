"""
GuardianAI - Dashboard sessions and owner binding

Admin actions (connecting accounts, creating agents, approving actions) need
a signed-in session. The first identity to sign in becomes the owner; any
other identity is refused afterwards, so a second Google account cannot take
over the local install.
"""
from __future__ import annotations

import secrets
import threading
import time

from guardianai.vault import Vault

SESSION_TTL_SECONDS = 8 * 3600
COOKIE_NAME = "gai_session"


class SessionStore:
    def __init__(self, ttl: int = SESSION_TTL_SECONDS):
        self._ttl = ttl
        self._sessions: dict[str, tuple[str, float]] = {}
        self._lock = threading.Lock()

    def create(self, identity: str) -> str:
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._sessions[token] = (identity, time.time() + self._ttl)
        return token

    def get(self, token: str | None) -> str | None:
        if not token:
            return None
        with self._lock:
            entry = self._sessions.get(token)
            if entry is None:
                return None
            identity, expires = entry
            if expires < time.time():
                del self._sessions[token]
                return None
            return identity

    def revoke(self, token: str | None) -> None:
        with self._lock:
            self._sessions.pop(token or "", None)


def claim_or_check_owner(vault: Vault, identity: str) -> bool:
    """First identity claims ownership; afterwards only the owner may sign in."""
    identity = identity.strip().lower()
    owner = vault.get("owner")
    if owner is None:
        vault.set("owner", {"identity": identity})
        return True
    return owner["identity"] == identity
