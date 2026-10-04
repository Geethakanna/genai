"""
GuardianAI - Human approval queue

When policy says REQUIRE_APPROVAL, the call is held here. Only a signed-in
user (dashboard) can approve or deny. An approval is one-time and bound to the
exact call (agent + tool + arguments); a changed call needs a new approval.
"""
from __future__ import annotations

import secrets
import threading
import time

APPROVAL_TTL = 600


class ApprovalStore:
    def __init__(self):
        self._items: dict[str, dict] = {}
        self._lock = threading.Lock()

    def _expire(self) -> None:
        cutoff = time.time() - APPROVAL_TTL
        for k in [k for k, v in self._items.items() if v["created"] < cutoff]:
            del self._items[k]

    def request(self, fingerprint: str, **info) -> dict:
        with self._lock:
            self._expire()
            for item in self._items.values():
                if item["fingerprint"] == fingerprint and item["status"] == "pending":
                    return item
            item = {"id": secrets.token_hex(4), "fingerprint": fingerprint, "status": "pending",
                    "created": time.time(), **info}
            self._items[item["id"]] = item
            return item

    def status_for(self, fingerprint: str) -> str | None:
        """'approved' (consumed on read) | 'denied' | 'pending' | None."""
        with self._lock:
            self._expire()
            for k, item in list(self._items.items()):
                if item["fingerprint"] == fingerprint:
                    if item["status"] == "approved":
                        del self._items[k]  # one-time use
                        return "approved"
                    return item["status"]
        return None

    def decide(self, approval_id: str, approve: bool) -> dict:
        with self._lock:
            item = self._items.get(approval_id)
            if item is None or item["status"] != "pending":
                raise KeyError(approval_id)
            item["status"] = "approved" if approve else "denied"
            return item

    def pending(self) -> list[dict]:
        with self._lock:
            self._expire()
            return [{k: v for k, v in i.items() if k != "fingerprint"}
                    for i in self._items.values() if i["status"] == "pending"]
