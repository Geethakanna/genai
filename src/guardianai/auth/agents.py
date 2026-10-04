"""
GuardianAI - Agent registry

Every AI agent that talks to the gateway gets its own bearer token and its
own permissions, so the dashboard can show, per agent, what it may reach.
Only a SHA-256 hash of the token is stored; the token itself is shown once.
Default permissions are read-only.
"""
from __future__ import annotations

import fnmatch
import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass, field

from guardianai.vault import Vault

_PREFIX = "agent:"


@dataclass
class AgentRecord:
    id: str
    name: str
    allowed_tools: list[str] = field(default_factory=lambda: ["*"])  # fnmatch on "server__tool"
    allow_write: bool = False
    created_at: float = 0.0

    def allows(self, full_tool_name: str) -> bool:
        return any(fnmatch.fnmatchcase(full_tool_name, p) for p in self.allowed_tools)

    def public(self) -> dict:
        return {"id": self.id, "name": self.name, "allowed_tools": self.allowed_tools,
                "allow_write": self.allow_write, "created_at": self.created_at}


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class AgentRegistry:
    def __init__(self, vault: Vault):
        self._vault = vault

    def _record(self, data: dict) -> AgentRecord:
        return AgentRecord(id=data["id"], name=data["name"], allowed_tools=data["allowed_tools"],
                           allow_write=data["allow_write"], created_at=data["created_at"])

    def create(self, name: str, allowed_tools: list[str] | None = None,
               allow_write: bool = False) -> tuple[AgentRecord, str]:
        name = name.strip()
        if not name or len(name) > 80:
            raise ValueError("Agent name must be 1-80 characters.")
        agent_id = secrets.token_hex(4)
        token = "gai_" + secrets.token_urlsafe(32)
        rec = AgentRecord(agent_id, name, allowed_tools or ["*"], allow_write, time.time())
        self._vault.set(_PREFIX + agent_id, {**rec.public(), "token_hash": _hash(token)})
        return rec, token

    def authenticate(self, token: str) -> AgentRecord | None:
        candidate = _hash(token)
        for key in self._vault.list_keys(_PREFIX):
            data = self._vault.get(key)
            if data and hmac.compare_digest(data["token_hash"], candidate):
                return self._record(data)
        return None

    def get(self, agent_id: str) -> AgentRecord | None:
        data = self._vault.get(_PREFIX + agent_id)
        return self._record(data) if data else None

    def list(self) -> list[AgentRecord]:
        return [self._record(self._vault.get(k)) for k in self._vault.list_keys(_PREFIX)]

    def update(self, agent_id: str, allowed_tools: list[str] | None = None,
               allow_write: bool | None = None) -> AgentRecord:
        data = self._vault.get(_PREFIX + agent_id)
        if data is None:
            raise KeyError(agent_id)
        if allowed_tools is not None:
            data["allowed_tools"] = allowed_tools
        if allow_write is not None:
            data["allow_write"] = allow_write
        self._vault.set(_PREFIX + agent_id, data)
        return self._record(data)

    def revoke(self, agent_id: str) -> None:
        self._vault.delete(_PREFIX + agent_id)
