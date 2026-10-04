"""
GuardianAI - Deterministic Policy Engine (Module 5)

The only component allowed to authorize an action. Plain, auditable Python:
no LLM call anywhere in this file. An agent can propose; this decides.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Decision(str, Enum):
    ALLOW = "allow"
    TRANSFORM = "transform"  # allowed, but sensitive values stay tokenized toward the agent
    QUARANTINE = "quarantine"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"


@dataclass
class ActionRequest:
    connector: str
    action: str
    kind: str = "read"  # "read" | "write" | "send"
    destinations: list[str] = field(default_factory=list)  # hosts/domains data would go to
    contains_pii: bool = False
    pii_categories: list[str] = field(default_factory=list)
    cross_context_flag: bool = False  # set when the session saw injection-like content
    trusted_domains: frozenset[str] = frozenset()


@dataclass
class PolicyResult:
    decision: Decision
    reason: str


def domain_trusted(host: str, trusted: frozenset[str]) -> bool:
    host = host.lower().rstrip(".")
    return any(host == d or host.endswith("." + d) for d in trusted)


def evaluate(req: ActionRequest) -> PolicyResult:
    # 1. Consequential action while the session has seen injection-like content.
    if req.cross_context_flag and req.kind != "read":
        return PolicyResult(
            Decision.REQUIRE_APPROVAL,
            "Untrusted content in this session contained instruction-like text; "
            "consequential actions need explicit user approval.",
        )

    # 2. Reads are low risk; sensitive values simply stay tokenized.
    if req.kind == "read":
        if req.contains_pii:
            return PolicyResult(Decision.TRANSFORM, f"Read allowed; {req.pii_categories} stay tokenized.")
        return PolicyResult(Decision.ALLOW, "Read allowed; nothing sensitive detected.")

    # 3. Outbound actions: the destination must be verifiable and trusted.
    if req.kind == "send":
        if not req.destinations:
            return PolicyResult(Decision.REQUIRE_APPROVAL, "Outbound action with no verifiable destination.")
        untrusted = [d for d in req.destinations if not domain_trusted(d, req.trusted_domains)]
        if untrusted and req.contains_pii:
            return PolicyResult(
                Decision.REQUIRE_APPROVAL,
                f"Would send {req.pii_categories} to unverified destination(s): {sorted(set(untrusted))}.",
            )
        if untrusted:
            return PolicyResult(Decision.ALLOW, f"No sensitive data; unverified destination(s) {sorted(set(untrusted))} logged.")
        return PolicyResult(Decision.ALLOW, "All destinations are on the trusted list.")

    # 4. Local writes.
    return PolicyResult(Decision.ALLOW, "Write allowed; no outbound destination involved.")
