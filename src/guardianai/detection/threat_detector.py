"""
GuardianAI - Threat detection (Module 7)

Heuristic scanner for instruction-like content hidden in *data* (email
bodies, web pages, tool results, tool descriptions). A hit does not block
reading; it marks the agent's session as tainted, and the policy engine then
requires approval for any consequential action while the taint lasts.

Honest scope: these are pattern heuristics. They catch common, lazy
injections and tool-poisoning tricks, not a determined adversary. That is
why the taint state feeds a deterministic policy instead of being the last
line of defence by itself.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Finding:
    rule: str
    excerpt: str


_F = re.IGNORECASE
_RULES: list[tuple[str, re.Pattern]] = [
    ("override_instructions", re.compile(
        r"\b(ignore|disregard|forget|override)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all|any)\b"
        r"[^.\n]{0,40}\b(instructions?|prompts?|rules?|context|guidelines)\b", _F)),
    ("role_spoof", re.compile(r"(^|\n)\s*(system|assistant|developer)\s*:|\[\s*(system|admin|developer)\s*\]", _F)),
    ("concealment", re.compile(
        r"\b(do not|don't|never)\b[^.\n]{0,30}\b(tell|inform|mention|reveal|show|notify)\b[^.\n]{0,30}\b(user|human|owner)\b", _F)),
    ("exfil_instruction", re.compile(
        r"\b(forward|send|email|mail|upload|post|transmit|share|attach)\b[^.\n]{0,100}"
        r"(@[\w-]+(\.[\w-]+)+|https?://)", _F)),
    ("sensitive_access_instruction", re.compile(
        r"\b(read|open|access|fetch|attach|include|retrieve)\b[^.\n]{0,60}"
        r"(\.ssh|id_rsa|passwords?|credentials?|api[ _-]?keys?|tax (document|return)|bank statements?|private keys?)", _F)),
    ("hidden_instruction_tag", re.compile(r"<\s*/?\s*(important|instructions?|system|secret)\s*>", _F)),
    ("invisible_characters", re.compile("[\u200b-\u200f\u2060\u202a-\u202e\U000e0000-\U000e007f]")),
]


def scan(text: str) -> list[Finding]:
    findings = []
    for rule, pattern in _RULES:
        m = pattern.search(text)
        if m:
            findings.append(Finding(rule, m.group(0).strip()[:80]))
    return findings
