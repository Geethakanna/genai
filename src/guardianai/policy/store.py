"""Persistent user policy settings (trusted destination domains), stored in the vault."""
from __future__ import annotations

import re

from guardianai.vault import Vault

_KEY = "policy:trusted_domains"
_DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9-]+\.)+[a-z]{2,}$")


class PolicyStore:
    def __init__(self, vault: Vault):
        self._vault = vault

    def trusted_domains(self) -> frozenset[str]:
        entry = self._vault.get(_KEY)
        return frozenset(entry["domains"]) if entry else frozenset()

    def add(self, domain: str) -> str:
        domain = domain.strip().lower()
        if not _DOMAIN.match(domain):
            raise ValueError(f"'{domain}' is not a valid domain name.")
        domains = set(self.trusted_domains()) | {domain}
        self._vault.set(_KEY, {"domains": sorted(domains)})
        return domain

    def remove(self, domain: str) -> None:
        domains = set(self.trusted_domains()) - {domain.strip().lower()}
        self._vault.set(_KEY, {"domains": sorted(domains)})
