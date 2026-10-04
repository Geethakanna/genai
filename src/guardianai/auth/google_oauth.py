"""
GuardianAI - Google sign-in and account connection (Module 2)

Uses the real OAuth 2.0 authorization-code flow with PKCE via
google-auth-oauthlib. Two separate purposes, so the app asks for the least it needs:
  - "identity": openid + email only (non-sensitive scopes). Signs the user in to
    the local dashboard. No Google review burden beyond basic verification.
  - "gmail":    gmail.readonly, for the optional native Gmail connector.
The OAuth client (ID/secret) is the developer's, bundled with the app.
"""
from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass
from urllib.parse import parse_qs, urlparse

from google.auth.transport.requests import Request
from google.oauth2 import id_token as google_id_token
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow

from guardianai.config import GoogleClient
from guardianai.vault import Vault

IDENTITY_SCOPES = ("openid", "https://www.googleapis.com/auth/userinfo.email")
GMAIL_SCOPES = ("https://www.googleapis.com/auth/gmail.readonly",)
_SCOPES = {"identity": IDENTITY_SCOPES, "gmail": GMAIL_SCOPES}
_PENDING_TTL = 600
GMAIL_VAULT_KEY = "oauth_token:gmail"


class GoogleAuthError(RuntimeError):
    pass


@dataclass
class AuthStart:
    authorization_url: str
    state: str


@dataclass
class CompletedAuth:
    purpose: str
    credentials: Credentials
    email: str | None


class GoogleAuth:
    def __init__(self, client: GoogleClient, redirect_uri: str):
        self._client = client
        self._redirect_uri = redirect_uri
        # state -> (purpose, PKCE verifier, created). The verifier made at "start"
        # must be reused at "callback", so it is held here in between.
        self._pending: dict[str, tuple[str, str, float]] = {}
        self._lock = threading.Lock()
        host = urlparse(redirect_uri).hostname
        if host in ("localhost", "127.0.0.1"):
            # oauthlib refuses plain http redirects; safe to relax for loopback only.
            os.environ.setdefault("OAUTHLIB_INSECURE_TRANSPORT", "1")
        os.environ.setdefault("OAUTHLIB_RELAX_TOKEN_SCOPE", "1")

    def _flow(self, purpose: str) -> Flow:
        config = {"installed": {
            "client_id": self._client.client_id,
            "client_secret": self._client.client_secret,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [self._redirect_uri],
        }}
        return Flow.from_client_config(config, scopes=list(_SCOPES[purpose]), redirect_uri=self._redirect_uri)

    def start(self, purpose: str) -> AuthStart:
        if purpose not in _SCOPES:
            raise GoogleAuthError(f"Unknown purpose '{purpose}'.")
        flow = self._flow(purpose)
        kwargs = {"access_type": "offline", "prompt": "consent"} if purpose == "gmail" else {}
        url, state = flow.authorization_url(**kwargs)
        with self._lock:
            now = time.time()
            self._pending = {s: v for s, v in self._pending.items() if now - v[2] < _PENDING_TTL}
            self._pending[state] = (purpose, flow.code_verifier, now)
        return AuthStart(url, state)

    def complete(self, response_url: str) -> CompletedAuth:
        state = parse_qs(urlparse(response_url).query).get("state", [""])[0]
        with self._lock:
            pending = self._pending.pop(state, None)
        if pending is None or time.time() - pending[2] > _PENDING_TTL:
            raise GoogleAuthError("Unknown or expired login attempt. Start again.")
        purpose, verifier, _ = pending
        flow = self._flow(purpose)
        flow.code_verifier = verifier
        flow.fetch_token(authorization_response=response_url)
        creds = flow.credentials
        email = None
        if purpose == "identity":
            claims = google_id_token.verify_oauth2_token(creds.id_token, Request(), self._client.client_id)
            if not claims.get("email_verified"):
                raise GoogleAuthError("Google account email is not verified.")
            email = claims["email"].lower()
        return CompletedAuth(purpose, creds, email)


def store_gmail_credentials(vault: Vault, creds: Credentials) -> None:
    vault.set(GMAIL_VAULT_KEY, {
        "token": creds.token, "refresh_token": creds.refresh_token, "token_uri": creds.token_uri,
        "client_id": creds.client_id, "client_secret": creds.client_secret, "scopes": list(creds.scopes or []),
    })


def get_gmail_credentials(vault: Vault) -> Credentials | None:
    stored = vault.get(GMAIL_VAULT_KEY)
    if stored is None:
        return None
    creds = Credentials(token=stored["token"], refresh_token=stored["refresh_token"],
                        token_uri=stored["token_uri"], client_id=stored["client_id"],
                        client_secret=stored["client_secret"], scopes=stored["scopes"])
    if creds.expired and creds.refresh_token:
        creds.refresh(Request())
        stored["token"] = creds.token
        vault.set(GMAIL_VAULT_KEY, stored)
    return creds
