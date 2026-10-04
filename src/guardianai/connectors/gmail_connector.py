"""
GuardianAI - Gmail Connector

Thin wrapper around the real Gmail API (googleapiclient). This module
makes actual HTTP calls to gmail.googleapis.com using the user's real,
vault-stored credentials — it does not generate sample messages.

If the user hasn't connected Gmail yet, functions here raise
NotConnectedError rather than returning placeholder data.
"""
from __future__ import annotations

import base64

from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build


class NotConnectedError(RuntimeError):
    pass


def _client(creds: Credentials | None):
    if creds is None:
        raise NotConnectedError(
            "Gmail is not connected. Complete the Google OAuth flow first."
        )
    return build("gmail", "v1", credentials=creds, cache_discovery=False)


def list_recent_messages(creds: Credentials | None, max_results: int = 5) -> list[dict]:
    """Return real recent Gmail messages (id, snippet, subject) for the
    connected account. Raises NotConnectedError if no account is linked."""
    service = _client(creds)
    resp = (
        service.users()
        .messages()
        .list(userId="me", maxResults=max_results)
        .execute()
    )
    messages = []
    for item in resp.get("messages", []):
        full = (
            service.users()
            .messages()
            .get(userId="me", id=item["id"], format="metadata",
                 metadataHeaders=["Subject", "From"])
            .execute()
        )
        headers = {h["name"]: h["value"] for h in full.get("payload", {}).get("headers", [])}
        messages.append(
            {
                "id": full["id"],
                "snippet": full.get("snippet", ""),
                "subject": headers.get("Subject", "(no subject)"),
                "from": headers.get("From", "(unknown)"),
            }
        )
    return messages


def get_message_body(creds: Credentials | None, message_id: str) -> str:
    """Fetch and decode the plain-text body of a real Gmail message."""
    service = _client(creds)
    msg = service.users().messages().get(userId="me", id=message_id, format="full").execute()

    def _walk(part) -> str:
        if part.get("mimeType") == "text/plain" and "data" in part.get("body", {}):
            return base64.urlsafe_b64decode(part["body"]["data"]).decode(
                "utf-8", errors="replace"
            )
        for sub in part.get("parts", []) or []:
            text = _walk(sub)
            if text:
                return text
        return ""

    return _walk(msg.get("payload", {})) or msg.get("snippet", "")
