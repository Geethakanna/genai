"""
GuardianAI - Configuration

Nothing here is a fabricated default. Google sign-in needs a real OAuth
client, looked up in this order:
  1. GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET environment variables
  2. the file named by GUARDIANAI_GOOGLE_CLIENT_FILE
  3. ~/.guardianai/google_client.json
  4. the bundled src/guardianai/data/google_client.json (what YOU, the
     developer, fill in once before shipping the app to users)
Files use the JSON Google's console lets you download for a "Desktop app"
client. If no real client is found, the app still runs; only Google sign-in
is unavailable and says why. End users never touch any of this.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

_ENV_PATH = Path(__file__).resolve().parents[2] / ".env"
if _ENV_PATH.exists():
    load_dotenv(_ENV_PATH)

BUNDLED_CLIENT_FILE = Path(__file__).resolve().parent / "data" / "google_client.json"


@dataclass(frozen=True)
class GoogleClient:
    client_id: str
    client_secret: str


@dataclass(frozen=True)
class ProxyConfig:
    host: str
    port: int
    vault_path: Path
    audit_path: Path

    @property
    def redirect_uri(self) -> str:
        # Desktop-app OAuth clients accept loopback redirects on any port,
        # so nothing has to be registered per user or per port.
        return f"http://127.0.0.1:{self.port}/oauth2/callback"


@dataclass(frozen=True)
class Settings:
    proxy: ProxyConfig
    google: GoogleClient | None


def _parse_client_file(path: Path) -> GoogleClient | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    block = data.get("installed") or data.get("web") or data
    cid, secret = block.get("client_id", ""), block.get("client_secret", "")
    if cid and secret and cid.endswith(".apps.googleusercontent.com"):
        return GoogleClient(cid, secret)
    return None


def load_google_client() -> GoogleClient | None:
    cid, secret = os.environ.get("GOOGLE_CLIENT_ID"), os.environ.get("GOOGLE_CLIENT_SECRET")
    if cid and secret:
        return GoogleClient(cid, secret)
    candidates = []
    if os.environ.get("GUARDIANAI_GOOGLE_CLIENT_FILE"):
        candidates.append(Path(os.environ["GUARDIANAI_GOOGLE_CLIENT_FILE"]).expanduser())
    candidates += [Path.home() / ".guardianai" / "google_client.json", BUNDLED_CLIENT_FILE]
    for path in candidates:
        if path.exists():
            client = _parse_client_file(path)
            if client:
                return client
    return None


SETTINGS_GOOGLE_CLIENT_KEY = "settings:google_client"


def load_settings() -> Settings:
    home = Path(os.environ.get("GUARDIANAI_HOME", str(Path.home() / ".guardianai"))).expanduser()
    home.mkdir(parents=True, exist_ok=True)
    proxy = ProxyConfig(
        host=os.environ.get("GUARDIANAI_HOST", "127.0.0.1"),
        port=int(os.environ.get("GUARDIANAI_PORT", "8765")),
        vault_path=home / "vault.db",
        audit_path=home / "audit.db",
    )
    return Settings(proxy=proxy, google=load_google_client())
