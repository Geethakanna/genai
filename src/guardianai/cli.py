"""GuardianAI - CLI entry point. `guardianai` (after pip install -e .) or `python -m guardianai.cli`."""
from __future__ import annotations

import logging
import socket
import threading
import time
import webbrowser

import uvicorn

from guardianai.config import load_settings


def _wait_then_open(host: str, port: int) -> None:
    """Poll the real socket instead of guessing a delay, then open the dashboard."""
    url = f"http://{host}:{port}/"
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                break
        except OSError:
            time.sleep(0.2)
    else:
        return  # server never came up; let uvicorn's own error speak for itself
    try:
        webbrowser.open(url)
    except Exception:
        pass  # headless machines just won't get an auto-opened tab; the URL is still printed


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    settings = load_settings()
    threading.Thread(target=_wait_then_open, args=(settings.proxy.host, settings.proxy.port), daemon=True).start()
    uvicorn.run("guardianai.proxy.server:app_factory", factory=True,
                host=settings.proxy.host, port=settings.proxy.port)


if __name__ == "__main__":
    main()
