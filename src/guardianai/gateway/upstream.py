"""
GuardianAI - Upstream MCP clients

The gateway is an MCP *server* toward agents and an MCP *client* toward the
user's real MCP servers ("upstreams"). Two transports are supported:
  - stdio  (a local command speaking newline-delimited JSON-RPC, e.g. `npx ...`)
  - http   (Streamable-HTTP style JSON-RPC over POST; JSON or SSE replies)
Upstream specs (which may hold secrets in env/headers) live in the vault.
"""
from __future__ import annotations

import json
import os
import queue
import re
import shutil
import subprocess
import threading
import time

import httpx

from guardianai.vault import Vault

PROTOCOL_VERSION = "2025-06-18"
CLIENT_INFO = {"name": "guardianai-gateway", "version": "0.2.0"}
_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,30}$")  # no "_" so "__" stays a safe separator


class UpstreamError(RuntimeError):
    pass


class Upstream:
    name: str

    def _request(self, method: str, params: dict | None, timeout: float) -> dict:
        raise NotImplementedError

    def close(self) -> None:
        pass

    def list_tools(self, timeout: float = 30) -> list[dict]:
        tools, cursor = [], None
        for _ in range(20):  # pagination guard
            result = self._request("tools/list", {"cursor": cursor} if cursor else {}, timeout)
            tools += result.get("tools", [])
            cursor = result.get("nextCursor")
            if not cursor:
                break
        return tools

    def call_tool(self, name: str, arguments: dict, timeout: float = 60) -> dict:
        return self._request("tools/call", {"name": name, "arguments": arguments}, timeout)


class StdioUpstream(Upstream):
    def __init__(self, name: str, command: str, args: list[str] | None = None, env: dict | None = None):
        self.name, self._command, self._args, self._env = name, command, args or [], env or {}
        self._proc: subprocess.Popen | None = None
        self._queue: queue.Queue = queue.Queue()
        self._lock = threading.Lock()
        self._next_id = 0

    def _start(self) -> None:
        exe = shutil.which(self._command)  # resolves npx -> npx.cmd on Windows too
        if exe is None:
            raise UpstreamError(f"Command '{self._command}' for upstream '{self.name}' was not found on PATH.")
        self._proc = subprocess.Popen(
            [exe, *self._args], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, encoding="utf-8", bufsize=1, env={**os.environ, **self._env},
        )
        self._queue = queue.Queue()
        threading.Thread(target=self._reader, args=(self._proc, self._queue), daemon=True).start()
        self._rpc("initialize", {"protocolVersion": PROTOCOL_VERSION, "capabilities": {},
                                 "clientInfo": CLIENT_INFO}, 20)
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    @staticmethod
    def _reader(proc, q) -> None:
        for line in proc.stdout:
            line = line.strip()
            if line:
                try:
                    q.put(json.loads(line))
                except ValueError:
                    pass  # non-JSON noise on stdout is ignored
        q.put(None)  # EOF marker

    def _send(self, message: dict) -> None:
        try:
            self._proc.stdin.write(json.dumps(message) + "\n")
            self._proc.stdin.flush()
        except (OSError, ValueError) as exc:
            raise UpstreamError(f"Upstream '{self.name}' closed its input.") from exc

    def _rpc(self, method: str, params: dict | None, timeout: float) -> dict:
        self._next_id += 1
        rid = self._next_id
        self._send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}})
        deadline = time.monotonic() + timeout
        while True:
            try:
                msg = self._queue.get(timeout=max(0.05, deadline - time.monotonic()))
            except queue.Empty:
                raise UpstreamError(f"Upstream '{self.name}' timed out on {method}.") from None
            if msg is None:
                raise UpstreamError(f"Upstream '{self.name}' exited unexpectedly.")
            if msg.get("id") == rid and ("result" in msg or "error" in msg):
                if "error" in msg:
                    raise UpstreamError(f"Upstream '{self.name}' error: {msg['error'].get('message', msg['error'])}")
                return msg["result"]
            if "method" in msg and "id" in msg:  # server->client request: only ping is answered
                reply = {"jsonrpc": "2.0", "id": msg["id"]}
                reply.update({"result": {}} if msg["method"] == "ping"
                             else {"error": {"code": -32601, "message": "Method not supported by gateway"}})
                self._send(reply)
            if time.monotonic() > deadline:
                raise UpstreamError(f"Upstream '{self.name}' timed out on {method}.")

    def _request(self, method, params, timeout):
        with self._lock:
            if self._proc is None or self._proc.poll() is not None:
                self._start()
            return self._rpc(method, params, timeout)

    def close(self) -> None:
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._proc.kill()


class HttpUpstream(Upstream):
    def __init__(self, name: str, url: str, headers: dict | None = None, client: httpx.Client | None = None):
        self.name, self._url, self._headers = name, url, headers or {}
        self._client = client or httpx.Client(timeout=60)
        self._session_id: str | None = None
        self._initialized = False
        self._next_id = 0
        self._lock = threading.Lock()

    def _post(self, payload: dict, timeout: float) -> httpx.Response:
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                   **self._headers}
        if self._session_id:
            headers["Mcp-Session-Id"] = self._session_id
        if self._initialized:
            headers["MCP-Protocol-Version"] = PROTOCOL_VERSION
        try:
            resp = self._client.post(self._url, json=payload, headers=headers, timeout=timeout)
        except httpx.HTTPError as exc:
            raise UpstreamError(f"Upstream '{self.name}' unreachable: {type(exc).__name__}") from exc
        if resp.status_code >= 400:
            raise UpstreamError(f"Upstream '{self.name}' returned HTTP {resp.status_code}.")
        return resp

    @staticmethod
    def _find_reply(resp: httpx.Response, rid: int) -> dict:
        if resp.headers.get("content-type", "").startswith("text/event-stream"):
            for line in resp.text.splitlines():
                if line.startswith("data:"):
                    try:
                        msg = json.loads(line[5:].strip())
                    except ValueError:
                        continue
                    if isinstance(msg, dict) and msg.get("id") == rid:
                        return msg
            raise UpstreamError("Upstream sent no reply for the request.")
        msg = resp.json()
        if isinstance(msg, list):
            msg = next((m for m in msg if m.get("id") == rid), {})
        return msg

    def _rpc(self, method: str, params: dict | None, timeout: float) -> dict:
        self._next_id += 1
        rid = self._next_id
        resp = self._post({"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}}, timeout)
        if method == "initialize":
            self._session_id = resp.headers.get("Mcp-Session-Id")
        msg = self._find_reply(resp, rid)
        if "error" in msg:
            raise UpstreamError(f"Upstream '{self.name}' error: {msg['error'].get('message', msg['error'])}")
        if "result" not in msg:
            raise UpstreamError(f"Upstream '{self.name}' sent an invalid reply.")
        return msg["result"]

    def _request(self, method, params, timeout):
        with self._lock:
            if not self._initialized:
                self._rpc("initialize", {"protocolVersion": PROTOCOL_VERSION, "capabilities": {},
                                         "clientInfo": CLIENT_INFO}, 20)
                self._initialized = True
                self._post({"jsonrpc": "2.0", "method": "notifications/initialized"}, 20)
            return self._rpc(method, params, timeout)

    def close(self) -> None:
        self._client.close()


class UpstreamRegistry:
    """Persisted upstream specs (vault) plus live client instances."""

    def __init__(self, vault: Vault):
        self._vault = vault
        self._live: dict[str, Upstream] = {}
        self._lock = threading.Lock()

    def add(self, name: str, spec: dict) -> None:
        if not _NAME.match(name):
            raise ValueError("Upstream name must be lowercase letters, digits or '-' (max 31 chars).")
        transport = spec.get("transport")
        if transport == "stdio" and spec.get("command"):
            clean = {"transport": "stdio", "command": spec["command"],
                     "args": list(spec.get("args", [])), "env": dict(spec.get("env", {}))}
        elif transport == "http" and str(spec.get("url", "")).startswith(("http://", "https://")):
            clean = {"transport": "http", "url": spec["url"], "headers": dict(spec.get("headers", {}))}
        else:
            raise ValueError("Spec needs transport 'stdio' (+command) or 'http' (+url).")
        self.remove(name)
        self._vault.set(f"upstream:{name}", clean)

    def remove(self, name: str) -> None:
        with self._lock:
            live = self._live.pop(name, None)
        if live:
            live.close()
        self._vault.delete(f"upstream:{name}")

    def names(self) -> list[str]:
        return [k.split(":", 1)[1] for k in self._vault.list_keys("upstream:")]

    def describe(self) -> list[dict]:
        out = []
        for name in self.names():
            spec = self._vault.get(f"upstream:{name}") or {}
            out.append({"name": name, "transport": spec.get("transport"),
                        "target": spec.get("command") or spec.get("url")})  # never expose env/headers
        return out

    def get(self, name: str) -> Upstream:
        with self._lock:
            if name in self._live:
                return self._live[name]
            spec = self._vault.get(f"upstream:{name}")
            if spec is None:
                raise UpstreamError(f"Unknown upstream '{name}'.")
            up = (StdioUpstream(name, spec["command"], spec["args"], spec["env"])
                  if spec["transport"] == "stdio" else HttpUpstream(name, spec["url"], spec["headers"]))
            self._live[name] = up
            return up

    def close_all(self) -> None:
        with self._lock:
            live, self._live = list(self._live.values()), {}
        for up in live:
            up.close()
