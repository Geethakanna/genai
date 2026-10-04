"""
GuardianAI - Local server (Module 1 + dashboard API)

One local HTTP service, three audiences:
  * Agents      -> POST /mcp            (Bearer agent token; the MCP gateway)
  * The owner   -> /admin/*, /audit ... (signed-in session cookie)
  * Anyone      -> /health, /auth/*     (sign-in flow)
Binds to 127.0.0.1 and rejects foreign Host headers (DNS-rebinding defence).
"""
from __future__ import annotations

import logging
import secrets
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from pydantic import BaseModel, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

from guardianai import __version__
from guardianai.audit import AuditLog
from guardianai.auth import google_oauth
from guardianai.auth.agents import AgentRegistry
from guardianai.auth.google_oauth import GoogleAuth, GoogleAuthError
from guardianai.auth.sessions import COOKIE_NAME, SessionStore, claim_or_check_owner
from guardianai.config import GoogleClient, Settings, SETTINGS_GOOGLE_CLIENT_KEY
from guardianai.connectors import catalog, gmail_connector
from guardianai.connectors.gmail_connector import NotConnectedError
from guardianai.gateway.approvals import ApprovalStore
from guardianai.gateway.core import Gateway, classify_tool
from guardianai.gateway.upstream import UpstreamError, UpstreamRegistry
from guardianai.policy.store import PolicyStore
from guardianai.vault import Vault
from guardianai.dashboard import DASHBOARD_HTML

logger = logging.getLogger("guardianai")


class UpstreamSpec(BaseModel):
    name: str
    transport: str
    command: str | None = None
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    url: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)


class AgentCreate(BaseModel):
    name: str
    allowed_tools: list[str] = Field(default_factory=lambda: ["*"])
    allow_write: bool = False


class AgentUpdate(BaseModel):
    allowed_tools: list[str] | None = None
    allow_write: bool | None = None


class DomainBody(BaseModel):
    domain: str


class LocalLogin(BaseModel):
    token: str


class GoogleClientBody(BaseModel):
    client_id: str
    client_secret: str


class GmailRead(BaseModel):
    max_results: int = Field(5, ge=1, le=25)


def create_app(settings: Settings, vault: Vault | None = None, google_auth=None,
               extra_allowed_hosts: tuple[str, ...] = ()) -> FastAPI:
    vault = vault or Vault(settings.proxy.vault_path)
    audit = AuditLog(settings.proxy.audit_path)
    registry = UpstreamRegistry(vault)
    agents = AgentRegistry(vault)
    approvals = ApprovalStore()
    policy = PolicyStore(vault)
    gateway = Gateway(vault, audit, registry, agents, approvals, policy)
    sessions = SessionStore()
    if google_auth is None:
        # A client saved from the dashboard (Settings) always wins over one baked
        # in at startup, so changing it takes effect without restarting the app.
        stored = vault.get(SETTINGS_GOOGLE_CLIENT_KEY)
        effective_client = GoogleClient(stored["client_id"], stored["client_secret"]) if stored else settings.google
        google_auth = GoogleAuth(effective_client, settings.proxy.redirect_uri) if effective_client else None
    admin_token = secrets.token_urlsafe(24)  # Jupyter-style local fallback sign-in

    @asynccontextmanager
    async def lifespan(_app):
        logger.info("GuardianAI %s ready. Sign in at http://%s:%s/auth/status", __version__,
                    settings.proxy.host, settings.proxy.port)
        yield
        registry.close_all()

    app = FastAPI(title="GuardianAI Local Gateway", version=__version__, lifespan=lifespan)
    app.add_middleware(TrustedHostMiddleware,
                       allowed_hosts=["127.0.0.1", "localhost", *extra_allowed_hosts])
    app.state.admin_token = admin_token
    app.state.gateway, app.state.vault, app.state.audit = gateway, vault, audit
    app.state.google_auth = google_auth

    # ---- auth dependencies ----------------------------------------------------
    def require_session(request: Request) -> str:
        identity = sessions.get(request.cookies.get(COOKIE_NAME))
        if identity is None:
            raise HTTPException(401, "Sign in first (see /auth/status).")
        return identity

    def require_agent(request: Request):
        header = request.headers.get("authorization", "")
        agent = agents.authenticate(header[7:]) if header.lower().startswith("bearer ") else None
        if agent is None:
            raise HTTPException(401, "Missing or invalid agent token.")
        return agent

    def _start_session(identity: str, response: Response) -> None:
        response.set_cookie(COOKIE_NAME, sessions.create(identity), httponly=True, samesite="strict",
                            max_age=8 * 3600)

    # ---- public ---------------------------------------------------------------
    @app.get("/health")
    def health():
        return {"status": "ok", "service": "guardianai-gateway", "version": __version__}

    @app.get("/auth/status")
    def auth_status(request: Request):
        return {"google_login_available": app.state.google_auth is not None,
                "signed_in": sessions.get(request.cookies.get(COOKIE_NAME)) is not None,
                "owner_claimed": vault.get("owner") is not None,
                "hint": None if google_auth else
                "Google sign-in is not configured in this build; use POST /auth/local with the "
                "admin token printed at startup."}

    @app.get("/auth/login/start")
    def login_start():
        if app.state.google_auth is None:
            raise HTTPException(503, "Google sign-in is not configured in this build.")
        return RedirectResponse(app.state.google_auth.start("identity").authorization_url)

    @app.post("/auth/local")
    def local_login(body: LocalLogin, response: Response):
        if not secrets.compare_digest(body.token, admin_token):
            audit.log("login_failed", method="local")
            raise HTTPException(401, "Wrong admin token.")
        if not claim_or_check_owner(vault, "local-admin"):
            raise HTTPException(403, "This install is owned by a different identity.")
        _start_session("local-admin", response)
        audit.log("login", method="local")
        return {"status": "signed_in", "identity": "local-admin"}

    @app.post("/auth/logout")
    def logout(request: Request, response: Response):
        sessions.revoke(request.cookies.get(COOKIE_NAME))
        response.delete_cookie(COOKIE_NAME)
        return {"status": "signed_out"}

    @app.get("/oauth2/callback", response_class=HTMLResponse)
    def oauth_callback(request: Request, code: str | None = None, error: str | None = None):
        if app.state.google_auth is None:
            raise HTTPException(503, "Google sign-in is not configured.")
        if error or not code:
            raise HTTPException(400, f"Google sign-in was not completed ({error or 'no code'}).")
        try:
            done = app.state.google_auth.complete(str(request.url))
        except GoogleAuthError as exc:
            raise HTTPException(400, str(exc)) from exc
        except Exception as exc:  # network / token errors from Google
            logger.warning("OAuth completion failed: %s", type(exc).__name__)
            raise HTTPException(502, "Could not complete sign-in with Google.") from exc

        if done.purpose == "identity":
            if not claim_or_check_owner(vault, done.email):
                audit.log("login_refused", method="google")
                raise HTTPException(403, "This install belongs to a different Google account.")
            page = HTMLResponse(f"<h3>Signed in as {done.email}. You can close this tab.</h3>")
            _start_session(done.email, page)
            audit.log("login", method="google")
            return page
        if sessions.get(request.cookies.get(COOKIE_NAME)) is None:
            raise HTTPException(401, "Sign in before connecting accounts.")
        google_oauth.store_gmail_credentials(vault, done.credentials)
        audit.log("connector_connected", connector="gmail")
        return HTMLResponse("<h3>Gmail connected. You can close this tab.</h3>")

    # ---- agent endpoint: the MCP gateway ---------------------------------------
    @app.post("/mcp")
    async def mcp_endpoint(request: Request, agent=Depends(require_agent)):
        try:
            body = await request.json()
        except ValueError:
            return JSONResponse({"jsonrpc": "2.0", "id": None,
                                 "error": {"code": -32700, "message": "Parse error"}}, status_code=400)
        import anyio  # upstream calls block, so keep them off the event loop
        if isinstance(body, list):
            replies = [r for r in [await anyio.to_thread.run_sync(gateway.handle, agent, m) for m in body] if r]
            return JSONResponse(replies) if replies else Response(status_code=202)
        reply = await anyio.to_thread.run_sync(gateway.handle, agent, body)
        return JSONResponse(reply) if reply is not None else Response(status_code=202)

    @app.get("/mcp")
    def mcp_get():
        return Response(status_code=405, headers={"Allow": "POST"})

    # ---- owner/admin API ------------------------------------------------------
    @app.get("/admin/connector-catalog")
    def connector_catalog(_: str = Depends(require_session)):
        return {"catalog": catalog.describe()}

    @app.get("/admin/overview")
    def overview(_: str = Depends(require_session)):
        gmail = vault.get(google_oauth.GMAIL_VAULT_KEY)
        recent = audit.recent(500)
        out_agents = []
        for a in agents.list():
            calls = [e for e in recent if e["agent"] == a.id and e["event"] == "tool_call"]
            out_agents.append({**a.public(), "tainted": gateway.is_tainted(a.id),
                               "recent_calls": len(calls),
                               "recent_blocked": sum(1 for e in calls if e["decision"] in ("deny", "require_approval"))})
        return {"agents": out_agents, "upstreams": registry.describe(),
                "native_connectors": [{"name": "gmail", "connected": gmail is not None,
                                       "scopes": gmail["scopes"] if gmail else []}],
                "trusted_domains": sorted(policy.trusted_domains()),
                "pending_approvals": approvals.pending()}

    @app.get("/connectors")
    def connectors(_: str = Depends(require_session)):
        return overview(_)

    @app.post("/admin/upstreams")
    def add_upstream(spec: UpstreamSpec, _: str = Depends(require_session)):
        try:
            registry.add(spec.name, spec.model_dump(exclude={"name"}))
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        audit.log("upstream_added", name=spec.name, transport=spec.transport)
        return {"status": "added", "name": spec.name}

    @app.get("/admin/upstreams/{name}/tools")
    def upstream_tools(name: str, _: str = Depends(require_session)):
        try:
            tools = registry.get(name).list_tools()
        except UpstreamError as exc:
            raise HTTPException(502, str(exc)) from exc
        return {"tools": [{"name": t["name"], "kind": classify_tool(t),
                           "description": t.get("description", "")} for t in tools]}

    @app.delete("/admin/upstreams/{name}")
    def remove_upstream(name: str, _: str = Depends(require_session)):
        registry.remove(name)
        audit.log("upstream_removed", name=name)
        return {"status": "removed"}

    @app.post("/admin/agents")
    def create_agent(body: AgentCreate, _: str = Depends(require_session)):
        try:
            rec, token = agents.create(body.name, body.allowed_tools, body.allow_write)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        audit.log("agent_created", agent=rec.id, name=rec.name, allow_write=rec.allow_write)
        return {**rec.public(), "token": token,
                "note": "Store this token now; it is never shown again."}

    @app.patch("/admin/agents/{agent_id}")
    def update_agent(agent_id: str, body: AgentUpdate, _: str = Depends(require_session)):
        try:
            rec = agents.update(agent_id, body.allowed_tools, body.allow_write)
        except KeyError:
            raise HTTPException(404, "No such agent.") from None
        audit.log("agent_updated", agent=agent_id, allow_write=rec.allow_write, tools=rec.allowed_tools)
        return rec.public()

    @app.delete("/admin/agents/{agent_id}")
    def revoke_agent(agent_id: str, _: str = Depends(require_session)):
        agents.revoke(agent_id)
        gateway.clear_taint(agent_id)
        audit.log("agent_revoked", agent=agent_id)
        return {"status": "revoked"}

    @app.get("/admin/approvals")
    def list_approvals(_: str = Depends(require_session)):
        return {"pending": approvals.pending()}

    @app.post("/admin/approvals/{approval_id}/{verdict}")
    def decide(approval_id: str, verdict: str, _: str = Depends(require_session)):
        if verdict not in ("approve", "deny"):
            raise HTTPException(404, "Verdict must be approve or deny.")
        try:
            item = approvals.decide(approval_id, verdict == "approve")
        except KeyError:
            raise HTTPException(404, "No such pending approval.") from None
        audit.log("approval_decision", agent=item["agent_id"], decision=item["status"], tool=item["tool"])
        return {"id": approval_id, "status": item["status"]}

    @app.post("/admin/agents/{agent_id}/clear-taint")
    def clear_taint(agent_id: str, _: str = Depends(require_session)):
        gateway.clear_taint(agent_id)
        audit.log("taint_cleared", agent=agent_id)
        return {"status": "cleared"}

    @app.post("/admin/trusted-domains")
    def add_domain(body: DomainBody, _: str = Depends(require_session)):
        try:
            domain = policy.add(body.domain)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        audit.log("trusted_domain_added", domain=domain)
        return {"trusted_domains": sorted(policy.trusted_domains())}

    @app.delete("/admin/trusted-domains/{domain}")
    def remove_domain(domain: str, _: str = Depends(require_session)):
        policy.remove(domain)
        audit.log("trusted_domain_removed", domain=domain)
        return {"trusted_domains": sorted(policy.trusted_domains())}

    @app.get("/", response_class=HTMLResponse)
    def dashboard():
        return DASHBOARD_HTML

    @app.get("/admin/settings")
    def get_settings(_: str = Depends(require_session)):
        return {"google_client_configured": app.state.google_auth is not None}

    @app.post("/admin/settings/google-client")
    def set_google_client(body: GoogleClientBody, _: str = Depends(require_session)):
        client_id, secret = body.client_id.strip(), body.client_secret.strip()
        if not client_id.endswith(".apps.googleusercontent.com") or not secret:
            raise HTTPException(422, "That doesn't look like a real Google OAuth client ID/secret pair.")
        vault.set(SETTINGS_GOOGLE_CLIENT_KEY, {"client_id": client_id, "client_secret": secret})
        app.state.google_auth = GoogleAuth(GoogleClient(client_id, secret), settings.proxy.redirect_uri)
        audit.log("google_client_configured", method="dashboard")
        return {"status": "configured"}

    @app.delete("/admin/settings/google-client")
    def clear_google_client(_: str = Depends(require_session)):
        vault.delete(SETTINGS_GOOGLE_CLIENT_KEY)
        app.state.google_auth = GoogleAuth(settings.google, settings.proxy.redirect_uri) if settings.google else None
        audit.log("google_client_removed", method="dashboard")
        return {"status": "removed", "google_client_configured": app.state.google_auth is not None}

    @app.get("/audit")
    def audit_log(limit: int = 50, agent: str | None = None, _: str = Depends(require_session)):
        return {"entries": audit.recent(limit, agent)}

    # ---- optional native Gmail connector (dashboard preview) ---------------------
    @app.get("/connectors/gmail/start")
    def gmail_start(_: str = Depends(require_session)):
        if app.state.google_auth is None:
            raise HTTPException(503, "Google sign-in is not configured in this build.")
        return RedirectResponse(app.state.google_auth.start("gmail").authorization_url)

    @app.post("/connectors/gmail/disconnect")
    def gmail_disconnect(_: str = Depends(require_session)):
        vault.delete(google_oauth.GMAIL_VAULT_KEY)
        audit.log("connector_disconnected", connector="gmail")
        return {"status": "disconnected"}

    @app.post("/gmail/messages")
    def gmail_messages(req: GmailRead, _: str = Depends(require_session)):
        try:
            raw = gmail_connector.list_recent_messages(google_oauth.get_gmail_credentials(vault), req.max_results)
        except NotConnectedError as exc:
            raise HTTPException(409, str(exc)) from exc
        out = []
        for m in raw:
            text, cats, findings = gateway.sanitize_text(f"{m['subject']} {m['snippet']}")
            out.append({"id": m["id"], "subject_and_snippet_tokenized": text,
                        "pii_categories_found": sorted(set(cats)),
                        "injection_rules": [f.rule for f in findings]})
        audit.log("gmail_preview", count=len(out))
        return {"messages": out}

    return app


def app_factory() -> FastAPI:
    """uvicorn --factory entry point."""
    from guardianai.config import load_settings
    settings = load_settings()
    app = create_app(settings)
    print(f"\n  GuardianAI admin token (local fallback sign-in): {app.state.admin_token}\n")
    return app
