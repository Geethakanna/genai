"""
GuardianAI - MCP Gateway core (Modules 1, 3, 5, 7 wired together)

Transport-agnostic logic for the local MCP gateway. Agents see ONE MCP server
(this gateway). Behind it sit the user's real MCP servers. For every request:

  tools/list  -> aggregate upstream tools, hide what the agent may not use,
                 drop tools whose descriptions look poisoned.
  tools/call  -> agent permissions -> resolve tokens in arguments -> find
                 destinations -> deterministic policy -> (approval) ->
                 upstream call -> tokenize results, scan for injection ->
                 taint session if needed -> audit.

Raw values only ever exist inside this process and the encrypted vault.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import threading
import time
from urllib.parse import urlparse

from guardianai import __version__
from guardianai.audit import AuditLog
from guardianai.auth.agents import AgentRecord, AgentRegistry
from guardianai.detection import pii_detector, threat_detector
from guardianai.gateway.approvals import ApprovalStore
from guardianai.gateway.upstream import UpstreamError, UpstreamRegistry
from guardianai.policy.engine import ActionRequest, Decision, evaluate
from guardianai.policy.store import PolicyStore
from guardianai.vault import Vault

SEP = "__"
TAINT_TTL = 900
TOOL_CACHE_TTL = 60

_READ_PREFIXES = {"read", "get", "list", "search", "fetch", "find", "query", "show", "view",
                  "describe", "check", "lookup", "count", "browse"}
_SEND_WORDS = {"send", "post", "upload", "share", "forward", "publish", "reply", "notify", "webhook",
               "transfer", "pay", "invite", "push", "tweet", "email", "mail", "message", "http", "request"}
_DEST_KEYS = {"to", "cc", "bcc", "recipient", "recipients", "email", "url", "uri", "endpoint",
              "webhook", "destination", "host", "address"}
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
_URL = re.compile(r"https?://([^\s/:\"'<>]+)")
_HOST = re.compile(r"^([a-z0-9-]+\.)+[a-z]{2,}$", re.IGNORECASE)


def classify_tool(tool: dict) -> str:
    """'read' | 'write' | 'send'. Unknown tools are 'write' (never assumed safe).
    Upstream annotations can only make a tool stricter, never looser."""
    tokens = [t for t in re.split(r"[^a-z0-9]+", tool.get("name", "").lower()) if t]
    if tokens and tokens[0] in _READ_PREFIXES:
        kind = "read"
    elif any(t in _SEND_WORDS for t in tokens):
        kind = "send"
    else:
        kind = "write"
    if kind == "read" and (tool.get("annotations") or {}).get("destructiveHint") is True:
        kind = "write"
    return kind


def _walk(obj, fn):
    if isinstance(obj, str):
        return fn(obj)
    if isinstance(obj, list):
        return [_walk(x, fn) for x in obj]
    if isinstance(obj, dict):
        return {k: _walk(v, fn) for k, v in obj.items()}
    return obj


def _strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, list):
        for x in obj:
            yield from _strings(x)
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _strings(v)


def extract_destinations(args: dict) -> list[str]:
    hosts: set[str] = set()
    for s in _strings(args):
        hosts.update(m.group(1).lower() for m in _EMAIL.finditer(s))
        for m in _URL.finditer(s):
            host = urlparse("http://" + m.group(1)).hostname
            if host:
                hosts.add(host.lower())

    def visit(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k.lower() in _DEST_KEYS and isinstance(v, str) and "@" not in v and "://" not in v \
                        and _HOST.match(v.strip()):
                    hosts.add(v.strip().lower())
                visit(v)
        elif isinstance(obj, list):
            for x in obj:
                visit(x)

    visit(args)
    return sorted(hosts)


def _rpc_error(mid, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}


def _blocked(message: str) -> dict:
    return {"content": [{"type": "text", "text": f"GuardianAI: {message}"}], "isError": True}


class Gateway:
    def __init__(self, vault: Vault, audit: AuditLog, registry: UpstreamRegistry, agents: AgentRegistry,
                 approvals: ApprovalStore, policy: PolicyStore):
        self._vault, self._audit, self._registry = vault, audit, registry
        self._agents, self._approvals, self._policy = agents, approvals, policy
        self._hmac_key = vault.get_or_create_secret("token-hmac")
        self._taint: dict[str, float] = {}
        self._tool_cache: dict[str, tuple[float, list[dict]]] = {}
        self._lock = threading.Lock()

    # ---- tokenization helpers -------------------------------------------------
    def _token_id(self, value: str) -> str:
        # Stable per install: the same real value always maps to the same token.
        return hmac.new(self._hmac_key, value.encode("utf-8"), hashlib.sha256).hexdigest()[:12]

    def sanitize_text(self, text: str) -> tuple[str, list[str], list[threat_detector.Finding]]:
        findings = threat_detector.scan(text)
        result = pii_detector.tokenize(text, id_fn=self._token_id)
        for token_id, match in result.tokens.items():
            self._vault.set(f"detoken:{token_id}", {"value": match.original_value,
                                                     "category": match.category.value})
        return result.text, [m.category.value for m in result.tokens.values()], findings

    def mark_tainted(self, agent_id: str) -> None:
        with self._lock:
            self._taint[agent_id] = time.time()

    def is_tainted(self, agent_id: str) -> bool:
        with self._lock:
            ts = self._taint.get(agent_id)
            if ts is not None and time.time() - ts > TAINT_TTL:
                del self._taint[agent_id]
                return False
            return ts is not None

    def clear_taint(self, agent_id: str) -> None:
        with self._lock:
            self._taint.pop(agent_id, None)

    # ---- protocol entry point -------------------------------------------------
    def handle(self, agent: AgentRecord, msg) -> dict | None:
        if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
            return _rpc_error(None, -32600, "Invalid JSON-RPC request")
        method, mid, params = msg.get("method"), msg.get("id"), msg.get("params") or {}
        if method is None or mid is None:
            return None  # notification or client response: nothing to answer
        try:
            if method == "initialize":
                result = {"protocolVersion": params.get("protocolVersion", "2025-06-18"),
                          "capabilities": {"tools": {"listChanged": False}},
                          "serverInfo": {"name": "guardianai-gateway", "version": __version__}}
            elif method == "ping":
                result = {}
            elif method == "tools/list":
                result = self.list_tools(agent)
            elif method == "tools/call":
                result = self.call_tool(agent, params)
            else:
                return _rpc_error(mid, -32601, f"Method not found: {method}")
        except Exception:  # never leak internals to the agent
            self._audit.log("gateway_error", agent=agent.id, method=method)
            return _rpc_error(mid, -32603, "Internal gateway error")
        return {"jsonrpc": "2.0", "id": mid, "result": result}

    # ---- tools/list -----------------------------------------------------------
    def _upstream_tools(self, server: str) -> list[dict]:
        cached = self._tool_cache.get(server)
        if cached and time.time() - cached[0] < TOOL_CACHE_TTL:
            return cached[1]
        tools = self._registry.get(server).list_tools()
        self._tool_cache[server] = (time.time(), tools)
        return tools

    def list_tools(self, agent: AgentRecord) -> dict:
        visible, dropped = [], []
        for server in self._registry.names():
            try:
                tools = self._upstream_tools(server)
            except UpstreamError:
                self._audit.log("upstream_unavailable", agent=agent.id, server=server)
                continue
            for tool in tools:
                full = f"{server}{SEP}{tool['name']}"
                if not agent.allows(full):
                    continue
                if not agent.allow_write and classify_tool(tool) != "read":
                    continue
                text = " ".join([tool.get("name", ""), tool.get("description", ""),
                                 json.dumps(tool.get("inputSchema", {}))])
                findings = threat_detector.scan(text)
                if findings:
                    dropped.append({"tool": full, "rules": [f.rule for f in findings]})
                    continue
                visible.append({**tool, "name": full,
                                "description": f"[via {server}] {tool.get('description', '')}".strip()})
        if dropped:
            self._audit.log("tool_description_blocked", agent=agent.id, decision="deny", tools=dropped)
        self._audit.log("tools_listed", agent=agent.id, visible=len(visible), blocked=len(dropped))
        return {"tools": visible}

    # ---- tools/call -----------------------------------------------------------
    def call_tool(self, agent: AgentRecord, params: dict) -> dict:
        full, args = params.get("name", ""), params.get("arguments") or {}
        if not isinstance(full, str) or SEP not in full or not isinstance(args, dict):
            return _blocked("Invalid tool call.")
        server, tool_name = full.split(SEP, 1)

        def deny(reason: str, **extra) -> dict:
            self._audit.log("tool_call", agent=agent.id, decision="deny", tool=full, reason=reason, **extra)
            return _blocked(reason)

        if not agent.allows(full):
            return deny("This agent is not permitted to use that tool.")
        try:
            tool = next((t for t in self._upstream_tools(server) if t["name"] == tool_name), None)
        except UpstreamError:
            return deny("The upstream server is unavailable.")
        if tool is None:
            return deny("Unknown tool.")
        kind = classify_tool(tool)
        if kind != "read" and not agent.allow_write:
            return deny(f"This agent is read-only; '{kind}' tools are not permitted.", kind=kind)
        if threat_detector.scan(f"{tool.get('name','')} {tool.get('description','')}"):
            return deny("Tool description looked poisoned; call refused.", kind=kind)

        # Resolve tokens the agent passed back (e.g. "reply to <<GUARDIANAI:email:ab12>>").
        token_ids = [t for s in _strings(args) for t in pii_detector.find_token_ids(s)]
        records = {t: self._vault.get(f"detoken:{t}") for t in set(token_ids)}
        unknown = [t for t, r in records.items() if r is None]
        if unknown:
            return deny("Arguments reference unknown tokens; refusing to send placeholders upstream.", kind=kind)
        real = {t: r["value"] for t, r in records.items()}
        resolved = _walk(args, lambda s: pii_detector.detokenize(s, real))

        cats = {r["category"] for r in records.values()}
        cats |= {m.category.value for s in _strings(resolved) for m in pii_detector.detect(s)}
        cats.discard(pii_detector.PiiCategory.EMAIL.value)  # recipients are judged by destination trust
        destinations = extract_destinations(resolved)

        result = evaluate(ActionRequest(
            connector=server, action=tool_name, kind=kind, destinations=destinations,
            contains_pii=bool(cats), pii_categories=sorted(cats),
            cross_context_flag=self.is_tainted(agent.id), trusted_domains=self._policy.trusted_domains()))
        detail = dict(tool=full, kind=kind, reason=result.reason, categories=sorted(cats),
                      destinations=destinations)

        if result.decision in (Decision.DENY, Decision.QUARANTINE):
            self._audit.log("tool_call", agent=agent.id, decision=result.decision.value, **detail)
            return _blocked(result.reason)

        if result.decision == Decision.REQUIRE_APPROVAL:
            fp = hashlib.sha256(f"{agent.id}|{full}|{json.dumps(args, sort_keys=True)}".encode()).hexdigest()
            status = self._approvals.status_for(fp)
            if status == "denied":
                self._audit.log("tool_call", agent=agent.id, decision="deny", **{**detail, "reason": "denied by user"})
                return _blocked("The user denied this action.")
            if status != "approved":
                preview = pii_detector.tokenize(json.dumps(args)[:500]).text
                item = self._approvals.request(fp, agent_id=agent.id, agent_name=agent.name, tool=full,
                                               reason=result.reason, destinations=destinations,
                                               args_preview=preview)
                self._audit.log("tool_call", agent=agent.id, decision="require_approval",
                                approval_id=item["id"], **detail)
                return _blocked(f"Action held for user approval (id {item['id']}). {result.reason} "
                                f"Ask the user to approve it in the GuardianAI dashboard, then retry the identical call.")
            detail["reason"] = "approved by user (one-time)"

        try:
            upstream_result = self._registry.get(server).call_tool(tool_name, resolved)
        except UpstreamError:
            return deny("The upstream server failed to complete the call.", kind=kind)

        cleaned, out_cats, findings, uninspected = self._sanitize_result(upstream_result)
        if findings:
            self.mark_tainted(agent.id)
        # If sensitive values were tokenized in what came back, the call was a "transform".
        self._audit.log("tool_call", agent=agent.id, decision="transform" if out_cats else "allow",
                        result_categories=sorted(set(out_cats)),
                        injection_rules=[f.rule for f in findings], uninspected_items=uninspected, **detail)
        return cleaned

    def _sanitize_result(self, result: dict):
        cats: list[str] = []
        findings: list[threat_detector.Finding] = []
        uninspected = 0

        def clean(text: str) -> str:
            t, c, f = self.sanitize_text(text)
            cats.extend(c)
            findings.extend(f)
            return t

        for item in result.get("content") or []:
            if item.get("type") == "text" and isinstance(item.get("text"), str):
                item["text"] = clean(item["text"])
            elif item.get("type") == "resource" and isinstance(item.get("resource", {}).get("text"), str):
                item["resource"]["text"] = clean(item["resource"]["text"])
            else:
                uninspected += 1  # images/audio/links cannot be scanned here
        if "structuredContent" in result:
            cleaned_text = clean(json.dumps(result["structuredContent"]))
            try:
                result["structuredContent"] = json.loads(cleaned_text)
            except ValueError:  # a bare number was replaced by a token; keep only the safe text form
                del result["structuredContent"]
                result.setdefault("content", []).append({"type": "text", "text": cleaned_text})
        return result, cats, findings, uninspected
