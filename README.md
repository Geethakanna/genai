# GuardianAI: local security gateway for AI agents

Agents connect to ONE local MCP server (GuardianAI). GuardianAI connects to
your real MCP servers behind it. Every call passes through per-agent
permissions, PII tokenization, injection detection, deterministic policy,
and human approval, and is written to a persistent audit log. Nothing
leaves your machine.

    Agent --(MCP, bearer token)--> GuardianAI /mcp --(MCP stdio/http)--> your MCP servers
                                        |
              permissions -> tokenize/detokenize -> policy -> approval -> audit

## Modules and honest status

| # | Module | Status |
|---|---|---|
| 1 | Local server + MCP gateway (`proxy/`, `gateway/`) | Working. Tested end-to-end over real HTTP and a real stdio MCP subprocess |
| 2 | Sign-in (`auth/`) | Google sign-in built (PKCE, identity-only scopes, owner binding), configurable from the dashboard's Settings page without editing files. The real network exchange with Google has **not** been tested live — see "What's actually been tested" below. Local admin-token fallback works and is tested |
| 3 | Connector registry / agent registry | Working: upstream MCP servers, per-agent tokens, patterns, read-only default |
| 4 | PII tokenizer (SecureGen) | Working for structured data (cards, IDs, keys, phone, email, IFSC, PAN, Aadhaar, SSN, IP). Stable tokens. Health/legal free-text needs NER: not built |
| 5 | Policy engine | Working, deterministic, no LLM. Trusted-domain list persisted |
| 6 | Dashboard | Working: a real web UI at `/` — Connectors, Agents, Approvals, Activity, Settings. Checked responsive down to a 320px-wide phone |
| 7 | Threat detection | Heuristic patterns for injection in results and poisoned tool descriptions. A determined attacker can evade patterns; that's why detection only *taints* and policy decides |
| 8 | Audit | Persistent SQLite, categories only, no raw PII |

## Install and run (end users)

    pip install -e .
    guardianai

The terminal prints an admin token, and a browser tab opens automatically at
`http://127.0.0.1:8765/` — this is the dashboard. Paste the token in to sign
in (or use "Continue with Google" once a client is configured in Settings),
then:
- **Connectors**: pick a known service (Local Files, Notion, GitHub, or a
  custom command/URL) and fill in the form.
- **Agents**: create one per AI assistant; the token and a ready-to-paste MCP
  config snippet are shown once, in a modal.
- **Approvals**: anything the policy engine held shows up here with
  Approve/Deny buttons.
- **Activity**: the audit log, in plain language, newest first.
- **Settings**: configure "Sign in with Google" for this install (see below).

`/docs` (FastAPI's interactive page) still exists underneath and is useful
for scripting or debugging, but the dashboard is the intended day-to-day
interface.

## Enabling "Sign in with Google"

Go to Settings in the dashboard, paste a real OAuth client ID and secret,
and click Save — no file editing, no restart. The client itself still has
to come from a real Google Cloud project (Credentials → OAuth client ID,
type **Desktop app**), which only you, with your own Google account, can
create; that one step can't be automated. Once saved, it's stored
encrypted in the local vault and survives restarts.

Identity scopes (`openid email`) used for dashboard sign-in are
non-sensitive and need no special approval from Google. The optional
native Gmail connector uses `gmail.readonly`, a *restricted* scope:
taking that beyond ~100 test users needs Google verification (and
possibly a security assessment). The MCP gateway route (adding Gmail as
an upstream MCP server instead) avoids this restriction entirely.

## What's actually been tested, and what hasn't

Being specific here on purpose, since "it's connected" and "it's tested"
are different claims:

- **Live-verified, for real, over the network**: the entire gateway
  pipeline (agent -> GuardianAI -> a real stdio MCP subprocess),
  tokenization, injection detection and tainting, the approval queue, the
  audit log, and the dashboard itself (including at real phone widths:
  320px/375px/768px, checked with a real headless browser, no horizontal
  overflow). Also: `api.github.com` is reachable from this build
  environment, but GitHub's own anonymous rate limit was already
  exhausted by other traffic sharing that IP when this was tested, so a
  genuinely live GitHub connector call could not be completed here.
- **Built and unit/mock-tested, but NOT exercised against the real
  service**: the Google OAuth code path (PKCE, token exchange, identity
  verification) — this build environment's network blocks
  `oauth2.googleapis.com`, `www.googleapis.com`, and `slack.com` outright
  (confirmed: direct requests return `403` before reaching Google/Slack
  at all). So Gmail, Drive, and Slack connectors are implemented
  following each service's real, documented API, and the OAuth logic is
  tested against a fake Google standing in for the real one — but none of
  it has actually talked to Google or Slack's servers. The first real
  test of that path will be yours, once you add your own OAuth client in
  Settings.

If you hit an error on that first real run, paste it back and I'll fix it
from the real failure rather than guessing.

## Packaging

Checked on PyPI: **`guardianai` is available**; `securegen` is already
taken by an unrelated project ("Multi-agent secure prompt CLI for AI code
generation"), so GuardianAI is the real package name going forward.

A real wheel builds and installs cleanly — verified by building it,
installing it into a brand-new virtual environment with none of the dev
setup, and confirming `guardianai` actually starts the server and serves
the dashboard from that clean install:

    python -m build --wheel
    pip install dist/guardianai-0.2.0-py3-none-any.whl   # works standalone, confirmed

**Not done yet**: actually publishing it. That needs a PyPI account (with
2FA) that only you can create and control:

    pip install twine
    twine upload dist/*

Once published, install becomes the one-liner from the original plan:

    pip install guardianai
    guardianai

## Tests

    python tests/test_workflow.py     # 10 end-to-end tests
    python tests/test_pii_detector.py # 6 detector tests

Tests inject a random encryption key instead of using the OS keychain, and
a fake Google standing in for the real OAuth servers (see above).

## Known limitations

- Vault keychain: needs Windows Credential Manager, macOS Keychain, or a
  Linux Secret Service. It fails loudly otherwise.
- Injection text stays visible to the agent (we taint and restrict
  actions instead of editing content).
- Images/audio in tool results cannot be scanned and pass through
  (counted in the audit as `uninspected_items`).
- Any email/URL in tool arguments counts as a destination, so approvals
  can be conservative.
- Token map entries in the vault never expire yet.
- Sessions and taint state are in memory and reset on restart; agents,
  upstreams, the audit log, and the Google client config persist.
- Only stdio and simple HTTP upstreams; no OAuth to remote MCP servers yet.
- Gmail/Drive/Slack: built, not live-tested (see above) — expect the
  first real run to surface something.
- A very long, hyphenated custom agent name wraps oddly on narrow phone
  widths (cosmetic only).
