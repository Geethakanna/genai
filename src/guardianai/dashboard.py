"""
GuardianAI - Local dashboard

One self-contained HTML page (no build step, no CDN dependency) served at
GET /. It talks to the same API a curl command would, so nothing here is
"fake" — every button is a real call to a real endpoint.
"""

DASHBOARD_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>GuardianAI</title>
<style>
  :root {
    --bg: #0f1417;
    --surface: #161c20;
    --surface-raised: #1d2428;
    --border: #2a3338;
    --text: #e9eef0;
    --text-muted: #8d9ba1;
    --accent: #2fb8a6;
    --accent-dim: #1f6e64;
    --ok: #4caf7d;
    --warn: #d9a441;
    --danger: #d9685f;
    --radius-panel: 10px;
    --radius-control: 6px;
    --radius-pill: 999px;
  }
  * { box-sizing: border-box; }
  html, body { height: 100%; }
  body {
    margin: 0;
    background: var(--bg);
    color: var(--text);
    font: 14px/1.5 -apple-system, "Segoe UI", system-ui, sans-serif;
  }
  code, .mono { font-family: ui-monospace, "SF Mono", Consolas, monospace; }
  button {
    font: inherit;
    cursor: pointer;
    border-radius: var(--radius-control);
    border: 1px solid var(--border);
    background: var(--surface-raised);
    color: var(--text);
    padding: 7px 14px;
  }
  button:hover { border-color: var(--accent-dim); }
  button.primary { background: var(--accent); border-color: var(--accent); color: #06201c; font-weight: 600; }
  button.primary:hover { background: #38cdb9; }
  button.danger { border-color: var(--danger); color: var(--danger); background: transparent; }
  button.quiet { background: transparent; border-color: transparent; color: var(--text-muted); padding: 4px 8px; }
  button:disabled { opacity: .5; cursor: default; }
  input, textarea {
    font: inherit;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: var(--radius-control);
    color: var(--text);
    padding: 8px 10px;
    width: 100%;
  }
  input:focus, textarea:focus, button:focus-visible {
    outline: 2px solid var(--accent); outline-offset: 1px;
  }
  label { display: block; font-size: 12.5px; color: var(--text-muted); margin: 10px 0 4px; }
  a { color: var(--accent); }

  #app { display: none; height: 100vh; grid-template-columns: 220px 1fr; grid-template-rows: 52px 1fr; }
  #app.ready { display: grid; }
  header {
    grid-column: 1 / -1;
    display: flex; align-items: center; justify-content: space-between;
    padding: 0 18px; border-bottom: 1px solid var(--border);
    min-width: 0;
  }
  .brand { display: flex; align-items: center; gap: 9px; font-weight: 600; letter-spacing: .2px; white-space: nowrap; }
  .brand .mark {
    width: 16px; height: 16px; border-radius: 4px; flex-shrink: 0;
    background: var(--accent);
  }
  .status { display: flex; align-items: center; gap: 8px; color: var(--text-muted); font-size: 13px; white-space: nowrap; }
  .dot { width: 7px; height: 7px; border-radius: 50%; background: var(--ok); flex-shrink: 0; }

  nav { border-right: 1px solid var(--border); padding: 14px 10px; overflow-y: auto; }
  nav button.nav-item {
    display: flex; width: 100%; align-items: center; gap: 10px;
    text-align: left; border: none; background: transparent; color: var(--text-muted);
    padding: 9px 10px; border-radius: var(--radius-control); margin-bottom: 2px;
    white-space: nowrap;
  }
  nav button.nav-item .count {
    margin-left: auto; font-size: 11.5px; background: var(--warn); color: #241a05;
    border-radius: var(--radius-pill); padding: 1px 7px; display: none;
  }
  nav button.nav-item.active { background: var(--surface-raised); color: var(--text); }
  nav button.nav-item:hover { color: var(--text); }

  main { overflow-y: auto; overflow-x: hidden; padding: 24px 28px 60px; min-width: 0; }

  /* Below this width a fixed sidebar leaves too little room for real content,
     so navigation becomes a horizontal, scrollable tab strip instead. */
  @media (max-width: 720px) {
    #app { grid-template-columns: 1fr; grid-template-rows: 52px auto 1fr; }
    header { padding: 0 14px; }
    .status .status-text { display: none; }
    .brand span:not(.mark) { font-size: 14px; }
    nav {
      border-right: none; border-bottom: 1px solid var(--border);
      display: flex; gap: 4px; padding: 8px 10px; overflow-x: auto;
    }
    nav button.nav-item { width: auto; margin-bottom: 0; flex-shrink: 0; }
    main { padding: 18px 16px 50px; }
    .grid { grid-template-columns: 1fr; }
    .row { flex-wrap: wrap; }
    .row .main-info { flex-basis: 100%; }
  }
  @media (max-width: 420px) {
    #login .card { width: calc(100vw - 32px); padding: 22px; }
    .modal { width: calc(100vw - 32px); }
  }
  h1 { font-size: 19px; margin: 0 0 4px; }
  .lede { color: var(--text-muted); margin: 0 0 20px; max-width: 60ch; }

  .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(230px, 1fr)); gap: 12px; }
  .panel {
    background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius-panel);
    padding: 16px;
  }
  .panel h3 { margin: 0 0 4px; font-size: 14.5px; }
  .panel p.desc { margin: 0 0 10px; color: var(--text-muted); font-size: 12.5px; min-height: 32px; }
  .badge {
    display: inline-block; font-size: 11px; padding: 1px 8px; border-radius: var(--radius-pill);
    border: 1px solid var(--border); color: var(--text-muted);
  }
  .badge.ok { border-color: var(--ok); color: var(--ok); }
  .badge.warn { border-color: var(--warn); color: var(--warn); }
  .badge.danger { border-color: var(--danger); color: var(--danger); }

  .list { display: flex; flex-direction: column; gap: 10px; margin-top: 18px; }
  .row {
    display: flex; align-items: center; gap: 12px;
    background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius-panel);
    padding: 12px 16px;
  }
  .row .main-info { flex: 1; min-width: 0; }
  .row .title { font-weight: 600; font-size: 13.5px; }
  .row .sub { color: var(--text-muted); font-size: 12px; margin-top: 2px; }
  .row .sub code { color: var(--text-muted); }

  .form-fields { margin-top: 10px; padding-top: 12px; border-top: 1px solid var(--border); }
  .form-actions { display: flex; gap: 8px; margin-top: 14px; }
  .note { font-size: 12px; color: var(--warn); margin-top: 8px; }
  .hint { font-size: 11.5px; color: var(--text-muted); margin-top: 3px; }

  .empty { color: var(--text-muted); font-size: 13px; padding: 30px 0; text-align: center; }

  #login { min-height: 100vh; display: flex; align-items: center; justify-content: center; }
  #login .card {
    width: 360px; background: var(--surface); border: 1px solid var(--border);
    border-radius: var(--radius-panel); padding: 28px;
  }
  #login .brand { justify-content: center; margin-bottom: 18px; font-size: 16px; }
  #login .error { color: var(--danger); font-size: 13px; margin-top: 10px; min-height: 18px; }

  .table-wrap { overflow-x: auto; border: 1px solid var(--border); border-radius: var(--radius-panel); }
  table { width: 100%; min-width: 560px; border-collapse: collapse; font-size: 12.5px; }
  th { text-align: left; color: var(--text-muted); font-weight: 500; padding: 6px 10px; border-bottom: 1px solid var(--border); white-space: nowrap; }
  td { padding: 7px 10px; border-bottom: 1px solid var(--border); vertical-align: top; }
  tr:last-child td { border-bottom: none; }

  .modal-backdrop {
    position: fixed; inset: 0; background: rgba(5,8,10,.6);
    display: flex; align-items: center; justify-content: center; z-index: 10;
  }
  .modal { width: 440px; background: var(--surface-raised); border: 1px solid var(--border);
          border-radius: var(--radius-panel); padding: 22px; }
  .token-box {
    background: var(--bg); border: 1px solid var(--border); border-radius: var(--radius-control);
    padding: 10px; word-break: break-all; font-size: 12.5px; margin: 10px 0;
  }
  pre.config {
    background: var(--bg); border: 1px solid var(--border); border-radius: var(--radius-control);
    padding: 10px; font-size: 11.5px; overflow-x: auto;
  }
</style>
</head>
<body>

<div id="login">
  <div class="card">
    <div class="brand"><span class="mark"></span>GuardianAI</div>
    <div id="login-google" style="display:none">
      <button class="primary" style="width:100%" onclick="window.open('/auth/login/start','_blank')">Continue with Google</button>
      <p class="hint" style="margin-top:10px">A tab will open for sign-in. Come back here when it's done.</p>
    </div>
    <div id="login-local" style="display:none">
      <label for="admin-token">Admin token</label>
      <input id="admin-token" placeholder="paste the token from your terminal">
      <div class="form-actions"><button class="primary" style="width:100%" onclick="doLocalLogin()">Sign in</button></div>
      <p class="hint" id="login-hint"></p>
    </div>
    <div class="error" id="login-error"></div>
    <div class="form-actions"><button class="quiet" style="width:100%" onclick="checkAuth()">I've signed in — continue</button></div>
  </div>
</div>

<div id="app">
  <header>
    <div class="brand"><span class="mark"></span>GuardianAI</div>
    <div class="status"><span class="dot"></span><span class="status-text">Running locally</span> <button class="quiet" onclick="logout()">Sign out</button></div>
  </header>
  <nav>
    <button class="nav-item active" data-view="connectors" onclick="showView('connectors')">Connectors</button>
    <button class="nav-item" data-view="agents" onclick="showView('agents')">Agents</button>
    <button class="nav-item" data-view="approvals" onclick="showView('approvals')"><span>Approvals</span><span class="count" id="approval-count">0</span></button>
    <button class="nav-item" data-view="activity" onclick="showView('activity')">Activity</button>
    <button class="nav-item" data-view="settings" onclick="showView('settings')">Settings</button>
  </nav>
  <main id="main"></main>
</div>

<script>
const $ = (sel, el) => (el || document).querySelector(sel);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));

async function api(path, opts) {
  const res = await fetch(path, { headers: { "Content-Type": "application/json" }, ...opts });
  let body = null;
  try { body = await res.json(); } catch (e) { /* no body */ }
  if (!res.ok) throw new Error((body && body.detail) || res.statusText);
  return body;
}

// ---- auth -------------------------------------------------------------
async function checkAuth() {
  const status = await api("/auth/status");
  if (status.signed_in) {
    $("#login").style.display = "none";
    $("#app").classList.add("ready");
    showView(currentView);
    pollApprovals();
    return;
  }
  $("#login-google").style.display = status.google_login_available ? "block" : "none";
  $("#login-local").style.display = status.google_login_available ? "none" : "block";
  $("#login-hint").textContent = status.hint || "";
}

async function doLocalLogin() {
  $("#login-error").textContent = "";
  try {
    await api("/auth/local", { method: "POST", body: JSON.stringify({ token: $("#admin-token").value.trim() }) });
    checkAuth();
  } catch (e) { $("#login-error").textContent = e.message; }
}

async function logout() {
  await api("/auth/logout", { method: "POST" });
  location.reload();
}

// ---- view routing -------------------------------------------------------
let currentView = "connectors";
const renderers = { connectors: renderConnectors, agents: renderAgents, approvals: renderApprovals, activity: renderActivity, settings: renderSettings };

function showView(name) {
  currentView = name;
  document.querySelectorAll(".nav-item").forEach(b => b.classList.toggle("active", b.dataset.view === name));
  renderers[name]();
}

async function pollApprovals() {
  try {
    const data = await api("/admin/approvals");
    const n = data.pending.length;
    const el = $("#approval-count");
    el.textContent = n;
    el.style.display = n > 0 ? "inline-block" : "none";
  } catch (e) { /* session may have expired; ignore until next real action */ }
  setTimeout(pollApprovals, 5000);
}

// ---- connectors ----------------------------------------------------------
async function renderConnectors() {
  const main = $("#main");
  main.innerHTML = "<p class='lede'>Loading…</p>";
  const [{ catalog }, overview] = await Promise.all([
    api("/admin/connector-catalog"), api("/admin/overview"),
  ]);

  const connected = overview.upstreams;
  main.innerHTML = `
    <h1>Connectors</h1>
    <p class="lede">These are the real services an agent can reach through GuardianAI. Nothing here grants access by itself — each agent still needs its own permission.</p>
    <div class="grid" id="catalog-grid"></div>
    <h1 style="margin-top:34px">Connected</h1>
    <div class="list" id="connected-list"></div>
  `;

  const grid = $("#catalog-grid");
  catalog.forEach(entry => {
    const card = document.createElement("div");
    card.className = "panel";
    card.innerHTML = `
      <h3>${esc(entry.name)}</h3>
      <p class="desc">${esc(entry.description)}</p>
      <span class="badge">${esc(entry.transport)}</span>
      <div class="form-fields" style="display:none"></div>
      <div class="form-actions"><button class="primary add-btn" style="width:100%">Connect</button></div>
    `;
    const fieldsBox = card.querySelector(".form-fields");
    const addBtn = card.querySelector(".add-btn");
    let open = false;
    addBtn.onclick = () => {
      if (!open) {
        fieldsBox.style.display = "block";
        fieldsBox.innerHTML = catalogForm(entry);
        addBtn.textContent = "Add";
        open = true;
        return;
      }
      submitCatalogEntry(entry, fieldsBox, card);
    };
    grid.appendChild(card);
  });

  const list = $("#connected-list");
  if (connected.length === 0) {
    list.innerHTML = "<div class='empty'>Nothing connected yet — add one above.</div>";
  }
  connected.forEach(up => {
    const row = document.createElement("div");
    row.className = "row";
    row.innerHTML = `
      <div class="main-info">
        <div class="title">${esc(up.name)}</div>
        <div class="sub">${esc(up.transport)}, <code>${esc(up.target || "")}</code></div>
        <div class="sub mono" id="tools-${esc(up.name)}"></div>
      </div>
      <button class="quiet" onclick="loadTools('${esc(up.name)}')">View tools</button>
      <button class="danger" onclick="removeUpstream('${esc(up.name)}')">Remove</button>
    `;
    list.appendChild(row);
  });
}

function catalogForm(entry) {
  const nameField = `<label>Name for this connection</label>
    <input id="f-name" value="${esc(entry.id)}" class="mono">`;
  const fields = entry.fields.map((f, i) => `
    <label>${esc(f.label)}</label>
    <input id="f-${i}" type="${f.secret ? "password" : "text"}" placeholder="${esc(f.placeholder)}">
    ${f.help ? `<div class="hint">${esc(f.help)}</div>` : ""}
  `).join("");
  const setup = entry.setup_url ? `<div class="hint">Get this at <a href="${esc(entry.setup_url)}" target="_blank">${esc(entry.setup_url)}</a></div>` : "";
  const note = entry.note ? `<div class="note">${esc(entry.note)}</div>` : "";
  return nameField + fields + setup + note;
}

async function submitCatalogEntry(entry, fieldsBox, card) {
  const name = fieldsBox.querySelector("#f-name").value.trim().toLowerCase().replace(/[^a-z0-9-]/g, "-");
  const values = entry.fields.map((_, i) => fieldsBox.querySelector(`#f-${i}`).value.trim());

  const spec = { name, transport: entry.transport, args: [...entry.base_args], env: {} };
  if (entry.transport === "http") spec.url = "";
  if (entry.command) spec.command = entry.command;

  entry.fields.forEach((f, i) => {
    const v = values[i];
    if (f.key === "arg") spec.args.push(v);
    else if (f.key === "command") spec.command = v;
    else if (f.key === "args") spec.args.push(...v.split(" ").filter(Boolean));
    else if (f.key === "url") spec.url = v;
    else if (f.key === "path") spec.command = v;
    else if (f.key.startsWith("env:")) spec.env[f.key.slice(4)] = v;
  });

  try {
    await api("/admin/upstreams", { method: "POST", body: JSON.stringify(spec) });
    renderConnectors();
  } catch (e) {
    const err = document.createElement("div");
    err.className = "note";
    err.style.color = "var(--danger)";
    err.textContent = e.message;
    card.appendChild(err);
  }
}

async function loadTools(name) {
  const el = $(`#tools-${name}`);
  el.textContent = "loading tools…";
  try {
    const data = await api(`/admin/upstreams/${encodeURIComponent(name)}/tools`);
    el.textContent = data.tools.length ? data.tools.map(t => t.name).join(", ") : "(no tools reported)";
  } catch (e) { el.textContent = "could not reach this server: " + e.message; }
}

async function removeUpstream(name) {
  if (!confirm(`Remove "${name}"? Any agent using it will lose access immediately.`)) return;
  await api(`/admin/upstreams/${encodeURIComponent(name)}`, { method: "DELETE" });
  renderConnectors();
}

// ---- agents ----------------------------------------------------------
async function renderAgents() {
  const main = $("#main");
  const overview = await api("/admin/overview");
  main.innerHTML = `
    <h1>Agents</h1>
    <p class="lede">Each AI agent or assistant gets its own token and its own permissions. New agents can only read, until you allow more.</p>
    <div class="panel" style="max-width:420px">
      <label>Name</label><input id="new-agent-name" placeholder="e.g. Claude Desktop">
      <label style="display:flex;align-items:center;gap:8px;margin-top:14px">
        <input type="checkbox" id="new-agent-write" style="width:auto"> Allow write and send actions
      </label>
      <div class="form-actions"><button class="primary" onclick="createAgent()">Create agent</button></div>
    </div>
    <div class="list" id="agent-list"></div>
  `;
  const list = $("#agent-list");
  if (overview.agents.length === 0) list.innerHTML = "<div class='empty'>No agents yet.</div>";
  overview.agents.forEach(a => {
    const row = document.createElement("div");
    row.className = "row";
    row.innerHTML = `
      <div class="main-info">
        <div class="title">${esc(a.name)} ${a.tainted ? '<span class="badge warn">flagged content seen</span>' : ""}</div>
        <div class="sub">${a.allow_write ? "Can read, write and send" : "Read-only"}. ${a.recent_calls} recent calls, ${a.recent_blocked} held or blocked.</div>
      </div>
      <button class="quiet" onclick="toggleWrite('${a.id}', ${!a.allow_write})">${a.allow_write ? "Make read-only" : "Allow write"}</button>
      ${a.tainted ? `<button class="quiet" onclick="clearTaint('${a.id}')">Clear flag</button>` : ""}
      <button class="danger" onclick="revokeAgent('${a.id}')">Revoke</button>
    `;
    list.appendChild(row);
  });
}

async function createAgent() {
  const name = $("#new-agent-name").value.trim();
  if (!name) return;
  const allow_write = $("#new-agent-write").checked;
  const data = await api("/admin/agents", { method: "POST", body: JSON.stringify({ name, allow_write }) });
  showTokenModal(data);
}

function showTokenModal(data) {
  const config = JSON.stringify({ mcpServers: { guardianai: { url: location.origin + "/mcp", headers: { Authorization: "Bearer " + data.token } } } }, null, 2);
  const backdrop = document.createElement("div");
  backdrop.className = "modal-backdrop";
  backdrop.innerHTML = `
    <div class="modal">
      <h3>${esc(data.name)} is ready</h3>
      <p class="hint">This token is shown once. Copy it before closing this window.</p>
      <div class="token-box mono">${esc(data.token)}</div>
      <label>Paste this into the agent's MCP configuration</label>
      <pre class="config">${esc(config)}</pre>
      <div class="form-actions">
        <button class="primary" style="width:100%" onclick="this.closest('.modal-backdrop').remove()">Done</button>
      </div>
    </div>`;
  document.body.appendChild(backdrop);
}

async function toggleWrite(id, value) {
  await api(`/admin/agents/${id}`, { method: "PATCH", body: JSON.stringify({ allow_write: value }) });
  renderAgents();
}
async function clearTaint(id) {
  await api(`/admin/agents/${id}/clear-taint`, { method: "POST" });
  renderAgents();
}
async function revokeAgent(id) {
  if (!confirm("Revoke this agent? Its token will stop working immediately.")) return;
  await api(`/admin/agents/${id}`, { method: "DELETE" });
  renderAgents();
}

// ---- approvals ----------------------------------------------------------
async function renderApprovals() {
  const main = $("#main");
  const data = await api("/admin/approvals");
  main.innerHTML = `
    <h1>Approvals</h1>
    <p class="lede">An agent asked to do something that needed a person to say yes. Nothing here has happened yet.</p>
    <div class="list" id="approval-list"></div>
  `;
  const list = $("#approval-list");
  if (data.pending.length === 0) list.innerHTML = "<div class='empty'>Nothing waiting on you right now.</div>";
  data.pending.forEach(p => {
    const row = document.createElement("div");
    row.className = "row";
    row.innerHTML = `
      <div class="main-info">
        <div class="title">${esc(p.agent_name)} wants to use <code>${esc(p.tool)}</code></div>
        <div class="sub">${esc(p.reason)}</div>
        ${p.destinations.length ? `<div class="sub">To: ${esc(p.destinations.join(", "))}</div>` : ""}
        <div class="sub mono">${esc(p.args_preview)}</div>
      </div>
      <button class="primary" onclick="decide('${p.id}','approve')">Approve</button>
      <button class="danger" onclick="decide('${p.id}','deny')">Deny</button>
    `;
    list.appendChild(row);
  });
}

async function decide(id, verdict) {
  await api(`/admin/approvals/${id}/${verdict}`, { method: "POST" });
  renderApprovals();
  pollApprovals();
}

// ---- activity ----------------------------------------------------------
async function renderActivity() {
  const main = $("#main");
  const data = await api("/audit?limit=100");
  const rows = data.entries.map(e => {
    const time = new Date(e.ts * 1000).toLocaleTimeString();
    const bits = [];
    if (e.detail.tool) bits.push(e.detail.tool);
    if (e.detail.reason) bits.push(e.detail.reason);
    if (e.detail.result_categories && e.detail.result_categories.length) bits.push("found: " + e.detail.result_categories.join(", "));
    return `<tr>
      <td>${time}</td>
      <td>${esc(e.event)}</td>
      <td>${e.decision ? `<span class="badge ${badgeClass(e.decision)}">${esc(e.decision)}</span>` : ""}</td>
      <td>${esc(bits.join(". "))}</td>
    </tr>`;
  }).join("");
  $("#main").innerHTML = `
    <h1>Activity</h1>
    <p class="lede">Every decision GuardianAI has made, most recent first. No real account numbers, keys or similar values are ever written here.</p>
    <div class="table-wrap"><table><thead><tr><th>Time</th><th>Event</th><th>Decision</th><th>Detail</th></tr></thead>
    <tbody>${rows || "<tr><td colspan=4 class='empty'>Nothing logged yet.</td></tr>"}</tbody></table></div>
  `;
}
function badgeClass(d) {
  if (d === "allow" || d === "transform") return "ok";
  if (d === "require_approval") return "warn";
  return "danger";
}

// ---- settings ----------------------------------------------------------
async function renderSettings() {
  const main = $("#main");
  const data = await api("/admin/settings");
  main.innerHTML = `
    <h1>Settings</h1>
    <p class="lede">Configuration for this install, kept on this computer only.</p>
    <div class="panel" style="max-width:460px">
      <h3>Google sign-in</h3>
      <p class="desc">${data.google_client_configured
        ? "A Google OAuth client is configured. People can sign in to this dashboard and connect Gmail with their Google account."
        : "Not configured yet. Until this is set, sign-in uses the admin token shown in the terminal."}</p>
      <div id="google-client-form"></div>
    </div>
  `;
  const box = $("#google-client-form");
  if (data.google_client_configured) {
    box.innerHTML = `<button class="danger" onclick="removeGoogleClient()">Remove configured client</button>`;
  } else {
    box.innerHTML = `
      <label>OAuth client ID</label>
      <input id="g-client-id" placeholder="xxxx.apps.googleusercontent.com">
      <label>OAuth client secret</label>
      <input id="g-client-secret" type="password" placeholder="GOCSPX-...">
      <div class="hint">From Google Cloud Console → Credentials → OAuth client ID (type: Desktop app).
      This only needs to be entered once for this install.</div>
      <div class="form-actions"><button class="primary" onclick="saveGoogleClient()">Save</button></div>
      <div class="note" id="g-client-error"></div>
    `;
  }
}

async function saveGoogleClient() {
  $("#g-client-error").textContent = "";
  try {
    await api("/admin/settings/google-client", { method: "POST", body: JSON.stringify({
      client_id: $("#g-client-id").value.trim(), client_secret: $("#g-client-secret").value.trim(),
    }) });
    renderSettings();
  } catch (e) { $("#g-client-error").textContent = e.message; }
}

async function removeGoogleClient() {
  if (!confirm("Remove the configured Google client? People will sign in with the admin token instead.")) return;
  await api("/admin/settings/google-client", { method: "DELETE" });
  renderSettings();
}

checkAuth();
</script>
</body>
</html>
"""
