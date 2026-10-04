"""
GuardianAI - Connector catalog

A short, honestly-vetted list of known MCP servers, used by the dashboard to
turn "add an upstream" from hand-written JSON into a form with the right
fields for that service. This is deliberately small: the MCP ecosystem moves
fast and packages get renamed/deprecated, so entries here are limited to ones
that could be checked at the time this was written. Everything else goes
through the "Custom" entries, which just expose the same stdio/HTTP fields
the backend has always accepted.

Nothing here embeds a token, API key, or path — `fields` just tells the
dashboard what to ask the user for and where to put each answer.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Field:
    key: str          # "env:NAME" -> goes into env; "arg" -> appended to args; "url" -> the url
    label: str
    placeholder: str = ""
    secret: bool = False
    help: str = ""


@dataclass(frozen=True)
class CatalogEntry:
    id: str
    name: str
    description: str
    transport: str  # "stdio" | "http"
    command: str | None = None
    base_args: list[str] = field(default_factory=list)
    fields: list[Field] = field(default_factory=list)
    setup_url: str = ""
    note: str = ""  # shown as a caution/caveat in the UI, when the package landscape is unsettled


CATALOG: list[CatalogEntry] = [
    CatalogEntry(
        id="filesystem",
        name="Local Files",
        description="Read and write files in one folder on this computer.",
        transport="stdio",
        command="npx",
        base_args=["-y", "@modelcontextprotocol/server-filesystem"],
        fields=[Field("arg", "Folder to share", "C:\\Users\\you\\Documents\\shared",
                      help="Only this folder (and its subfolders) will be reachable.")],
    ),
    CatalogEntry(
        id="notion",
        name="Notion",
        description="Search and edit pages in a Notion workspace.",
        transport="stdio",
        command="npx",
        base_args=["-y", "@notionhq/notion-mcp-server"],
        fields=[Field("env:NOTION_TOKEN", "Internal integration secret", "secret_...", secret=True)],
        setup_url="https://www.notion.so/my-integrations",
    ),
    CatalogEntry(
        id="github",
        name="GitHub",
        description="Issues, pull requests and repositories.",
        transport="stdio",
        command=None,  # the official server is a downloaded binary, not an npm package — see note
        fields=[Field("path", "Path to github-mcp-server", "C:\\tools\\github-mcp-server.exe"),
               Field("env:GITHUB_PERSONAL_ACCESS_TOKEN", "Personal access token", "ghp_...", secret=True)],
        setup_url="https://github.com/github/github-mcp-server",
        note="GitHub's official MCP server ships as a downloaded program, not an npm package. "
             "Download it from the link above, then point this at the downloaded file.",
    ),
    CatalogEntry(
        id="custom-stdio",
        name="Custom command",
        description="Any MCP server you already run as a local command.",
        transport="stdio",
        fields=[Field("command", "Command", "npx"), Field("args", "Arguments (space-separated)", "-y some-mcp-server")],
    ),
    CatalogEntry(
        id="custom-http",
        name="Custom HTTP server",
        description="An MCP server reachable over HTTP, local or remote.",
        transport="http",
        fields=[Field("url", "Server URL", "https://example.com/mcp")],
    ),
]


def describe() -> list[dict]:
    return [
        {"id": e.id, "name": e.name, "description": e.description, "transport": e.transport,
         "command": e.command, "base_args": list(e.base_args),
         "setup_url": e.setup_url, "note": e.note,
         "fields": [{"key": f.key, "label": f.label, "placeholder": f.placeholder,
                    "secret": f.secret, "help": f.help} for f in e.fields]}
        for e in CATALOG
    ]
