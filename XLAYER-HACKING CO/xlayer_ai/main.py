"""
XLayer AI - Autonomous Web Vulnerability Hunter
Modern interactive CLI with rich TUI.

Run without arguments for interactive mode:
    xlayer-ai

Or use direct commands:
    xlayer-ai scan https://target.com
    xlayer-ai hunter sqli https://target.com --param id
    xlayer-ai auth login gemini
    xlayer-ai test-llm
"""

import asyncio
import json
import os
import sys
import time
from pathlib import Path
from typing import List, Optional, Tuple

import click
import questionary
from loguru import logger
from rich import box
from rich.columns import Columns
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import (BarColumn, Progress, SpinnerColumn,
                           TaskProgressColumn, TextColumn, TimeElapsedColumn)
from rich.prompt import Confirm, Prompt
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from xlayer_ai.config.settings import Settings, get_settings
from xlayer_ai.src.agent.coordinator import Coordinator
from xlayer_ai.engine.llm import LLMClient
from xlayer_ai.core.vuln_hunters import HUNTER_REGISTRY
from xlayer_ai.utils.logger import setup_logger
from xlayer_ai.utils.validators import validate_url

# ─── Constants ────────────────────────────────────────────────────────────────

console = Console()
err_console = Console(stderr=True)

AVAILABLE_HUNTERS = sorted(HUNTER_REGISTRY.keys())
ENV_FILE = Path(__file__).parent / ".env"

VERSION = "1.0.0"

# Provider catalog
PROVIDERS = {
    "gemini": {
        "label":    "Google Gemini  (API key — free tier available)",
        "color":    "green",
        "auth":     "api_key",
        "models":   ["gemini-2.0-flash", "gemini-1.5-flash", "gemini-1.5-pro", "gemini-2.0-pro"],
        "env_key":  "XLAYER_LLM__API_KEY",
        "free":     True,
        "note":     "Get free key: aistudio.google.com/apikey",
    },
    "gemini_adc": {
        "label":    "Google Gemini  (gcloud OAuth — no API key needed)",
        "color":    "green",
        "auth":     "adc",
        "models":   ["gemini-2.0-flash", "gemini-1.5-flash", "gemini-1.5-pro"],
        "env_key":  None,
        "free":     True,
        "note":     "Requires: gcloud auth application-default login",
    },
    "openai": {
        "label":    "OpenAI         (API key)",
        "color":    "blue",
        "auth":     "api_key",
        "models":   ["gpt-4o-mini", "gpt-4o", "gpt-4-turbo", "gpt-3.5-turbo"],
        "env_key":  "XLAYER_LLM__API_KEY",
        "free":     False,
        "note":     "Get key: platform.openai.com/api-keys",
    },
    "openai_oauth": {
        "label":    "OpenAI         (ChatGPT OAuth — subscription login)",
        "color":    "blue",
        "auth":     "oauth",
        "models":   ["gpt-4o", "gpt-4o-mini"],
        "env_key":  "XLAYER_LLM__OPENAI_CLIENT_ID",
        "free":     False,
        "note":     "Requires ChatGPT Max/Codex plan + client_id",
    },
    "ollama": {
        "label":    "Ollama         (local models — completely free)",
        "color":    "yellow",
        "auth":     "none",
        "models":   ["llama3.1", "llama3.2", "codellama", "mistral", "phi3", "gemma2"],
        "env_key":  None,
        "free":     True,
        "note":     "Requires: ollama serve (localhost:11434)",
    },
    "none": {
        "label":    "No LLM         (static payloads only — fastest)",
        "color":    "dim",
        "auth":     "none",
        "models":   [],
        "env_key":  None,
        "free":     True,
        "note":     "Adaptive AI engine disabled. Static payloads + WAF mutations only.",
    },
}

# Module name -> display label + color for live log
LOG_CATEGORIES = {
    "recon":            ("[RECON  ]", "bold blue"),
    "vuln_hunter":      ("[HUNT   ]", "bold yellow"),
    "adaptive_engine":  ("[ENGINE ]", "bold cyan"),
    "llm":              ("[LLM    ]", "bold magenta"),
    "exploit":          ("[EXPLOIT]", "bold red"),
    "planner":          ("[PLAN   ]", "bold white"),
    "reporter":         ("[REPORT ]", "bold green"),
    "solver":           ("[SOLVER ]", "bold cyan"),
}


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _env_write(key: str, value: str):
    """Write or update a key=value line in .env file."""
    lines = ENV_FILE.read_text().splitlines() if ENV_FILE.exists() else []
    found = False
    new_lines = []
    for line in lines:
        if line.startswith(f"{key}=") or line.startswith(f"# {key}="):
            new_lines.append(f"{key}={value}")
            found = True
        else:
            new_lines.append(line)
    if not found:
        new_lines.append(f"{key}={value}")
    ENV_FILE.write_text("\n".join(new_lines) + "\n")


def _env_read(key: str) -> Optional[str]:
    if not ENV_FILE.exists():
        return None
    for line in ENV_FILE.read_text().splitlines():
        if line.startswith(f"{key}="):
            return line.split("=", 1)[1].strip()
    return None


def _banner():
    console.print()
    console.print(Panel.fit(
        "[bold red]X[/][bold white]LAYER[/] [bold red]AI[/]\n"
        "[dim]Autonomous Web Vulnerability Hunter[/]\n"
        "[dim italic]\"Hack before hackers hack — Prove before you report\"[/]",
        border_style="red",
        padding=(0, 4),
    ))
    console.print()


def _llm_status_panel(settings: Settings) -> Panel:
    t = Table.grid(padding=(0, 2))
    t.add_column(style="dim", width=16)
    t.add_column()

    provider  = settings.llm.provider
    model     = settings.llm.model or "(default)"
    api_key   = settings.llm.api_key
    valid, vm = settings.llm.validate_config()

    pinfo   = PROVIDERS.get(provider, {})
    p_color = pinfo.get("color", "white")

    status_icon = "[bold green]connected[/]" if valid else "[bold red]not configured[/]"

    t.add_row("Provider",  f"[{p_color}]{provider}[/]")
    t.add_row("Model",     model)
    t.add_row("Auth",      pinfo.get("auth", "?"))
    t.add_row("API key",   f"[green]set[/]" if api_key else "[red]not set[/]")
    t.add_row("Status",    status_icon)
    if not valid:
        t.add_row("", f"[dim]{vm}[/]")

    return Panel(t, title="[bold]LLM[/]", border_style="dim", padding=(0, 1))


def _providers_table() -> Table:
    t = Table(box=box.ROUNDED, border_style="dim", show_header=True,
              header_style="bold", padding=(0, 1))
    t.add_column("#",         style="dim", width=3)
    t.add_column("Provider",  width=12)
    t.add_column("Description")
    t.add_column("Free",      width=5, justify="center")

    for i, (key, info) in enumerate(PROVIDERS.items(), 1):
        free_mark = "[green]yes[/]" if info["free"] else "[red]no[/]"
        t.add_row(
            str(i),
            f"[{info['color']}]{key}[/]",
            info["label"],
            free_mark,
        )
    return t


def _category_from_module(name: str) -> Tuple[str, str]:
    for key, (label, color) in LOG_CATEGORIES.items():
        if key in name:
            return label, color
    return "[OTHER  ]", "dim"


# ─── Live Scan Display ────────────────────────────────────────────────────────

class ScanLiveDisplay:
    """
    Captures loguru log records during a scan and renders them
    in a Rich Live panel with color-coded agent events.
    """

    MAX_EVENTS = 30

    def __init__(self):
        self._events:   List[Text] = []
        self._findings: List[Text] = []
        self._phase:    str = "INIT"
        self._spinner_text: str = "Initializing..."
        self._sink_id:  Optional[int] = None

    def start_capture(self):
        """Register loguru sink to capture scan events."""
        self._sink_id = logger.add(self._handle_log, level="INFO", format="{message}")

    def stop_capture(self):
        if self._sink_id is not None:
            logger.remove(self._sink_id)
            self._sink_id = None

    def _handle_log(self, message):
        record = message.record
        name   = record["name"]
        text   = record["message"].strip()
        if not text:
            return

        label, color = _category_from_module(name)

        # Detect phase changes
        if "PHASE 1" in text or "recon" in text.lower():
            self._phase = "RECON"
        elif "PHASE 2" in text or "hunt" in text.lower():
            self._phase = "HUNT"
        elif "PHASE 3" in text or "exploit" in text.lower():
            self._phase = "EXPLOIT"
        elif "PHASE 4" in text or "report" in text.lower():
            self._phase = "REPORT"

        # Build rich text line
        line = Text()
        line.append(f"{label} ", style=color)
        line.append(text, style="white" if "ERROR" not in record["level"].name else "bold red")
        self._events.append(line)
        self._events = self._events[-self.MAX_EVENTS:]

        # Findings detection
        if any(k in text.lower() for k in ["hypothesis", "found", "confirmed", "high", "medium"]):
            self._findings.append(Text(text, style="bold yellow"))
            self._findings = self._findings[-20:]

        self._spinner_text = text[:80]

    def set_phase(self, phase: str):
        self._phase = phase

    def render(self) -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(name="phase",    size=3),
            Layout(name="events",   ratio=3),
            Layout(name="findings", ratio=1),
        )

        # Phase bar
        phase_steps = ["RECON", "HUNT", "EXPLOIT", "REPORT"]
        phase_parts = []
        for step in phase_steps:
            if step == self._phase:
                phase_parts.append(f"[bold reverse white] {step} [/]")
            elif phase_steps.index(step) < phase_steps.index(self._phase) if self._phase in phase_steps else False:
                phase_parts.append(f"[dim green] {step} [/]")
            else:
                phase_parts.append(f"[dim] {step} [/]")
        phase_bar = Text.from_markup("  ->  ".join(phase_parts))
        layout["phase"].update(Panel(phase_bar, border_style="dim", padding=(0, 1)))

        # Events panel
        if self._events:
            ev_lines = Text()
            for line in self._events[-20:]:
                ev_lines.append_text(line)
                ev_lines.append("\n")
        else:
            ev_lines = Text("[dim]Waiting for scan events...[/dim]", justify="center")
        layout["events"].update(Panel(
            ev_lines,
            title=f"[bold cyan]Agent Events[/]  [dim]{self._spinner_text[:60]}[/]",
            border_style="cyan",
            padding=(0, 1),
        ))

        # Findings panel
        if self._findings:
            f_lines = Text()
            for f in self._findings[-8:]:
                f_lines.append("  [+] ", style="bold yellow")
                f_lines.append_text(f)
                f_lines.append("\n")
        else:
            f_lines = Text("[dim]No findings yet...[/]", justify="center")
        layout["findings"].update(Panel(
            f_lines,
            title="[bold yellow]Findings[/]",
            border_style="yellow",
            padding=(0, 1),
        ))

        return layout


# ─── Interactive Mode ─────────────────────────────────────────────────────────

async def _interactive_main():
    """Full interactive TUI session."""
    _banner()

    settings = get_settings()
    console.print(_llm_status_panel(settings))

    while True:
        console.print()
        action = await asyncio.to_thread(
            questionary.select,
            "What do you want to do?",
            choices=[
                questionary.Choice("  Scan a target",               value="scan"),
                questionary.Choice("  Run single hunter",           value="hunter"),
                questionary.Choice("  Switch LLM provider / model", value="model"),
                questionary.Choice("  Login / Auth setup",          value="auth"),
                questionary.Choice("  Test LLM connection",         value="test_llm"),
                questionary.Choice("  View config",                  value="config"),
                questionary.Choice("  List hunters",                 value="hunters"),
                questionary.Separator(),
                questionary.Choice("  Exit",                         value="exit"),
            ],
            use_shortcuts=False,
            style=questionary.Style([
                ("selected",        "fg:#ff5555 bold"),
                ("pointer",         "fg:#ff5555 bold"),
                ("highlighted",     "fg:#ff5555 bold"),
                ("answer",          "fg:#aaaaaa"),
                ("question",        "bold"),
            ]),
        ).unsafe_ask_async()

        if action == "exit" or action is None:
            console.print("\n[dim]Goodbye.[/]\n")
            break
        elif action == "scan":
            await _interactive_scan(settings)
        elif action == "hunter":
            await _interactive_hunter(settings)
        elif action == "model":
            await _interactive_model_select(settings)
        elif action == "auth":
            await _interactive_auth()
        elif action == "test_llm":
            await _do_test_llm(settings.llm.provider, settings.llm.model, "sqli")
        elif action == "config":
            _show_config(settings)
        elif action == "hunters":
            _show_hunters()


async def _interactive_scan(settings: Settings):
    console.print(Rule("[bold red]Scan Target[/]", style="red"))

    target = await asyncio.to_thread(
        questionary.text,
        "Target URL:",
        validate=lambda v: True if v.startswith("http") else "URL must start with http:// or https://",
    ).unsafe_ask_async()
    if not target:
        return

    # Hunter selection
    console.print()
    hunter_choice = await asyncio.to_thread(
        questionary.select,
        "Hunters to run:",
        choices=[
            questionary.Choice("All hunters (full scan)",    value="all"),
            questionary.Choice("Quick (sqli, xss, lfi)",     value="quick"),
            questionary.Choice("Choose manually",             value="manual"),
        ],
    ).unsafe_ask_async()

    hunter_list = None
    if hunter_choice == "quick":
        hunter_list = ["sqli", "xss", "lfi"]
    elif hunter_choice == "manual":
        chosen = await asyncio.to_thread(
            questionary.checkbox,
            "Select hunters:",
            choices=AVAILABLE_HUNTERS,
        ).unsafe_ask_async()
        hunter_list = chosen if chosen else None

    # Options
    console.print()
    no_exploit = not await asyncio.to_thread(
        questionary.confirm, "Run exploitation phase?", default=True
    ).unsafe_ask_async()

    console.print()
    console.print(Panel(
        f"[bold]Target[/]  : [cyan]{target}[/]\n"
        f"[bold]Hunters[/] : [yellow]{hunter_list or 'all'}[/]\n"
        f"[bold]Exploit[/] : [green]{'yes' if not no_exploit else 'no'}[/]\n"
        f"[bold]LLM[/]     : [magenta]{settings.llm.provider} / {settings.llm.model or 'default'}[/]",
        title="[bold]Scan Configuration[/]",
        border_style="green",
    ))

    go = await asyncio.to_thread(
        questionary.confirm, "Start scan?", default=True
    ).unsafe_ask_async()
    if not go:
        return

    settings.exploit.enabled = not no_exploit
    await _run_scan_live(target, hunter_list, settings)


async def _interactive_hunter(settings: Settings):
    console.print(Rule("[bold yellow]Single Hunter[/]", style="yellow"))

    hunter_name = await asyncio.to_thread(
        questionary.select,
        "Select hunter:",
        choices=AVAILABLE_HUNTERS,
    ).unsafe_ask_async()
    if not hunter_name:
        return

    target = await asyncio.to_thread(
        questionary.text,
        "Target URL:",
        validate=lambda v: True if v.startswith("http") else "URL must start with http://",
    ).unsafe_ask_async()
    if not target:
        return

    param = await asyncio.to_thread(
        questionary.text, "Parameter name to inject:",
    ).unsafe_ask_async()
    if not param:
        return

    method = await asyncio.to_thread(
        questionary.select, "HTTP method:",
        choices=["GET", "POST", "PUT"],
    ).unsafe_ask_async()

    await _run_single_hunter(hunter_name, target, param, method.upper(), settings)


async def _interactive_model_select(settings: Settings):
    console.print(Rule("[bold magenta]LLM Provider & Model[/]", style="magenta"))
    console.print()
    console.print(_providers_table())
    console.print()

    provider = await asyncio.to_thread(
        questionary.select,
        "Choose LLM provider:",
        choices=[
            questionary.Choice(f"{info['label']}", value=key)
            for key, info in PROVIDERS.items()
        ],
    ).unsafe_ask_async()
    if not provider:
        return

    pinfo = PROVIDERS[provider]

    # Model selection
    if pinfo["models"]:
        console.print()
        model = await asyncio.to_thread(
            questionary.select,
            "Choose model:",
            choices=pinfo["models"],
        ).unsafe_ask_async()
    else:
        model = ""

    # Credentials
    console.print()
    if pinfo["auth"] == "api_key":
        existing = _env_read("XLAYER_LLM__API_KEY") or ""
        masked = f"{existing[:8]}..." if existing else "not set"
        console.print(f"  [dim]Current API key: {masked}[/]")
        console.print(f"  [dim]{pinfo['note']}[/]")
        console.print()
        change = await asyncio.to_thread(
            questionary.confirm,
            "Enter a new API key?",
            default=not bool(existing),
        ).unsafe_ask_async()
        if change:
            new_key = await asyncio.to_thread(
                questionary.password, "API key:"
            ).unsafe_ask_async()
            if new_key:
                _env_write("XLAYER_LLM__API_KEY", new_key)
                console.print("  [green]API key saved to .env[/]")

    elif pinfo["auth"] == "adc":
        console.print(f"  [dim]{pinfo['note']}[/]")
        console.print(f"  [dim]Run in terminal: [cyan]gcloud auth application-default login[/][/]")

    elif pinfo["auth"] == "oauth":
        console.print(f"  [dim]{pinfo['note']}[/]")
        client_id = await asyncio.to_thread(
            questionary.text, "OAuth client_id:"
        ).unsafe_ask_async()
        if client_id:
            _env_write("XLAYER_LLM__OPENAI_CLIENT_ID", client_id)

    # Write provider + model to .env
    _env_write("XLAYER_LLM__PROVIDER", provider)
    if model:
        _env_write("XLAYER_LLM__MODEL", model)

    console.print()
    console.print(Panel(
        f"[bold]Provider[/] : [cyan]{provider}[/]\n"
        f"[bold]Model[/]    : [cyan]{model or '(default)'}[/]\n"
        f"[bold]Saved[/]    : [green]{ENV_FILE}[/]",
        title="[green]LLM Updated[/]",
        border_style="green",
    ))

    # Offer to test
    test = await asyncio.to_thread(
        questionary.confirm, "Test LLM connection now?", default=True
    ).unsafe_ask_async()
    if test:
        # Reload settings with new values
        os.environ["XLAYER_LLM__PROVIDER"] = provider
        if model:
            os.environ["XLAYER_LLM__MODEL"] = model
        new_settings = Settings()
        await _do_test_llm(provider, model, "sqli")


async def _interactive_auth():
    console.print(Rule("[bold green]Authentication[/]", style="green"))

    provider = await asyncio.to_thread(
        questionary.select,
        "Login to which provider?",
        choices=[
            questionary.Choice("Google Gemini  (API key)",    value="gemini"),
            questionary.Choice("Google Gemini  (gcloud ADC)", value="gemini_adc"),
            questionary.Choice("OpenAI OAuth   (browser)",    value="openai_oauth"),
        ],
    ).unsafe_ask_async()
    if not provider:
        return

    console.print()

    if provider in ("gemini", "gemini_adc"):
        if provider == "gemini_adc":
            console.print(Panel(
                "[bold]gcloud Application Default Credentials[/]\n\n"
                "Run this in your terminal, then come back:\n\n"
                "  [bold cyan]gcloud auth application-default login[/]\n\n"
                "[dim]This opens your browser and stores credentials at:[/]\n"
                "[dim]~/.config/gcloud/application_default_credentials.json[/]",
                border_style="green", title="[bold]Google ADC Setup[/]"
            ))
            _env_write("XLAYER_LLM__PROVIDER", "gemini_adc")
            console.print("[green]Provider set to gemini_adc in .env[/]")
            return

        # API key flow
        console.print(Panel(
            "[bold]Gemini API Key[/]\n\n"
            "Get your free key at:\n"
            "  [bold cyan]https://aistudio.google.com/apikey[/]\n\n"
            "[dim]Free tier: gemini-2.0-flash — 15 requests/min, 1M tokens/day[/]",
            border_style="green", title="[bold]Gemini Login[/]"
        ))
        console.print()
        api_key = await asyncio.to_thread(
            questionary.password, "Paste your Gemini API key:"
        ).unsafe_ask_async()
        if not api_key:
            return

        # Test it
        with console.status("[cyan]Testing Gemini API key...[/]"):
            from xlayer_ai.llm.gemini_provider import GeminiProvider
            p = GeminiProvider(model="gemini-2.0-flash")
            ok = await p.initialize(api_key=api_key)

        if ok:
            # Smoke test
            with console.status("[cyan]Running smoke test...[/]"):
                try:
                    resp = await p.complete('Reply exactly: {"status":"ok"}')
                    smoke_ok = "ok" in resp.lower()
                except Exception:
                    smoke_ok = False

            if smoke_ok:
                _env_write("XLAYER_LLM__PROVIDER",  "gemini")
                _env_write("XLAYER_LLM__MODEL",      "gemini-2.0-flash")
                _env_write("XLAYER_LLM__API_KEY",    api_key)
                console.print(Panel(
                    "[bold green]Login successful![/]\n\n"
                    f"Provider : gemini\n"
                    f"Model    : gemini-2.0-flash\n"
                    f"Key      : {api_key[:8]}...\n"
                    f"Saved to : {ENV_FILE}",
                    border_style="green", title="[green]Gemini Connected[/]"
                ))
            else:
                console.print("[yellow]API key accepted but smoke test gave unexpected response.[/]")
                console.print("[yellow]Saving anyway. Try: xlayer-ai test-llm[/]")
                _env_write("XLAYER_LLM__PROVIDER", "gemini")
                _env_write("XLAYER_LLM__API_KEY", api_key)
        else:
            console.print("[red]API key is invalid.[/] Get a new key at https://aistudio.google.com/apikey")

    elif provider == "openai_oauth":
        existing_cid = _env_read("XLAYER_LLM__OPENAI_CLIENT_ID") or ""
        console.print(Panel(
            "[bold]OpenAI OAuth (ChatGPT/Codex subscription)[/]\n\n"
            "This flow opens your browser and logs you in with your OpenAI account.\n"
            "Requires a [bold]registered OAuth client_id[/] for XLayer AI.\n\n"
            "[dim]Tokens saved to: ~/.xlayer/auth/openai_token.json[/]",
            border_style="blue", title="[bold]OpenAI OAuth[/]"
        ))
        console.print()
        client_id = await asyncio.to_thread(
            questionary.text,
            "OAuth client_id:",
            default=existing_cid,
        ).unsafe_ask_async()
        if not client_id:
            return

        # Run PKCE flow
        console.print("\n[cyan]Opening browser for OpenAI login...[/]")
        from xlayer_ai.llm.openai_oauth import OpenAIOAuthProvider
        p = OpenAIOAuthProvider(client_id=client_id)
        ok = await p.initialize()

        if ok:
            _env_write("XLAYER_LLM__PROVIDER",          "openai_oauth")
            _env_write("XLAYER_LLM__OPENAI_CLIENT_ID",   client_id)
            _env_write("XLAYER_LLM__MODEL",               "gpt-4o-mini")
            console.print(Panel(
                "[bold green]Login successful![/]\n\n"
                "Tokens saved. Next login will be automatic.",
                border_style="blue", title="[green]OpenAI OAuth Connected[/]"
            ))
            await p.close()
        else:
            console.print("[red]OAuth login failed.[/]")


# ─── Report helper (Coordinator output → display-compatible object) ───────────

def _vulns_to_report(target: str, vulns: list):
    """Convert Coordinator List[Dict] output into a display-compatible report."""
    _CRITICAL = {"rce", "sqli", "xxe", "deserialization", "http_smuggling"}
    _HIGH = {"auth_bypass", "jwt_bypass", "jwt_crack", "ssrf", "lfi",
             "path_traversal", "xss_stored", "ssti"}
    _LOW = {"cors", "header_misconfig", "dev_comment_lead", "secret_verify"}

    def _sev(vuln_type: str) -> str:
        vt = vuln_type.lower()
        if any(k in vt for k in _CRITICAL): return "critical"
        if any(k in vt for k in _HIGH):     return "high"
        if any(k in vt for k in _LOW):      return "low"
        return "medium"

    class _Sev:
        def __init__(self, v): self.value = v

    class _Risk:
        def __init__(self, v): self.value = v

    class _Finding:
        def __init__(self, title, endpoint, sev):
            self.title    = title
            self.endpoint = endpoint
            self.severity = _Sev(sev)

    class _Stats:
        def __init__(self):
            self.total = self.critical = self.high = self.medium = self.low = 0

    class _Report:
        def __init__(self, findings, stats, risk):
            self.findings = findings
            self.stats    = stats
            self._risk    = risk
        @property
        def overall_risk(self): return _Risk(self._risk)

    stats    = _Stats()
    findings = []
    for v in vulns:
        sev = _sev(v.get("vuln_type", ""))
        stats.total += 1
        if sev == "critical": stats.critical += 1
        elif sev == "high":   stats.high += 1
        elif sev == "medium": stats.medium += 1
        else:                 stats.low += 1
        vt    = v.get("vuln_type", "unknown").replace("_", " ").title()
        param = v.get("parameter", "")
        findings.append(_Finding(
            title    = vt + (f" in {param}" if param else ""),
            endpoint = v.get("target_url", target),
            sev      = sev,
        ))

    risk = "secure"
    if stats.critical: risk = "critical"
    elif stats.high:   risk = "high"
    elif stats.medium: risk = "medium"
    elif stats.low:    risk = "low"
    return _Report(findings=findings, stats=stats, risk=risk)


# ─── Core Scan (with live display) ────────────────────────────────────────────

async def _run_scan_live(target: str, hunters: Optional[List[str]], settings: Settings):
    display = ScanLiveDisplay()
    display.start_capture()

    # Silence stderr loguru during rich live display
    logger.remove()
    logger.add(lambda m: None, level="TRACE")  # discard all to stderr during live
    display.start_capture()  # re-add rich sink

    console.print()
    start_time = time.monotonic()

    with Live(display.render(), console=console, refresh_per_second=8,
              vertical_overflow="visible") as live:

        async def _tick():
            while True:
                live.update(display.render())
                await asyncio.sleep(0.12)

        tick_task = asyncio.create_task(_tick())

        try:
            display.set_phase("RECON")
            coordinator = Coordinator(llm=LLMClient.from_settings())
            validated_vulns = await coordinator.run(target)
            report = _vulns_to_report(target, validated_vulns)
            display.set_phase("REPORT")
        except KeyboardInterrupt:
            tick_task.cancel()
            display.stop_capture()
            console.print("\n[yellow]Scan interrupted.[/]")
            return
        except Exception as e:
            tick_task.cancel()
            display.stop_capture()
            console.print(f"\n[red]Scan error: {e}[/]")
            return
        finally:
            tick_task.cancel()

    display.stop_capture()

    # Re-enable normal logger
    setup_logger("INFO")

    elapsed = time.monotonic() - start_time

    # Results table
    console.print()
    rt = Table(title="[bold]Scan Results[/]", box=box.ROUNDED, border_style="green")
    rt.add_column("Metric",  style="dim")
    rt.add_column("Value",   style="bold")
    rt.add_row("Target",          target)
    rt.add_row("Duration",        f"{elapsed:.1f}s")
    rt.add_row("Overall Risk",    f"[bold red]{report.overall_risk.value.upper()}[/]")
    rt.add_row("Total Findings",  str(report.stats.total))
    rt.add_row("  Critical",      f"[red]{report.stats.critical}[/]")
    rt.add_row("  High",          f"[orange1]{report.stats.high}[/]")
    rt.add_row("  Medium",        f"[yellow]{report.stats.medium}[/]")
    rt.add_row("  Low",           f"[green]{report.stats.low}[/]")
    rt.add_row("Reports saved",   settings.report.output_dir)
    console.print(rt)

    if report.findings:
        console.print()
        ft = Table(title="[bold]Findings[/]", box=box.SIMPLE, border_style="yellow")
        ft.add_column("Severity",  width=10)
        ft.add_column("Vulnerability")
        ft.add_column("Location")
        for f in report.findings[:10]:
            sev = f.severity.value.upper()
            sev_color = {"CRITICAL":"red","HIGH":"orange1","MEDIUM":"yellow","LOW":"green"}.get(sev,"white")
            ft.add_row(
                f"[{sev_color}]{sev}[/]",
                f.title,
                getattr(f, "endpoint", "")[:60],
            )
        console.print(ft)


# ─── Single Hunter ────────────────────────────────────────────────────────────

async def _run_single_hunter(hunter_name, target_url, param, method, settings):
    from urllib.parse import urlparse
    from xlayer_ai.models.target import AttackSurface, Endpoint, Parameter
    from xlayer_ai.tools.http_client import HTTPClient
    from xlayer_ai.tools.payload_manager import PayloadManager

    hunter_class = HUNTER_REGISTRY.get(hunter_name)
    if not hunter_class:
        console.print(f"[red]Unknown hunter: {hunter_name}[/]")
        return

    parsed   = urlparse(target_url)
    endpoint = Endpoint(
        url=target_url, method=method,
        parameters=[Parameter(name=param, value="test", param_type="query")]
    )
    surface = AttackSurface(
        base_url=f"{parsed.scheme}://{parsed.netloc}",
        endpoints=[endpoint],
    )

    llm_engine = None
    if settings.llm.is_enabled:
        try:
            from xlayer_ai.llm.engine import LLMEngine
            llm_engine = LLMEngine(settings=settings)
            await llm_engine.initialize()
            if not llm_engine.is_ready:
                llm_engine = None
        except Exception:
            pass

    http = HTTPClient(
        timeout=settings.scan.timeout,
        rate_limit=settings.scan.rate_limit,
        user_agent=settings.scan.user_agent,
        verify_ssl=settings.scan.verify_ssl,
    )

    display = ScanLiveDisplay()

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task(
            f"Running [bold yellow]{hunter_name}[/] on [cyan]{target_url}[/]...",
            total=None,
        )
        try:
            await http.start()
            display.start_capture()
            hunter = hunter_class(
                http_client=http,
                payload_manager=PayloadManager(),
                settings=settings,
                llm_engine=llm_engine,
            )
            result = await hunter.hunt(surface)
        finally:
            display.stop_capture()
            await http.close()
            if llm_engine:
                await llm_engine.close()

    # Display results
    console.print()
    st = Table(box=box.ROUNDED, border_style="yellow",
               title=f"[bold]{hunter_name.upper()} Results[/]")
    st.add_column("Metric",  style="dim")
    st.add_column("Value",   style="bold")
    st.add_row("Endpoints tested",  str(result.endpoints_tested))
    st.add_row("Payloads sent",     str(result.payloads_sent))
    st.add_row("Findings",          str(result.findings_count))
    st.add_row("Duration",          f"{result.duration_seconds:.1f}s")
    console.print(st)

    if result.hypotheses:
        console.print()
        ft = Table(box=box.SIMPLE, border_style="red", title="[bold]Findings[/]")
        ft.add_column("Confidence", width=10)
        ft.add_column("Vuln Type")
        ft.add_column("Param")
        ft.add_column("Evidence")
        for h in result.hypotheses:
            conf  = h.confidence.value if hasattr(h.confidence, "value") else str(h.confidence)
            vtype = h.vuln_type.value  if hasattr(h.vuln_type,  "value") else str(h.vuln_type)
            evid  = (h.indicators[0].detail if h.indicators else "")[:60]
            conf_color = {"high":"red","medium":"yellow","low":"green"}.get(conf.lower(),"white")
            ft.add_row(f"[{conf_color}]{conf.upper()}[/]", vtype, h.parameter, evid)
        console.print(ft)

        # Payloads
        for h in result.hypotheses[:3]:
            if getattr(h, "suggested_payloads", []):
                console.print()
                console.print(Panel(
                    "\n".join(h.suggested_payloads[:5]),
                    title=f"[yellow]Suggested Payloads — {h.parameter}[/]",
                    border_style="yellow",
                ))
    else:
        console.print(Panel(
            "[green]No vulnerabilities found.[/]",
            border_style="green",
        ))


# ─── test-llm ─────────────────────────────────────────────────────────────────

async def _do_test_llm(provider: Optional[str], model: Optional[str], vuln_type: str):
    settings = get_settings()
    if provider:
        settings.llm.provider = provider
    if model:
        settings.llm.model = model

    console.print()
    console.print(Panel(
        f"Provider : [cyan]{settings.llm.provider}[/]\n"
        f"Model    : [cyan]{settings.llm.model or '(default)'}[/]",
        title="[bold]Testing LLM[/]", border_style="magenta",
    ))

    valid, vm = settings.llm.validate_config()
    if not valid:
        console.print(f"[red]Config invalid: {vm}[/]")
        console.print("[dim]Run: xlayer-ai auth login gemini[/]")
        return

    with console.status("[cyan]Initializing LLM...[/]"):
        try:
            from xlayer_ai.llm.engine import LLMEngine
            from xlayer_ai.llm.payload_generator import AIPayloadGenerator, AttackContext

            engine = LLMEngine(settings=settings)
            await engine.initialize()
        except Exception as e:
            console.print(f"[red]Init error: {e}[/]")
            return

    if not engine.is_ready:
        console.print("[red]LLM not ready — check auth[/]")
        return

    console.print("[green]LLM initialized[/]")

    # Test 1: raw
    with console.status("[cyan]Test 1: raw completion...[/]"):
        try:
            raw = await engine._complete('Reply exactly: {"status":"ok","provider":"working"}')
            console.print(Panel(raw.strip()[:200], title="[dim]Raw completion[/]", border_style="dim"))
        except Exception as e:
            console.print(f"[red]Raw completion failed: {e}[/]")
            return

    # Test 2: payload generation
    with console.status(f"[cyan]Test 2: generating {vuln_type} payloads...[/]"):
        try:
            gen = AIPayloadGenerator(engine)
            ctx = AttackContext(
                url="https://test.example.com/search",
                parameter="q",
                method="GET",
                vuln_type=vuln_type,
                server="nginx",
                language="php",
                framework="laravel",
                database="mysql",
            )
            payloads = await gen.generate(ctx)
        except Exception as e:
            console.print(f"[red]Payload generation failed: {e}[/]")
            payloads = []

    if payloads:
        pt = Table(
            title=f"[bold]Generated {vuln_type.upper()} Payloads[/]",
            box=box.SIMPLE, border_style="magenta",
        )
        pt.add_column("#",       style="dim", width=4)
        pt.add_column("Payload", style="cyan")
        for i, p in enumerate(payloads[:8], 1):
            pt.add_row(str(i), p[:100])
        console.print(pt)
        console.print(f"\n[green]LLM is fully working![/] Generated {len(payloads)} payloads.")
    else:
        console.print("[yellow]No payloads generated — but LLM connection works.[/]")

    await engine.close()


# ─── Config display ───────────────────────────────────────────────────────────

def _show_config(settings: Optional[Settings] = None):
    settings = settings or get_settings()

    console.print()
    t = Table(box=box.ROUNDED, border_style="dim", title="[bold]Configuration[/]")
    t.add_column("Setting",  style="dim", width=22)
    t.add_column("Value")

    valid, vm = settings.llm.validate_config()
    t.add_row("llm.provider",       f"[cyan]{settings.llm.provider}[/]")
    t.add_row("llm.model",          settings.llm.model or "(default)")
    t.add_row("llm.api_key",        "[green]set[/]" if settings.llm.api_key else "[red]not set[/]")
    t.add_row("llm.status",         f"[green]OK[/] {vm}" if valid else f"[red]ERR[/] {vm}")
    t.add_row("", "")
    t.add_row("scan.timeout",       f"{settings.scan.timeout}s")
    t.add_row("scan.rate_limit",    f"{settings.scan.rate_limit}s")
    t.add_row("scan.max_depth",     str(settings.scan.max_depth))
    t.add_row("scan.verify_ssl",    str(settings.scan.verify_ssl))
    t.add_row("", "")
    t.add_row("exploit.enabled",    str(settings.exploit.enabled))
    t.add_row("report.output_dir",  settings.report.output_dir)
    t.add_row("report.formats",     ", ".join(settings.report.formats))
    t.add_row("", "")
    t.add_row("hunters",            f"{len(settings.hunters)} enabled")
    t.add_row(".env file",          str(ENV_FILE))

    console.print(t)
    console.print()
    console.print("[dim]To change settings: edit .env or run 'xlayer-ai' interactive mode[/]")


def _show_hunters():
    console.print()
    t = Table(
        title=f"[bold]Available Hunters ({len(AVAILABLE_HUNTERS)})[/]",
        box=box.ROUNDED, border_style="dim",
    )
    t.add_column("Hunter",      style="bold yellow", width=22)
    t.add_column("Type",        style="dim",          width=10)
    t.add_column("Description")

    HUNTER_META = {
        "sqli":               ("injection",  "Error, boolean, time-based, union — MySQL/PG/MSSQL/Oracle"),
        "xss":                ("injection",  "Reflected, DOM, stored — 15+ context variants"),
        "auth":               ("auth",       "Auth bypass, IDOR, weak creds, JWT, session fixation"),
        "ssrf":               ("server",     "Internal net, cloud metadata, file://, blind OOB"),
        "lfi":                ("traversal",  "Path traversal, PHP wrappers, log poisoning"),
        "ssti":               ("injection",  "Jinja2, Twig, Freemarker, ERB, Velocity, Mako, SpEL"),
        "rce":                ("execution",  "Command injection, time-based, output-based, OOB"),
        "xxe":                ("xml",        "File read, SSRF, OOB, XInclude, PHP filter"),
        "open_redirect":      ("redirect",   "18 bypass variants — encoded, @-trick, Unicode"),
        "cors":               ("header",     "Origin reflection, null, wildcard+credentials"),
        "csrf":               ("logic",      "Missing token, SameSite absent, referrer bypass"),
        "subdomain_takeover": ("dns",        "Dangling CNAME -> S3, GitHub Pages, Heroku"),
        "graphql":            ("api",        "Introspection, batch, depth bypass, injection"),
        "race_condition":     ("logic",      "15 parallel requests, double-spend detection"),
        "deserialization":    ("injection",  "Java, PHP, Python pickle, .NET magic bytes + time"),
        "http_smuggling":     ("protocol",   "CL.TE, TE.CL, timeout-based detection"),
    }

    for h in AVAILABLE_HUNTERS:
        meta = HUNTER_META.get(h, ("other", ""))
        t.add_row(h, meta[0], meta[1])

    console.print(t)
    console.print()
    console.print("[dim]Usage: xlayer-ai hunter <name> <url> --param <param>[/]")


# ─── Click CLI ────────────────────────────────────────────────────────────────

@click.group(invoke_without_command=True)
@click.option("--debug",  is_flag=True, help="Enable debug logging")
@click.option("--quiet",  is_flag=True, help="Suppress banner in interactive mode")
@click.pass_context
def cli(ctx, debug: bool, quiet: bool):
    """XLayer AI — Autonomous Web Vulnerability Hunter

    Run without arguments for interactive mode.
    """
    ctx.ensure_object(dict)
    ctx.obj["debug"] = debug

    setup_logger("DEBUG" if debug else "WARNING")  # suppress during rich TUI

    if ctx.invoked_subcommand is None:
        # Interactive mode
        if not quiet:
            pass  # banner shown inside _interactive_main
        asyncio.run(_interactive_main())


# ── scan ──────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("target_url")
@click.option("--hunters",    "-h", default=None,  help="Hunters: sqli,xss,... or 'all'")
@click.option("--depth",      "-d", default=3,     type=int)
@click.option("--output",     "-o", default="./reports")
@click.option("--format",     "-f", default="json,html")
@click.option("--no-exploit",       is_flag=True)
@click.option("--no-port-scan",     is_flag=True)
@click.option("--timeout",          default=30, type=int)
@click.option("--rate-limit",       default=0.5, type=float)
@click.option("--llm-provider",     default=None,
              help="openai | gemini | gemini_adc | openai_oauth | ollama | none")
@click.option("--llm-model",        default=None)
@click.pass_context
def scan(ctx, target_url, hunters, depth, output, format,
         no_exploit, no_port_scan, timeout, rate_limit, llm_provider, llm_model):
    """Scan a target URL for vulnerabilities."""
    is_valid, error = validate_url(target_url)
    if not is_valid:
        console.print(f"[red]Invalid URL: {error}[/]")
        sys.exit(1)

    settings = get_settings()
    if llm_provider: settings.llm.provider  = llm_provider
    if llm_model:    settings.llm.model     = llm_model
    settings.scan.max_depth       = depth
    settings.scan.timeout         = timeout
    settings.scan.rate_limit      = rate_limit
    settings.report.output_dir    = output
    settings.report.formats       = format.split(",")
    settings.exploit.enabled      = not no_exploit
    settings.port_scan.enabled    = not no_port_scan

    hunter_list = None
    if hunters:
        hunter_list = [h.strip() for h in hunters.split(",")]
        if "all" in [h.lower() for h in hunter_list]:
            hunter_list = None

    _banner()
    asyncio.run(_run_scan_live(target_url, hunter_list, settings))


# ── hunter ────────────────────────────────────────────────────────────────────

@cli.command("hunter")
@click.argument("hunter_name", metavar="HUNTER",
                type=click.Choice(AVAILABLE_HUNTERS, case_sensitive=False))
@click.argument("target_url")
@click.option("--param",  "-p", required=True)
@click.option("--method", "-m", default="GET",
              type=click.Choice(["GET","POST","PUT"], case_sensitive=False))
@click.option("--llm-provider", default=None)
@click.pass_context
def run_hunter_cmd(ctx, hunter_name, target_url, param, method, llm_provider):
    """Run ONE hunter on a single endpoint/parameter.

    \b
    Examples:
      xlayer-ai hunter sqli  https://site.com/search --param q
      xlayer-ai hunter xss   https://site.com/page   --param name
      xlayer-ai hunter ssti  https://site.com/render --param template
    """
    is_valid, error = validate_url(target_url)
    if not is_valid:
        console.print(f"[red]{error}[/]")
        sys.exit(1)

    settings = get_settings()
    if llm_provider:
        settings.llm.provider = llm_provider

    asyncio.run(_run_single_hunter(hunter_name, target_url, param, method.upper(), settings))


# ── auth group ────────────────────────────────────────────────────────────────

@cli.group()
def auth():
    """Manage LLM provider authentication."""
    pass


@auth.command("login")
@click.argument("provider",
                type=click.Choice(["gemini","gemini_adc","openai-oauth"], case_sensitive=False))
@click.option("--api-key",    default=None, envvar="GEMINI_API_KEY")
@click.option("--client-id",  default=None, envvar="XLAYER_LLM__OPENAI_CLIENT_ID")
@click.option("--model",      default=None)
def auth_login(provider, api_key, client_id, model):
    """Authenticate with an LLM provider.

    \b
    Examples:
      xlayer-ai auth login gemini                          (prompts for API key)
      xlayer-ai auth login gemini --api-key AIza...
      xlayer-ai auth login gemini_adc                     (gcloud ADC instructions)
      xlayer-ai auth login openai-oauth --client-id <id>
    """
    async def _run():
        settings = get_settings()
        if provider == "gemini_adc":
            console.print(Panel(
                "[bold]gcloud ADC Setup[/]\n\n"
                "Run: [bold cyan]gcloud auth application-default login[/]\n\n"
                "[dim]Browser opens -> sign in with Google -> done[/]",
                border_style="green",
            ))
            _env_write("XLAYER_LLM__PROVIDER", "gemini_adc")
            return

        if provider == "gemini":
            key = api_key or Prompt.ask("[cyan]Gemini API key[/]", password=True, console=console)
            if not key:
                return
            with console.status("[cyan]Testing...[/]"):
                from xlayer_ai.llm.gemini_provider import GeminiProvider
                p = GeminiProvider(model=model or "gemini-2.0-flash")
                ok = await p.initialize(api_key=key)
            if ok:
                try:
                    resp = await p.complete('Reply: {"status":"ok"}')
                    smoke = "ok" in resp.lower()
                except Exception:
                    smoke = False

                _env_write("XLAYER_LLM__PROVIDER", "gemini")
                _env_write("XLAYER_LLM__API_KEY",  key)
                if model: _env_write("XLAYER_LLM__MODEL", model)
                icon = "[green][OK][/]" if smoke else "[yellow][WARN][/]"
                console.print(f"{icon} Gemini connected. .env updated.")
            else:
                console.print("[red]Invalid API key.[/] https://aistudio.google.com/apikey")

        elif provider == "openai-oauth":
            if not client_id:
                console.print("[red]--client-id required[/]")
                return
            from xlayer_ai.llm.openai_oauth import OpenAIOAuthProvider
            p = OpenAIOAuthProvider(client_id=client_id, model=model or "gpt-4o-mini")
            ok = await p.initialize()
            if ok:
                _env_write("XLAYER_LLM__PROVIDER",        "openai_oauth")
                _env_write("XLAYER_LLM__OPENAI_CLIENT_ID", client_id)
                console.print("[green][OK] OpenAI OAuth connected.[/]")
                await p.close()
            else:
                console.print("[red]OAuth login failed.[/]")

    asyncio.run(_run())


@auth.command("status")
def auth_status():
    """Show authentication status for all LLM providers."""
    import time as _time
    settings = get_settings()
    console.print()

    t = Table(title="[bold]LLM Auth Status[/]", box=box.ROUNDED, border_style="dim")
    t.add_column("Provider",  style="bold",  width=16)
    t.add_column("Status",    width=14)
    t.add_column("Details")

    # Active provider
    valid, vm = settings.llm.validate_config()
    t.add_row(
        f"[cyan]{settings.llm.provider}[/]  [dim](active)[/]",
        "[green]OK[/]" if valid else "[red]not ready[/]",
        vm,
    )

    # Gemini ADC
    try:
        import google.auth
        creds, project = google.auth.default(
            scopes=["https://www.googleapis.com/auth/generative-language"]
        )
        t.add_row("gemini_adc", "[green]available[/]", f"project={project or 'N/A'}")
    except Exception:
        t.add_row("gemini_adc", "[red]not configured[/]", "run: gcloud auth application-default login")

    # Gemini API key
    key = os.getenv("GEMINI_API_KEY") or _env_read("XLAYER_LLM__API_KEY")
    if key:
        t.add_row("gemini", "[green]key set[/]", f"{key[:8]}...")
    else:
        t.add_row("gemini", "[red]no key[/]", "aistudio.google.com/apikey")

    # OpenAI OAuth
    from xlayer_ai.llm.openai_oauth import TOKEN_PATH
    if TOKEN_PATH.exists():
        try:
            tok = json.loads(TOKEN_PATH.read_text())
            remaining = tok.get("expires_at", 0) - _time.time()
            if remaining > 0:
                t.add_row("openai_oauth", "[green]tokens valid[/]", f"expires in {int(remaining//60)} min")
            else:
                t.add_row("openai_oauth", "[red]expired[/]", "re-run: auth login openai-oauth")
        except Exception:
            t.add_row("openai_oauth", "[red]corrupt[/]", "re-login required")
    else:
        t.add_row("openai_oauth", "[dim]not logged in[/]", "auth login openai-oauth --client-id <id>")

    # OpenAI API key
    oai = os.getenv("OPENAI_API_KEY")
    t.add_row("openai", "[green]key set[/]" if oai else "[dim]no key[/]",
              f"{oai[:8]}..." if oai else "set OPENAI_API_KEY")

    console.print(t)


@auth.command("logout")
@click.argument("provider", type=click.Choice(["openai-oauth"], case_sensitive=False))
def auth_logout(provider):
    """Clear stored auth tokens."""
    from xlayer_ai.llm.openai_oauth import TOKEN_PATH
    if TOKEN_PATH.exists():
        TOKEN_PATH.unlink()
        console.print(f"[green]Removed {TOKEN_PATH}[/]")
    else:
        console.print("[dim]No tokens found.[/]")


# ── test-llm ──────────────────────────────────────────────────────────────────

@cli.command("test-llm")
@click.option("--provider",  default=None)
@click.option("--model",     default=None)
@click.option("--vuln-type", "vuln_type", default="sqli",
              type=click.Choice(["sqli","xss","ssrf","lfi","ssti","rce","xxe","open_redirect"],
                                case_sensitive=False))
def test_llm_cmd(provider, model, vuln_type):
    """Test LLM connection and generate sample payloads."""
    asyncio.run(_do_test_llm(provider, model, vuln_type))


# ── config ────────────────────────────────────────────────────────────────────

@cli.command("config")
@click.option("--show", is_flag=True, help="Show full configuration")
def config_cmd(show):
    """View XLayer AI configuration."""
    _show_config()


# ── hunters list ──────────────────────────────────────────────────────────────

@cli.command("hunters")
def hunters_cmd():
    """List all 16 available hunters."""
    _show_hunters()


# ── version ───────────────────────────────────────────────────────────────────

@cli.command("version")
def version_cmd():
    """Show version information."""
    settings = get_settings()
    valid, vm = settings.llm.validate_config()
    console.print(Panel(
        f"[bold red]XLayer AI[/] v{VERSION}\n\n"
        f"Hunters  : [yellow]{len(AVAILABLE_HUNTERS)}[/]\n"
        f"LLM      : [cyan]{settings.llm.provider}[/] / {settings.llm.model or 'default'}\n"
        f"Status   : {'[green]ready[/]' if valid else '[red]not configured[/]'}\n\n"
        f"[dim]'NO EXPLOIT = NO REPORT'[/]",
        border_style="red",
    ))


# ─── Entry ────────────────────────────────────────────────────────────────────

def main():
    cli(obj={})


if __name__ == "__main__":
    main()
