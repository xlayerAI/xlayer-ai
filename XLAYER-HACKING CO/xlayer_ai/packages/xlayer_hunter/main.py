"""
XLayer AI - Autonomous Web Vulnerability Hunter

Main CLI entry point.

Usage:
    python -m xlayer_ai scan https://target.com
    python -m xlayer_ai scan https://target.com --hunters sqli,xss
    python -m xlayer_ai config --show
"""

import asyncio
import sys
from typing import Optional, List

import click
from loguru import logger

from xlayer_hunter.core.planner import PlannerAgent
from xlayer_hunter.config.settings import Settings, get_settings
from xlayer_hunter.utils.logger import setup_logger
from xlayer_hunter.utils.validators import validate_url


BANNER = r"""
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   ██╗  ██╗██╗      █████╗ ██╗   ██╗███████╗██████╗            ║
║   ╚██╗██╔╝██║     ██╔══██╗╚██╗ ██╔╝██╔════╝██╔══██╗           ║
║    ╚███╔╝ ██║     ███████║ ╚████╔╝ █████╗  ██████╔╝           ║
║    ██╔██╗ ██║     ██╔══██║  ╚██╔╝  ██╔══╝  ██╔══██╗           ║
║   ██╔╝ ██╗███████╗██║  ██║   ██║   ███████╗██║  ██║           ║
║   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝           ║
║                                                               ║
║           Autonomous Web Vulnerability Hunter                 ║
║       "Hack before hackers hack — Prove before you report"    ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
"""


@click.group()
@click.option('--debug', is_flag=True, help='Enable debug mode')
@click.option('--quiet', is_flag=True, help='Suppress banner and verbose output')
@click.pass_context
def cli(ctx, debug: bool, quiet: bool):
    """XLayer AI - Autonomous Web Vulnerability Hunter"""
    ctx.ensure_object(dict)
    ctx.obj['debug'] = debug
    ctx.obj['quiet'] = quiet
    
    log_level = "DEBUG" if debug else "INFO"
    setup_logger(level=log_level)
    
    if not quiet:
        click.echo(BANNER)


@cli.command()
@click.argument('target_url')
@click.option(
    '--hunters', '-h',
    default=None,
    help='Comma-separated list of hunters to use (sqli,xss,auth,ssrf,lfi)'
)
@click.option(
    '--depth', '-d',
    default=3,
    type=int,
    help='Maximum crawl depth (default: 3)'
)
@click.option(
    '--output', '-o',
    default='./reports',
    help='Output directory for reports (default: ./reports)'
)
@click.option(
    '--format', '-f',
    default='json,html',
    help='Report formats: json,html,pdf (default: json,html)'
)
@click.option(
    '--no-exploit',
    is_flag=True,
    help='Skip exploitation phase (hypothesis only)'
)
@click.option(
    '--no-port-scan',
    is_flag=True,
    help='Skip port scanning'
)
@click.option(
    '--timeout',
    default=30,
    type=int,
    help='Request timeout in seconds (default: 30)'
)
@click.option(
    '--rate-limit',
    default=0.5,
    type=float,
    help='Delay between requests in seconds (default: 0.5)'
)
@click.pass_context
def scan(
    ctx,
    target_url: str,
    hunters: Optional[str],
    depth: int,
    output: str,
    format: str,
    no_exploit: bool,
    no_port_scan: bool,
    timeout: int,
    rate_limit: float
):
    """
    Scan a target URL for vulnerabilities.
    
    Example:
        xlayer-ai scan https://example.com
        xlayer-ai scan https://example.com --hunters sqli,xss --depth 2
    """
    is_valid, error = validate_url(target_url)
    if not is_valid:
        click.echo(f"Error: {error}", err=True)
        sys.exit(1)
    
    settings = get_settings()
    
    settings.scan.max_depth = depth
    settings.scan.timeout = timeout
    settings.scan.rate_limit = rate_limit
    settings.report.output_dir = output
    settings.report.formats = format.split(',')
    settings.exploit.enabled = not no_exploit
    settings.port_scan.enabled = not no_port_scan
    
    hunter_list = None
    if hunters:
        hunter_list = [h.strip() for h in hunters.split(',')]
        valid_hunters = ['sqli', 'xss', 'auth', 'ssrf', 'lfi']
        for h in hunter_list:
            if h not in valid_hunters:
                click.echo(f"Warning: Unknown hunter '{h}', skipping", err=True)
        hunter_list = [h for h in hunter_list if h in valid_hunters]
    
    click.echo(f"\nTarget: {target_url}")
    click.echo(f"Hunters: {hunter_list or settings.hunters}")
    click.echo(f"Output: {output}")
    click.echo("")
    
    asyncio.run(_run_scan(target_url, hunter_list, settings))


async def _run_scan(
    target_url: str,
    hunters: Optional[List[str]],
    settings: Settings
):
    """Run the vulnerability scan"""
    try:
        async with PlannerAgent(settings=settings) as planner:
            report = await planner.start_mission(target_url, hunters=hunters)
        
        click.echo("\n" + "=" * 60)
        click.echo("SCAN COMPLETE")
        click.echo("=" * 60)
        click.echo(f"Overall Risk: {report.overall_risk.value.upper()}")
        click.echo(f"Total Findings: {report.stats.total}")
        click.echo(f"  - Critical: {report.stats.critical}")
        click.echo(f"  - High: {report.stats.high}")
        click.echo(f"  - Medium: {report.stats.medium}")
        click.echo(f"  - Low: {report.stats.low}")
        click.echo(f"\nReports saved to: {settings.report.output_dir}")
        
        if report.stats.total > 0:
            click.echo("\nTop Findings:")
            for finding in report.findings[:5]:
                click.echo(f"  [{finding.severity.value.upper()}] {finding.title}")
        
    except KeyboardInterrupt:
        click.echo("\nScan interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.exception("Scan failed")
        click.echo(f"\nError: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option('--show', is_flag=True, help='Show current configuration')
@click.option('--set', 'set_value', multiple=True, help='Set configuration value (key=value)')
@click.pass_context
def config(ctx, show: bool, set_value: tuple):
    """
    View or modify XLayer AI configuration.
    
    Example:
        xlayer-ai config --show
        xlayer-ai config --set llm.provider=openai
    """
    settings = get_settings()
    
    if show:
        click.echo("\nCurrent Configuration:")
        click.echo("-" * 40)
        click.echo(f"Debug: {settings.debug}")
        click.echo(f"Verbose: {settings.verbose}")
        click.echo(f"\nLLM Settings:")
        click.echo(f"  Provider: {settings.llm.provider}")
        click.echo(f"  Model: {settings.llm.model}")
        click.echo(f"  API Key: {'***' if settings.llm.api_key else 'Not set'}")
        click.echo(f"\nScan Settings:")
        click.echo(f"  Max Depth: {settings.scan.max_depth}")
        click.echo(f"  Max Pages: {settings.scan.max_pages}")
        click.echo(f"  Timeout: {settings.scan.timeout}s")
        click.echo(f"  Rate Limit: {settings.scan.rate_limit}s")
        click.echo(f"\nPort Scan Settings:")
        click.echo(f"  Enabled: {settings.port_scan.enabled}")
        click.echo(f"  Top Ports: {settings.port_scan.top_ports}")
        click.echo(f"\nExploit Settings:")
        click.echo(f"  Enabled: {settings.exploit.enabled}")
        click.echo(f"  Screenshot: {settings.exploit.screenshot}")
        click.echo(f"\nReport Settings:")
        click.echo(f"  Output Dir: {settings.report.output_dir}")
        click.echo(f"  Formats: {settings.report.formats}")
        click.echo(f"\nEnabled Hunters: {settings.hunters}")
    
    if set_value:
        click.echo("\nConfiguration changes require editing .env file or environment variables.")
        click.echo("Example: XLAYER_LLM__PROVIDER=openai")
        for kv in set_value:
            if '=' in kv:
                key, value = kv.split('=', 1)
                env_key = f"XLAYER_{key.upper().replace('.', '__')}"
                click.echo(f"  Set: {env_key}={value}")


@cli.command()
@click.pass_context
def version(ctx):
    """Show XLayer AI version information."""
    from xlayer_ai import __version__
    
    click.echo(f"\nXLayer AI v{__version__}")
    click.echo("Autonomous Web Vulnerability Hunter")
    click.echo("\nComponents:")
    click.echo("  - Planner Agent (Mission Orchestration)")
    click.echo("  - Recon Agent (Attack Surface Mapping)")
    click.echo("  - Vulnerability Hunters (SQLi, XSS, Auth, SSRF, LFI)")
    click.echo("  - Exploit Agent (Proof Validation)")
    click.echo("  - Reporter (Professional Reports)")
    click.echo("\nPhilosophy: 'NO EXPLOIT = NO REPORT'")


@cli.command()
@click.pass_context
def hunters(ctx):
    """List available vulnerability hunters."""
    click.echo("\nAvailable Vulnerability Hunters:")
    click.echo("-" * 40)
    
    hunter_info = {
        "sqli": {
            "name": "SQL Injection Hunter",
            "detects": ["Error-based SQLi", "Boolean-based blind", "Time-based blind", "Union-based"],
            "databases": ["MySQL", "PostgreSQL", "MSSQL", "Oracle", "SQLite"]
        },
        "xss": {
            "name": "Cross-Site Scripting Hunter",
            "detects": ["Reflected XSS", "DOM-based XSS", "Stored XSS indicators"],
            "contexts": ["HTML body", "Attributes", "JavaScript", "URL"]
        },
        "auth": {
            "name": "Authentication Hunter",
            "detects": ["Auth bypass", "IDOR", "Session issues", "JWT vulnerabilities"],
            "methods": ["SQL injection in login", "Parameter tampering", "Session manipulation"]
        },
        "ssrf": {
            "name": "SSRF Hunter",
            "detects": ["Internal network access", "Cloud metadata exposure", "File protocol abuse"],
            "targets": ["AWS metadata", "GCP metadata", "Azure metadata", "Internal services"]
        },
        "lfi": {
            "name": "File Inclusion Hunter",
            "detects": ["Local File Inclusion", "Path Traversal", "PHP wrapper abuse"],
            "files": ["/etc/passwd", "Windows hosts", "Config files", "Source code"]
        }
    }
    
    for hunter_id, info in hunter_info.items():
        click.echo(f"\n[{hunter_id}] {info['name']}")
        click.echo(f"  Detects: {', '.join(info['detects'])}")
        if 'databases' in info:
            click.echo(f"  Databases: {', '.join(info['databases'])}")
        if 'contexts' in info:
            click.echo(f"  Contexts: {', '.join(info['contexts'])}")
        if 'methods' in info:
            click.echo(f"  Methods: {', '.join(info['methods'])}")
        if 'targets' in info:
            click.echo(f"  Targets: {', '.join(info['targets'])}")
        if 'files' in info:
            click.echo(f"  Files: {', '.join(info['files'])}")


def main():
    """Main entry point"""
    cli(obj={})


if __name__ == "__main__":
    main()
