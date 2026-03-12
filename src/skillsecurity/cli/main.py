"""CLI entry point for SkillSecurity."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import click

from skillsecurity import PolicyLoadError, SkillGuard
from skillsecurity.cli.formatter import DecisionFormatter
from skillsecurity.cli.prompter import AskPrompter
from skillsecurity.config.defaults import BUILTIN_POLICIES_DIR


@click.group()
@click.option("--policy", "-p", default=None, help="Policy template name or file path")
@click.option(
    "--format",
    "-f",
    "output_format",
    default="human",
    type=click.Choice(["human", "json"]),
    help="Output format",
)
@click.option("--verbose", "-v", is_flag=True, help="Show detailed info including allow decisions")
@click.option("--no-color", is_flag=True, help="Disable colored output")
@click.option("--no-emoji", is_flag=True, help="Disable emoji in output")
@click.option("--lang", default="en", type=click.Choice(["en", "zh"]), help="Output language")
@click.option("--config", "-c", default=None, help="Configuration file path")
@click.pass_context
def cli(
    ctx: click.Context,
    policy: str | None,
    output_format: str,
    verbose: bool,
    no_color: bool,
    no_emoji: bool,
    lang: str,
    config: str | None,
) -> None:
    """SkillSecurity — AI Agent tool call security protection."""
    ctx.ensure_object(dict)
    ctx.obj["policy"] = policy
    ctx.obj["format"] = output_format
    ctx.obj["verbose"] = verbose
    ctx.obj["formatter"] = DecisionFormatter(
        use_color=not no_color and sys.stderr.isatty(),
        use_emoji=not no_emoji,
        lang=lang,
    )
    ctx.obj["config"] = config


def _make_guard(ctx: click.Context) -> SkillGuard:
    policy = ctx.obj.get("policy")
    config_path = ctx.obj.get("config")

    if config_path:
        return SkillGuard(policy_file=config_path)
    if policy:
        policy_path = Path(policy)
        if policy_path.exists():
            return SkillGuard(policy_file=str(policy_path))
        return SkillGuard(policy=policy)
    return SkillGuard()


@cli.command()
@click.option("--tool", "-t", required=False, help="Tool type (shell, file.read, file.write, etc.)")
@click.option("--command", required=False, help="Command string (for shell tool)")
@click.option("--path", required=False, help="File path (for file tools)")
@click.option("--url", required=False, help="URL (for network tools)")
@click.option("--json-input", "--json", "json_mode", is_flag=True, help="Read JSON from stdin")
@click.pass_context
def check(
    ctx: click.Context,
    tool: str | None,
    command: str | None,
    path: str | None,
    url: str | None,
    json_mode: bool,
) -> None:
    """Check a tool call against security policies."""
    formatter: DecisionFormatter = ctx.obj["formatter"]
    output_format: str = ctx.obj["format"]

    if json_mode:
        raw = sys.stdin.read()
        try:
            tool_call = json.loads(raw)
        except json.JSONDecodeError as e:
            click.echo(f"Invalid JSON input: {e}", err=True)
            ctx.exit(3)
            return
    else:
        if not tool:
            click.echo("Error: --tool is required (or use --json for JSON input)", err=True)
            ctx.exit(3)
            return
        tool_call: dict[str, Any] = {"tool": tool}
        if command:
            tool_call["command"] = command
        if path:
            tool_call["path"] = path
        if url:
            tool_call["url"] = url

    try:
        guard = _make_guard(ctx)
        decision = guard.check(tool_call)
    except PolicyLoadError as e:
        click.echo(f"Policy error: {e}", err=True)
        ctx.exit(3)
        return
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        ctx.exit(3)
        return

    if output_format == "json":
        click.echo(formatter.format_json(decision))
    else:
        click.echo(formatter.format_human(decision, tool_call), err=True)
        if output_format == "human":
            click.echo(json.dumps(decision.to_dict(), ensure_ascii=False))

    if decision.is_blocked:
        ctx.exit(1)
    elif decision.needs_confirmation:
        prompter = AskPrompter()
        if sys.stdin.isatty():
            allowed = prompter.prompt(
                message=f"Risk: {decision.severity.value} — {decision.reason}",
                severity=decision.severity.value,
            )
            ctx.exit(0 if allowed else 1)
        else:
            ctx.exit(2)
    else:
        ctx.exit(0)


@cli.command()
@click.option(
    "--template",
    default="default",
    type=click.Choice(["default", "strict", "development"]),
    help="Policy template to use",
)
@click.option("--output", "-o", default="./skillsecurity.yaml", help="Output file path")
def init(template: str, output: str) -> None:
    """Initialize a new security policy configuration file."""
    source = BUILTIN_POLICIES_DIR / f"{template}.yaml"
    if not source.exists():
        click.echo(f"Template '{template}' not found", err=True)
        raise SystemExit(3)

    dest = Path(output)
    if dest.exists():
        click.echo(f"File already exists: {dest}", err=True)
        raise SystemExit(3)

    dest.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
    click.echo(f"Created {dest} from '{template}' template")


@cli.command()
@click.argument("manifest_path", type=click.Path(exists=True))
@click.pass_context
def register(ctx: click.Context, manifest_path: str) -> None:
    """Register a Skill permission manifest."""
    from skillsecurity.manifest.parser import ManifestParser, ManifestValidationError

    try:
        manifest = ManifestParser.parse_file(manifest_path)
        click.echo(f"Registered Skill: {manifest.skill_id}")
        click.echo(f"  Name: {manifest.name}")
        click.echo(f"  Version: {manifest.version}")
        click.echo(f"  Permissions: {', '.join(manifest.permissions.keys()) or 'none'}")
        if manifest.deny_permissions:
            click.echo(f"  Denied: {', '.join(manifest.deny_permissions)}")
    except ManifestValidationError as e:
        click.echo(f"Invalid manifest: {e}", err=True)
        ctx.exit(3)


@cli.command("log")
@click.option("--action", type=click.Choice(["allow", "block", "ask"]), help="Filter by action")
@click.option(
    "--severity",
    type=click.Choice(["low", "medium", "high", "critical"]),
    help="Filter by severity",
)
@click.option("--agent-id", help="Filter by agent ID")
@click.option("--since", help="Start date (ISO format)")
@click.option("--until", help="End date (ISO format)")
@click.option("--limit", default=100, help="Max results")
@click.option("--log-path", default="./logs/skillsecurity-audit.jsonl", help="Log file path")
@click.pass_context
def log_cmd(
    ctx: click.Context,
    action: str | None,
    severity: str | None,
    agent_id: str | None,
    since: str | None,
    until: str | None,
    limit: int,
    log_path: str,
) -> None:
    """Query audit logs."""
    from skillsecurity.audit.query import AuditQuery

    q = AuditQuery(log_path)
    results = q.query(
        action=action, severity=severity, agent_id=agent_id, since=since, until=until, limit=limit
    )
    output_format = ctx.obj["format"]
    if output_format == "json":
        click.echo(json.dumps(results, indent=2, ensure_ascii=False))
    else:
        if not results:
            click.echo("No log entries found.")
            return
        for entry in results:
            ts = entry.get("timestamp", "")[:19]
            decision = entry.get("decision", {})
            act = decision.get("action", "?")
            reason = decision.get("reason", "")[:60]
            click.echo(f"{ts}  {act:6s}  {reason}")


@cli.command()
@click.argument("skill_path", type=click.Path(exists=True))
@click.option(
    "--manifest",
    "-m",
    default=None,
    type=click.Path(exists=True),
    help="Skill manifest file for permission analysis",
)
@click.pass_context
def scan(ctx: click.Context, skill_path: str, manifest: str | None) -> None:
    """Scan a Skill directory for dangerous code patterns."""
    output_format = ctx.obj["format"]
    try:
        guard = _make_guard(ctx)
        report = guard.scan_skill(skill_path, manifest=manifest)
    except Exception as e:
        click.echo(f"Scan error: {e}", err=True)
        ctx.exit(3)
        return
    if output_format == "json":
        click.echo(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        risk = report["risk_level"]
        summary = report["summary"]
        click.echo(f"\nScan Results: {skill_path}")
        click.echo(f"  Risk Level: {risk.upper()}")
        click.echo(f"  Files scanned: {summary['total_files']}")
        click.echo(
            f"  Issues: {summary['total_issues']} (critical: {summary['critical']}, high: {summary['high']}, medium: {summary['medium']}, low: {summary['low']})"
        )
        if report.get("permission_analysis"):
            pa = report["permission_analysis"]
            if pa["undeclared"]:
                click.echo(f"  Undeclared permissions: {', '.join(pa['undeclared'])}")
            if pa["unused"]:
                click.echo(f"  Unused declared permissions: {', '.join(pa['unused'])}")
        if report["recommendation"]:
            click.echo(f"\n  {report['recommendation']}")
        for issue in report["issues"]:
            click.echo(f"\n  [{issue['severity'].upper()}] {issue['file']}:{issue['line']}")
            click.echo(f"    {issue['description']}")
            if issue.get("code_snippet"):
                click.echo(f"    > {issue['code_snippet']}")
    risk = report["risk_level"]
    if risk in ("critical", "high"):
        ctx.exit(1)
    elif risk == "medium":
        ctx.exit(2)
    else:
        ctx.exit(0)


_SUPPORTED_FRAMEWORKS = ["langchain", "autogen", "crewai", "llamaindex", "mcp", "n8n"]
_CONFIG_FILE = ".skillsecurity.yaml"
_PTH_FILE_NAME = "skillsecurity-autoprotect.pth"


def _get_site_packages() -> Path:
    import site

    paths = site.getsitepackages()
    for p in paths:
        pp = Path(p)
        if pp.exists():
            return pp
    user_site = site.getusersitepackages()
    if user_site:
        Path(user_site).mkdir(parents=True, exist_ok=True)
        return Path(user_site)
    raise click.ClickException("Cannot locate site-packages directory")


_PTH_CONTENT = (
    "import importlib.util as _u;"
    ' exec("import skillsecurity.startup")'
    ' if _u.find_spec("skillsecurity") else None\n'
)


def _install_pth_hook() -> Path:
    sp = _get_site_packages()
    pth = sp / _PTH_FILE_NAME
    pth.write_text(_PTH_CONTENT, encoding="utf-8")
    return pth


def _remove_pth_hook() -> None:
    sp = _get_site_packages()
    pth = sp / _PTH_FILE_NAME
    if pth.exists():
        pth.unlink()


def _read_config() -> dict:
    p = Path(_CONFIG_FILE)
    if not p.exists():
        return {}
    import yaml

    data = yaml.safe_load(p.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


def _write_config(data: dict) -> None:
    import yaml

    Path(_CONFIG_FILE).write_text(
        yaml.dump(data, default_flow_style=False, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )


@cli.command("protect")
@click.argument("framework", type=click.Choice(_SUPPORTED_FRAMEWORKS, case_sensitive=False))
@click.option("--policy", "-p", default=None, help="Policy template name or file")
def protect_cmd(framework: str, policy: str | None) -> None:
    """Enable SkillSecurity protection for a framework (zero code change).

    \b
    Examples:
        skillsecurity protect langchain
        skillsecurity protect mcp --policy strict
        skillsecurity protect crewai -p ./my-policy.yaml

    After running this command, all tool calls in the framework will be
    automatically checked by SkillSecurity. No code changes needed.
    """
    config = _read_config()
    protected = config.get("auto_protect", [])

    fw = framework.lower()
    if fw not in protected:
        protected.append(fw)
    config["auto_protect"] = protected

    if policy:
        if Path(policy).exists():
            config["policy_file"] = str(Path(policy).resolve())
        else:
            config["policy"] = policy

    _write_config(config)

    try:
        _install_pth_hook()
        click.echo(f"  {fw} is now protected by SkillSecurity.")
        click.echo()
        click.echo(f"  Config written to {_CONFIG_FILE}")
        click.echo("  Auto-protect hook installed in site-packages.")
        click.echo()
        click.echo(
            f"  All Python programs in this environment will now auto-protect {fw} on startup."
        )
        click.echo()
        click.echo(f"  To undo:  skillsecurity unprotect {fw}")
    except Exception as e:
        click.echo(f"  {fw} config saved to {_CONFIG_FILE}.")
        click.echo(f"  Could not install auto-hook ({e}).")
        click.echo("  Manual fallback: add `import skillsecurity.startup` to your entry point.")


@cli.command("unprotect")
@click.argument(
    "framework",
    type=click.Choice([*_SUPPORTED_FRAMEWORKS, "all"], case_sensitive=False),
)
def unprotect_cmd(framework: str) -> None:
    """Remove SkillSecurity protection from a framework.

    \b
    Examples:
        skillsecurity unprotect langchain
        skillsecurity unprotect all
    """
    config = _read_config()
    protected = config.get("auto_protect", [])

    fw = framework.lower()
    if fw == "all":
        config["auto_protect"] = []
        _remove_pth_hook()
        config_path = Path(_CONFIG_FILE)
        if config_path.exists():
            config_path.unlink()
        click.echo("  All frameworks unprotected.")
        click.echo(f"  Removed {_CONFIG_FILE} and auto-protect hook.")
    else:
        if fw in protected:
            protected.remove(fw)
        config["auto_protect"] = protected

        if protected:
            _write_config(config)
            click.echo(f"  {fw} unprotected. Still protecting: {', '.join(protected)}")
        else:
            _remove_pth_hook()
            config_path = Path(_CONFIG_FILE)
            if config_path.exists():
                config_path.unlink()
            click.echo(f"  {fw} unprotected. No frameworks left — hook removed.")


@cli.command("status")
def status_cmd() -> None:
    """Show current SkillSecurity protection status.

    \b
    Example:
        skillsecurity status
    """
    config = _read_config()
    protected = config.get("auto_protect", [])

    if not protected:
        click.echo("  No frameworks currently protected.")
        click.echo()
        click.echo("  Get started:  skillsecurity protect langchain")
        return

    click.echo(f"  Protected frameworks: {', '.join(protected)}")

    policy = config.get("policy_file") or config.get("policy") or "default"
    click.echo(f"  Policy: {policy}")

    sp = _get_site_packages()
    pth = sp / _PTH_FILE_NAME
    hook_status = "installed" if pth.exists() else "not installed"
    click.echo(f"  Auto-protect hook: {hook_status}")


@cli.command()
@click.argument("policy_file", type=click.Path(exists=True))
def validate(policy_file: str) -> None:
    """Validate a security policy file."""
    try:
        from skillsecurity.config.loader import validate_policy_file

        warnings = validate_policy_file(policy_file)

        from skillsecurity.engine.policy import PolicyEngine

        engine = PolicyEngine()
        engine.load_file(policy_file)

        click.echo(f"Policy file valid: {policy_file}")
        click.echo(f"  Rules: {len(engine.rules)}")
        click.echo(f"  Version: {engine.global_config.default_action}")

        for w in warnings:
            click.echo(f"  Warning: {w}", err=True)

    except PolicyLoadError as e:
        click.echo(f"Policy file invalid: {policy_file}", err=True)
        click.echo(f"  Error: {e}", err=True)
        raise SystemExit(3) from e


@cli.command("dashboard")
@click.option("--host", default="127.0.0.1", help="Bind address")
@click.option("--port", default=9099, help="Port number")
@click.option("--log-path", default="./logs/skillsecurity-audit.jsonl", help="Audit log file")
@click.option("--no-browser", is_flag=True, help="Don't open browser automatically")
def dashboard_cmd(host: str, port: int, log_path: str, no_browser: bool) -> None:
    """Launch the SkillSecurity visual dashboard.

    \b
    Opens a web-based dashboard showing:
      - Real-time defense statistics
      - Recent security logs
      - Framework protection status (with toggle on/off)
      - Skill code scanner

    \b
    Examples:
        skillsecurity dashboard
        skillsecurity dashboard --port 8080
        skillsecurity dashboard --no-browser
    """
    from skillsecurity.dashboard.server import run_dashboard

    run_dashboard(host=host, port=port, log_path=log_path, open_browser=not no_browser)
