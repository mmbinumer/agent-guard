from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import click


def _read_events(log_path: Path) -> list[dict]:
    if not log_path.exists():
        return []
    events = []
    with open(log_path) as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


@click.group()
def main() -> None:
    """Agent Guard CLI - inspect and control the audit log / kill switch."""


@main.command()
@click.option("--log", "log_path", default="~/.agent-guard/audit.log", show_default=True)
@click.option("--no-follow", is_flag=True, default=False, help="Print existing events and exit (no live tail)")
def tail(log_path: str, no_follow: bool) -> None:
    """Tail the audit log (human-readable)."""
    path = Path(log_path).expanduser()
    for event in _read_events(path):
        verdict = event["verdict"]
        risk = event["risk_score"]
        click.echo(
            f"[{event['ts']}] {event['tool']:<24} risk={risk:<6} {verdict}"
        )
    if not no_follow:
        click.echo("(live following not implemented in v1; use --no-follow)")


@main.command()
@click.option("--log", "log_path", default="~/.agent-guard/audit.log", show_default=True)
def report(log_path: str) -> None:
    """Print summary stats from the audit log."""
    path = Path(log_path).expanduser()
    events = _read_events(path)

    verdicts = Counter(e["verdict"] for e in events)
    detection_types = Counter(
        d["type"] for e in events for d in e["detections"]
    )

    click.echo(f"Total events: {len(events)}")
    click.echo("By verdict:")
    for verdict, count in verdicts.items():
        click.echo(f"  {verdict}: {count}")
    click.echo("By detection type:")
    for dtype, count in detection_types.items():
        click.echo(f"  {dtype}: {count}")


@main.command()
@click.option("--config", "config_path", default="agent-guard.yaml", show_default=True)
def kill(config_path: str) -> None:
    """Set kill_switch: true in the config file (proxy must reload to pick it up)."""
    path = Path(config_path)
    text = path.read_text()
    if "kill_switch:" in text:
        import re
        new_text = re.sub(r"kill_switch:\s*\w+", "kill_switch: true", text)
    else:
        new_text = text.rstrip() + "\nkill_switch: true\n"
    path.write_text(new_text)
    click.echo(f"kill_switch: true written to {config_path}")


@main.command()
@click.option("--config", "config_path", default="agent-guard.yaml", show_default=True)
def run(config_path: str) -> None:
    """Run Agent Guard as a stdio MCP proxy server."""
    import asyncio
    import uuid

    from agent_guard.audit import AuditLogger
    from agent_guard.config import load_config
    from agent_guard.detectors.taint import TaintStore
    from agent_guard.pipeline import Pipeline
    from agent_guard.proxy import AgentGuardProxy

    config = load_config(config_path)
    audit_log_path = Path("~/.agent-guard/audit.log").expanduser()
    logger = AuditLogger(audit_log_path)
    taint_store = TaintStore(
        max_value_bytes=config.limits.max_taint_value_bytes,
        max_entries=config.limits.max_taint_entries,
    )
    pipeline = Pipeline(config=config, audit=logger, taint=taint_store, session_id=str(uuid.uuid4()))
    proxy = AgentGuardProxy(config=config, pipeline=pipeline)

    async def _run():
        async with proxy.connected():
            await proxy.serve_stdio()

    asyncio.run(_run())


if __name__ == "__main__":
    main()
