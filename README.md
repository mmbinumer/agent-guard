# Agent Guard

[![PyPI](https://img.shields.io/pypi/v/mcp-agent-guard)](https://pypi.org/project/mcp-agent-guard/)
[![Tests](https://github.com/mmbinumer/agent-guard/actions/workflows/tests.yml/badge.svg)](https://github.com/mmbinumer/agent-guard/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A runtime security proxy for MCP (Model Context Protocol) agent tool calls.

Agent Guard sits between your MCP client (Claude Desktop, Claude Code, or any
MCP-compatible client) and your real MCP servers. It checks every tool call
before it runs and every result on the way back, then allows, warns, or
blocks - and writes down what it did.

It looks for secrets in transit, destructive commands, malicious arguments,
prompt-injection markers, and data from a sensitive source escaping to an
external one. Full list under [Detections](#detections).

Every call is logged to `~/.agent-guard/audit.log` as JSONL with a risk score
and verdict. The log is safe for concurrent writers (cross-process file lock)
and rotates at 50 MB to one prior file (`audit.log.1`).

## What this looks like in practice

Say your agent has a wiki server and a database server connected, and you ask
it to tidy up some onboarding docs and check today's signups:

| What the agent does | Agent Guard |
|---|---|
| Reads a normal wiki page | **allows** it, logs it |
| Reads a page containing "ignore previous instructions…" | **warns** - a wiki is untrusted input, anyone can edit it |
| Edits a page, pasting in an API key it found in your config | **blocks** - the key never lands on the wiki |
| Edits a page using a password it read from your ops runbook | **blocks** - it remembers where that value came from |
| Runs `SELECT COUNT(*) FROM customers WHERE …` | **allows** it, logs it |
| Runs `DELETE FROM customers` with no `WHERE` | **blocks** |

Nobody had to be malicious for the two blocked edits to happen. An agent
pulling a credential into a doc it is writing is just an agent being
thorough - which is exactly why it goes unnoticed.

Most of the time nothing fires and you get an audit trail. The value shows up
on the one call that goes sideways.

Which tools count as somewhere data can escape to is up to you: `wiki__*`
edits are not treated as an exfiltration route by default, so add them to
`external_sinks` if your wiki is shared. See Configuration.

## Install

```bash
pip install mcp-agent-guard
```

The distribution is `mcp-agent-guard` (the shorter name belongs to an
unrelated project); the command and the import package are both
`agent-guard` / `agent_guard`.

To work on it instead:

```bash
git clone https://github.com/mmbinumer/agent-guard
cd agent-guard
pip install -e ".[dev]"
```

> **Windows note:** if `agent-guard` isn't found after install, pip installed
> the script to a `Scripts` directory that isn't on your `PATH` (pip will
> print a warning showing the path). Add that directory to your `PATH` and
> open a new terminal, or invoke it as `python -m agent_guard <command>`.

## Quick start

1. Copy `agent-guard.example.yaml` to `agent-guard.yaml` and list your
   downstream MCP servers under `servers:`.
2. Run `agent-guard run --config agent-guard.yaml` to start Agent Guard as a
   stdio MCP proxy server, and point your MCP client (e.g. Claude Desktop) at
   this running process instead of your servers directly.
3. Run `agent-guard tail --no-follow` to see recent activity, or
   `agent-guard report` for a summary.
4. If a legitimate call gets blocked, set `mode: audit-only` in
   `agent-guard.yaml` to downgrade all blocks to warnings while you tune the
   config, or run `agent-guard kill` to halt everything immediately.

## Examples

`examples/verdict_demos.py` runs Agent Guard in-process against a real
`@modelcontextprotocol/server-filesystem`, scoped to a temp directory, and
walks through all four verdicts (`allowed`, `warned`, `blocked` for a
credential in args, `blocked` for a taint leak), printing the resulting
audit log:

```bash
pip install -e .
python examples/verdict_demos.py
```

Requires Node.js (`npx`) on `PATH`.

## Detections

Each detection has a configurable action (`block` / `redact` / `warn` /
`allow`). Defaults below; override any of them under `actions:` in your config.

| Detection | Catches | Phase | Default |
|---|---|---|---|
| `dangerous_command` | `rm -rf`, `curl \| sh`, `chmod 777`, destructive SQL (`DROP`/`DELETE`/`UPDATE` without `WHERE`) | pre-call args | `block` |
| `secret_in_args` | API keys, AWS creds, tokens, private keys in args (+1 level base64/hex) | pre-call args | `block` |
| `path_traversal` | encoded `../`, null bytes, deep climbs (`../../../`), sensitive targets (`/etc/passwd`, `.ssh/`) | pre-call args | `warn` |
| `sql_injection` | tautologies (`' OR '1'='1`), stacked queries (`'; DROP`), `UNION SELECT`, comment terminators | pre-call args | `warn` |
| `taint_leak` | a value read from a sensitive source reappearing in a call to an external sink | pre-call args | `block` |
| `taint_unknown` | a sink call scanned clean *after* taint evidence was evicted, so the result isn't conclusive | pre-call args | `warn` |
| `secret_in_output` | secrets in tool results (redacted in audit log only) | post-call result | `redact` |
| `prompt_injection_marker` | verbatim phrases like "ignore previous instructions" in results | post-call result | `warn` |

`path_traversal`, `sql_injection`, and `prompt_injection_marker` are
heuristic tripwires (see Limitations). They default to `warn` so they surface
suspicious activity in the audit log without blocking legitimate calls while
you tune. Set them to `block` once you trust them for your workload.

## Configuration

See `agent-guard.example.yaml` for the full schema: per-detection actions
(`block` / `redact` / `warn` / `allow`), taint sources/sinks, size limits,
and the global kill switch.

## Limitations (read this)

- **Redaction is audit-log-only**: when a secret is detected in a tool's
  *output*, it's redacted in the audit log but the agent still receives the
  unredacted result (so its reasoning isn't disrupted). This means the audit
  log is not a faithful record of what the agent saw - relevant if you're
  using this for compliance purposes.
- **The prompt injection scanner is a tripwire, not a defense.** It matches
  verbatim/near-verbatim phrasing like "ignore previous instructions". A
  rephrased or obfuscated injection will not be caught. A clean scan does
  **not** mean the output is safe.
- **Taint tracking matches exact values (plus one level of base64/hex
  decoding)**. An agent that paraphrases a secret or applies further
  encoding will not be caught.
- **The taint store is bounded and per-session.** It holds at most
  `max_taint_entries` values and evicts oldest-first. Once anything has been
  evicted, a sink call that scans clean is no longer conclusive, so Agent
  Guard reports `taint_unknown` instead of silently treating the call as
  clean. Raise `max_taint_entries` for long sessions, or set
  `taint_unknown: block` to fail closed.
- **The path-traversal and SQL-injection checks are tripwires, not
  validators.** They match known-suspicious patterns in tool call args
  (encoded traversal, tautologies, etc.) and default to `warn`. They scan
  top-level string args only, won't catch novel/obfuscated payloads, and are
  no substitute for the downstream server doing real input validation and
  parameterized queries.
- **The config file is not tamper-proof.** Anyone with filesystem access to
  `agent-guard.yaml` can disable detections or flip the kill switch. This is
  not a hardened security boundary in v1.

## Security

Found a way past a detection? See [SECURITY.md](SECURITY.md) for how to report
it privately, and for what is in scope versus a known limitation.

## License

MIT
