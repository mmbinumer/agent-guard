# Agent Guard

A runtime security proxy for MCP (Model Context Protocol) agent tool calls.

Agent Guard sits between your MCP client (Claude Desktop, etc.) and your real
MCP servers, inspecting every tool call for:

- **Secrets in transit** - API keys, AWS credentials, private keys, tokens
  found in tool call arguments or results (one level of base64/hex decoding
  is checked too).
- **Dangerous commands** - `rm -rf`, `curl | sh`, destructive SQL without a
  `WHERE` clause, `chmod 777`, etc.
- **Malicious inbound args** - heuristic tripwires (warn by default) for
  path traversal (encoded `../`, null bytes, `/etc/passwd`-style targets) and
  SQL injection (tautologies, stacked queries, `UNION SELECT`) in tool call
  arguments. Tripwires, not guarantees - see Limitations.
- **Accidental data exfiltration (taint tracking)** - if an agent reads a
  sensitive file (e.g. `.env`) and a value from it later appears in a call to
  an external-facing tool (HTTP, email, Slack), the call is blocked.
- **Prompt injection markers** - a *tripwire*, not a defense (see
  Limitations below).

Every tool call is logged to `~/.agent-guard/audit.log` as JSONL with a
risk score and verdict. The log is safe for concurrent writers (cross-process
file lock) and rotates at 50 MB to one prior file (`audit.log.1`).

## Install

Not yet published to PyPI. Install from source:

```bash
git clone https://github.com/mmbinumer/agent-guard
cd agent-guard
pip install -e .
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
- **The path-traversal and SQL-injection checks are tripwires, not
  validators.** They match known-suspicious patterns in tool call args
  (encoded traversal, tautologies, etc.) and default to `warn`. They scan
  top-level string args only, won't catch novel/obfuscated payloads, and are
  no substitute for the downstream server doing real input validation and
  parameterized queries.
- **The config file is not tamper-proof.** Anyone with filesystem access to
  `agent-guard.yaml` can disable detections or flip the kill switch. This is
  not a hardened security boundary in v1.

## License

MIT
