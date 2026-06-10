# Agent Guard

A runtime security proxy for MCP (Model Context Protocol) agent tool calls.

Agent Guard sits between your MCP client (Claude Desktop, etc.) and your real
MCP servers, inspecting every tool call for:

- **Secrets in transit** - API keys, AWS credentials, private keys, tokens
  found in tool call arguments or results (one level of base64/hex decoding
  is checked too).
- **Dangerous commands** - `rm -rf`, `curl | sh`, destructive SQL without a
  `WHERE` clause, `chmod 777`, etc.
- **Accidental data exfiltration (taint tracking)** - if an agent reads a
  sensitive file (e.g. `.env`) and a value from it later appears in a call to
  an external-facing tool (HTTP, email, Slack), the call is blocked.
- **Prompt injection markers** - a *tripwire*, not a defense (see
  Limitations below).

Every tool call is logged to `~/.agent-guard/audit.log` as JSONL with a
risk score and verdict.

## Install

```bash
pip install agent-guard
```

## Quick start

1. Copy `agent-guard.example.yaml` to `agent-guard.yaml` and list your
   downstream MCP servers under `servers:`.
2. Point your MCP client at Agent Guard instead of your servers directly.
3. Run `agent-guard tail --no-follow` to see recent activity, or
   `agent-guard report` for a summary.
4. If a legitimate call gets blocked, set `mode: audit-only` in
   `agent-guard.yaml` to downgrade all blocks to warnings while you tune the
   config, or run `agent-guard kill` to halt everything immediately.

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
- **The config file is not tamper-proof.** Anyone with filesystem access to
  `agent-guard.yaml` can disable detections or flip the kill switch. This is
  not a hardened security boundary in v1.

## License

MIT
