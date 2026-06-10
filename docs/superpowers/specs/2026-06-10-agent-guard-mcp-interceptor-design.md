# Agent Guard — MCP Security Interceptor (v1 Design)

## Problem

AI agents with real tool access (via MCP) have no runtime security layer. Two concrete, demoable failure modes drive v1 scope:

- An agent reads a secret (`.env`, credentials file, API key) and later passes it (directly or encoded) to an external-facing tool (HTTP, email, Slack) — accidental exfiltration.
- An agent is instructed (directly or via prompt injection in fetched content) to run a destructive command (`rm -rf`, destructive SQL, `curl | sh`).

v1 is an open-source MCP proxy that detects and blocks/redacts these patterns, with full audit logging.

## Architecture

```
Agent (MCP client) → Agent Guard (MCP proxy) → Real MCP Server(s)
                            │
                            ├─ Pre-call pipeline (per tools/call)
                            ├─ Post-call pipeline (per tool result)
                            └─ Audit log (JSONL)
```

`tools/list` and other non-call messages pass through unchanged. `tools/call` goes through the full pipeline. The proxy can front **multiple** downstream MCP servers (stdio or SSE), each declared in config.

### Session scope

A "session" = one Agent Guard process lifetime (one agent run). Taint state and any per-session counters are shared **across all configured downstream servers** within that session — taint tracking is not per-server. This must be explicit so the filesystem-server-read → Slack-server-send case is actually caught.

## Pipeline

### Pre-call (on `tools/call` request, before forwarding)

1. **Dangerous command match** — args checked against a configurable pattern list (`rm -rf`, `curl|sh`, destructive SQL without WHERE, `chmod 777`, etc.).
2. **Secret-in-args scan** — regex/entropy-based scan for API keys, AWS keys, private keys, generic high-entropy tokens.
3. **Taint check** — args checked (after encoding normalization, see below) for substrings matching values previously tagged as sensitive in this session, when the target tool matches a configured "sink" pattern (`http.*`, `email.*`, `slack.*`, etc.).

Each detector's match maps to an **action**: `block`, `redact`, `warn`, or `allow`, per YAML config (see below). `block` returns an MCP error to the agent instead of forwarding the call. `redact` is not meaningful pre-call for args (treated as `block` if configured as redact pre-call) — only block/warn/allow apply to args.

### Post-call (on tool result, before returning to agent)

1. **Secret-in-output scan** — same scanner as above, run on the result payload.
   - `redact` action replaces matched substrings with `[REDACTED]` **in the audit log only** — the agent receives the unredacted result. (Redacting what the agent sees risks confusing its reasoning/looping; the goal is audit visibility, not altering agent behavior. This is a documented v1 tradeoff.)
   - **Compliance caveat**: this means the audit log is not a faithful record of what the agent actually saw — it shows what *would* have been redacted, not the real (unredacted) data the agent received. For v1's "demo + dev tooling" positioning this is acceptable, but any future compliance/SOC2-oriented offering must either record the unredacted value in a separately access-controlled store, or switch this action to redact-for-agent-too. This is flagged here so it isn't silently inherited as the compliance product's behavior.
2. **Injection marker scan** — output checked for instruction-like patterns (e.g. "ignore previous instructions", "you are now...") — `warn` only in v1 (no auto-block, too high false-positive risk). **This is a tripwire, not a defense**: it only catches unsophisticated/verbatim injection phrasing. README must state this explicitly so users don't treat a clean scan as "this output is safe from injection."
3. **Taint tagging** — if the source tool/path matches a configured sensitive source (file glob, db table), extract candidate sensitive values (secret-pattern matches, or full output for small results under the size cap) and add to session taint store.

### Size cap

Outputs/args larger than a configured byte threshold (default 256KB) are **not** scanned for secrets/taint (too slow, diminishing returns) but still pass through dangerous-command and audit logging. This is logged as `scan_skipped: size_limit` so it's visible, not silent.

### Encoding normalization

Before substring/pattern matching (secret scan and taint check), values are checked against the raw string **and** base64-decoded / hex-decoded variants (one level deep) of both the candidate and stored taint values. This catches the common "agent base64-encodes the secret before sending" evasion without building a general deobfuscation engine.

## Detectors detail

- **Secret patterns**: built-in regex set (AWS access keys, generic `sk-...`/`ghp_...`/JWT-like tokens, PEM private key blocks) + Shannon-entropy check on long alphanumeric tokens above a length threshold.
- **Dangerous commands**: built-in pattern list, user-extensible via config.
- **Taint sources**: built-in defaults (`.env`, `*secret*`, `*credentials*`, `id_rsa*`) + user-configurable file globs and db table names.
- **Taint sinks**: user-configurable tool name patterns (default suggestions: `http.*`, `email.*`, `slack.*`, `*send*`, `*post*`).

### Taint store sizing

A single sensitive read can contain many secret-pattern matches (e.g. a 50KB `.env` with 30 keys). v1 stores **all** distinct matches found (post-dedup, post-encoding-normalization), each capped at `max_taint_value_bytes` (default 512 bytes per value — long enough for any realistic key/token, short enough to bound memory). The taint store itself is capped at `max_taint_entries` per session (default 1000); beyond that, oldest entries are evicted (FIFO) and an `entry: taint_store_truncated` audit event is logged once per session when eviction first occurs, so the limit is visible rather than silent.

## Config format (`agent-guard.yaml`)

```yaml
servers:
  - name: filesystem
    command: ["mcp-server-filesystem", "/path"]
  - name: slack
    command: ["mcp-server-slack"]

mode: enforce   # enforce | audit-only

actions:
  dangerous_command: block
  secret_in_args: block
  secret_in_output: redact     # audit-log only, see Pipeline notes
  taint_leak: block
  prompt_injection_marker: warn

taint:
  sensitive_sources:
    files: [".env", "*secret*", "*credentials*", "id_rsa*"]
    db_tables: ["users", "customers"]
  external_sinks:
    tools: ["http.*", "email.*", "slack.*", "*send*"]

limits:
  max_scan_bytes: 262144

kill_switch: false
```

### Audit-only mode

`mode: audit-only` (global) downgrades all `block` actions to `warn` — every detection is logged with the verdict it *would* have had, but the call proceeds. This is the escape hatch for false positives breaking an agent's task; users can run audit-only first to tune config before enabling enforcement. `kill_switch: true` overrides everything and blocks all calls regardless of mode.

## Audit log

JSONL, one line per `tools/call`, appended to `~/.agent-guard/audit.log`:

```json
{
  "ts": "2026-06-10T12:01:05Z",
  "session_id": "...",
  "tool": "slack.post_message",
  "server": "slack",
  "args_summary": "...",
  "detections": [
    {"type": "taint_leak", "rule": "external_sinks", "matched_source": ".env", "action": "block"}
  ],
  "verdict": "blocked",
  "risk_score": "high",
  "scan_skipped": null
}
```

Risk score is a simple heuristic: `high` if any block-eligible detection fired (regardless of mode), `medium` if warn-level fired, `low` otherwise.

## CLI

- `agent-guard tail` — live-tail audit log, human-readable, color-coded by risk/verdict.
- `agent-guard report` — summary stats (counts by detection type, verdict, tool) over the log.
- `agent-guard kill` — flips `kill_switch: true` in the running config (file-watch reload).

## Components / project layout

```
agent_guard/
  proxy.py          # MCP proxy core, multi-server passthrough
  pipeline.py        # pre/post-call orchestration
  detectors/
    secrets.py       # patterns + entropy
    dangerous.py      # command pattern matching
    taint.py          # session taint store, encoding normalization
    injection.py      # prompt injection marker scan
  config.py          # YAML load/validate, hot-reload for kill switch
  audit.py           # JSONL writer
  cli.py             # tail / report / kill
```

## Error handling

- Config parse errors or detector exceptions → fail closed (treat as `block` + log an `error` detection), proxy stays up.
- Downstream MCP server connection failure → surfaced as MCP error to agent for that call, not silently passed through, logged.

## Testing

- Unit tests per detector against fixture payloads: known secrets (incl. base64-encoded), dangerous commands, taint scenarios across two simulated servers, oversized payloads (size cap path).
- Integration test: full proxy against a mock downstream MCP server, covering `enforce` and `audit-only` modes, kill switch, and audit log line correctness/schema.

## Out of scope for v1 (documented, not silently dropped)

- Tamper-proof/signed policy config — anyone with filesystem access can edit `agent-guard.yaml`. v1 is not a hardened control boundary.
- Multi-level/iterative deobfuscation beyond one-level base64/hex.
- Non-MCP framework support (LangChain, etc.) — detection logic is structured to be reusable later.
- Hosted dashboard, RBAC, SSO, anomaly detection, ML-based scoring — future paid tiers per business plan.

## Business framing recap

OSS (free, forever): everything above. Paid (hosted, future): multi-agent dashboard, team/RBAC/SSO, compliance exports, alerting, retention. Distribution: MCP community channels, Show HN, security-research content highlighting real MCP server gaps.
