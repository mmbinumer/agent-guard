# Security Policy

## Reporting a vulnerability

Please report security issues privately through
[GitHub Security Advisories](https://github.com/mmbinumer/agent-guard/security/advisories/new)
rather than opening a public issue.

Include what you'd expect: affected version or commit, a description of the
issue, and the smallest reproduction you can manage (a config snippet plus the
tool call that triggers it is usually enough).

This is a solo-maintained project, so response times depend on availability.
Expect an acknowledgement within a week. If a report is valid, the fix and the
advisory will be published together.

## Supported versions

Only the latest commit on `master` is supported. There are no maintained
release branches or backports.

## Scope

**In scope** — a detection can be bypassed in a way the documentation does not
already acknowledge, for example:

- A payload that evades `dangerous_command`, `secret_in_args`, or
  `secret_in_output` through a mechanism the README does not list.
- A taint-tracked value reaching a configured sink without producing
  `taint_leak` or `taint_unknown`.
- Any path where a `block` action is configured but the call still reaches the
  downstream server.
- Secrets or taint-tracked values written to the audit log in plaintext.
- Anything letting a downstream MCP server read or corrupt another server's
  state through the proxy.

**Out of scope** — the documented limitations in the README are known and
intentional, not vulnerabilities:

- **Detectors are pattern matchers.** The prompt-injection, path-traversal, and
  SQL-injection checks are tripwires. Rephrased, obfuscated, or novel payloads
  evading them is expected behaviour, not a bug.
- **Taint tracking matches exact values** plus one level of base64/hex decoding.
  A paraphrased, reformatted, or re-encoded secret slipping through is a known
  gap.
- **Redaction is audit-log-only.** The agent still receives unredacted tool
  output by design.
- **The config file is not tamper-proof.** Anyone who can write
  `agent-guard.yaml` can disable detections or flip the kill switch. Filesystem
  access is outside the threat model.
- **Coverage is scoped to the client-to-server direction.** Tool calls and
  `resources/read` are inspected. Prompts and server-initiated calls
  (`sampling/createMessage`, `elicitation`, `roots/list`) are not. This is a
  known scope limit, tracked publicly.

If you're unsure which side of that line something falls on, report it
privately anyway.

## What this tool is not

Agent Guard is defence in depth, not a security boundary. It reduces the blast
radius of an agent behaving badly; it does not make an untrusted agent or an
untrusted MCP server safe to run. Treat a clean audit log as absence of
evidence, not evidence of absence.
