# DSH Security Audit

[简体中文](README.md) | English

`dsh-security-audit` is a local-first security audit Skill for [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness). It audits DSH Skills, profile plugins, Bundle/Cordis configuration, MCP servers, package supply-chain settings, and selected runtime exposure without executing the target code.

The scanner is best-effort detection, not a security certificate. A report with no findings does not prove that an extension is safe.

## What it checks

- Hard-coded API keys, tokens, private keys, passwords, and secret-shaped values, with evidence redaction.
- Sensitive environment/file access combined with outbound network sinks.
- Download-and-execute chains, dynamic evaluation, subprocesses, destructive commands, and opaque binaries.
- LaunchAgents, systemd user units, cron, shell startup files, Git hooks, SSH persistence, tunnels, and public listeners.
- Host-root/container volumes, Docker socket access, remote/FUSE mounts, Kubernetes credentials, and privilege escalation.
- npm/pnpm lifecycle scripts, `allowBuilds`, floating versions, and remote dependencies not pinned to a commit.
- DSH `dsh.bundle.patch`, Cordis `!!js`, dangerous permission combinations, telemetry export, and profile configuration.
- MCP stdio commands, package runners, sensitive environment forwarding, and insecure remote HTTP endpoints.
- Prompt injection, hidden HTML instructions, zero-width/bidirectional Unicode, Base64/hex payloads, and decoded high-risk content.
- Optional SHA-256 baselines, Markdown/JSON/SARIF output, CI severity thresholds, and read-only runtime posture checks.

## DSH-specific security assumptions

DSH's `workspace-write` mode primarily constrains file writes. It does not automatically isolate reads, network access, or process visibility. The local credential document can still be read by a process running as the same OS user. MCP stdio commands and approved package lifecycle scripts execute on the host outside the agent file-write sandbox.

For those reasons, this Skill never imports target modules, runs package lifecycle scripts, starts MCP servers, or executes scanned binaries.

## Install

Clone the repository into the user DSH Skill root:

```sh
mkdir -p ~/.dsh/skills
git clone https://github.com/yhny1001/dsh-security-audit.git ~/.dsh/skills/dsh-security-audit
```

DSH discovers the Skill as `dsh-security-audit`. Existing Web processes should observe the new Skill through the filesystem watcher; otherwise restart DSH.

## Use from DSH

Invoke it explicitly:

```text
/dsh-security-audit Audit the current DSH environment, including runtime checks.
```

The Skill directs the agent to run the bundled zero-dependency Node.js scanner, confirm high-risk findings without executing samples, and produce an evidence-driven report.

## Use the scanner directly

Requires Node.js 22.19 or newer, matching the current DSH runtime floor.

```sh
node ~/.dsh/skills/dsh-security-audit/scripts/dsh-security-audit.mjs \
  --cwd "$PWD" \
  --runtime \
  --format markdown
```

Scan an extension before installation:

```sh
node scripts/dsh-security-audit.mjs \
  --cwd "$PWD" \
  --target /path/to/untrusted-skill-or-plugin \
  --format json
```

CI/SARIF example:

```sh
node scripts/dsh-security-audit.mjs \
  --cwd "$PWD" \
  --format sarif \
  --output dsh-security-audit.sarif \
  --fail-on high
```

Run `node scripts/dsh-security-audit.mjs --help` for profile filters, deep dependency scanning, report formats, file limits, and baseline options.

## Baselines

Baseline creation writes a digest-only JSON document and must be an explicit operator action. Keep it outside every scanned root:

```sh
node scripts/dsh-security-audit.mjs \
  --cwd "$PWD" \
  --write-baseline ../dsh-security-baseline.json \
  --format json
```

Compare it later without modifying the target:

```sh
node scripts/dsh-security-audit.mjs \
  --cwd "$PWD" \
  --baseline ../dsh-security-baseline.json \
  --format markdown
```

## Design and prior art

The threat categories are informed by the OWASP Agentic Skills Top 10 and AI Agent Security guidance, Cisco AI Defense Skill Scanner, NVIDIA SkillSpector, and Snyk Agent Scan. The implementation is independently written and adds DSH-specific profile, Bundle, Cordis, MCP, permission, telemetry, and credential checks.

See [the risk model](references/risk-model.md) and [prior-art notes](references/prior-art.md) for details and authoritative links.

## Limitations

- Regex and file-level source/sink correlation are not complete interprocedural taint analysis.
- Obfuscation, native code, runtime-generated payloads, and novel techniques can evade static analysis.
- Runtime checks are point-in-time and limited to state visible to the current OS user.
- Offline mode does not query live CVEs, package revocation, publisher reputation, or malware databases.
- High-value environments should also use human review, immutable dependency pins, network egress controls, isolation, EDR, and audit logs.

## License

Released under the [MIT License](LICENSE).
