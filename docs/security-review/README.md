# Security Review & Audit

Svault is a secret manager, so its own security posture is part of the product. To
keep that honest and verifiable, **every minor release (`0.x.0`) goes through a full
security review and bulletproofing pass before it ships.** Patch releases (`0.x.y`)
inherit the most recent minor review unless they change the security model.

This folder is the record of that process: the prompt used to commission independent
reviews, the resulting review for each release, and — most importantly — the
**maintainer's human triage and sign-off** on every finding.

The model reviews exist for breadth and independence; they are **inputs, not verdicts**.
A human maintainer reads every finding, decides what to do about it, and signs the
result. See the per-release findings register for that human review of record.

## Contents

| File | What it is |
|---|---|
| [PROMPT.md](PROMPT.md) | A reusable, model-agnostic prompt for commissioning an **independent** security review of the current codebase. Kept current with the latest released version and features. |
| [reviews/](reviews/) | The reviews themselves, named `<version>-<reviewer>.md` (more than one independent reviewer per release is encouraged). |
| [findings/](findings/) | The consolidated **findings register** per release — every reviewer's findings de-duplicated into one table with cross-model agreement, our disposition, and justification notes. This is the document of record for what we decided and why. Later releases add a **carry-forward** register (e.g. [findings/0.6.0.md](findings/0.6.0.md)) restating each prior finding as fixed / improved / unchanged. |
| [stress/](stress/) | **Concurrency / pressure simulations** per release — a logged stress run of the daemon under heavy parallel load, backing the connection-DoS findings. See [stress/0.6.0.md](stress/0.6.0.md). |

## Reviews

The reviewers below are **AI models**, run for breadth and cross-checking. Their findings
are not the final word: they are consolidated and then **reviewed, triaged, and signed off
by a human maintainer** in the per-release findings register —
**[findings/0.5.0.md](findings/0.5.0.md)** (all 22 findings dispositioned by Nima Karimi,
2026-05-29). **0.6.0** acted on four of them (#4, #8, #13, #20) plus added connect
resilience and a logged stress simulation — see the carry-forward register
**[findings/0.6.0.md](findings/0.6.0.md)** and **[stress/0.6.0.md](stress/0.6.0.md)**.
**0.7.0** was reviewed by three independent models, which unanimously re-confirmed
the advisory-policy gap (#2/#5/#22) as the blocker for a 1.0.0 "enforced" claim and
surfaced a handful of new items — consolidated with dispositions in
**[findings/0.7.0.md](findings/0.7.0.md)**. 0.8.0 acts on them. **0.9.0** closes the
policy thread — enforcement + audit moved **inside the daemon**, classification in
the signed `meta.yaml`, anchored fail-closed discovery — and adds the AI judge. The
maintainer pre-review register **[findings/0.9.0.md](findings/0.9.0.md)** records
those closures, the one residual (N-1: caller authorization still self-asserted,
audit now peer-UID-stamped), and the judge's new surface (prompt injection, data
egress, key handling). 0.9.9 ships with independent reviews (enforced gate + daemon + full encryption + Yubi + conditional seal + MCP now covered). The process continues for 1.0.0.

The **desktop GUI** (Tauri) is reviewed separately from the core, since it adds its
own attack surface — the webview as a possible adversary and the IPC command set as
a capability boundary. The maintainer deep-dive register is
**[findings/gui-1.1.0.md](findings/gui-1.1.0.md)** (arbitrary-path file-write IPC
commands, disabled CSP, `change_master` re-auth, clipboard handling, and the
read-only commands that skip the master gate).

| Version | Date | Reviewer | Overall posture | Review |
|---|---|---|---|---|
| 0.9.9 | 2026-06-02 | opencode (x-ai/grok-build-0.1) | Low-Medium (Unix + daemon with enforced gate) — sound policy enforcement for cooperative agents; Windows / no-daemon remains higher residual; suitable for corporate CI/agent use under the documented same-UID model | [reviews/0.9.9-opencode.md](reviews/0.9.9-opencode.md) |
| 0.7.0 | 2026-05-30 | Claude Opus 4.8 (Anthropic) | Moderate — conditionally OK on Unix as at-rest store + audit/guardrails; policy is advisory (bypassable same-UID), so not an enforcement boundary; not for high-value prod or Windows fleets | [reviews/0.7.0-claude-opus-4.8.md](reviews/0.7.0-claude-opus-4.8.md) |
| 0.7.0 | 2026-05-30 | GLM-5.1 (z-ai, via opencode) | Moderate — with caveats; strong crypto + daemon on Unix, but policy unenforced at the daemon (bypassable same-UID); weaker on Windows | [reviews/0.7.0-glm5.1.md](reviews/0.7.0-glm5.1.md) |
| 0.7.0 | 2026-05-30 | opencode (Qwen3-Coder-Next) | Medium-High (Unix + daemon) -> High (Windows / regulated); daemon is a real improvement but policy is advisory and bypassable same-UID | [reviews/0.7.0-opencode.md](reviews/0.7.0-opencode.md) |
| 0.5.0 | 2026-05-29 | Grok 4.3 (xAI) | Low–Medium (Unix + daemon) -> High (Windows / regulated) | [reviews/0.5.0-grok-4.3.md](reviews/0.5.0-grok-4.3.md) |
| 0.5.0 | 2026-05-29 | GLM-5-1 (z-ai) | Moderate — conditionally OK on Unix + daemon; unsuitable for Windows / high-security | [reviews/0.5.0-glm-5.1.md](reviews/0.5.0-glm-5.1.md) |
| 0.5.0 | 2026-05-29 | Gemini 3.5 Flash | Moderate — conditionally acceptable on Unix + daemon; unsuitable for Windows & shared CI | [reviews/0.5.0-gemini-3.5-flash.md](reviews/0.5.0-gemini-3.5-flash.md) |
| 0.5.0 | 2026-05-29 | DeepSeek-V4-Pro | Low–Medium (Unix + daemon) -> Medium-High (server/CI) -> High (Windows / non-Unix) | [reviews/0.5.0-deepseek-v4-pro.md](reviews/0.5.0-deepseek-v4-pro.md) |
| 0.5.0 | 2026-05-29 | Claude Opus 4.8 (Anthropic) | Moderate, context-dependent — OK for individuals/small teams on Unix (low/med secrets); not yet for high-value prod, Windows fleets, or as an enforcing control | [reviews/0.5.0-claude-opus-4.8.md](reviews/0.5.0-claude-opus-4.8.md) |

## The process

Each `0.x.0` release is gated on the following before tagging:

1. **Tooling pass (bulletproofing).** Run and resolve, on the locked tree:
   - `cargo test --locked` — all tests green
   - `cargo clippy --all-targets -- -D warnings` — clean
   - `cargo audit --deny warnings` — no unaddressed advisories (document any accepted ones)
2. **Independent review.** Take the prompt in [PROMPT.md](PROMPT.md), update it for the
   new version's headline security-relevant changes, and run it through one or more
   capable models that did **not** write the code. Each reviewer works from a fresh
   clone, independently of any prior review. Using several different models is
   encouraged — agreement across independent models is strong signal.
3. **Record each review.** Save every result as `reviews/<version>-<reviewer>.md` and add
   a row to the **Reviews** table above.
4. **Consolidate.** De-duplicate all reviewers' findings into one register at
   `findings/<version>.md`: one row per distinct finding, which models raised it, our
   status, and a written disposition/justification. This is what makes the decisions
   defensible and auditable.
5. **Human triage & sign-off.** The maintainer reads every finding and records a
   disposition for each in the register: status, justification, and notes — signed and
   dated. Every High/Critical finding is either fixed before release or explicitly
   accepted in writing (with rationale) here and in the [roadmap](../roadmap.md). This
   step is non-negotiable: the AI reviews never decide anything on their own.
6. **Carry forward.** Open items become tracked work; the next release's register
   re-states each prior finding as *fixed*, *improved*, or *unchanged*.

## Why independent review

The author of a system is the worst judge of its weaknesses. Using a separate model —
working only from the public source tree and the neutral prompt — keeps the assessment
unbiased and reproducible: anyone can run the same prompt and compare results. Reviews
are kept blunt and evidence-based, not marketing.

## On human vs. AI review

The reviews here are AI-generated, which buys **breadth and speed** — multiple independent
passes over the whole codebase per release. What makes the result trustworthy is the
**human triage**: a named maintainer reviews and signs off on every finding (see the
findings register). AI for coverage, human for judgment.

To be clear about the current limitation: these are AI reviews plus maintainer sign-off,
**not** a third-party human security audit. An independent external human audit is a
planned step as the project matures, and will be recorded here alongside the model reviews
when it happens.

## Reporting a vulnerability

These reviews are proactive, not a substitute for disclosure. To report a security
issue privately, open a [private security advisory](https://github.com/nim444/Svault/security/advisories/new)
on GitHub rather than a public issue.
