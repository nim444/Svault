# Security Review & Audit

Svault is a secret manager, so its own security posture is part of the product. To
keep that honest and verifiable, **every minor release (`0.x.0`) goes through a full
security review and bulletproofing pass before it ships.** Patch releases (`0.x.y`)
inherit the most recent minor review unless they change the security model.

This folder is the record of that process: the prompt used to commission independent
reviews, and the resulting review for each release.

## Contents

| File | What it is |
|---|---|
| [PROMPT.md](PROMPT.md) | A reusable, model-agnostic prompt for commissioning an **independent** security review of the current codebase. Kept current with the latest released version and features. |
| [reviews/](reviews/) | The reviews themselves, named `<version>-<reviewer>.md` (more than one independent reviewer per release is encouraged). |
| [findings/](findings/) | The consolidated **findings register** per release — every reviewer's findings de-duplicated into one table with cross-model agreement, our disposition, and justification notes. This is the document of record for what we decided and why. |

## Reviews

Per release, the findings from every reviewer below are consolidated into one decision
log: **[findings/0.5.0.md](findings/0.5.0.md)**.

| Version | Date | Reviewer | Overall posture | Review |
|---|---|---|---|---|
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
5. **Triage findings.** Every High/Critical finding is either fixed before release or
   explicitly accepted in writing (with rationale) in the register and the
   [roadmap](../roadmap.md).
6. **Carry forward.** Open items become tracked work; the next release's register
   re-states each prior finding as *fixed*, *improved*, or *unchanged*.

## Why independent review

The author of a system is the worst judge of its weaknesses. Using a separate model —
working only from the public source tree and the neutral prompt — keeps the assessment
unbiased and reproducible: anyone can run the same prompt and compare results. Reviews
are kept blunt and evidence-based, not marketing.

## Reporting a vulnerability

These reviews are proactive, not a substitute for disclosure. To report a security
issue privately, open a [private security advisory](https://github.com/Soluzy/Svault/security/advisories/new)
on GitHub rather than a public issue.
