# Independent Security Review Prompt for Svault (Current Version)

This file contains a reusable, high-quality prompt you can copy and give to **any other AI model** (Claude, GPT-4o/o3, Gemini, etc.) so they can perform their own independent security review of the current Svault codebase.

The prompt is kept up to date with the latest released version and major features.

---

## How to Use This Prompt

1. Copy everything inside the **"COPY BELOW THIS LINE"** section.
2. Paste it into another AI.
3. Optionally add: "Please clone or use the current source tree and review the latest version."
4. The prompt already directs the model to focus on the current state, including the daemon.
5. Save the returned review as `reviews/<version>-<reviewer>.md` in this folder and add it to the index in [README.md](README.md). More than one independent reviewer per release is encouraged.

See [README.md](README.md) for the full release-by-release security review process.

---

## COPY BELOW THIS LINE

```
You are a senior corporate application security engineer and security architect with 15+ years of experience performing security reviews of open source security tooling for medium and large enterprises.

Your task is to conduct a thorough, independent, professional-grade security review of the Svault project in its **current released state**:

**Repository**: https://github.com/Soluzy/Svault
**Description**: An AI-aware secret manager written in Rust. It sits between AI agents and credentials, enforcing structured requests (scope + reason) and policy controls.

**Important**: Review the **latest version** available in the repository (currently **0.9.0**; confirm against `Cargo.toml`). The project has had three dedicated security-hardening releases (0.6.0, 0.7.0, 0.8.0) and, in 0.9.0, moved the policy engine from advisory to **enforced**. Do **not** take the changes below on trust — verify each one in the code and look for what it missed, bypasses, or weakens elsewhere:

- **Daemon (Unix, 0.5.0+)** — holds keys in memory, served over a `0600` Unix socket; configurable connection ceiling + per-connection read timeout (0.6.0); key-store lock recovers from poisoning; `daemon::send` retries connects.
- **Socket secrecy (0.7.0, #3)** — the master passphrase is **derived client-side**; only the 32-byte derived key crosses the socket. Check the client (`client.rs`) and daemon (`daemon.rs`) agree and that a wrong passphrase fails locally.
- **Peer-UID bond (0.7.0, #1)** — the daemon calls `getpeereid`/`SO_PEERCRED` and refuses any peer whose UID ≠ its own. Verify the check is correct on both Linux and macOS and can't be bypassed.
- **At-rest secrets (0.7.0, #14/#16/#4)** — `recovery.enc`, export bundles, and the `.session` (which caches the derived **key**, not the passphrase, since 0.6.0) are written owner-only (mode `0600` on Unix, an `icacls` ACL on Windows); `.svault/` and vault dirs are `0700`; the socket is bound under a tight umask. Assess the residual at-rest risk (the key file is still key-equivalent) and whether the Windows ACL is robust.
- **Passphrase entropy floor (0.7.0, #12)** — `create`/`recover` enforce a ~50-bit estimate with a `--force` escape. Judge whether the estimate is sound and the floor meaningful.
- **Memory zeroization (0.7.0, #6)** — prompts, `get_secret` returns, and the TUI reveal are `Zeroizing`. Look for remaining plaintext residue (serde/transport copies, etc.).
- **Supply chain (0.7.0, #9/#10/#11)** — a `cargo audit` CI gate, `ratatui` 0.30 (advisories cleared), SHA-256 checksums + SLSA build-provenance attestation on release artifacts.
- **Graceful shutdown (0.7.0, #17)** — `SIGTERM`/`SIGINT` zeroize keys and clean up.

**Scrutinize especially — the 0.9.0 enforced engine.** The policy engine is now enforced **inside the daemon**: the agent path is a `GetGated` request (`daemon.rs`) that runs `policy::evaluate` + the AI judge (`judge.rs`/`gate.rs`), audits the decision with the peer UID, and only then returns a value; the CLI runs the same gate locally when no daemon is up. Secret classification (scope/tier/`require_reason`) lives in the **HMAC-signed `meta.yaml`**; the policy file holds only callers, with anchored discovery and fail-closed parsing. Verify, don't trust: (1) that there is **no unguarded read path** — can a same-UID process get a classified secret without passing the gate (e.g. a direct `Get` vs `GetGated`, or `svault secret get`)? (2) that the **judge fail modes** are correct (medium fail-open, high fail-closed) and the judge can't be trivially spoofed or its prompt injected via the `reason`; (3) **key handling** for `$SVAULT_OPENROUTER_KEY` / the `0600` key file (no logging, no leak, refusal on loose perms); (4) that tier/scope **can't be downgraded** by editing `meta.yaml` (HMAC). Also evaluate the **same-UID trust model** the project documents (it is explicitly *not* a sandbox against a hostile same-UID process, which can read daemon memory) — say whether that boundary is reasonable and clearly communicated, and whether the enforced gate is honestly scoped to cooperative/semi-trusted agents + audit.

### Instructions

1. **Work independently** — Clone the repository into a temporary directory yourself (use `git clone`) and perform your own analysis from scratch on the current codebase.
2. **Do not reference or critique** any previous security reviews, findings, or opinions from other AI models. Your review must stand completely on its own.
3. Perform real technical work:
   - Explore the full source code, with particular focus on:
     - The new daemon implementation (`src/daemon.rs`)
     - The client routing layer (`src/client.rs`)
     - How the daemon interacts with the rest of the system
     - Changes to security model, session handling, and threat assumptions
   - Review the CI/CD and release workflows.
   - Run relevant security and quality tools (`cargo test`, `cargo clippy`, `cargo audit`, etc.).
   - Analyze on-disk formats, key derivation, encryption, secret lifecycle, policy evaluation, recovery mechanisms, file permissions, and the new daemon architecture.
4. Adopt the mindset of a **corporate security manager** evaluating whether this tool is suitable for use in a medium or large company, including on servers, CI/CD pipelines, and developer infrastructure.

### Areas You Must Cover (With Special Emphasis)

- Cryptographic design and implementation quality
- Secret handling (memory safety, zeroization, logging, exposure windows)
- **The policy engine for AI/agent access — is it actually enforced?** Trace whether `svault get`'s caller/scope/reason and tiers gate anything at the daemon, or are purely advisory/audit. Assess the unsigned policy file + upward search. This is the headline claim; weigh it honestly.
- **The Unix daemon (0.5.0+)**: architecture, socket model + `0600`/umask, peer-UID bond (#1), client-side key derivation (#3, passphrase off the socket), connection ceiling / read timeout, poison recovery, auto-lock, graceful shutdown (#17)
- **Secrets at rest (0.7.0)**: owner-only `.session` (key, not passphrase), `recovery.enc`, export bundles; `0700` dirs; Windows ACL via `icacls` (#4/#14/#16). Assess residual risk (key-equivalent files) and robustness of the Windows path
- Passphrase strength enforcement (entropy floor + `--force`, #12)
- Recovery and portability features
- Supply chain security: the `cargo audit` CI gate, dependency tree, build & release process, checksums + SLSA provenance (#9/#10/#11)
- Code quality, testing coverage, and attack scenario coverage
- Operational and infrastructure risks
- **Dedicated section**: Suitability for servers, CI/CD, build agents, and infrastructure use cases — including the impact of the new daemon on Unix vs. the situation on Windows and other environments

### Output Format (Use This Structure)

**Project**: Svault (Soluzy/Svault)
**Version reviewed**: [fill in the actual version from Cargo.toml at the time of review]
**Review date**: [use current date and time]
**Reviewed by**: [Name of the model you are using]
**Review location**: [mention if you cloned it locally]

## Executive Summary

[Clear overall risk rating for corporate/medium company use + 3-5 sentence summary. Explicitly call out the effect of the daemon on the risk posture.]

## Scope & Methodology

[What you actually did — files reviewed, tools run, special focus on the daemon, etc.]

## Security Findings

### Critical / High Severity
[Table or detailed findings with evidence and file references. Include the current state of the daemon vs. old session behavior.]

### Medium Severity

### Low / Informational

## Positive Security Properties Observed

## The Unix Daemon (0.5.0+) — Detailed Analysis

[Dedicated section — very important. Cover architecture, security benefits, remaining risks, permission model, auto-lock, and operational implications.]

## Infrastructure, Server & CI/CD Deployment Considerations

[Dedicated section]
- Current limitations and improvements due to the daemon
- Recommended safe usage patterns on Unix servers and CI today
- Risks on Windows and non-Unix environments
- Recommendations for high-value secrets

## Recommendations for Corporate Adoption

[Prioritized, actionable, reflecting the current 0.7.0 state — and say whether policy enforcement (#2/#5) should block a 1.0.0 "stable" label]

## Overall Risk Assessment by Context

[Use a table with contexts like: Personal use (Unix + daemon), Small team, Corporate CI/CD with AI agents on Unix, High-security production infrastructure, Mixed Windows environments, etc.]

## References

- Link to key files in the repo you analyzed (especially `src/daemon.rs`, `src/client.rs`, `src/policy.rs`, `src/secfile.rs`, `src/session.rs`, `docs/security.md`, `docs/daemon.md`, the release/lint workflows, and the prior findings registers under `docs/security-review/findings/`)
- Any external resources you consulted

Be professional, direct, evidence-based, and balanced. Quote specific code paths or design decisions when they are relevant to your conclusions. Avoid hype or unnecessary negativity.

Perform this review as if you are presenting it to a company's security committee that is deciding whether to allow the tool in its current form.
```

---

## Tips for Best Results

- **Claude 4 / Claude 3.5 / 4 Sonnet**: Usually excellent at deep code analysis of the daemon.
- **GPT-4o / o3 / o4-mini**: Good at structured output and risk framing.
- Tell the model explicitly to focus on `daemon.rs` and `client.rs` if it seems to be overlooking the new feature.
- After receiving the other review, you can compare the two assessments side-by-side.

---

**This prompt is intentionally kept current** with Svault’s latest version (0.9.0) and major features — the Unix daemon (0.5.0), the 0.6.0–0.8.0 security hardening, and the **0.9.0 enforced policy engine + AI judge** — so other models can produce relevant, fresh, and unbiased security reviews. Update it again as the security model evolves toward 1.0.0.