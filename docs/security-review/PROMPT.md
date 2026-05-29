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

**Important**: Review the **latest version** available in the repository (as of your knowledge cutoff or by inspecting the code directly). Pay special attention to the Unix daemon (added in 0.5.0) and the 0.6.0 security-hardening changes: the file session now caches the derived **key** rather than the passphrase, the daemon has a configurable connection ceiling + per-connection read timeout, the key-store lock recovers from poisoning, and `daemon::send` retries connects. Do not assume these are correct — verify them and look for what they missed.

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
- The policy engine for AI/agent access
- **The Unix daemon (0.5.0+)**: architecture, security properties, limitations, socket model, auto-lock behavior, the connection ceiling / read timeout (0.6.0), and how it changes the previous on-disk risk
- **Session at rest (0.6.0)**: the file session now stores the derived key (hex, mode 0600), not the passphrase — assess the residual risk (key-equivalent at rest, Windows ACL gap) and whether key-vs-passphrase materially helps
- Recovery and portability features
- Supply chain security (dependencies, build & release process, distribution)
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

[Prioritized, actionable, reflecting the current (0.6.0) state]

## Overall Risk Assessment by Context

[Use a table with contexts like: Personal use (Unix + daemon), Small team, Corporate CI/CD with AI agents on Unix, High-security production infrastructure, Mixed Windows environments, etc.]

## References

- Link to key files in the repo you analyzed (especially daemon.rs, client.rs, security.md, daemon.md)
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

**This prompt is intentionally kept current** with Svault’s latest released version and major features (especially the Unix daemon added in 0.5.0) so other models can produce relevant, fresh, and unbiased security reviews.