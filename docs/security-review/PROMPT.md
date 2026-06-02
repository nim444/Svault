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

**Important**: Review the **latest version** available in the repository (currently **0.9.9**; confirm against `Cargo.toml`). The project has had three dedicated security-hardening releases (0.6.0, 0.7.0, 0.8.0); in 0.9.0 it moved the policy engine from advisory to **enforced**; and 0.9.1–0.9.9 added the AI judge, full at-rest encryption of policy/config, a unified master-keyslot unlock model, a layered library split, a local **MCP** server, **YubiKey** hardware unlock with a 6-hour re-auth cap, and **conditional access + seal/escalate**. Do **not** take any of the changes below on trust — verify each one in the code and look for what it missed, bypasses, or weakens elsewhere:

- **Daemon (Unix, 0.5.0+)** — holds keys in memory, served over a `0600` Unix socket; configurable connection ceiling + per-connection read timeout (0.6.0); key-store lock recovers from poisoning; `daemon::send` retries connects.
- **Socket secrecy (0.7.0, #3)** — the master passphrase is **derived client-side**; only the 32-byte derived key crosses the socket. Check the client (`client.rs`) and daemon (`daemon.rs`) agree and that a wrong passphrase fails locally.
- **Peer-UID bond (0.7.0, #1)** — the daemon calls `getpeereid`/`SO_PEERCRED` and refuses any peer whose UID ≠ its own. Verify the check is correct on both Linux and macOS and can't be bypassed.
- **At-rest secrets (0.7.0, #14/#16/#4)** — `recovery.enc`, export bundles, and the `.session` (which caches the derived **key**, not the passphrase, since 0.6.0) are written owner-only (mode `0600` on Unix, an `icacls` ACL on Windows); `.svault/` and vault dirs are `0700`; the socket is bound under a tight umask. Assess the residual at-rest risk (the key file is still key-equivalent) and whether the Windows ACL is robust.
- **Passphrase entropy floor (0.7.0, #12)** — `create`/`recover` enforce a ~50-bit estimate with a `--force` escape. Judge whether the estimate is sound and the floor meaningful.
- **Memory zeroization (0.7.0, #6)** — prompts, `get_secret` returns, and the TUI reveal are `Zeroizing`. Look for remaining plaintext residue (serde/transport copies, etc.).
- **Supply chain (0.7.0, #9/#10/#11)** — a `cargo audit` CI gate, `ratatui` 0.30 (advisories cleared), SHA-256 checksums + SLSA build-provenance attestation on release artifacts.
- **Graceful shutdown (0.7.0, #17)** — `SIGTERM`/`SIGINT` zeroize keys and clean up.
- **Everything-encrypted-at-rest (0.9.2–0.9.3)** — the **entire policy surface**
  (per-secret scope/tier/`require_reason`/description, caller rules, access
  fallback, judge assignment) is now AES-256-GCM encrypted **inside `vault.enc`**,
  not the signed-but-readable `meta.yaml`; all global config + the judge registry
  (with API keys) live encrypted in `.svault/keyring.enc`. The plaintext
  `config.yaml` / `openrouter.key` are gone. Verify nothing policy-relevant leaks at
  rest in `meta.yaml`, and that a same-UID agent can no longer *read* the tiers/
  scopes to plan a passing request.
- **Unified master keyslot model (0.9.4–0.9.5)** — one master passphrase wraps a
  random data key per store; per-vault and keyring passphrases are gone. The MK is
  wrapped under the passphrase (`master.enc`), a recovery code
  (`master.recovery.enc`), and (0.9.8) a YubiKey (`master.yubikey.enc`). Verify the
  wrap/unwrap (`master.rs`), that "any one slot opens it" is **OR not 2FA**, that a
  wrong passphrase/slot fails closed, and that recovery re-attaches without
  re-encrypting or weakening anything.
- **YubiKey unlock (0.9.8, opt-in `yubikey` feature)** — a FIDO2 **hmac-secret**
  keyslot over the MK (`yubikey.rs`): enroll creates a credential; unlock derives a
  KEK from a touch (+ PIN if set) to unwrap the MK. Verify the hmac-secret is used
  as a KEK (not stored), the credential-id/salt meta is non-secret, and that losing
  the key still leaves passphrase + recovery code working.
- **6-hour re-auth cap (0.9.8)** — every unlock path re-prompts the master at least
  every 6h. File sessions (`.session`, `.master.session`, `.keyring.session`) now
  carry an unlock timestamp and expire at `MAX_SESSION_SECS` (they previously never
  expired); the daemon's in-memory hard cap is the same 6h. Verify a back-dated
  session reads as locked and is removed (`session.rs`), and that the daemon ticker
  enforces it.
- **Local MCP server (0.9.7)** — `svault mcp` is a stdio JSON-RPC frontend over the
  **same** gate (`mcp/mod.rs`). It never sees the master passphrase — it serves only
  from already-unlocked state (daemon keys or the `0600` session key). Verify there
  is **no** privileged or ungated path: every `svault_get_secret` runs
  `gate::gated_get`, a locked vault is a dead end, denials are generic, and the
  capability descriptor advertises the *interface* but never the decision criteria.
- **Conditional access + seal/escalate (0.9.9)** — secrets can carry **time
  windows** (local time) and **required callers** in the encrypted policy, and the
  gate **seals** a medium/high secret after 5 denials in 5 minutes (across any
  caller), persisting the seal into `vault.enc`; a sealed secret denies every agent
  get until a human clears it (`svault approve`). Verify (a) conditions are checked
  before a value is returned and deny generically (no window leak), (b) a seal
  cannot be set, read, or cleared by an agent without the master, (c) the seal
  **write-on-deny** path can't be weaponized (forced `vault.enc` rewrites = DoS;
  note it should short-circuit once sealed), and (d) the deny-counting can't be
  evaded by rotating the self-asserted `--caller`.

**Scrutinize especially — the 0.9.0 enforced engine.** The policy engine is now enforced **inside the daemon**: the agent path is a `GetGated` request (`daemon.rs`) that runs `policy::evaluate` + the AI judge (`judge.rs`/`gate.rs`), audits the decision with the peer UID, and only then returns a value; the CLI runs the same gate locally when no daemon is up. Secret classification (scope/tier/`require_reason`) lives in the **HMAC-signed `meta.yaml`**; the policy file holds only callers, with anchored discovery and fail-closed parsing. Verify, don't trust: (1) that there is **no unguarded read path** — can a same-UID process get a classified secret without passing the gate (e.g. a direct `Get` vs `GetGated`, or `svault secret get`)? (2) that the **judge fail modes** are correct (medium fail-open, high fail-closed) and the judge can't be trivially spoofed or its prompt injected via the `reason`; (3) **key handling** for `$SVAULT_OPENROUTER_KEY` / the `0600` key file (no logging, no leak, refusal on loose perms); (4) that tier/scope **can't be downgraded** by editing `meta.yaml` (HMAC). Also evaluate the **same-UID trust model** the project documents (it is explicitly *not* a sandbox against a hostile same-UID process, which can read daemon memory) — say whether that boundary is reasonable and clearly communicated, and whether the enforced gate is honestly scoped to cooperative/semi-trusted agents + audit.

### Instructions

1. **Work independently** — Clone the repository into a temporary directory yourself (use `git clone`) and perform your own analysis from scratch on the current codebase.
2. **Do not reference or critique** any previous security reviews, findings, or opinions from other AI models. Your review must stand completely on its own.
3. Perform real technical work:
   - Explore the full source code, with particular focus on:
     - The daemon implementation (`src/daemon/mod.rs`)
     - The client routing layer (`src/daemon/client.rs`)
     - How the daemon interacts with the rest of the system
     - Changes to security model, session handling, and threat assumptions
   - Review the CI/CD and release workflows.
   - Run relevant security and quality tools (`cargo test`, `cargo clippy`, `cargo audit`, etc.).
   - Analyze on-disk formats, key derivation, encryption, secret lifecycle, policy evaluation, recovery mechanisms, file permissions, and the new daemon architecture.
4. Adopt the mindset of a **corporate security manager** evaluating whether this tool is suitable for use in a medium or large company, including on servers, CI/CD pipelines, and developer infrastructure.

### Areas You Must Cover (With Special Emphasis)

- Cryptographic design and implementation quality
- Secret handling (memory safety, zeroization, logging, exposure windows)
- **The policy engine for AI/agent access — is the 0.9.0 enforcement sound?** Trace the `GetGated` daemon path (`daemon.rs` → `gate::authorize` → `policy::evaluate` + `judge::evaluate` → audit). Confirm there is **no unguarded path** to a classified secret, that classification in the signed `meta.yaml` can't be tampered without the key, that policy discovery is anchored + fails closed, and that the AI-judge fail modes (medium fail-open, high fail-closed) and key handling are correct. This is the headline claim; weigh it honestly.
- **The Unix daemon (0.5.0+)**: architecture, socket model + `0600`/umask, peer-UID bond (#1), client-side key derivation (#3, passphrase off the socket), connection ceiling / read timeout, poison recovery, auto-lock, graceful shutdown (#17)
- **Secrets at rest (0.7.0)**: owner-only `.session` (key, not passphrase), `recovery.enc`, export bundles; `0700` dirs; Windows ACL via `icacls` (#4/#14/#16). Assess residual risk (key-equivalent files) and robustness of the Windows path
- **Encrypted policy + master keyslot model (0.9.2–0.9.5)**: confirm the whole policy surface is encrypted in `vault.enc` (nothing exploitable in `meta.yaml`), and audit the keyslot wrap/unwrap (`master.rs`) — OR-not-2FA, fail-closed on a wrong slot, recovery soundness
- **YubiKey FIDO2 keyslot + 6h re-auth cap (0.9.8)**: hmac-secret used as a KEK (not stored), opt-in feature isolation (no system deps in the base crate), and timestamped session expiry across file sessions + daemon (`session.rs`)
- **MCP server (0.9.7)**: `svault mcp` is a thin gate frontend — no ungated/privileged path, never sees the passphrase, locked = dead end, generic denials, descriptor leaks no criteria (`mcp/mod.rs`)
- **Conditional access + seal/escalate (0.9.9)**: windows/required-callers deny generically (no window leak); seals live encrypted and are human-clear-only; the deny-write seal path isn't a DoS or `--caller`-rotation bypass (`policy.rs`, `gate.rs`)
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

[Prioritized, actionable, reflecting the current 0.9.0 state — and say whether the enforced policy engine + AI judge are sound enough to support a 1.0.0 "stable" label, or what must change first]

## Overall Risk Assessment by Context

[Use a table with contexts like: Personal use (Unix + daemon), Small team, Corporate CI/CD with AI agents on Unix, High-security production infrastructure, Mixed Windows environments, etc.]

## References

- Link to key files in the repo you analyzed (especially `src/daemon/mod.rs`, `src/daemon/client.rs`, `src/core/policy.rs`, `src/core/gate.rs`, `src/core/judge.rs`, `src/core/master.rs`, `src/core/keyring.rs`, `src/core/yubikey.rs`, `src/core/session.rs`, `src/core/secfile.rs`, `src/mcp/mod.rs`, `docs/security.md`, `docs/daemon.md`, `docs/policy-engine.md`, `docs/mcp.md`, the release/lint workflows, and the prior findings registers under `docs/security-review/findings/`)
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

**This prompt is intentionally kept current** with Svault’s latest version (0.9.9) and major features — the Unix daemon (0.5.0), the 0.6.0–0.8.0 security hardening, the **0.9.0 enforced policy engine + AI judge**, full at-rest encryption + the unified master keyslot (0.9.2–0.9.5), the local **MCP** server (0.9.7), **YubiKey** unlock + the 6-hour re-auth cap (0.9.8), and **conditional access + seal/escalate** (0.9.9) — so other models can produce relevant, fresh, and unbiased security reviews. This is the full agent-ready surface that the 1.0.0 independent review must cover; update it again as the security model evolves.