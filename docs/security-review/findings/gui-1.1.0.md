# Svault GUI 1.1.0 — Security findings (deep dive)

> **Scope: the desktop GUI only** (`gui/` — the Tauri backend in
> `gui/src-tauri/src/` and the React frontend in `gui/src/`). The `core`,
> `daemon`, policy engine, and AI judge are out of scope here — they are covered
> by the main [findings register](0.9.9.md) and [security.md](../../security.md).
> This document gathers the attack surface the GUI *adds* on top of that core.

- **Component:** `svault-gui` 1.1.0 (Tauri 2, React 19, `svault-cli` as a linked lib)
- **Date:** 2026-06-06
- **Reviewer:** maintainer pre-review (self-audit, no independent GUI review yet)
- **Trust model inherited from core:** single-user, **same-UID cooperative**. The
  GUI does not claim to defend against another process running as the same user —
  that process can already read `~/.svault` files directly. The findings below are
  about surface the GUI introduces *within* that model, and the defense-in-depth
  gaps that matter if the **webview** itself is ever subverted (a malicious string
  reaching the renderer, a supply-chain'd npm dep, or a dev build with devtools).

## Why the webview is a real trust boundary

The GUI's stated design is "all secret-handling stays in Rust; the React frontend
only sends structured commands and renders results" (`lib.rs`). That is true for
*crypto*, but the frontend is **not** a passive renderer from a security view:

- It renders strings an **agent controls** — `caller`, the request `reason`, the
  judge `rationale`, audit denial reasons, provider model names. An agent is the
  adversary in Svault's threat model, and its text reaches the renderer.
- It holds **decrypted secret values** in JS heap (reveal modal) and pushes them
  to the OS clipboard.
- It can invoke **file-write and file-read IPC commands with arbitrary paths**.

So "is the webview trustworthy?" is a live question, and several findings below
are about hardening that boundary. The single most important config fact:
**CSP is disabled** (`tauri.conf.json` → `"security": { "csp": null }`), which
removes the one cheap, blanket mitigation for renderer compromise.

## Findings

| # | Severity | Title | Status |
|---|----------|-------|--------|
| G-1 | High | Arbitrary-path file **write** primitives exposed as IPC commands | Open |
| G-2 | High | Content-Security-Policy disabled (`csp: null`) | Open |
| G-3 | Medium | `change_master` rekeys with no current-passphrase / re-auth check | Open |
| G-4 | Medium | Clipboard: plaintext secret copied with no auto-clear; `read-text` over-granted | Open |
| G-5 | Medium | Read-only commands bypass the master-session gate (audit/diagnostics readable while "locked") | By-design, document |
| G-6 | Low | Provider `base_url` not constrained to HTTPS — API key / judge context can leave over cleartext | Open |
| G-7 | Low | Judge **test bench** sends a user-typed sample secret to the live third-party model | By-design, label it |
| G-8 | Low | `opener` capability granted but unused (over-grant) | Open |
| G-9 | Low | Decrypted secret residue in the JS heap / IPC buffer is not (cannot be) zeroized | Residual, document |
| G-10 | Info | Devtools must stay off in release; verify no `withGlobalTauri` | Verify |
| G-11 | Info (resolved) | Daemon-autostart fork-bomb via case-insensitive sidecar match | Fixed — keep the guard |

---

### G-1 (High) — Arbitrary-path file-write IPC primitives

Three commands accept a caller-supplied destination `path: String` and write to
it with no constraint on where it points:

- `audit::export_log(leaf_id, path)` → `std::fs::write(&path, json)` (`audit.rs:138`)
- `mcp::write_mcp_config(path, bin, caller)` → `std::fs::write(&path, …)` (`mcp.rs:128`),
  with `bin`/`caller` strings landing inside the written JSON
- `backup::export_vault(leaf_id, path)` → `secfile::write_owner_only(path, …)` (`backup.rs:20`)

And two read primitives: `backup::import_vault(path, …)` and the `recover_master`
flow read arbitrary paths.

In normal use the frontend picks `path` via the dialog plugin, so a human chooses
the target. But the **backend command trusts the path unconditionally** — it does
not verify the path came from a dialog, sits under the store, or has an expected
extension. If the renderer is ever subverted (see G-2), these become a direct
**write-what-where** primitive: a malicious frontend can call
`writeMcpConfig("~/.zshrc", "...", "...")` or `export_log(leaf, "~/.bashrc")` to
plant attacker-controlled content into a shell rc file, `~/.ssh/authorized_keys`,
a launch agent, etc. — i.e. XSS-to-RCE. `export_vault` is the least bad (content
is an encrypted bundle, written owner-only) but still lets a path be clobbered.

**Recommendation:** treat these paths as untrusted in the backend. Options, in
order of strength: (a) have the backend itself open the OS save-dialog and never
accept a path from the frontend; or (b) canonicalize and require the target to be
within an allowed root (the store, the user's Documents/Downloads) and reject
paths that traverse to dotfiles or resolve through symlinks; or at minimum
(c) refuse to overwrite an existing file the GUI didn't create, and pin an
expected extension (`.json`, `.svault`). Combine with G-2 so a renderer
compromise can't reach the primitive in the first place.

### G-2 (High) — CSP disabled

`tauri.conf.json` sets `"csp": null`. With no Content-Security-Policy the webview
will execute inline script and load/connect anywhere if any HTML injection ever
occurs. Today React escapes interpolated text and the codebase has **no**
`dangerouslySetInnerHTML`, `innerHTML`, `eval`, or `new Function` (verified), so
there is no *known* injection sink — but CSP is precisely the defense-in-depth
that contains the unknown one (a future `dangerouslySetInnerHTML`, a markdown
renderer for judge rationales, a vulnerable transitive npm dep). Given that
agent-controlled strings reach this renderer and G-1 hands it file-write power, a
strict CSP is high-value.

**Recommendation:** set a strict CSP, e.g.
`default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';
img-src 'self' data:; connect-src 'self' ipc: http://ipc.localhost;
object-src 'none'; frame-src 'none'; base-uri 'none'`. Note the judge/provider
**network calls run in Rust, not the webview**, so `connect-src` does not need to
allow provider URLs — confirm nothing in the frontend does a direct `fetch` to a
provider before tightening.

### G-3 (Medium) — `change_master` needs no current-passphrase

`settings::change_master(new_passphrase)` calls `require_master()` (the cached
session) then `m.rekey(&new)` — it **never asks for the current passphrase**. So
anyone at an unlocked, signed-in GUI can rotate the master passphrase to one they
choose: they don't need to know the old one, and the legitimate user is then
locked out of the new passphrase (they'd fall back to the recovery code). Same
class of exposure: `reveal_secret`, `export_vault`, `enroll_yubikey` all act off
the cached session with no step-up. The GUI "sign-in" gate that would stop a
walk-up attacker is **frontend-only** (`store/session.ts`, a zustand flag) and is
not enforced by any backend command — the real gate is the core master session.

This is partly inherent to the "unlocked laptop" threat, but a destructive,
account-takeover-grade action like rekey deserves a step-up.

**Recommendation:** require the current passphrase (or a fresh YubiKey touch) in
`change_master` specifically — re-derive and verify before `rekey`. Consider the
same step-up for `remove_yubikey` and `export_vault`.

### G-4 (Medium) — Clipboard handling

Reveal (`Secrets.tsx`), the recovery codes (`Onboarding.tsx`, `VaultConfig.tsx`,
`Backup.tsx`), and diagnostics all copy via `writeText`. Two issues:

1. **No auto-clear.** A revealed secret / recovery code is left on the OS
   clipboard indefinitely, where every other app and clipboard-history manager
   (macOS Universal Clipboard, third-party managers) can read it. There is no TTL
   or "clear after N seconds" and no clear-on-lock.
2. **`clipboard-manager:allow-read-text` is granted** (`capabilities/default.json`)
   but the app only ever *writes* — no `readText` in the frontend. Read is an
   unnecessary capability: a subverted renderer could harvest whatever the user
   has on their clipboard (often other passwords).

**Recommendation:** drop `allow-read-text` from the capability set (keep
`allow-write-text`). For revealed secrets/codes, clear the clipboard after a short
timeout and on Lock-all, and tell the user it was copied + will clear.

### G-5 (Medium, by-design) — read-only commands skip the master gate

`audit_events`, `audit_callers`, `connected_agents`, `recovery_status`,
`daemon_info`, `diagnostics`, `store_folder`, `mcp_enabled` read straight from
disk and **do not** call `require_master()`. They surface secret *names*, scopes,
callers, **real denial reasons**, and peer UIDs from the append-only audit log
even when the GUI presents as "locked." Because the audit log is a `0600` file
the same UID can read anyway, this is **not** a privilege escalation — but it does
mean the lock UX is weaker than it looks, and it widens what a subverted renderer
can read without unlocking.

**Recommendation:** accept as same-UID by-design, but document it in the GUI
security notes, and consider gating the audit/policy *screens* behind the
master-unlocked session so "locked" visibly means "no sensitive data on screen."

### G-6 (Low) — provider `base_url` not pinned to HTTPS

`provider_save` accepts any `base_url` (only trims a trailing slash). `judge_test`
and `provider_models` then send the **API key** (and, for a real judge call, the
request context: caller, reason, secret, scope) to that URL. A user who types an
`http://` base — or whose stored config is tampered — sends the key and context
in cleartext. `local` providers legitimately use `http://localhost`, so a blanket
HTTPS requirement is wrong, but non-local cleartext should be refused or warned.

**Recommendation:** require `https://` for non-`local` provider kinds (allow
`http://localhost`/`127.0.0.1`/`::1` for `local`); warn in the UI otherwise.

### G-7 (Low, by-design) — test bench sends a sample secret to the model

`judge_test` runs the **real** model against the form's `secret`/`reason` fields.
A user testing their policy may paste a *real* secret value to "see what the judge
does," shipping it to the third-party provider. This is inherent to a live test
bench, but the field invites it.

**Recommendation:** label the secret field as a *sample / placeholder* that is
sent to the provider, and pre-fill a dummy; never echo a real stored value into
it.

### G-8 (Low) — `opener` capability over-granted

`tauri-plugin-opener` is registered and `opener:default` is in the capability set,
but no frontend code calls it (verified — no `openUrl`/`openPath`/opener import in
`src/`). An unused URL/path opener is latent surface (a subverted renderer could
`open` an arbitrary URL or file).

**Recommendation:** if nothing opens external URLs/paths, drop the plugin and the
`opener:default` permission. If a "reveal in folder / open log folder" affordance
is planned, scope the permission to that.

### G-9 (Low, residual) — plaintext secret residue in JS / IPC

`reveal_secret` returns the value as a JSON `String` across the Tauri IPC, where
it lives in the renderer's JS heap (`revealed` state) and the IPC buffer.
JavaScript strings are immutable and **cannot be zeroized** — unlike the Rust
side, which uses `Zeroizing`. The value persists until GC, and longer if devtools
or a heap snapshot is taken. The GUI therefore *widens* the in-memory plaintext
window compared to the CLI. Consistent with the same-UID model, but real.

**Recommendation:** document it; minimize lifetime (clear `revealed` on modal
close / route change / lock, which the code largely does); never log it; keep
devtools off in release (G-10).

### G-10 (Info) — verify devtools off in release

Tauri only enables the inspector in debug by default, and the config does not set
`app.windows[].devtools` or `withGlobalTauri`. Good — but a shipped devtools build
would expose the IPC and the JS heap (G-9) to anyone at the machine. Keep it off
and add it to the release checklist.

### G-11 (Info, resolved) — daemon-autostart fork-bomb guard

`autostart_daemon` / `locate_sidecar` already defend against running the GUI's own
`Svault` binary as the daemon (which would relaunch the GUI → re-autostart → fork
bomb) on case-insensitive macOS/Windows filesystems: it matches sidecar names
case-sensitively and rejects the current exe by **canonical path** (`lib.rs:52`,
`settings.rs:178`). Noted here so the guard isn't lost in a refactor — it is a
correctness *and* availability control.

## Summary of the highest-value fixes

1. **Lock down the file-path commands (G-1)** and **turn on a strict CSP (G-2)** —
   together they close the XSS-to-arbitrary-write chain, the only path by which a
   renderer bug becomes code execution.
2. **Step up `change_master` (G-3)** and **stop copying/holding the clipboard
   read capability, add clipboard auto-clear (G-4)** — the two walk-up / leak
   issues a real user is most likely to hit.
3. The rest are defense-in-depth and labeling: HTTPS pinning (G-6), test-bench
   labeling (G-7), dropping the unused `opener` grant (G-8), and the documented
   residuals (G-5, G-9, G-10).

None of these break the inherited core trust model; they harden the **new**
surface the desktop app introduces — the webview as a possible adversary and the
IPC command set as a capability boundary.
