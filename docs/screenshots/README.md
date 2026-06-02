# Screenshots — capture guide

Drop each screenshot here using the **exact filename** below, so the README and docs
can reference stable paths (`docs/screenshots/<name>.png`). Capture these during the
manual [QA pass](../qa-checklist.md) — the section in brackets is where each shot is
produced. PNG, light terminal background ideally, crop to the panel (no desktop chrome).

> Tip: run the TUI in a clean store so timelines look tidy:
> `export SVAULT_HOME=/tmp/svault-shots` then `svault`.

| # | Filename | What to capture | Used in |
|---|----------|-----------------|---------|
| 1 | `dashboard.png` | TUI home — header showing `daemon running` + the Activity timeline with a few events | README hero, [tui.md](../tui.md) |
| 2 Done| `onboarding-disclaimer.png` | First-run disclaimer / same-UID boundary screen (the honest-scope accept) | README positioning, [security.md](../security.md) |
| 3 | `onboarding-recovery.png` | The one-time master recovery-code screen | [tui.md](../tui.md), [recovery.md](../recovery.md) |
| 4 | `vault-list.png` | Vault list showing locked vs unlocked vaults | README, [tui.md](../tui.md) |
| 5 | `classify-form.png` | The `c` reclassify form with Scope / Tier / Windows / Required-callers fields visible | [policy-engine.md](../policy-engine.md), [tui.md](../tui.md) |
| 6 | `secret-sealed.png` | Secret browser with a SEALED secret (red marker + "press A to approve") | [policy-engine.md](../policy-engine.md) (seal & escalate) |
| 7 | `policy-check.png` | `svault policy check <caller>` output — access + conditions + seals (CLI, not TUI) | [commands.md](../commands.md), [policy-engine.md](../policy-engine.md) |
| 8 | `mcp-allow.png` | An MCP client (Claude Code) calling `svault_get_secret` and getting a `get.allow` | README, [mcp.md](../mcp.md) |
| 9 | `mcp-deny.png` | An MCP `get.deny` (generic message to the agent) | [mcp.md](../mcp.md), [security.md](../security.md) |
| 10 | `timeline-deny-allow.png` | Activity timeline showing a deny → (fix) → allow on the same secret (the audit-honesty story) | README, [policy-engine.md](../policy-engine.md) |

## Optional / nice-to-have

| Filename | What to capture |
|----------|-----------------|
| `judge-screen.png` | The TUI judge manager (`shift-J`) — judges, thresholds, criteria |
| `yubikey-touch.png` | The in-TUI "Touch your YubiKey" modal during unlock (hardware build) |
| `pending-approve.png` | `svault pending` listing a sealed secret, then `svault approve` clearing it |

Once a file is here, reference it in docs as e.g.
`![Svault dashboard](docs/screenshots/dashboard.png)` (README) or
`![…](screenshots/dashboard.png)` (from inside `docs/`).
