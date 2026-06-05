# Svault GUI — UX fix tracker

Per-screen log of UX changes during the v2.0.0 GUI polish pass. Status legend:
**OK** = user-approved, **WIP** = in progress / awaiting review.

Functionality is considered correct across the board; this pass is purely UX.

## Onboarding flow

### Splash — OK
- First-run only (renders before setup; returning users go straight to Sign in).
- "Svault" title rises 10px + fades in over 0.5s.
- Tagline "secret access layer for AI agents" rises + fades in 0.1s after the
  title settles.
- "Get Started" button fades in last, advances into Terms.
- Whole entrance lands in ~1.6s (under the 5s target).

### Terms — OK
- No changes requested; approved as-is.

### Passphrase — OK
- No changes requested; approved as-is.

### Recovery — OK
- Warning text "Shown once, never stored in plaintext…" now in red.
- Recovery code box recolored from amber to green.
- "I've stored this somewhere safe" checkbox label is now semibold.
- "Continue" is clearly disabled (muted gray, no pointer) until the box is
  checked, then flips to the full primary button.

### YubiKey — OK
- Added copy stating the key must be touched **twice** (once to register, once to
  confirm): a help line when ready, and the busy button now reads
  "Touch your key twice…".
- Confirmed working by user.

## App shell

### Getting started (home) — WIP
- New first page after sign-in: a four-step checklist instead of dropping
  straight into the vault list. The index route lands there until the store has
  a vault with at least one secret; from then on the vault list is home.
- Step 1: **Add an AI provider** — inline OpenRouter API key form (stored
  encrypted in the keyring as a named provider).
- Step 2: **Create a judge (optional)** — pick a provider + model, defaults for
  thresholds; creating it also flips the global judge switch on. Locked until a
  provider exists.
- Step 3: **Create a vault** — navigates to the create form.
- Step 4: **Add a secret** — navigates to the first vault; locked until a vault
  exists.
- Sidebar shows a "Getting started" entry with a remaining-step badge while
  incomplete; it disappears once steps 1/3/4 are done (judge stays optional).

### Sidebar icons — WIP
- Every nav item now carries a small lucide icon (Vault, Scale, Plug,
  ScrollText, Hourglass, ArchiveRestore, Settings; ListChecks for Getting
  started).

### Judge options hidden until a judge is active — WIP
- "Active" = global judge switch on **and** at least one judge defined.
- Until then: the vault list drops its Judge column, vault config hides the
  AI-judge field, and the secret form hides "Always judge"; tier hints switch
  to "medium/high are human-only until an AI judge is active."

### AI providers (own sidebar section) — WIP
- Promoted out of Judges & Policy into a dedicated "AI providers" screen with
  its own sidebar item: add, edit, **enable/disable** (disabled = its judges go
  keyless, gate falls back to human-only for medium/high; nothing deleted),
  **set default**, remove (refused while a judge references it).
- Four kinds: openrouter, openai, anthropic (OpenAI-compat endpoint), local
  (Ollama/LM Studio — no API key needed). Kind prefills the base URL; one
  shared judge transport.
- The judge editor's Provider select lists only enabled providers and the
  model field became a **live model picker** (fetched from the provider's
  /models endpoint, free text fallback). Choosing a provider hides the
  per-judge API key field.
- Getting-started step 1 gained the kind select (key optional for local).
- Add/Edit now open in a centered **modal with a blurred backdrop** instead of
  an inline card under the list.
- Per-provider **Test** button: live-calls the provider's /models endpoint.
  The result shows as a bottom-right **toast** (new shared `Toast` primitive,
  rise-in animation): green "valid — N models available" for 2s on success;
  failures stay 5s so the real error is readable.
- Provider list is a **responsive tile grid** — 1 column narrow, 2 from md,
  3 from xl — growing right and down instead of a capped single column in a
  sea of empty space. Cards restructured as tiles: badges + enable toggle on
  top, URL/usage/test result in the middle, action row pinned at the bottom.

### Guardian (Judges) — WIP
- Sidebar item renamed **Judges & Policy → Guardian** (page title too); first
  sub-tab is now just "Judges".
- The always-visible Live test panel is gone — each judge card has a **Test**
  button that opens the live test in a modal, pre-targeting that judge. Judge
  cards are a responsive grid (1/2/3 columns) like providers.
- Judge registry redesigned as **cards** (provider logo, name, default / no-key
  badges, model in mono, "via provider · allow ≥60 · high ≥80" summary line,
  Set default / Edit / Remove actions) — the old cramped inline editor is gone.
- Remove is now confirm-gated, explaining the fallback (vaults fall back to the
  default judge; none left = medium/high go human-only).
- **Add/Edit is a 3-step wizard in a modal** (blurred backdrop, step indicator):
  1. **Provider** — pick an enabled provider (default pre-selected). With no
     provider available the wizard explains it instead of dead-ending: "without
     a provider the judge has no model to reason with — only static policies
     apply and medium/high stay human-only", with an "Add a provider" button.
  2. **Model** — live dropdown of the provider's models with a
     **(recommended)** pick pre-selected per kind (gemini-flash for OpenRouter,
     4.1-mini for OpenAI, haiku for Anthropic, llama3-class for local); free
     text fallback when the list can't load.
  3. **Tuning** — name, Allow/High scores with a plain-words explainer (judge
     scores 0–100; medium released ≥ Allow, high needs ≥ High), optional
     criteria with an example. Creating the first judge flips the global judge
     switch on.

### Audit: Activity view + config-change events — WIP
- Provider/judge/MCP config changes now land in the audit trail: every GUI
  mutation (provider add/update/remove/enable/disable/default, judge
  add/update/remove/default/enable/disable, MCP door on/off) records a global
  usage event (`.svault/usage.log`) — the same pattern the TUI uses for judge
  changes.
- The Audit screen gained two sub-tabs: **Gate decisions** and **Activity**
  (all vault usage logs merged with the global one). Pause button removed —
  both views always live-poll.
- Both views are real **data tables** (TanStack Table): sortable columns,
  full timestamps ("Jun 6, 14:32:05", monospace), quick-search box,
  client-side **pagination** (25/50/100/250 per page, first/prev/next/last,
  row count) over up to 5000 fetched rows.
- **Date-range gadget** shared by both views: preset chips (1h / Today / 7d /
  30d / All) plus a Custom from→to date picker; presets stay anchored to
  "now" while polling. Range filtering is applied server-side (unix bounds on
  `audit_events` / `activity_events`).
- Gate decisions keep their structured filters (result / vault / caller) next
  to the range bar; the table adds a Details column (rule + real reason,
  truncated with hover tooltip).

## Daemon

### Auto-start on launch — done
- On supported platforms (Unix/macOS/Linux) the daemon now starts automatically
  when the app launches, if not already running, so Svault behaves like a running
  service. Keys still live only in the daemon's memory and only after a human
  unlock.
- Windows has no daemon (core's 0600 session fallback) — auto-start is a no-op
  there. Failures are non-fatal; Settings still shows daemon state.
- Implementation: the GUI launches the bundled `svault` sidecar (or `svault` on
  PATH in dev) via the new `daemon::start_quiet_with_exe`, because the GUI's own
  executable can't run the daemon.

#### Fork-bomb fix (regression caught in dev)
- macOS/Windows filesystems are case-insensitive, so the old
  `dir.join("svault").exists()` sidecar lookup `stat`-matched the GUI's own
  `Svault` binary. Auto-start then ran `Svault daemon run`, which relaunches the
  GUI, which auto-starts again — spawning endless instances (a wall of tray
  icons).
- Fixed: `locate_sidecar` now matches only the real on-disk file name
  (case-sensitive) and rejects the current executable by canonical path, plus a
  hard guard in `autostart_daemon` that refuses to spawn if the located binary
  canonicalizes to our own exe.
- In dev there is no separate `svault` next to the app, so auto-start needs
  `svault` on PATH (e.g. after "Install CLI to PATH"); otherwise it safely skips.
- Second cause (also fixed): a loose `starts_with("svault-")` match grabbed a
  stale `svault-gui` build artifact in `target/debug` (left from before the bin
  was renamed to `Svault`) and ran it as the daemon. Matcher is now exact
  (`svault` / `svault.exe`) and the stale artifact was deleted.
- Dev `svault` on PATH was 0.9.9; reinstalled 1.0.0 so the daemon binary matches
  the GUI's daemon client (avoids socket protocol skew).

#### Deferred packaging note
- On a case-insensitive macOS volume a sidecar literally named `svault` cannot
  coexist with the app binary `Svault` in `Contents/MacOS/`. When wiring the
  release `externalBin`, give the sidecar a distinct name (e.g. the
  target-triple form Tauri already uses) so the two don't collide.
