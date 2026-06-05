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
