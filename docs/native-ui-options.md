# Native-feeling UI options for the desktop app

> **Status: research note, no decision taken.** Written 2026-06-10 while the GUI is
> Tauri 2 + React 19 over the Rust core (`svault-cli` as a linked lib). The question:
> what would make the app *feel* native on macOS and Windows — not like HTML in a
> window — and what would each path cost?

## The one architectural fact that matters

Svault's core is already a **frontend-agnostic Rust library + Unix-socket daemon +
CLI**. Every candidate below talks to the same core; nothing about crypto, the
policy gate, the judge, or the audit log changes. The frontend is a swappable
shell. That means this decision is never one-way — we can ship on Tauri today and
add a truly native shell later without touching the core.

## Why a webview app "feels like HTML"

Concretely, the tells are: web font rendering and selection behavior, non-native
scrolling physics and scrollbars, custom-drawn controls that don't match the OS,
missing platform conventions (macOS menu bar, Windows snap layouts), and a
titlebar/window chrome that doesn't match the system. Some of these are fixable
inside Tauri; some are inherent to a webview.

## The options

### 1. Keep Tauri, do a deliberate native-polish pass (lowest cost)

Most "feels like a website" complaints are fixable without leaving the stack:

- **System font stacks** — `-apple-system`/`SF Pro` on macOS, `Segoe UI Variable`
  on Windows, correct sizes/weights per platform (13px body on macOS, not 16px).
- **Native menu bar** (Tauri `Menu` API) with standard roles — Edit/Copy/Paste,
  Window, app menu on macOS. A real menu bar is the single biggest "this is a Mac
  app" signal.
- **Window chrome** — `titleBarStyle: overlay` + traffic-light inset on macOS,
  Mica/acrylic backdrop on Windows 11 (`windowEffects`), vibrancy sidebars on
  macOS.
- **Platform-conditional CSS** — different control sizing, focus rings, and
  spacing per OS; kill web scrollbars (`overlay` style), disable text selection
  on chrome, disable the context menu except in fields.
- **Keyboard + conventions** — Cmd-, for Settings, Cmd-W closes window, Esc
  behavior, correct dialog button order per platform (OK/Cancel flips on macOS).
- Native dialogs, notifications, tray are already used.

Ceiling: controls are still drawn by us, scrolling is still the webview's. Gets to
roughly "polished Electron-class app" (Linear, Slack level), not "Apple Notes."

**Cost: days, not weeks. Keeps all 12 screens.**

### 2. Slint (single Rust codebase, native-styled widgets)

[Slint](https://slint.dev) renders its own widgets but ships **platform styles**
(`cupertino` for macOS, `fluent` for Windows) and is a real Rust-first toolkit
with its own markup language. Closer to native than HTML, one codebase, tiny
binaries, no webview.

- Pros: pure Rust, no JS/npm supply chain (relevant to GUI finding G-2's whole
  threat class disappearing), good accessibility story, declarative `.slint` UI.
- Cons: a **full rewrite of all 12 screens**; widgets *mimic* native rather than
  being native (a sharp eye still tells); smaller ecosystem (no off-the-shelf
  equivalents of the React component library); GPL or paid royalty-free license.

Other Rust-native toolkits for completeness: **Iced** and **egui** are
custom-drawn and make no attempt at native look (egui is immediate-mode,
game-style); **GPUI** (Zed) is fast but macOS-first and custom-drawn; **Dioxus**
desktop still renders through a webview (its native renderer, Blitz, is
experimental). None of these beat Slint for the specific goal of "look native."

**Cost: weeks of rewrite. Single codebase preserved.**

### 3. True native shells: SwiftUI (macOS) + WinUI 3 (Windows) — the gold standard

The only way to actually *be* native is to use the platform toolkits:

- **macOS:** SwiftUI/AppKit app. Real NSScrollView physics, real controls, real
  menu bar, sandboxing/notarization story, and — notably for Svault — access to
  the **entitlement-gated biometry keychain ACL** (`kSecAccessControlBiometryAny`)
  that the cargo-installed CLI can't get (`errSecMissingEntitlement`, see
  `core/touchid.rs`). A signed, entitled .app would upgrade Touch ID from
  in-process enforcement to an OS-enforced boundary. That is a *security* win,
  not just cosmetics.
- **Windows:** WinUI 3 (or WPF) in C#. Real Fluent controls, Mica, snap layouts.

Both talk to the Rust core via **UniFFI** (Mozilla's FFI bindgen — generates Swift
and C# bindings from the Rust crate) or simply via the **existing daemon socket /
CLI JSON**, which is the lazier and very viable option: the GUI becomes a thin
native client of the daemon, the same way MCP already is.

- Pros: indistinguishable from native because it is native; per-platform security
  integrations (Touch ID entitlement, Windows Hello); each app can follow its
  platform's design language instead of a compromise.
- Cons: **two frontends to build and maintain** in two non-Rust languages; the 12
  screens get written twice; release/signing pipelines per platform; slower
  feature velocity forever after.

**Cost: months. Highest ceiling, including a real Touch ID security upgrade.**

### 4. Hybrid (pragmatic long game)

Ship and keep improving the Tauri app as the cross-platform baseline, then add a
**native SwiftUI shell for macOS only** when justified — macOS users are the most
sensitive to non-native UI, and macOS is where the Touch ID entitlement payoff
lives. Windows stays on the polished Tauri build (Windows users' native
expectations are far looser; most popular Windows apps are webview-based anyway).

### Not recommended

- **Flutter** — custom-drawn like Slint but a whole Dart toolchain for no gain
  over Slint in a Rust project.
- **Qt / cxx-qt** — genuinely native-ish styling, but a heavy C++ dependency,
  licensing complexity, and a second language; the payoff doesn't beat option 3.
- **Electron** — strictly worse than Tauri here (bigger, same webview feel).

## Comparison

| | Native feel | Effort | Codebases | Rust purity | Security notes |
|---|---|---|---|---|---|
| 1. Tauri polish pass | Good (Electron-class polish) | Days | 1 | Core Rust, UI TS | Webview/CSP surface remains (G-1/G-2 still to fix) |
| 2. Slint rewrite | Near-native mimicry | Weeks | 1 | Fully Rust | Drops npm/webview attack surface entirely |
| 3. SwiftUI + WinUI | Actually native | Months | 3 (core + 2 shells) | Core Rust, shells Swift/C# | Touch ID becomes OS-enforced via entitlement |
| 4. Hybrid (Tauri + later SwiftUI) | Native on macOS, good on Windows | Staged | 2 eventually | Mixed | Gets the entitlement win where it matters |

## Recommendation (non-binding)

For 2.0.0: **option 1** — do the native-polish pass on the existing Tauri app
(menu bar, system fonts, window effects, platform-conditional styling) alongside
the open GUI security fixes (G-1, G-2). All 12 screens are built and working;
rewriting them now would stall the release for cosmetics.

Post-2.0.0, if native feel remains a priority: **option 4** — a SwiftUI macOS
shell speaking to the existing daemon, prioritized over Windows because (a) macOS
users notice, and (b) the signed-app Touch ID entitlement is a genuine security
upgrade the current architecture cannot reach. A Slint rewrite (option 2) only
wins if dropping the webview/npm surface entirely becomes a goal in itself.

## FAQ: would SwiftUI still need the Rust backend?

Yes — and keeping it is the point, not a limitation. Swift *could* reimplement
the core (CryptoKit has AES-GCM; Argon2 via libsodium), but the CLI, MCP, TUI,
and daemon stay Rust regardless, so a Swift core would be a **second
implementation of the security-critical code**: two codebases that must produce
byte-identical vault formats and identical gate decisions, each needing its own
review. Everything in `security-review/` covers the Rust core only.

The two clean integration shapes for a SwiftUI shell:

1. **In-process link (preferred):** compile `svault-cli` as a `staticlib` and
   generate Swift bindings with **UniFFI**. Single .app binary, SwiftUI calling
   Rust directly — the same architecture the Tauri GUI uses today, different
   shell. This is the path that unlocks the entitlement-gated Touch ID upgrade,
   and it is the industry-standard pattern (1Password ships native Swift/Kotlin
   shells over one shared Rust core).
2. **Daemon client:** a thin SwiftUI client of the existing Unix-socket JSON
   protocol (or the CLI's JSON output), the same way MCP is a thin frontend.
   No FFI work, but requires the daemon and is a chattier integration.
