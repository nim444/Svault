# GUI redesign — sequencing plan

> **Status: planning note, no decision taken.** Written 2026-06-10. Context: the
> maintainer wants (a) a visual redesign toward Apple's Liquid Glass design
> language (macOS 26 Tahoe), and (b) a restructure of the GUI logic — the current
> implementation works but carries some design decisions worth revisiting. This
> note recommends an order of operations. Companion doc:
> [native-ui-options.md](native-ui-options.md).

## Liquid Glass reality check

- The real material — refraction, specular highlights, lensing as content moves
  beneath it — exists only through SwiftUI/AppKit on macOS 26: `.glassEffect()`,
  `GlassEffectContainer`, and standard toolbars/sidebars adopting it
  automatically when built against the Tahoe SDK.
- A webview can only imitate it with `backdrop-filter` blur + transparency.
  Imitation glass is the most recognizable "this is HTML" tell there is — using
  it would recreate the exact complaint driving the redesign.
- It is macOS-only. Windows 11's Mica/Acrylic is a different design language; a
  glass-everywhere design does not translate to Windows on any stack.
- Apple themselves reduced the effect's intensity during the 26.0 betas for
  legibility. Use it with restraint, and degrade gracefully on pre-Tahoe macOS.

## Recommended order of operations

Decouple the three workstreams — security fixes, logic restructure, visual
redesign — and run them in that order.

### Stage 0 — ship 2.0.0 with the open security fixes

G-1, G-2, G-3, G-4 (see [findings/gui-1.1.0.md](security-review/findings/gui-1.1.0.md))
live in the Rust command layer, which survives any frontend. Land them on the
current GUI and ship; do not tangle them into a redesign branch.

### Stage 1 — write the "bad decisions" register

Before touching code, list every design decision now considered wrong — one entry
each, split into **logic** (command-layer shape, state handling, screen flows)
and **visual** (what the redesign replaces). The restructure should be driven by
this explicit list, not by momentum. (A critical design-decisions audit of the
current GUI can seed the list.)

### Stage 2 — restructure the logic, frontend-agnostically

Shape the Tauri command layer into the clean API it should have been — that same
surface is what UniFFI would expose to a future SwiftUI shell, so done right the
restructure pays off in both futures. Svault has no users yet: breaking changes
are cheap now (no migrations; wipe and rebuild) and only get more expensive.

### Stage 3 — visual redesign, choosing the shell deliberately

Two honest paths:

1. **Glass-inspired theme inside Tauri** — cheap, cross-platform, one codebase;
   but imitation glass, and it will read as such next to real Tahoe apps.
2. **SwiftUI shell for macOS (real Liquid Glass) + Tauri stays for Windows** —
   the hybrid from native-ui-options.md. Genuine material, plus the
   entitlement-gated Touch ID upgrade as a side effect; Windows keeps the
   polished Tauri build with Mica, which fits its platform language.

If the trigger for the redesign is Apple's new material specifically, path 2 is
the only one that actually delivers it.

### Throughout — keep the screen-by-screen discipline

Build the design system first (tokens, core components, one reference screen),
then migrate screens one at a time. The incremental rule has served the GUI
well; a big-bang rewrite of 12 screens is where projects stall.
