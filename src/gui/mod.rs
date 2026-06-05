//! GUI frontend — stub.
//!
//! The desktop GUI is **not** implemented in this module. It is a separate Tauri
//! app crate at `gui-app/` (crate `svault-gui`) that path-depends on `svault-ai`
//! and drives [`crate::core`] + the [`crate::daemon`] client over thin Tauri
//! commands — so `tauri` never becomes a dependency of the published library.
//! See `docs/gui.md`. This module is kept only as the historical frontend slot.
