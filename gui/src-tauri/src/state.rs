//! Backend-held GUI state. Deliberately tiny: the Rust core/daemon is the source
//! of truth for everything security-relevant (unlocked keys live only in the
//! daemon's memory, never here). We track only the moment of the last successful
//! GUI unlock so the sidebar can show a real re-auth countdown.

use std::sync::Mutex;

#[derive(Default)]
pub struct GuiState {
    /// Unix seconds of the last successful master unlock through the GUI, used to
    /// derive the 6-hour re-auth deadline. `None` once locked.
    pub unlocked_at: Mutex<Option<i64>>,
}
