//! Backend-held GUI state. Deliberately tiny: the Rust core/daemon is the source
//! of truth for everything security-relevant (unlocked keys live only in the
//! daemon's memory, never here). We track only the moment of the last successful
//! GUI unlock so the sidebar can show a real re-auth countdown.

use std::sync::Mutex;

#[derive(Default)]
pub struct GuiState {
    /// Unix seconds of the last successful master unlock through the GUI, used to
    /// derive the re-auth deadline. `None` once locked.
    pub unlocked_at: Mutex<Option<i64>>,
    /// The re-auth cap (seconds) that applied at the last unlock — the keyring's
    /// `lock.max_unlocked_secs`, captured once at stamp time so the once-a-second
    /// status poll doesn't decrypt the keyring. `None` before the first unlock.
    pub reauth_cap_secs: Mutex<Option<u64>>,
}
