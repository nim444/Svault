//! Command result type. `anyhow::Error` isn't `Serialize`, so commands return
//! `Result<T, String>` and map errors with [`emsg`]. Denials and other
//! security-sensitive messages are produced by `core` already (generic to
//! agents); this only transports them — it never invents detail.

pub type CmdResult<T> = Result<T, String>;

/// Map any displayable error to the wire string.
pub fn emsg<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}
