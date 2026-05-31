//! A single process-wide lock for tests that change the current working
//! directory. The working directory is global to the process, so any two tests
//! that `set_current_dir` must be serialized against *each other* — separate
//! per-module mutexes would not do that. Every chdir-based test (keyring,
//! master) takes this one lock.
#![cfg(test)]

use std::sync::Mutex;

pub static CWD_LOCK: Mutex<()> = Mutex::new(());
