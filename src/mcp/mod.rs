//! MCP frontend — placeholder.
//!
//! Intended to expose Svault's gated secret access over the Model Context
//! Protocol, so MCP-aware agents request secrets through the same policy engine
//! and AI judge as the CLI and daemon. This frontend will reuse
//! [`crate::core`] (policy, judge, vault) and the [`crate::daemon`] client; it
//! adds no new secret-handling logic of its own.
//
// TODO(post-0.9.6): implement the MCP server frontend.
