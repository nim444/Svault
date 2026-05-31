//! Thin entry point for the `svault` binary. All logic lives in the library
//! crate; the CLI frontend is [`svault_ai::cli`].

fn main() -> anyhow::Result<()> {
    svault_ai::cli::run()
}
