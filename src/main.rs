//! Thin entry point for the `svault` binary. All logic lives in the library
//! crate; the CLI frontend is [`svault_cli::cli`].

fn main() -> anyhow::Result<()> {
    svault_cli::cli::run()
}
