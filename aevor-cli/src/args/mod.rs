//! Global CLI argument definitions.
use clap::Args;
#[derive(Debug, Args)]
pub struct GlobalArgs {
    #[arg(short, long)] pub endpoint: Option<String>,
    #[arg(short, long, default_value = "mainnet")] pub network: String,
    #[arg(long)] pub no_confirm: bool,
}
