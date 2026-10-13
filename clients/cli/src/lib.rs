mod cli;
mod client;
mod commands;
mod output;

pub use commands::{
    migrate::{Authorization, RequiredSigners, stake::StakeMigrationOutput},
    nonce::{create::NonceCreateOutput, show::NonceShowOutput},
};
use {
    anyhow::Result,
    clap::{CommandFactory, FromArgMatches},
    cli::Cli,
};

pub async fn run() -> Result<()> {
    let matches = Cli::command().get_matches();
    let cli = Cli::from_arg_matches(&matches).unwrap_or_else(|error| error.exit());
    let output = commands::run(cli, matches).await?;
    println!("{output}");
    Ok(())
}
