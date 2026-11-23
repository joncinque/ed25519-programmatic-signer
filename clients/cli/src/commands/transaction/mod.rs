mod decode;
mod parse;
mod sign;
mod simulate;
mod state_changes;
mod submit;
pub(crate) mod summary;
pub(crate) mod v1_transaction;

use {
    crate::{client::Client, output::OutputFormat},
    anyhow::Result,
    clap::{Args, Subcommand},
};

#[derive(Debug, Args)]
pub(crate) struct TransactionCommand {
    #[clap(subcommand)]
    command: TransactionSubcommand,
}

#[derive(Debug, Subcommand)]
enum TransactionSubcommand {
    /// Wrap an execution message in an authorization message and sign it offline, returning
    /// signatures and the authorization message.
    Sign(sign::SignCommand),
    /// Simulate an execution message through Submit and the executor, without authority
    /// signatures.
    Simulate(simulate::SimulateCommand),
    /// Collect signatures for an authorization message, then submit it in a relay transaction.
    Submit(submit::SubmitCommand),
}

pub(crate) async fn run(
    command: TransactionCommand,
    client: &Client,
    output: OutputFormat,
) -> Result<String> {
    match command.command {
        TransactionSubcommand::Sign(command) => sign::run(command, client, output),
        TransactionSubcommand::Simulate(command) => simulate::run(command, client, output).await,
        TransactionSubcommand::Submit(command) => submit::run(command, client, output).await,
    }
}
