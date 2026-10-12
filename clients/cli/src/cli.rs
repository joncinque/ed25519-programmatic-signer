use {
    crate::{
        commands::{address::AddressCommand, nonce::NonceCommand, transaction::TransactionCommand},
        output::OutputFormat,
    },
    clap::{Args, Parser, Subcommand, ValueHint, builder::ValueParser},
    solana_clap_v3_utils::{
        input_parsers::{
            parse_url_or_moniker,
            signer::{SignerSource, SignerSourceParserBuilder},
        },
        keypair::SKIP_SEED_PHRASE_VALIDATION_ARG,
    },
    solana_commitment_config::CommitmentConfig,
    std::path::PathBuf,
};

#[derive(Debug, Parser)]
#[clap(
    name = "spl-programmatic-signer",
    about = "Manage programmatic signer setup and transaction workflows",
    version,
    subcommand_required = true,
    arg_required_else_help = true
)]
pub struct Cli {
    /// Format used for command output.
    #[clap(long, global = true, value_enum, default_value_t)]
    pub(crate) output: OutputFormat,

    #[clap(flatten)]
    pub(crate) client: ClientArgs,

    /// Skip validation of seed phrases. Use this if your phrase does not use the BIP39 official
    /// English word list.
    //
    // Note: signer_from_path resolves prompt:// and ASK sources by looking this
    // argument up in ArgMatches and fails if it is not defined.
    #[clap(
        name = SKIP_SEED_PHRASE_VALIDATION_ARG.name,
        long = SKIP_SEED_PHRASE_VALIDATION_ARG.long,
        global = true
    )]
    pub(crate) skip_seed_phrase_validation: bool,

    #[clap(subcommand)]
    pub(crate) command: Command,
}

/// Global options consumed by [`crate::client::Client`]. Each one overrides a value the Solana
/// CLI configuration file otherwise supplies.
#[derive(Debug, Args)]
pub(crate) struct ClientArgs {
    /// Solana CLI configuration file. Uses the standard path when omitted.
    #[clap(
        short = 'C',
        long,
        global = true,
        value_hint = ValueHint::FilePath
    )]
    pub(crate) config: Option<PathBuf>,

    /// Solana RPC URL or cluster moniker. Full monikers and their first letters are supported.
    #[clap(
        short = 'u',
        long,
        global = true,
        value_parser = parse_url_or_moniker
    )]
    pub(crate) url: Option<String>,

    /// Commitment level used for RPC queries and transaction confirmation.
    /// Uses Solana CLI config when omitted.
    #[clap(long, global = true)]
    pub(crate) commitment: Option<CommitmentConfig>,

    /// Fee payer signer source: a keypair file, usb:// URL, prompt:// URL, or the ASK keyword.
    /// `transaction submit --sign-only` also accepts an address, whose signature is collected
    /// separately. Defaults to the configured keypair.
    #[clap(long, global = true, value_parser = keypair_source_parser())]
    pub(crate) fee_payer: Option<SignerSource>,

    /// Skip the preflight check when sending transactions.
    #[clap(long, global = true)]
    pub(crate) skip_preflight: bool,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Derive and print a programmatic signer PDA from an authority address.
    Address(AddressCommand),
    /// Manage SPL Nonce accounts used by programmatic signer transactions.
    Nonce(NonceCommand),
    /// Sign authorization messages offline and submit them in a relay transaction.
    Transaction(TransactionCommand),
}

pub(crate) fn keypair_source_parser() -> ValueParser {
    SignerSourceParserBuilder::default().allow_all().build()
}
