pub(crate) mod advance;
pub(crate) mod create;
pub(crate) mod show;

use {
    crate::{
        client::Client,
        commands::transaction::v1_transaction::{compile_message, try_partial_sign},
        output::OutputFormat,
    },
    anyhow::{Context, Result, ensure},
    clap::{Args, Subcommand},
    solana_address::Address,
    solana_clap_v3_utils::input_parsers::signer::{SignerSource, SignerSourceKind},
    solana_instruction::Instruction,
    solana_message::VersionedMessage,
    solana_signature::Signature,
    solana_signer::Signer,
    solana_transaction::versioned::VersionedTransaction,
};

#[derive(Debug, Args)]
pub(crate) struct NonceCommand {
    #[clap(subcommand)]
    pub(crate) command: NonceSubcommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum NonceSubcommand {
    /// Show the nonce, authority, owner, and balance of an SPL Nonce account.
    Show(show::ShowCommand),
    /// Create and initialize an SPL Nonce account for a nonce authority.
    Create(create::CreateCommand),
    /// Advance an SPL Nonce account, invalidating anything signed against its current value.
    Advance(advance::AdvanceCommand),
}

pub(crate) async fn run(
    command: NonceCommand,
    client: &Client,
    output: OutputFormat,
) -> Result<String> {
    match command.command {
        NonceSubcommand::Show(command) => show::run(command, client, output).await,
        NonceSubcommand::Create(command) => create::run(command, client, output).await,
        NonceSubcommand::Advance(command) => advance::run(command, client, output).await,
    }
}

/// The nonce authority signer source, or the configured keypair.
struct NonceAuthority {
    signer: Box<dyn Signer>,
    address: Address,
    /// False when given as an address, for an authority that signs externally.
    can_sign: bool,
}

impl NonceAuthority {
    fn load(client: &Client, source: Option<SignerSource>) -> Result<Self> {
        let source = match source {
            Some(source) => source,
            None => client.config_keypair_source()?,
        };
        // An address loads as a null signer, for an authority that signs externally.
        let signer = client.load_signer(&source, "nonce authority", true)?;
        let address = signer
            .try_pubkey()
            .context("failed to read nonce authority pubkey")?;
        Ok(Self {
            signer,
            address,
            can_sign: !matches!(source.kind, SignerSourceKind::Pubkey(_)),
        })
    }

    /// A nonce authority that is not a PDA signs the relay transaction, so it can't sign
    /// externally.
    fn ensure_can_sign(&self) -> Result<()> {
        ensure!(
            self.can_sign,
            "nonce authority {} signs the relay transaction directly, so it must be passed as a \
             signer. Only a PDA nonce authority's authority can be given as an address",
            self.address
        );
        Ok(())
    }
}

/// Sign `instruction` with the fee payer and `signer`, and send it.
async fn send_relay_transaction(
    client: &Client,
    instruction: Instruction,
    signer: Option<&dyn Signer>,
) -> Result<String> {
    let fee_payer = client.fee_payer()?;
    let fee_payer_address = fee_payer
        .try_pubkey()
        .context("failed to read fee payer pubkey")?;
    let mut signers = vec![fee_payer.as_ref()];
    if let Some(signer) = signer {
        if signer.try_pubkey()? != fee_payer_address {
            signers.push(signer);
        }
    }

    let blockhash = client.latest_blockhash().await?;
    let message = compile_message(&fee_payer_address, &[instruction], blockhash)?;
    let mut transaction = VersionedTransaction {
        signatures: vec![Signature::default(); usize::from(message.header.num_required_signatures)],
        message: VersionedMessage::V1(message),
    };
    let message_data = transaction.message.serialize();
    try_partial_sign(&mut transaction, &signers, &message_data)
        .context("failed to sign relay transaction")?;
    client
        .send_and_confirm_transaction(&transaction)
        .await
        .with_context(|| format!("relay transaction {}", transaction.signatures[0]))
}
