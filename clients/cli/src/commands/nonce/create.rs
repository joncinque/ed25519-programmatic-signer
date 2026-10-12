use {
    crate::{cli::keypair_source_parser, client::Client, output::OutputFormat},
    anyhow::{Context, Result, bail},
    clap::Args,
    serde::{Deserialize, Serialize},
    solana_address::Address,
    solana_clap_v3_utils::input_parsers::signer::SignerSource,
    solana_keypair::Keypair,
    solana_native_token::Sol,
    solana_signer::Signer,
    solana_transaction::Transaction,
    spl_ed25519_signer_client::ProgrammaticSigner,
    spl_nonce_interface::state::Nonce,
    std::fmt,
};

#[derive(Debug, Args)]
pub(crate) struct CreateCommand {
    /// Address stored verbatim as the nonce authority. No derivation is performed.
    #[clap(
        long,
        required_unless_present = "cold-authority",
        conflicts_with = "cold-authority"
    )]
    pub(crate) nonce_authority: Option<Address>,

    /// Cold authority address. Its derived ProgrammaticSigner PDA becomes the nonce authority.
    /// Only the address is used and the cold key is never loaded.
    #[clap(long)]
    pub(crate) cold_authority: Option<Address>,

    /// Keypair for the new nonce account. Its public key determines the account address.
    /// Accepts a keypair file, usb:// URL, prompt:// URL, or ASK.
    /// If omitted, generates a temporary keypair used only for account creation.
    #[clap(long, value_parser = keypair_source_parser())]
    pub(crate) nonce_keypair: Option<SignerSource>,
}

pub(super) async fn run(
    command: CreateCommand,
    client: &Client,
    output: OutputFormat,
) -> Result<String> {
    let nonce_keypair = match &command.nonce_keypair {
        Some(source) => client.load_signer(source, "nonce account", false)?,
        None => Box::new(Keypair::new()),
    };
    let fee_payer = client.fee_payer()?;
    let fee_payer_address = fee_payer
        .try_pubkey()
        .context("failed to read fee payer pubkey")?;
    let nonce_account = nonce_keypair
        .try_pubkey()
        .context("failed to read nonce account pubkey")?;
    if fee_payer_address == nonce_account {
        bail!("fee payer and nonce account must use different keypairs");
    }

    let nonce_authority = match (command.nonce_authority, command.cold_authority) {
        (Some(nonce_authority), None) => nonce_authority,
        (None, Some(cold_authority)) => {
            ProgrammaticSigner::derive_address(&spl_ed25519_signer_client::id(), &cold_authority)
        }
        _ => unreachable!("clap enforces exactly one nonce authority source"),
    };

    let rent_lamports = client
        .minimum_balance_for_rent_exemption(Nonce::LEN)
        .await?;

    let recent_blockhash = client.latest_blockhash().await?;

    let [create, initialize] = spl_nonce_client::instruction::create_account(
        &fee_payer_address,
        &nonce_account,
        &nonce_authority,
        rent_lamports,
    );
    let mut transaction =
        Transaction::new_with_payer(&[create, initialize], Some(&fee_payer_address));
    let signers: [&dyn Signer; 2] = [fee_payer.as_ref(), nonce_keypair.as_ref()];
    transaction
        .try_sign(signers.as_slice(), recent_blockhash)
        .context("failed to sign nonce-account creation")?;
    let signature = client.send_and_confirm_transaction(&transaction).await?;

    let account = client
        .nonce_account(&nonce_account)
        .await
        .with_context(|| {
            format!(
                "transaction {signature} confirmed, but failed to read created nonce account \
                 {nonce_account}"
            )
        })?;

    output.render(&NonceCreateOutput {
        signature,
        nonce_account: nonce_account.to_string(),
        authority: account.state.authority.to_string(),
        nonce: account.state.nonce.to_string(),
        lamports: account.lamports,
    })
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NonceCreateOutput {
    pub signature: String,
    pub nonce_account: String,
    pub authority: String,
    pub nonce: String,
    pub lamports: u64,
}

impl fmt::Display for NonceCreateOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(formatter, "Signature: {}", self.signature)?;
        writeln!(formatter, "Nonce account: {}", self.nonce_account)?;
        writeln!(formatter, "Authority: {}", self.authority)?;
        writeln!(formatter, "Nonce: {}", self.nonce)?;
        write!(formatter, "Balance: {}", Sol(self.lamports))
    }
}
