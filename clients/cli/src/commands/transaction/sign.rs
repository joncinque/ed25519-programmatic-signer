use {
    super::{
        decode::read_execution_message,
        summary::{confirm_signing, render_signing_summary, sign_authorization_message},
    },
    crate::{cli::keypair_source_parser, client::Client, output::OutputFormat},
    anyhow::{Context, Result, ensure},
    base64::{Engine, prelude::BASE64_STANDARD},
    clap::Args,
    serde::Serialize,
    solana_address::Address,
    solana_clap_v3_utils::input_parsers::signer::SignerSource,
    solana_hash::Hash,
    solana_message::{VersionedMessage, v1},
    solana_signer::Signer,
    spl_ed25519_signer_client::ProgrammaticSigner,
    spl_message_executor_client::instruction::execute,
    std::{collections::BTreeSet, fmt},
};

#[derive(Debug, Args)]
pub(super) struct SignCommand {
    /// Base64-encoded v1 execution message.
    #[clap(long)]
    execution_message: String,

    /// SPL nonce account protecting this execution.
    #[clap(long)]
    nonce_account: Address,

    /// Nonce account authority.
    #[clap(long)]
    nonce_authority: Address,

    /// Expected nonce value, which replaces the execution message's recent blockhash.
    #[clap(long)]
    nonce_hash: Hash,

    /// Full set of authorities promoting their derived PDA signers. Repeat for each authority.
    /// Each derived signer must be the nonce authority or a signer on the execution message.
    /// Addresses are sorted and de-duplicated before constructing the authorization message.
    #[clap(long, required = true)]
    authority: Vec<Address>,

    /// Signer source: a keypair file, usb:// URL, prompt:// URL, or the ASK keyword.
    /// Repeat to sign with multiple local keys. Each must be in --authority.
    /// Defaults to the configured keypair.
    #[clap(long, value_parser = keypair_source_parser())]
    signer: Vec<SignerSource>,

    /// Hide the signing summary. Confirmation prompts and errors are still shown.
    #[clap(long)]
    quiet: bool,

    /// Skip the confirmation prompt for non-interactive signers (e.g. file keypairs).
    /// Hardware wallets still require approval on the device.
    #[clap(long)]
    yes: bool,
}

pub(super) fn run(command: SignCommand, client: &Client, output: OutputFormat) -> Result<String> {
    let mut execution_message = read_execution_message(&command.execution_message)?;
    execution_message.lifetime_specifier = command.nonce_hash;
    // Sort/dedupe so participants construct identical messages.
    let mut authorities = command.authority;
    authorities.sort_unstable();
    authorities.dedup();
    let instruction = execute(
        &command.nonce_account,
        &command.nonce_authority,
        &execution_message,
    );
    let execution_signers = &execution_message.account_keys
        [..usize::from(execution_message.header.num_required_signatures)];
    let derived_signers = authorities
        .iter()
        .map(|authority| {
            ProgrammaticSigner::derive_address(&spl_ed25519_signer_client::id(), authority)
        })
        .collect::<BTreeSet<_>>();
    // Signers the executor uses directly must sign at submission, including authorities that
    // are also used directly. Derived PDAs are promoted by Submit instead.
    let forwarded_signers = execution_signers
        .iter()
        .chain(std::iter::once(&command.nonce_authority))
        .filter(|address| !derived_signers.contains(*address))
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    // Forwarded signers need a slot in the authorization message header to forward their
    // submission signature. Their authorization message approvals must also be collected.
    let authorization_signers = authorities
        .iter()
        .chain(&forwarded_signers)
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    // Every authority is an authorization signer, so this also bounds the authorization message's
    // account keys well below the 256 at which authorization_message panics compiling u8 indexes.
    // Check it before building the message.
    ensure!(
        authorization_signers.len() <= usize::from(v1::MAX_SIGNATURES),
        "too many required signers for the authorization message: {} exceeds the v1 limit of {}",
        authorization_signers.len(),
        v1::MAX_SIGNATURES
    );
    for authority in &authorities {
        let pda = ProgrammaticSigner::derive_address(&spl_ed25519_signer_client::id(), authority);
        ensure!(
            pda == command.nonce_authority || execution_signers.contains(&pda),
            "Authority {authority}'s derived signer {pda} is neither the nonce authority nor a \
             signer on the execution message"
        );
    }
    let VersionedMessage::V1(authorization_message) =
        spl_ed25519_signer_client::message::authorization_message(
            &instruction,
            &authorization_signers,
        )
    else {
        unreachable!("authorization_message builds a v1 message");
    };
    // Validate the v1 message directly. Its errors name the violated limit, which sanitize's
    // generic errors do not.
    authorization_message
        .validate()
        .context("invalid authorization message")?;
    let encoded_authorization_message = BASE64_STANDARD.encode(authorization_message.serialize());

    let signers = if command.signer.is_empty() {
        vec![client.load_signer_or_config_default(None, "message authority")?]
    } else {
        command
            .signer
            .iter()
            .map(|source| client.load_signer(source, "message authority"))
            .collect::<Result<Vec<_>>>()?
    };
    let mut unique_signers = Vec::new();
    for signer in signers {
        let address = signer.try_pubkey()?;
        ensure!(
            authorities.contains(&address),
            "Signer {address} is not in the supplied --authority list"
        );
        if !unique_signers
            .iter()
            .any(|(existing, _)| existing == &address)
        {
            unique_signers.push((address, signer));
        }
    }

    if !command.quiet {
        eprintln!(
            "{}",
            render_signing_summary(
                &execution_message,
                &authorization_message,
                &command.nonce_account,
                &command.nonce_authority,
                &authorities,
                &forwarded_signers,
                "Signing returns addresses, signatures, forwarded signers, and the base64 \
                 authorization message. Nothing is submitted.",
            )?
        );
    }
    confirm_signing(&unique_signers, command.yes)?;
    let mut entries = Vec::new();
    for (authority, signature) in
        sign_authorization_message(&authorization_message, &unique_signers)?
    {
        entries.push(SignOutput {
            address: authority.to_string(),
            signature: signature.to_string(),
            forwarded_signers: forwarded_signers.iter().map(ToString::to_string).collect(),
            authorization_message: encoded_authorization_message.clone(),
        });
    }
    output.render(&SignOutputs(entries))
}

#[derive(Serialize)]
struct SignOutput {
    address: String,
    signature: String,
    forwarded_signers: Vec<String>,
    authorization_message: String,
}

#[derive(Serialize)]
#[serde(transparent)]
struct SignOutputs(Vec<SignOutput>);

impl fmt::Display for SignOutputs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for entry in &self.0 {
            writeln!(f, "Address: {}", entry.address)?;
            writeln!(f, "Signature: {}", entry.signature)?;
            writeln!(f)?;
        }
        if let Some(entry) = self.0.first() {
            if !entry.forwarded_signers.is_empty() {
                writeln!(f, "Forwarded signers (sign at submission):")?;
                for address in &entry.forwarded_signers {
                    writeln!(f, "  {address}")?;
                }
                writeln!(f)?;
            }
            write!(
                f,
                "Authorization message (base64):\n{}",
                entry.authorization_message
            )?;
        }
        Ok(())
    }
}
