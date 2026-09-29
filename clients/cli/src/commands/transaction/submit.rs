use {
    super::{
        decode::{executable_inner_message, read_message},
        summary::{confirm_signing, render_signing_summary},
    },
    crate::{cli::keypair_source_parser, client::Client, output::OutputFormat},
    anyhow::{Context, Result, bail, ensure},
    clap::Args,
    serde::Serialize,
    solana_address::Address,
    solana_clap_v3_utils::input_parsers::signer::SignerSource,
    solana_hash::Hash,
    solana_message::{VersionedMessage, v1},
    solana_signature::Signature,
    solana_signer::Signer,
    solana_transaction::Transaction,
    spl_ed25519_signer_client::ProgrammaticSigner,
    spl_message_executor_interface::instruction::Instruction as ExecutorInstruction,
    std::{
        collections::{BTreeMap, BTreeSet},
        fmt,
        str::FromStr,
    },
};

#[derive(Debug, Args)]
pub(super) struct SubmitCommand {
    /// Base64-encoded execute message returned by `transaction sign`.
    #[clap(long)]
    execute_message: String,

    /// Authority address and signature returned by `transaction sign`. Repeat for each PDA
    /// authority.
    #[clap(long = "authority", value_name = "ADDRESS=SIGNATURE")]
    authorities: Vec<String>,

    /// Signer source for a signer the executor uses directly: a keypair file, usb:// URL,
    /// prompt:// URL, or the ASK keyword. Repeat for each signer. These sign both the execute
    /// message and the relay transaction, after a signing summary. The fee payer is always a
    /// relay transaction signer.
    #[clap(long, value_parser = keypair_source_parser())]
    signer: Vec<SignerSource>,

    /// Hide the signing summary shown when a relay signer signs the execute message.
    /// Confirmation prompts and errors are still shown.
    #[clap(long)]
    quiet: bool,

    /// Skip the confirmation prompt for non-interactive signers (e.g. file keypairs).
    /// Hardware wallets still require approval on the device.
    #[clap(long)]
    yes: bool,
}

pub(super) async fn run(
    command: SubmitCommand,
    client: &Client,
    output: OutputFormat,
) -> Result<String> {
    let message = read_message(&command.execute_message, "execute message")?;
    let execute = ExecuteAccounts::try_new(&message)?;
    let required_signers = message.static_account_keys()
        [..usize::from(message.header().num_required_signatures)]
        .to_vec();
    let authority_signatures =
        verify_authority_signatures(&command.authorities, &message, &required_signers, &execute)?;

    let fee_payer = client.fee_payer()?;
    let fee_payer_address = fee_payer.try_pubkey()?;
    let mut relay_signers = vec![(fee_payer_address, fee_payer)];
    for source in &command.signer {
        let signer = client.load_signer(source, "signer")?;
        let address = signer.try_pubkey()?;
        // Relay signers only sign for accounts the executor uses directly. Authorities sign
        // through `transaction sign`.
        ensure!(
            required_signers.contains(&address) && execute.is_forwarded(&address),
            "{address} is not a forwarded signer on the execute message{}",
            if execute.is_pda_authority(&address) {
                ", PDA authorities sign with `transaction sign`"
            } else {
                ""
            }
        );
        if !relay_signers
            .iter()
            .any(|(existing, _)| existing == &address)
        {
            relay_signers.push((address, signer));
        }
    }
    // Relay signers on the execute message have their signer privilege forwarded to the
    // executor, so they review it like `transaction sign`. A fee payer that is not on the
    // execute message only signs the relay transaction.
    let (message_signers, relay_only_signers): (Vec<_>, Vec<_>) = relay_signers
        .into_iter()
        .partition(|(address, _)| required_signers.contains(address));
    let is_relay = |address: &Address| message_signers.iter().any(|(relay, _)| relay == address);

    // Authorities need a signature from `transaction sign`. Signers the executor uses directly
    // only keep their signer privilege if they also sign the relay transaction. An authority can
    // be both.
    for address in &required_signers {
        let is_pda_authority = execute.is_pda_authority(address);
        let is_forwarded = execute.is_forwarded(address);
        ensure!(
            is_pda_authority || is_forwarded,
            "{address} is neither a PDA authority nor a signer the executor uses"
        );
        ensure!(
            !is_pda_authority || authority_signatures.contains_key(address),
            "missing signature for authority {address}, authorities sign with `transaction sign`"
        );
        ensure!(
            !is_forwarded || is_relay(address),
            "{address} is a forwarded signer and must sign the relay transaction; pass it with \
             --signer"
        );
    }

    // Check the live nonce before asking relay signers to sign.
    let nonce = client.nonce_account(&execute.nonce_account).await?.state;
    ensure!(
        nonce.nonce == execute.expected_nonce,
        "execute message uses nonce value {}, but nonce account {} currently has {}",
        execute.expected_nonce,
        execute.nonce_account,
        nonce.nonce
    );
    ensure!(
        nonce.authority == execute.nonce_authority,
        "execute message uses nonce authority {}, but nonce account {} has authority {}",
        execute.nonce_authority,
        execute.nonce_account,
        nonce.authority
    );

    if !message_signers.is_empty() {
        if !command.quiet {
            // An authority the executor also uses directly is in both lists.
            let pda_authorities = required_signers
                .iter()
                .filter(|address| execute.is_pda_authority(address))
                .copied()
                .collect::<Vec<_>>();
            let forwarded_signers = required_signers
                .iter()
                .filter(|address| execute.is_forwarded(address))
                .copied()
                .collect::<Vec<_>>();
            eprintln!(
                "{}",
                render_signing_summary(
                    &execute.inner,
                    &message,
                    &execute.nonce_account,
                    &execute.nonce_authority,
                    &pda_authorities,
                    &forwarded_signers,
                    "Signing submits this Execute call immediately.",
                )?
            );
        }
        confirm_signing(&message_signers, command.yes)?;
    }

    let message_bytes = message.serialize();
    let signatures = required_signers
        .iter()
        .map(|address| {
            if let Some(signature) = authority_signatures.get(address) {
                return Ok(*signature);
            }
            let (_, signer) = message_signers
                .iter()
                .find(|(relay, _)| relay == address)
                .context("missing relay signer")?;
            signer
                .try_sign_message(&message_bytes)
                .with_context(|| format!("failed to sign execute message with {address}"))
        })
        .collect::<Result<Vec<_>>>()?;

    let mut instruction = spl_ed25519_signer_client::instruction::submit(signatures, message);
    // Forwarded signers need to sign the relay transaction.
    for meta in &mut instruction.accounts {
        meta.is_signer |=
            required_signers.contains(&meta.pubkey) && execute.is_forwarded(&meta.pubkey);
    }
    let relay_signers = message_signers
        .iter()
        .chain(&relay_only_signers)
        .map(|(_, signer)| signer.as_ref())
        .collect::<Vec<_>>();

    let mut transaction = Transaction::new_with_payer(&[instruction], Some(&fee_payer_address));
    let blockhash = client.latest_blockhash().await?;
    transaction
        .try_sign(&relay_signers, blockhash)
        .context("failed to sign relay transaction")?;
    let signature = client
        .send_and_confirm_transaction(&transaction)
        .await
        .with_context(|| format!("relay transaction {}", transaction.signatures[0]))?;

    output.render(&SubmitOutput { signature })
}

/// The accounts of an execute message's single `Execute` instruction.
struct ExecuteAccounts {
    nonce_authority: Address,
    nonce_account: Address,
    expected_nonce: Hash,
    inner: v1::Message,
    accounts: BTreeSet<Address>,
}

impl ExecuteAccounts {
    fn try_new(message: &VersionedMessage) -> Result<Self> {
        let account_keys = message.static_account_keys();
        let [instruction] = message.instructions() else {
            bail!("expected an Executor Execute instruction");
        };
        ensure!(
            account_keys.get(usize::from(instruction.program_id_index))
                == Some(&spl_message_executor_interface::id()),
            "expected an Executor Execute instruction"
        );
        let ExecutorInstruction::Execute(inner) =
            ExecutorInstruction::try_from_bytes(&instruction.data)
                .context("invalid Execute instruction")?;
        let inner = executable_inner_message(inner)?;

        // The signer program does not resolve address lookup tables.
        let accounts = instruction
            .accounts
            .iter()
            .map(|index| account_keys.get(usize::from(*index)).copied())
            .collect::<Option<Vec<_>>>()
            .context("Execute accounts must use static account keys")?;
        let [nonce_authority, nonce_account, _nonce_program, ..] = accounts.as_slice() else {
            bail!(
                "expected the nonce authority, nonce account, and SPL Nonce program in Execute \
                 accounts"
            );
        };
        Ok(Self {
            nonce_authority: *nonce_authority,
            nonce_account: *nonce_account,
            expected_nonce: inner.lifetime_specifier,
            inner,
            accounts: accounts.into_iter().collect(),
        })
    }

    /// The executor receives the signer's derived PDA, which Submit promotes.
    fn is_pda_authority(&self, signer: &Address) -> bool {
        let pda = ProgrammaticSigner::derive_address(&spl_ed25519_signer_client::id(), signer);
        self.accounts.contains(&pda)
    }

    /// The executor uses the signer itself as the nonce authority or an inner message signer,
    /// so it must be a relay transaction signer.
    fn is_forwarded(&self, signer: &Address) -> bool {
        signer == &self.nonce_authority
            || self
                .inner
                .account_keys
                .iter()
                .position(|address| address == signer)
                .is_some_and(|index| self.inner.is_signer(index))
    }
}

/// Verify each `ADDRESS=SIGNATURE` pair from `transaction sign` against the message and its
/// PDA authorities.
fn verify_authority_signatures(
    entries: &[String],
    message: &VersionedMessage,
    required_signers: &[Address],
    execute: &ExecuteAccounts,
) -> Result<BTreeMap<Address, Signature>> {
    let message_bytes = message.serialize();
    let mut signatures = BTreeMap::new();
    for entry in entries {
        let (address, signature) = entry
            .split_once('=')
            .context("invalid authority: expected ADDRESS=SIGNATURE")?;
        let address = Address::from_str(address).context("invalid authority address")?;
        let signature = Signature::from_str(signature).context("invalid authority signature")?;
        ensure!(
            required_signers.contains(&address),
            "{address} is not a signer on the execute message"
        );
        ensure!(
            execute.is_pda_authority(&address),
            "{address} is not a PDA authority on the execute message; pass it with --signer"
        );
        ensure!(
            signature.verify(address.as_ref(), &message_bytes),
            "invalid signature for authority {address}"
        );
        signatures.insert(address, signature);
    }
    Ok(signatures)
}

#[derive(Serialize)]
struct SubmitOutput {
    signature: String,
}

impl fmt::Display for SubmitOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.signature)
    }
}
