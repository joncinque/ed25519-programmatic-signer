use {
    super::{
        decode::{read_authorization_message, validate_execution_message},
        summary::{confirm_signing, render_signing_summary},
    },
    crate::{cli::keypair_source_parser, client::Client, output::OutputFormat},
    anyhow::{Context, Result, bail, ensure},
    clap::Args,
    serde::Serialize,
    solana_address::Address,
    solana_clap_v3_utils::input_parsers::signer::{SignerSource, SignerSourceKind},
    solana_cli_output::{ReturnSignersConfig, return_signers_data},
    solana_hash::Hash,
    solana_message::{VersionedMessage, v1},
    solana_signature::Signature,
    solana_signer::Signer,
    solana_system_interface::instruction::advance_nonce_account,
    solana_transaction::Transaction,
    spl_ed25519_signer_client::ProgrammaticSigner,
    spl_message_executor_interface::instruction::Instruction as ExecutorInstruction,
    std::{collections::BTreeMap, fmt, str::FromStr},
};

#[derive(Debug, Args)]
pub(super) struct SubmitCommand {
    /// Base64-encoded v1 authorization message returned by `transaction sign`.
    #[clap(long)]
    authorization_message: String,

    /// Authority address and signature returned by `transaction sign`. Repeat for each PDA
    /// authority.
    #[clap(long = "signer", value_name = "ADDRESS=SIGNATURE")]
    signers: Vec<String>,

    /// Signer source for a signer the executor uses directly: a keypair file, usb:// URL,
    /// prompt:// URL, or the ASK keyword. Repeat for each signer. Each signs the relay
    /// transaction after a signing summary, which forwards its signer privilege to the executor.
    /// The fee payer is always a relay transaction signer. With --sign-only, forwarded signers
    /// that are not passed are reported as absent.
    #[clap(long, value_parser = keypair_source_parser())]
    relay_signer: Vec<SignerSource>,

    /// System Program nonce account to use as the relay transaction's durable nonce, in place of
    /// a recent blockhash. The relay transaction advances it first. This is separate from the SPL
    /// nonce account protecting the execution message.
    #[clap(long, value_name = "ADDRESS")]
    durable_nonce: Option<Address>,

    /// Durable nonce authority signer source: a keypair file, usb:// URL, prompt:// URL, or the
    /// ASK keyword. With --sign-only, also accepts an address, whose signature is collected
    /// separately. Defaults to the fee payer.
    #[clap(
        long,
        requires = "durable-nonce",
        value_parser = keypair_source_parser()
    )]
    durable_nonce_authority: Option<SignerSource>,

    /// Blockhash for the relay transaction. Defaults to the latest blockhash.
    /// With --durable-nonce, pass the nonce stored in the durable nonce account instead. It
    /// defaults to that nonce, and must match it when submitting.
    #[clap(long, value_name = "HASH")]
    blockhash: Option<Hash>,

    /// Sign the relay transaction without submitting it, and print the signatures of local
    /// signers along with any absent signers. Makes no RPC calls. Each run must use the same
    /// arguments, apart from which signers are local. Requires --blockhash.
    #[clap(long, requires = "blockhash")]
    sign_only: bool,

    /// With --sign-only, also print the base64-encoded relay transaction message, to check that
    /// separate runs sign the same message.
    #[clap(long, requires = "sign-only")]
    dump_transaction_message: bool,

    /// Hide the signing summary shown when a forwarded signer signs the relay transaction.
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
    let authorization_message = read_authorization_message(&command.authorization_message)?;
    let execute = ExecuteAccounts::try_new(&authorization_message)?;
    let required_signers = authorization_message.account_keys
        [..usize::from(authorization_message.header.num_required_signatures)]
        .to_vec();
    let authority_signatures = verify_authority_signatures(
        &command.signers,
        &authorization_message,
        &required_signers,
        &execute,
    )?;

    // With --sign-only, the fee payer and durable nonce authority may be given as an address.
    // They load as null signers, leaving their signatures absent for another run to provide.
    let mut relay_signers = Vec::new();
    let fee_payer_source = client.fee_payer_source()?;
    let fee_payer_address = load_relay_signer(
        &mut relay_signers,
        client,
        &fee_payer_source,
        "fee payer",
        command.sign_only,
    )?;
    let durable_nonce = match command.durable_nonce {
        Some(address) => {
            let authority = match &command.durable_nonce_authority {
                Some(source) => load_relay_signer(
                    &mut relay_signers,
                    client,
                    source,
                    "durable nonce authority",
                    command.sign_only,
                )?,
                None => fee_payer_address,
            };
            Some((address, authority))
        }
        None => None,
    };
    for source in &command.relay_signer {
        let signer = client.load_signer(source, "relay signer", false)?;
        let address = signer.try_pubkey()?;
        // Relay signers only sign for accounts the executor uses directly. Authorities sign
        // through `transaction sign`.
        ensure!(
            required_signers.contains(&address) && execute.is_executor_signer(&address),
            "{address} is not a forwarded signer on the authorization message{}",
            if execute.is_pda_authority(&address) {
                ", PDA authorities sign with `transaction sign`"
            } else {
                ""
            }
        );
        add_relay_signer(&mut relay_signers, address, signer);
    }
    // Relay signers on the authorization message have their signer privilege forwarded to the
    // executor, so they review it like `transaction sign`. A fee payer or durable nonce authority
    // that is not on the authorization message only signs for the relay transaction.
    let (authorization_signers, relay_only_signers): (Vec<_>, Vec<_>) = relay_signers
        .into_iter()
        .partition(|(address, _)| required_signers.contains(address));
    let is_relay = |address: &Address| {
        authorization_signers
            .iter()
            .any(|(relay, _)| relay == address)
    };

    // Authorities sign the authorization message with `transaction sign`. Signers the executor
    // uses directly sign the relay transaction instead, which is how the executor gets their
    // signer privilege. One address can be both. A --sign-only run signs for the forwarded
    // signers it has, and reports the rest as absent.
    for address in &required_signers {
        let is_pda_authority = execute.is_pda_authority(address);
        let is_forwarded = execute.is_executor_signer(address);
        ensure!(
            is_pda_authority || is_forwarded,
            "{address} is neither a PDA authority nor a signer the executor uses"
        );
        ensure!(
            !is_pda_authority || authority_signatures.contains_key(address),
            "missing signature for authority {address}, authorities sign with `transaction sign`"
        );
        ensure!(
            !is_forwarded || is_relay(address) || command.sign_only,
            "{address} is a forwarded signer and must sign the relay transaction; pass it with \
             --relay-signer"
        );
    }

    // Check the live nonces before asking relay signers to sign. A --sign-only run makes no RPC
    // calls, so the online run checks them instead.
    let blockhash = if command.sign_only {
        // Infallible: clap requires --blockhash with --sign-only.
        command.blockhash.unwrap()
    } else {
        check_execution_nonce(client, &execute).await?;
        match durable_nonce {
            Some((address, authority)) => {
                check_durable_nonce(client, &address, &authority, command.blockhash).await?
            }
            None => match command.blockhash {
                Some(blockhash) => blockhash,
                None => client.latest_blockhash().await?,
            },
        }
    };

    if !authorization_signers.is_empty() {
        if !command.quiet {
            // An authority the executor also uses directly is in both lists.
            let pda_authorities = required_signers
                .iter()
                .filter(|address| execute.is_pda_authority(address))
                .copied()
                .collect::<Vec<_>>();
            let forwarded_signers = required_signers
                .iter()
                .filter(|address| execute.is_executor_signer(address))
                .copied()
                .collect::<Vec<_>>();
            eprintln!(
                "{}",
                render_signing_summary(
                    &execute.execution_message,
                    &authorization_message,
                    &execute.nonce_account,
                    &execute.nonce_authority,
                    &pda_authorities,
                    &forwarded_signers,
                    if command.sign_only {
                        "Signing returns relay transaction signatures. Nothing is submitted."
                    } else {
                        "Signing submits this Execute call immediately."
                    },
                )?
            );
        }
        confirm_signing(&authorization_signers, command.yes)?;
    }

    // Forwarded signers without an authority signature approve through their relay transaction
    // signature instead, which Submit accepts in place of an authorization message signature.
    let signatures = required_signers
        .iter()
        .map(|address| authority_signatures.get(address).copied())
        .collect();

    let mut submit = spl_ed25519_signer_client::instruction::submit(
        signatures,
        VersionedMessage::V1(authorization_message),
    );
    // Forwarded signers need to sign the relay transaction.
    for meta in &mut submit.accounts {
        meta.is_signer |=
            required_signers.contains(&meta.pubkey) && execute.is_executor_signer(&meta.pubkey);
    }
    // A durable nonce transaction must advance its nonce in its first instruction.
    let instructions = match durable_nonce {
        Some((address, authority)) => vec![advance_nonce_account(&address, &authority), submit],
        None => vec![submit],
    };
    let relay_signers = authorization_signers
        .iter()
        .map(|(_, signer)| signer.as_ref())
        .chain(relay_only_signers.iter().map(|(_, signer)| signer.as_ref()))
        .collect::<Vec<_>>();

    let mut transaction = Transaction::new_with_payer(&instructions, Some(&fee_payer_address));
    if command.sign_only {
        // Signers given as an address stay absent for another run to provide.
        transaction
            .try_partial_sign(&relay_signers, blockhash)
            .context("failed to sign relay transaction")?;
        return output.render(&return_signers_data(
            &transaction,
            &ReturnSignersConfig {
                dump_transaction_message: command.dump_transaction_message,
            },
        ));
    }
    // Every signature must be present before submitting.
    transaction
        .try_sign(&relay_signers, blockhash)
        .context("failed to sign relay transaction")?;
    let signature = client
        .send_and_confirm_transaction(&transaction)
        .await
        .with_context(|| format!("relay transaction {}", transaction.signatures[0]))?;

    output.render(&SubmitOutput { signature })
}

/// Load and add a relay signer, returning its address. With `allow_null_signer`, an address source
/// only gives the address, and its signature is left absent.
fn load_relay_signer(
    relay_signers: &mut Vec<(Address, Box<dyn Signer>)>,
    client: &Client,
    source: &SignerSource,
    name: &str,
    allow_null_signer: bool,
) -> Result<Address> {
    let signer = client.load_signer(source, name, allow_null_signer)?;
    let address = signer.try_pubkey()?;
    // A null signer has nothing to sign with, so only its address is needed.
    if !matches!(source.kind, SignerSourceKind::Pubkey(_)) {
        add_relay_signer(relay_signers, address, signer);
    }
    Ok(address)
}

/// Add a relay signer unless its address is already present.
fn add_relay_signer(
    relay_signers: &mut Vec<(Address, Box<dyn Signer>)>,
    address: Address,
    signer: Box<dyn Signer>,
) {
    if !relay_signers
        .iter()
        .any(|(existing, _)| existing == &address)
    {
        relay_signers.push((address, signer));
    }
}

/// Check the SPL nonce account still has the value and authority the execution message uses.
async fn check_execution_nonce(client: &Client, execute: &ExecuteAccounts) -> Result<()> {
    let nonce = client.nonce_account(&execute.nonce_account).await?.state;
    ensure!(
        nonce.nonce == execute.expected_nonce,
        "authorization message uses nonce value {}, but nonce account {} currently has {}",
        execute.expected_nonce,
        execute.nonce_account,
        nonce.nonce
    );
    ensure!(
        nonce.authority == execute.nonce_authority,
        "authorization message uses nonce authority {}, but nonce account {} has authority {}",
        execute.nonce_authority,
        execute.nonce_account,
        nonce.authority
    );
    Ok(())
}

/// Check the System Program nonce account still has the value and authority the relay
/// transaction uses, returning its current value. Without an expected value, any value is used.
async fn check_durable_nonce(
    client: &Client,
    address: &Address,
    authority: &Address,
    expected_value: Option<Hash>,
) -> Result<Hash> {
    let durable_nonce = client.durable_nonce_account(address).await?;
    let value = durable_nonce.blockhash();
    if let Some(expected_value) = expected_value {
        ensure!(
            value == expected_value,
            "relay transaction uses durable nonce value {}, but durable nonce account {} \
             currently has {}",
            expected_value,
            address,
            value
        );
    }
    ensure!(
        durable_nonce.authority == *authority,
        "relay transaction uses durable nonce authority {}, but durable nonce account {} has \
         authority {}",
        authority,
        address,
        durable_nonce.authority
    );
    Ok(value)
}

/// The accounts of an authorization message's single `Execute` instruction.
struct ExecuteAccounts {
    nonce_authority: Address,
    nonce_account: Address,
    expected_nonce: Hash,
    execution_message: v1::Message,
}

impl ExecuteAccounts {
    fn try_new(message: &v1::Message) -> Result<Self> {
        let account_keys = &message.account_keys;
        let [instruction] = message.instructions.as_slice() else {
            bail!("expected an Executor Execute instruction");
        };
        ensure!(
            account_keys.get(usize::from(instruction.program_id_index))
                == Some(&spl_message_executor_interface::id()),
            "expected an Executor Execute instruction"
        );
        let ExecutorInstruction::Execute(execution_message) =
            ExecutorInstruction::try_from_bytes(&instruction.data)
                .context("invalid Execute instruction")?;
        let execution_message = validate_execution_message(execution_message)?;

        // Infallible: read_authorization_message sanitized the message, which checks every
        // instruction account index is within the account keys.
        let accounts = instruction
            .accounts
            .iter()
            .map(|index| account_keys[usize::from(*index)])
            .collect::<Vec<_>>();
        let [nonce_authority, nonce_account, _nonce_program, ..] = accounts.as_slice() else {
            bail!(
                "expected the nonce authority, nonce account, and SPL Nonce program in Execute \
                 accounts"
            );
        };
        Ok(Self {
            nonce_authority: *nonce_authority,
            nonce_account: *nonce_account,
            expected_nonce: execution_message.lifetime_specifier,
            execution_message,
        })
    }

    /// The executor uses the signer's derived PDA as a signer, which Submit promotes. A PDA in
    /// any other role needs no authorization, matching `transaction sign`.
    fn is_pda_authority(&self, signer: &Address) -> bool {
        let pda = ProgrammaticSigner::derive_address(&spl_ed25519_signer_client::id(), signer);
        self.is_executor_signer(&pda)
    }

    /// Whether the executor uses the address as the nonce authority or an execution message
    /// signer.
    fn is_executor_signer(&self, address: &Address) -> bool {
        address == &self.nonce_authority
            || self
                .execution_message
                .account_keys
                .iter()
                .position(|key| key == address)
                .is_some_and(|index| self.execution_message.is_signer(index))
    }
}

/// Verify each `ADDRESS=SIGNATURE` pair from `transaction sign` against the message and its
/// PDA authorities.
fn verify_authority_signatures(
    entries: &[String],
    message: &v1::Message,
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
            "{address} is not a signer on the authorization message"
        );
        ensure!(
            execute.is_pda_authority(&address),
            "{address} is not a PDA authority on the authorization message; pass it with \
             --relay-signer"
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
