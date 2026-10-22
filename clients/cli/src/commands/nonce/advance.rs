use {
    super::{NonceAuthority, send_relay_transaction},
    crate::{
        cli::keypair_source_parser, client::Client, commands::transaction::summary::next_nonce,
        output::OutputFormat,
    },
    anyhow::{Context, Result, bail},
    base64::{Engine, prelude::BASE64_STANDARD},
    clap::Args,
    serde::{Deserialize, Serialize},
    solana_address::Address,
    solana_clap_v3_utils::input_parsers::signer::SignerSource,
    solana_hash::Hash,
    solana_message::{MessageHeader, VersionedMessage, v1},
    spl_ed25519_signer_client::ProgrammaticSigner,
    spl_message_executor_client::instruction::execute,
    std::fmt,
};

#[derive(Debug, Args)]
pub(crate) struct AdvanceCommand {
    /// Address of the SPL Nonce account to advance.
    nonce_account: Address,

    /// The nonce authority, or the authority whose derived ProgrammaticSigner PDA is the nonce
    /// authority: a keypair file, usb:// URL, prompt:// URL, or the ASK keyword. Defaults to the
    /// configured keypair. For a PDA nonce authority, also accepts the authority's address, which
    /// prints the authorization message for it to sign externally and pass to
    /// `transaction submit`.
    #[clap(long, value_parser = keypair_source_parser())]
    nonce_authority: Option<SignerSource>,

    /// Read-only account in the empty execution message that advances the nonce, which sets the
    /// next nonce value. Defaults to a random address, so the next nonce value can't be predicted.
    #[clap(long, value_name = "ADDRESS")]
    salt: Option<Address>,
}

pub(super) async fn run(
    command: AdvanceCommand,
    client: &Client,
    output: OutputFormat,
) -> Result<String> {
    let authority = NonceAuthority::load(client, command.nonce_authority)?;
    let authority_address = authority.address;

    let nonce_account = command.nonce_account;
    let previous = client.nonce_account(&nonce_account).await?.state;
    let pda =
        ProgrammaticSigner::derive_address(&spl_ed25519_signer_client::id(), &authority_address);
    let salt = command
        .salt
        .unwrap_or_else(|| Address::new_from_array(rand::random()));

    // The executor always runs the same empty execution message, signed by the nonce
    // authority, so the next nonce value is derived the same way.
    let (execution_message, relay_instruction, authority_signer) = if previous.authority
        == authority_address
    {
        authority.ensure_can_sign()?;
        let execution_message = empty_execution_message(&authority_address, &salt, previous.nonce)?;
        let execute = execute(&nonce_account, &authority_address, &execution_message);
        (execution_message, execute, Some(authority.signer))
    } else if previous.authority == pda {
        // The authority signs an authorization message, which promotes its PDA to sign the Execute
        let execution_message = empty_execution_message(&pda, &salt, previous.nonce)?;
        let execute = execute(&nonce_account, &pda, &execution_message);
        let VersionedMessage::V1(authorization_message) =
            spl_ed25519_signer_client::message::authorization_message(
                &execute,
                &[authority_address],
            )
        else {
            unreachable!("authorization_message builds a v1 message");
        };
        authorization_message
            .validate()
            .context("invalid authorization message")?;

        if !authority.can_sign {
            return output.render(&NonceAdvanceAuthorizationOutput {
                nonce_account: nonce_account.to_string(),
                current_nonce: previous.nonce.to_string(),
                authorization_message: BASE64_STANDARD.encode(authorization_message.serialize()),
                next_nonce: next_nonce(&nonce_account, &execution_message).to_string(),
                signer: authority_address.to_string(),
            });
        }

        let signature = authority
            .signer
            .try_sign_message(&authorization_message.serialize())
            .with_context(|| {
                format!("failed to sign authorization message with {authority_address}")
            })?;
        let submit = spl_ed25519_signer_client::instruction::submit(
            vec![Some(signature)],
            VersionedMessage::V1(authorization_message),
        );
        (execution_message, submit, None)
    } else {
        bail!(
            "nonce account {nonce_account} has authority {}, but the nonce authority given is \
             {authority_address} and its derived signer is {pda}",
            previous.authority
        );
    };

    let signature =
        send_relay_transaction(client, relay_instruction, authority_signer.as_deref()).await?;

    output.render(&NonceAdvanceOutput {
        signature,
        nonce_account: nonce_account.to_string(),
        previous_nonce: previous.nonce.to_string(),
        nonce: next_nonce(&nonce_account, &execution_message).to_string(),
    })
}

/// An execution message with no instructions, signed by the nonce authority. Executing it only
/// advances the nonce. The nonce commits to this message, so the salt sets the next nonce value.
fn empty_execution_message(
    nonce_authority: &Address,
    salt: &Address,
    current_nonce: Hash,
) -> Result<v1::Message> {
    // v1 messages need a writable signer, which the nonce authority fills.
    let message = v1::Message {
        header: MessageHeader {
            num_required_signatures: 1,
            num_readonly_signed_accounts: 0,
            num_readonly_unsigned_accounts: 1,
        },
        config: v1::TransactionConfig::default(),
        lifetime_specifier: current_nonce,
        account_keys: vec![*nonce_authority, *salt],
        instructions: vec![],
    };
    message.validate().context("invalid execution message")?;
    Ok(message)
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NonceAdvanceOutput {
    pub signature: String,
    pub nonce_account: String,
    pub previous_nonce: String,
    pub nonce: String,
}

impl fmt::Display for NonceAdvanceOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(formatter, "Signature: {}", self.signature)?;
        writeln!(formatter, "Nonce account: {}", self.nonce_account)?;
        writeln!(formatter, "Previous nonce: {}", self.previous_nonce)?;
        write!(formatter, "Nonce: {}", self.nonce)
    }
}

/// The unsigned authorization message for an authority that signs externally, and submits it with
/// `transaction submit`.
#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NonceAdvanceAuthorizationOutput {
    pub nonce_account: String,
    pub current_nonce: String,
    pub authorization_message: String,
    pub next_nonce: String,
    pub signer: String,
}

impl fmt::Display for NonceAdvanceAuthorizationOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(formatter, "Nonce account: {}", self.nonce_account)?;
        writeln!(formatter, "Signer: {}", self.signer)?;
        writeln!(formatter, "Current nonce value: {}", self.current_nonce)?;
        writeln!(formatter, "Next nonce value: {}", self.next_nonce)?;
        writeln!(formatter)?;
        writeln!(
            formatter,
            "Authorization message (base64):\n{}",
            self.authorization_message
        )?;
        writeln!(formatter)?;
        writeln!(
            formatter,
            "Sign authorization message with {}, then run:",
            self.signer
        )?;
        write!(
            formatter,
            "  transaction submit --authorization-message <MESSAGE> --signer {}=<SIGNATURE>",
            self.signer
        )
    }
}
