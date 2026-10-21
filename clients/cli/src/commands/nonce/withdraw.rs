use {
    super::{NonceAuthority, send_relay_transaction},
    crate::{
        cli::keypair_source_parser, client::Client, commands::transaction::summary::next_nonce,
        output::OutputFormat,
    },
    anyhow::{Context, Result, bail, ensure},
    base64::{Engine, prelude::BASE64_STANDARD},
    clap::Args,
    serde::{Deserialize, Serialize},
    solana_address::Address,
    solana_clap_v3_utils::input_parsers::signer::SignerSource,
    solana_message::{VersionedMessage, v1},
    solana_native_token::{Sol, sol_str_to_lamports},
    spl_ed25519_signer_client::ProgrammaticSigner,
    spl_message_executor_client::instruction::execute,
    spl_nonce_interface::state::Nonce,
    std::fmt,
};

#[derive(Debug, Args)]
pub(crate) struct WithdrawCommand {
    /// Address of the SPL Nonce account to withdraw from.
    nonce_account: Address,

    /// Account receiving the withdrawn lamports.
    #[clap(value_name = "RECIPIENT_ADDRESS")]
    destination: Address,

    /// Amount to withdraw in SOL, or ALL to withdraw the whole balance and close the nonce
    /// account. A partial withdrawal must leave the nonce account rent-exempt.
    #[clap(value_parser = parse_amount)]
    amount: Amount,

    /// The nonce authority, or the authority whose derived ProgrammaticSigner PDA is the nonce
    /// authority: a keypair file, usb:// URL, prompt:// URL, or the ASK keyword. Defaults to the
    /// configured keypair. For a PDA nonce authority, also accepts the authority's address, which
    /// prints the authorization message for it to sign externally and pass to
    /// `transaction submit`.
    #[clap(long, value_parser = keypair_source_parser())]
    nonce_authority: Option<SignerSource>,
}

#[derive(Clone, Copy, Debug)]
enum Amount {
    All,
    Lamports(u64),
}

/// Parse a SOL amount exactly, like the other Solana CLI withdraw commands, or ALL.
fn parse_amount(arg: &str) -> Result<Amount, String> {
    if arg == "ALL" {
        return Ok(Amount::All);
    }
    sol_str_to_lamports(arg)
        .map(Amount::Lamports)
        .ok_or_else(|| format!("invalid amount {arg:?}, expected a SOL amount or ALL"))
}

pub(super) async fn run(
    command: WithdrawCommand,
    client: &Client,
    output: OutputFormat,
) -> Result<String> {
    let authority = NonceAuthority::load(client, command.nonce_authority)?;
    let nonce_account = command.nonce_account;
    let destination = command.destination;
    ensure!(
        destination != nonce_account,
        "destination must differ from nonce account {nonce_account}"
    );

    let account = client.nonce_account(&nonce_account).await?;
    let previous = account.state;
    let lamports = match command.amount {
        Amount::All => account.lamports,
        Amount::Lamports(lamports) => lamports,
    };
    ensure!(lamports > 0, "withdrawal amount must be greater than zero");
    let remaining = account.lamports.checked_sub(lamports).with_context(|| {
        format!(
            "nonce account {nonce_account} has {}, less than the {} to withdraw",
            Sol(account.lamports),
            Sol(lamports)
        )
    })?;
    let closes = remaining == 0;
    if !closes {
        let rent_exempt_minimum = client
            .minimum_balance_for_rent_exemption(Nonce::LEN)
            .await?;
        ensure!(
            remaining >= rent_exempt_minimum,
            "withdrawing {} would leave nonce account {nonce_account} with {}, below its \
             rent-exempt minimum of {}. Withdraw ALL to close it",
            Sol(lamports),
            Sol(remaining),
            Sol(rent_exempt_minimum)
        );
    }

    let pda =
        ProgrammaticSigner::derive_address(&spl_ed25519_signer_client::id(), &authority.address);
    let (signature, nonce) = if previous.authority == authority.address {
        // The authority withdraws directly, which leaves the nonce unchanged.
        authority.ensure_can_sign()?;
        let withdraw = spl_nonce_client::instruction::withdraw(
            &authority.address,
            &nonce_account,
            &destination,
            lamports,
        );
        let signature =
            send_relay_transaction(client, withdraw, Some(authority.signer.as_ref())).await?;
        (signature, previous.nonce)
    } else if previous.authority == pda {
        // The authority signs an authorization message, which promotes its PDA to sign the
        // withdrawal. The executor protects it with this nonce account, so advances it first.
        let withdraw =
            spl_nonce_client::instruction::withdraw(&pda, &nonce_account, &destination, lamports);
        let execution_message = v1::Message::try_compile(&pda, &[withdraw], previous.nonce)
            .context("failed to compile execution message")?;
        execution_message
            .validate()
            .context("invalid execution message")?;
        let next_nonce = next_nonce(&nonce_account, &execution_message);
        let execute = execute(&nonce_account, &pda, &execution_message);
        let VersionedMessage::V1(authorization_message) =
            spl_ed25519_signer_client::message::authorization_message(
                &execute,
                &[authority.address],
            )
        else {
            unreachable!("authorization_message builds a v1 message");
        };
        authorization_message
            .validate()
            .context("invalid authorization message")?;

        if !authority.can_sign {
            return output.render(&NonceWithdrawAuthorizationOutput {
                nonce_account: nonce_account.to_string(),
                current_nonce: previous.nonce.to_string(),
                next_nonce: (!closes).then(|| next_nonce.to_string()),
                destination: destination.to_string(),
                lamports,
                signer: authority.address.to_string(),
                authorization_message: BASE64_STANDARD.encode(authorization_message.serialize()),
            });
        }

        let signature = authority
            .signer
            .try_sign_message(&authorization_message.serialize())
            .with_context(|| {
                format!(
                    "failed to sign authorization message with {}",
                    authority.address
                )
            })?;
        let submit = spl_ed25519_signer_client::instruction::submit(
            vec![Some(signature)],
            VersionedMessage::V1(authorization_message),
        );
        (
            send_relay_transaction(client, submit, None).await?,
            next_nonce,
        )
    } else {
        bail!(
            "nonce account {nonce_account} has authority {}, but the nonce authority given is {} \
             and its derived signer is {pda}",
            previous.authority,
            authority.address
        );
    };

    output.render(&NonceWithdrawOutput {
        signature,
        nonce_account: nonce_account.to_string(),
        destination: destination.to_string(),
        lamports,
        nonce: (!closes).then(|| nonce.to_string()),
    })
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NonceWithdrawOutput {
    pub signature: String,
    pub nonce_account: String,
    pub destination: String,
    pub lamports: u64,
    /// The nonce value after the withdrawal, or `None` when it closed the nonce account.
    pub nonce: Option<String>,
}

impl fmt::Display for NonceWithdrawOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(formatter, "Signature: {}", self.signature)?;
        writeln!(formatter, "Nonce account: {}", self.nonce_account)?;
        writeln!(formatter, "Destination: {}", self.destination)?;
        writeln!(formatter, "Withdrawn: {}", Sol(self.lamports))?;
        match &self.nonce {
            Some(nonce) => write!(formatter, "Nonce: {nonce}"),
            None => write!(formatter, "Nonce account closed"),
        }
    }
}

/// The unsigned authorization message for an authority that signs externally, and submits it with
/// `transaction submit`.
#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NonceWithdrawAuthorizationOutput {
    pub nonce_account: String,
    pub current_nonce: String,
    /// `None` when the withdrawal closes the nonce account.
    pub next_nonce: Option<String>,
    pub destination: String,
    pub lamports: u64,
    pub signer: String,
    pub authorization_message: String,
}

impl fmt::Display for NonceWithdrawAuthorizationOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(formatter, "Nonce account: {}", self.nonce_account)?;
        writeln!(formatter, "Destination: {}", self.destination)?;
        match &self.next_nonce {
            Some(_) => writeln!(formatter, "Withdraw: {}", Sol(self.lamports))?,
            None => writeln!(
                formatter,
                "Withdraw: {} (closes the nonce account)",
                Sol(self.lamports)
            )?,
        }
        writeln!(formatter, "Signer: {}", self.signer)?;
        writeln!(formatter, "Current nonce value: {}", self.current_nonce)?;
        if let Some(next_nonce) = &self.next_nonce {
            writeln!(formatter, "Next nonce value: {next_nonce}")?;
        }
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
