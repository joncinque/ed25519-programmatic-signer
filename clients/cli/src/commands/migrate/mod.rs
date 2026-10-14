pub(crate) mod program;
pub(crate) mod stake;
pub(crate) mod vote;

use {
    crate::{client::Client, output::OutputFormat},
    anyhow::{Context, Result, ensure},
    clap::{Args, Subcommand},
    serde::{Deserialize, Serialize},
    solana_address::Address,
    solana_hash::Hash,
    solana_instruction::Instruction,
    solana_message::v1,
    spl_ed25519_signer_client::ProgrammaticSigner,
    std::fmt,
};

#[derive(Debug, Args)]
pub(crate) struct MigrateCommand {
    #[clap(subcommand)]
    command: MigrateSubcommand,
}

#[derive(Debug, Subcommand)]
enum MigrateSubcommand {
    /// Build an execution message moving a program's upgrade authority to a programmatic signer.
    Program(program::ProgramCommand),
    /// Build an execution message moving a stake account's authorities to a programmatic signer.
    Stake(stake::StakeCommand),
    /// Build an execution message moving a vote account's withdraw authority to a programmatic
    /// signer.
    Vote(vote::VoteCommand),
}

pub(crate) async fn run(
    command: MigrateCommand,
    client: &Client,
    output: OutputFormat,
) -> Result<String> {
    match command.command {
        MigrateSubcommand::Program(command) => program::run(command, client, output).await,
        MigrateSubcommand::Stake(command) => stake::run(command, client, output).await,
        MigrateSubcommand::Vote(command) => vote::run(command, client, output).await,
    }
}

/// The programmatic signer that becomes the new authority. Its signing pubkey must be an Ed25519
/// key, since only an Ed25519 key can sign authorization messages for its PDA.
fn new_owner_programmatic_signer(new_authority_signing_pubkey: &Address) -> Result<Address> {
    ensure!(
        new_authority_signing_pubkey.is_on_curve(),
        "new authority signing pubkey {new_authority_signing_pubkey} is not an on-curve address. \
         Pass the signing pubkey, not its programmatic signer"
    );
    Ok(ProgrammaticSigner::derive_address(
        &spl_ed25519_signer_client::id(),
        new_authority_signing_pubkey,
    ))
}

/// The new authority's signing pubkey when none is given: the current authority, which then moves
/// to its own programmatic signer. `current_name` describes the current authority in errors.
fn default_new_authority(current_name: impl fmt::Display, current: Address) -> Result<Address> {
    ensure!(
        current.is_on_curve(),
        "{current_name} is {current}, which is not an on-curve address, so it can't be the \
         default new authority signing pubkey. Pass --new-authority-signing-pubkey"
    );
    Ok(current)
}

/// Compile the execution message for a migration to `new_owner_programmatic_signer`.
///
/// An execution message pays no fee, but v1 requires a writable signer first. The new authority's
/// programmatic signer signs every migration, so using it adds no signer. Submit promotes it
/// rather than verifying a signature for it, so it does not need to be on curve.
fn execution_message(
    new_owner_programmatic_signer: &Address,
    instructions: &[Instruction],
) -> Result<v1::Message> {
    // `transaction sign` replaces the blockhash with the SPL nonce value.
    let message =
        v1::Message::try_compile(new_owner_programmatic_signer, instructions, Hash::default())
            .context("failed to compile execution message")?;
    message.validate().context("invalid execution message")?;
    Ok(message)
}

/// Who must sign an execution message, besides the nonce authority chosen in `transaction sign`.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequiredSigners {
    /// Off-curve signers, which a signing pubkey promotes by signing with `transaction sign`.
    pub authorizations: Vec<Authorization>,
    /// On-curve signers, which sign the relay transaction with `transaction submit`.
    pub forwarded_signers: Vec<String>,
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Authorization {
    pub programmatic_signer: String,
    /// Known when the signer derives from an address the command was given. A PDA can't be
    /// traced back to its signing pubkey.
    pub signer_pubkey: Option<String>,
}

impl RequiredSigners {
    fn new(execution_message: &v1::Message, known_signer_pubkeys: &[Address]) -> Self {
        let signers = &execution_message.account_keys
            [..usize::from(execution_message.header.num_required_signatures)];
        let (forwarded_signers, programmatic_signers): (Vec<&Address>, Vec<_>) =
            signers.iter().partition(|address| address.is_on_curve());
        Self {
            authorizations: programmatic_signers
                .into_iter()
                .map(|programmatic_signer| Authorization {
                    programmatic_signer: programmatic_signer.to_string(),
                    signer_pubkey: known_signer_pubkeys
                        .iter()
                        .find(|signer_pubkey| {
                            ProgrammaticSigner::derive_address(
                                &spl_ed25519_signer_client::id(),
                                signer_pubkey,
                            ) == *programmatic_signer
                        })
                        .map(ToString::to_string),
                })
                .collect(),
            forwarded_signers: forwarded_signers.iter().map(ToString::to_string).collect(),
        }
    }
}

impl fmt::Display for RequiredSigners {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.authorizations.is_empty() {
            writeln!(
                f,
                "Programmatic signers (authorize with `transaction sign`):"
            )?;
            for authorization in &self.authorizations {
                match &authorization.signer_pubkey {
                    Some(signer_pubkey) => writeln!(
                        f,
                        "  {} (signing pubkey: {signer_pubkey})",
                        authorization.programmatic_signer
                    )?,
                    None => writeln!(
                        f,
                        "  {} (signing pubkey unknown)",
                        authorization.programmatic_signer
                    )?,
                }
            }
        }
        if !self.forwarded_signers.is_empty() {
            writeln!(f, "Forwarded signers (sign with `transaction submit`):")?;
            for address in &self.forwarded_signers {
                writeln!(f, "  {address}")?;
            }
        }
        write!(
            f,
            "The nonce authority also signs. It is chosen in `transaction sign`."
        )
    }
}
