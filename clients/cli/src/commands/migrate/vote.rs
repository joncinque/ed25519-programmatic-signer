use {
    super::{
        RequiredSigners, default_new_authority, execution_message, new_owner_programmatic_signer,
    },
    crate::{client::Client, output::OutputFormat},
    anyhow::{Result, bail, ensure},
    base64::{Engine, prelude::BASE64_STANDARD},
    clap::Args,
    serde::{Deserialize, Serialize},
    solana_address::Address,
    solana_vote_interface::{
        instruction::authorize_checked,
        state::{VoteAuthorize, VoteStateVersions},
    },
    std::fmt,
};

#[derive(Debug, Args)]
pub(crate) struct VoteCommand {
    /// Vote account to migrate.
    vote_account: Address,

    /// Signing pubkey of the new authority. Its programmatic signer becomes the withdraw authority.
    /// Pass the signing pubkey itself, not its programmatic signer. Defaults to the current
    /// withdrawer, which then moves to its own programmatic signer.
    #[clap(long)]
    new_authority_signing_pubkey: Option<Address>,
}

pub(super) async fn run(
    command: VoteCommand,
    client: &Client,
    output: OutputFormat,
) -> Result<String> {
    let withdrawer = authorized_withdrawer(
        &client.vote_account(&command.vote_account).await?,
        &command.vote_account,
    )?;
    let new_authority_signing_pubkey = match command.new_authority_signing_pubkey {
        Some(new_authority_signing_pubkey) => new_authority_signing_pubkey,
        None => default_new_authority(
            format_args!("the withdrawer of vote account {}", command.vote_account),
            withdrawer,
        )?,
    };
    let new_owner_programmatic_signer =
        new_owner_programmatic_signer(&new_authority_signing_pubkey)?;
    ensure!(
        withdrawer != new_owner_programmatic_signer,
        "the withdrawer of vote account {} is already {new_owner_programmatic_signer}",
        command.vote_account
    );

    let instruction = authorize_checked(
        &command.vote_account,
        &withdrawer,
        &new_owner_programmatic_signer,
        VoteAuthorize::Withdrawer,
    );
    let execution_message = execution_message(&new_owner_programmatic_signer, &[instruction])?;

    output.render(&VoteMigrationOutput {
        vote_account: command.vote_account.to_string(),
        new_authority: new_owner_programmatic_signer.to_string(),
        new_authority_signing_pubkey: new_authority_signing_pubkey.to_string(),
        required_signers: RequiredSigners::new(&execution_message, &[new_authority_signing_pubkey]),
        execution_message: BASE64_STANDARD.encode(execution_message.serialize()),
    })
}

fn authorized_withdrawer(state: &VoteStateVersions, vote_account: &Address) -> Result<Address> {
    if state.is_uninitialized() {
        bail!("vote account {vote_account} is not initialized");
    }
    Ok(match state {
        VoteStateVersions::Uninitialized => unreachable!("checked above"),
        VoteStateVersions::V1_14_11(state) => state.authorized_withdrawer,
        VoteStateVersions::V3(state) => state.authorized_withdrawer,
        VoteStateVersions::V4(state) => state.authorized_withdrawer,
    })
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VoteMigrationOutput {
    pub vote_account: String,
    pub new_authority: String,
    pub new_authority_signing_pubkey: String,
    #[serde(flatten)]
    pub required_signers: RequiredSigners,
    pub execution_message: String,
}

impl fmt::Display for VoteMigrationOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Vote account: {}", self.vote_account)?;
        writeln!(f, "Authority moved: withdrawer")?;
        writeln!(
            f,
            "New authority: {} (signing pubkey: {})",
            self.new_authority, self.new_authority_signing_pubkey
        )?;
        writeln!(f)?;
        writeln!(f, "{}", self.required_signers)?;
        writeln!(f)?;
        write!(f, "Execution message (base64):\n{}", self.execution_message)
    }
}
