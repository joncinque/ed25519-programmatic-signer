use {
    super::{
        RequiredSigners, default_new_authority, execution_message, new_owner_programmatic_signer,
    },
    crate::{client::Client, output::OutputFormat},
    anyhow::{Context, Result, ensure},
    base64::{Engine, prelude::BASE64_STANDARD},
    clap::{Args, ValueEnum},
    serde::{Deserialize, Serialize},
    solana_address::Address,
    solana_stake_interface::{
        instruction::authorize_checked,
        state::{Authorized, StakeAuthorize},
    },
    std::fmt,
};

#[derive(Clone, Copy, Debug, ValueEnum)]
enum AuthorityType {
    Staker,
    Withdrawer,
}

#[derive(Debug, Args)]
pub(crate) struct StakeCommand {
    /// Stake account to migrate.
    stake_account: Address,

    /// Signing pubkey of the new authority. Its programmatic signer becomes the stake authority.
    /// Pass the signing pubkey itself, not its programmatic signer. Defaults to the current
    /// authority, which then moves to its own programmatic signer.
    #[clap(long)]
    new_authority_signing_pubkey: Option<Address>,

    /// Move only this authority type. Moves both the staker and the withdrawer when omitted.
    #[clap(long, value_enum)]
    authority_type: Option<AuthorityType>,
}

pub(super) async fn run(
    command: StakeCommand,
    client: &Client,
    output: OutputFormat,
) -> Result<String> {
    let meta = client
        .stake_account(&command.stake_account)
        .await?
        .meta()
        .with_context(|| format!("stake account {} is not initialized", command.stake_account))?;
    let roles: &[StakeAuthorize] = match command.authority_type {
        None => &[StakeAuthorize::Staker, StakeAuthorize::Withdrawer],
        Some(AuthorityType::Staker) => &[StakeAuthorize::Staker],
        Some(AuthorityType::Withdrawer) => &[StakeAuthorize::Withdrawer],
    };
    let new_authority_signing_pubkey = match command.new_authority_signing_pubkey {
        Some(new_authority_signing_pubkey) => new_authority_signing_pubkey,
        None => default_stake_authority(&command.stake_account, &meta.authorized, roles)?,
    };
    let new_owner_programmatic_signer =
        new_owner_programmatic_signer(&new_authority_signing_pubkey)?;
    // Changing the withdrawer during a lockup also needs the custodian. Whether a lockup is in
    // force is checked against the current state.
    let custodian = if roles.contains(&StakeAuthorize::Withdrawer) {
        let clock = client.clock().await?;
        meta.lockup
            .is_in_force(&clock, None)
            .then_some(meta.lockup.custodian)
    } else {
        None
    };

    let instructions = roles
        .iter()
        .map(|role| {
            let current = current_authority(&meta.authorized, *role);
            let custodian = match role {
                StakeAuthorize::Staker => None,
                StakeAuthorize::Withdrawer => custodian.as_ref(),
            };
            ensure!(
                current != new_owner_programmatic_signer,
                "the {} of stake account {} is already {new_owner_programmatic_signer}",
                role_name(*role),
                command.stake_account
            );
            Ok(authorize_checked(
                &command.stake_account,
                &current,
                &new_owner_programmatic_signer,
                *role,
                custodian,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let execution_message = execution_message(&new_owner_programmatic_signer, &instructions)?;

    output.render(&StakeMigrationOutput {
        stake_account: command.stake_account.to_string(),
        authority_types: roles
            .iter()
            .map(|role| role_name(*role).to_string())
            .collect(),
        new_authority: new_owner_programmatic_signer.to_string(),
        new_authority_signing_pubkey: new_authority_signing_pubkey.to_string(),
        custodian: custodian.as_ref().map(ToString::to_string),
        required_signers: RequiredSigners::new(&execution_message, &[new_authority_signing_pubkey]),
        execution_message: BASE64_STANDARD.encode(execution_message.serialize()),
    })
}

/// The default new authority is the current authority of the roles being moved, so they must
/// share one.
fn default_stake_authority(
    stake_account: &Address,
    authorized: &Authorized,
    roles: &[StakeAuthorize],
) -> Result<Address> {
    let current = current_authority(authorized, roles[0]);
    ensure!(
        roles
            .iter()
            .all(|role| current_authority(authorized, *role) == current),
        "the staker {} and withdrawer {} of stake account {stake_account} differ, so neither can \
         be the default new authority signing pubkey. Pass --new-authority-signing-pubkey, or \
         move one with --authority-type",
        authorized.staker,
        authorized.withdrawer
    );
    default_new_authority(
        format_args!("the current authority of stake account {stake_account}"),
        current,
    )
}

fn current_authority(authorized: &Authorized, role: StakeAuthorize) -> Address {
    match role {
        StakeAuthorize::Staker => authorized.staker,
        StakeAuthorize::Withdrawer => authorized.withdrawer,
    }
}

fn role_name(role: StakeAuthorize) -> &'static str {
    match role {
        StakeAuthorize::Staker => "staker",
        StakeAuthorize::Withdrawer => "withdrawer",
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StakeMigrationOutput {
    pub stake_account: String,
    pub authority_types: Vec<String>,
    pub new_authority: String,
    pub new_authority_signing_pubkey: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custodian: Option<String>,
    #[serde(flatten)]
    pub required_signers: RequiredSigners,
    pub execution_message: String,
}

impl fmt::Display for StakeMigrationOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Stake account: {}", self.stake_account)?;
        writeln!(f, "Authorities moved: {}", self.authority_types.join(", "))?;
        writeln!(
            f,
            "New authority: {} (signing pubkey: {})",
            self.new_authority, self.new_authority_signing_pubkey
        )?;
        if let Some(custodian) = &self.custodian {
            writeln!(f, "Lockup custodian: {custodian}")?;
        }
        writeln!(f)?;
        writeln!(f, "{}", self.required_signers)?;
        writeln!(f)?;
        write!(f, "Execution message (base64):\n{}", self.execution_message)
    }
}
