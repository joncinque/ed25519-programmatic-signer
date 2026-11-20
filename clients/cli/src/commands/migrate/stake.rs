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
        instruction::{LockupArgs, authorize_checked, set_lockup_checked},
        state::{Meta, StakeAuthorize},
    },
    std::fmt,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum AuthorityType {
    Staker,
    Withdrawer,
    /// The lockup custodian. Only moves while the lockup is in force; otherwise the withdrawer
    /// controls the lockup.
    Custodian,
}

impl AuthorityType {
    fn name(self) -> &'static str {
        match self {
            Self::Staker => role_name(StakeAuthorize::Staker),
            Self::Withdrawer => role_name(StakeAuthorize::Withdrawer),
            Self::Custodian => "custodian",
        }
    }

    fn current_authority(self, meta: &Meta) -> Address {
        match self {
            Self::Staker => meta.authorized.staker,
            Self::Withdrawer => meta.authorized.withdrawer,
            Self::Custodian => meta.lockup.custodian,
        }
    }
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

    /// Move only this authority type. Moves both the staker and the withdrawer when omitted, and
    /// the lockup custodian too if a lockup is in force and the custodian is the current staker or
    /// withdrawer.
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
    // While a lockup is in force only its custodian can change it, and changing the withdrawer
    // also needs the custodian. Whether a lockup is in force is checked against the current state.
    // Moving only the staker never involves the custodian, so it skips the clock lookup.
    let lockup_custodian = if matches!(command.authority_type, Some(AuthorityType::Staker)) {
        None
    } else {
        let clock = client.clock().await?;
        meta.lockup
            .is_in_force(&clock, None)
            .then_some(meta.lockup.custodian)
    };
    let authority_types = match command.authority_type {
        None => {
            let mut authority_types = vec![AuthorityType::Staker, AuthorityType::Withdrawer];
            // A custodian that is an old key moves with it, or that key could keep extending the
            // lockup. Any other custodian is a third party and stays.
            if lockup_custodian.is_some_and(|custodian| {
                authority_types
                    .iter()
                    .any(|authority_type| authority_type.current_authority(&meta) == custodian)
            }) {
                authority_types.push(AuthorityType::Custodian);
            }
            authority_types
        }
        Some(AuthorityType::Custodian) => {
            ensure!(
                lockup_custodian.is_some(),
                "stake account {} has no lockup in force, so its custodian has no authority to \
                 move",
                command.stake_account
            );
            vec![AuthorityType::Custodian]
        }
        Some(authority_type) => vec![authority_type],
    };
    let new_authority_signing_pubkey = match command.new_authority_signing_pubkey {
        Some(new_authority_signing_pubkey) => new_authority_signing_pubkey,
        None => default_stake_authority(&command.stake_account, &meta, command.authority_type)?,
    };
    let new_owner_programmatic_signer =
        new_owner_programmatic_signer(&new_authority_signing_pubkey)?;
    // The custodian co-signs changes to the withdrawer and to itself.
    let custodian = lockup_custodian.filter(|_| {
        authority_types.iter().any(|authority_type| {
            matches!(
                authority_type,
                AuthorityType::Withdrawer | AuthorityType::Custodian
            )
        })
    });

    let instructions = authority_types
        .iter()
        .map(|authority_type| {
            let current = authority_type.current_authority(&meta);
            ensure!(
                current != new_owner_programmatic_signer,
                "the {} of stake account {} is already {new_owner_programmatic_signer}",
                authority_type.name(),
                command.stake_account
            );
            Ok(match authority_type {
                AuthorityType::Staker => authorize_checked(
                    &command.stake_account,
                    &current,
                    &new_owner_programmatic_signer,
                    StakeAuthorize::Staker,
                    None,
                ),
                AuthorityType::Withdrawer => authorize_checked(
                    &command.stake_account,
                    &current,
                    &new_owner_programmatic_signer,
                    StakeAuthorize::Withdrawer,
                    custodian.as_ref(),
                ),
                AuthorityType::Custodian => set_lockup_checked(
                    &command.stake_account,
                    &LockupArgs {
                        unix_timestamp: None,
                        epoch: None,
                        custodian: Some(new_owner_programmatic_signer),
                    },
                    &current,
                ),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let execution_message = execution_message(&new_owner_programmatic_signer, &instructions)?;

    output.render(&StakeMigrationOutput {
        stake_account: command.stake_account.to_string(),
        authority_types: authority_types
            .iter()
            .map(|authority_type| authority_type.name().to_string())
            .collect(),
        new_authority: new_owner_programmatic_signer.to_string(),
        new_authority_signing_pubkey: new_authority_signing_pubkey.to_string(),
        current_custodian: custodian.as_ref().map(ToString::to_string),
        required_signers: RequiredSigners::new(&execution_message, &[new_authority_signing_pubkey]),
        execution_message: BASE64_STANDARD.encode(execution_message.serialize()),
    })
}

/// The default new authority is the current authority of the type being moved. Moving everything
/// needs the staker and withdrawer to share one.
fn default_stake_authority(
    stake_account: &Address,
    meta: &Meta,
    authority_type: Option<AuthorityType>,
) -> Result<Address> {
    let current = match authority_type {
        Some(authority_type) => authority_type.current_authority(meta),
        None => {
            ensure!(
                meta.authorized.staker == meta.authorized.withdrawer,
                "the staker {} and withdrawer {} of stake account {stake_account} differ, so \
                 neither can be the default new authority signing pubkey. Pass \
                 --new-authority-signing-pubkey, or move one with --authority-type",
                meta.authorized.staker,
                meta.authorized.withdrawer
            );
            meta.authorized.staker
        }
    };
    default_new_authority(
        format_args!("the current authority of stake account {stake_account}"),
        current,
    )
}

pub(super) fn role_name(role: StakeAuthorize) -> &'static str {
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
    /// The lockup custodian before the migration, which co-signs it. Set when the withdrawer or
    /// custodian moves while a lockup is in force.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_custodian: Option<String>,
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
        if let Some(custodian) = &self.current_custodian {
            writeln!(f, "Current lockup custodian: {custodian}")?;
        }
        writeln!(f)?;
        writeln!(f, "{}", self.required_signers)?;
        writeln!(f)?;
        write!(f, "Execution message (base64):\n{}", self.execution_message)
    }
}
