use {
    super::{
        RequiredSigners, default_new_authority, execution_message, new_owner_programmatic_signer,
    },
    crate::{client::Client, output::OutputFormat},
    anyhow::{Context, Result, bail, ensure},
    base64::{Engine, prelude::BASE64_STANDARD},
    clap::{Args, ValueEnum},
    serde::{Deserialize, Serialize},
    solana_address::Address,
    spl_associated_token_account_interface::address::get_associated_token_address_with_program_id,
    spl_memo_interface::instruction::build_memo,
    spl_token_2022_interface::{
        extension::{
            BaseStateWithExtensions, StateWithExtensions, cpi_guard::CpiGuard,
            immutable_owner::ImmutableOwner,
        },
        instruction::{AuthorityType as TokenAuthorityType, set_authority},
        state::Account as TokenAccount,
    },
    std::fmt,
};

#[derive(Clone, Copy, Debug, PartialEq, ValueEnum)]
pub(super) enum AuthorityType {
    Owner,
    Close,
}

impl AuthorityType {
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Close => "close",
        }
    }

    /// How the authority is described in errors and the memo.
    fn description(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Close => "close authority",
        }
    }

    fn token_authority_type(self) -> TokenAuthorityType {
        match self {
            Self::Owner => TokenAuthorityType::AccountOwner,
            Self::Close => TokenAuthorityType::CloseAccount,
        }
    }
}

#[derive(Debug, Args)]
pub(crate) struct TokenAccountCommand {
    /// Token or Token-2022 token account to migrate. Its tokens stay in the account. To move them
    /// to the new authority's associated token account instead, use `migrate token`.
    token_account: Address,

    /// Signing public key that controls the destination programmatic signer, which becomes the
    /// token account's authorities. Pass the signing pubkey itself, not its programmatic signer.
    /// Defaults to the current authority, which then moves to its own programmatic signer.
    #[clap(long)]
    new_authority_signing_pubkey: Option<Address>,

    /// Move only this authority. Moves the owner and the close authority when omitted, skipping
    /// the close authority if it is not set, since it then defaults to the owner.
    #[clap(long, value_enum)]
    authority_type: Option<AuthorityType>,

    /// Allow moving the owner of a Token Program associated token account. The account keeps the
    /// address derived from its current owner.
    /// Warning: wallets won't find it under the new owner,
    /// tokens sent to the current owner for this mint still arrive in it, and the current owner
    /// can no longer create its associated token account for this mint. Token-2022 associated
    /// token accounts can never change owner.
    #[clap(long)]
    allow_ata: bool,
}

pub(super) async fn run(
    command: TokenAccountCommand,
    client: &Client,
    output: OutputFormat,
) -> Result<String> {
    let address = command.token_account;
    let account = client
        .token_program_account(&address, "token account")
        .await?;
    let token_program = account.owner;
    let state = StateWithExtensions::<TokenAccount>::unpack(&account.data)
        .with_context(|| format!("account {address} is not a token account"))?;
    let mint = state.base.mint;
    let owner = state.base.owner;
    let close_authority: Option<Address> = state.base.close_authority.into();
    let current_authority = |role| match role {
        AuthorityType::Owner => Some(owner),
        AuthorityType::Close => close_authority,
    };

    // An unset close authority means the owner can close the account, so the
    // new owner will be able to close it too
    let (roles, unset): (Vec<_>, Vec<_>) = match command.authority_type {
        None => [AuthorityType::Owner, AuthorityType::Close]
            .into_iter()
            .partition(|role| current_authority(*role).is_some()),
        Some(role) => (vec![role], vec![]),
    };
    let current_authorities = roles
        .iter()
        .map(|role| match role {
            AuthorityType::Owner => Ok(owner),
            // Only reachable with --authority-type close, since the default skips it when unset.
            AuthorityType::Close => close_authority.with_context(|| {
                format!(
                    "token account {address} has no close authority, so its owner can close it. \
                     Use --authority-type owner or omit --authority-type to change the owner"
                )
            }),
        })
        .collect::<Result<Vec<_>>>()?;

    // Checked by the token program for any authority change.
    ensure!(
        !state.base.is_frozen(),
        "token account {address} is frozen, so its authorities can't change"
    );
    if let Ok(guard) = state.get_extension::<CpiGuard>() {
        ensure!(
            !bool::from(guard.lock_cpi),
            "token account {address} has the CPI guard enabled, which blocks changing its \
             authorities through the message executor. Disable it first"
        );
    }
    let moves_owner = roles.contains(&AuthorityType::Owner);
    let associated =
        get_associated_token_address_with_program_id(&owner, &mint, &token_program) == address;
    if moves_owner {
        // Every Token-2022 associated token account has this extension.
        if state.get_extension::<ImmutableOwner>().is_ok() {
            let alternative = if associated {
                ". Use `migrate token` to move its tokens instead"
            } else {
                ""
            };
            bail!(
                "token account {address} has an immutable owner, so its owner can't \
                 change{alternative}",
            );
        }
        ensure!(
            !associated || command.allow_ata,
            "token account {address} is {owner}'s associated token account. Use `migrate token` \
             to move its tokens to the new authority's associated token account instead. Pass \
             --allow-ata to move its owner anyway. Note the warnings associated with that flag: \
             wallets won't find it under the new owner, tokens sent to the current owner for this \
             mint still arrive in it, and the current owner can no longer create its associated \
             token account for this mint"
        );
    }

    let new_authority_signing_pubkey = match command.new_authority_signing_pubkey {
        Some(new_authority_signing_pubkey) => new_authority_signing_pubkey,
        None => {
            // The authorities being moved must share one to default to it.
            let current = current_authorities[0];
            ensure!(
                current_authorities
                    .iter()
                    .all(|authority| *authority == current),
                "the owner {current} and close authority {} of token account {address} differ, so \
                 neither can be the default new authority signing pubkey. Pass \
                 --new-authority-signing-pubkey, or move one with --authority-type",
                current_authorities[1],
            );
            default_new_authority(
                format_args!("the current authority of token account {address}"),
                current,
            )?
        }
    };
    let new_owner_programmatic_signer =
        new_owner_programmatic_signer(&new_authority_signing_pubkey)?;

    // The close authority must move before the owner. Changing a wrapped SOL account's owner unsets
    // its close authority, so the close authority couldn't sign after that.
    let mut instructions = vec![];
    for role in [AuthorityType::Close, AuthorityType::Owner] {
        let Some(index) = roles.iter().position(|moved| *moved == role) else {
            continue;
        };
        let current = &current_authorities[index];
        ensure!(
            *current != new_owner_programmatic_signer,
            "the {} of token account {address} is already {new_owner_programmatic_signer}",
            role.description(),
        );
        instructions.push(
            set_authority(
                &token_program,
                &address,
                Some(&new_owner_programmatic_signer),
                role.token_authority_type(),
                current,
                &[],
            )
            .context("failed to build set authority instruction")?,
        );
    }
    // `SetAuthority` does not require the new authority as a signer, so the memo does. Its
    // programmatic signer must sign, confirming the new authority can sign before it takes over
    // the account.
    instructions.push(build_memo(
        &spl_memo_interface::v4::id(),
        memo(&roles, &new_owner_programmatic_signer).as_bytes(),
        &[&new_owner_programmatic_signer],
    ));
    let execution_message = execution_message(&new_owner_programmatic_signer, &instructions)?;

    // Changing the owner revokes any delegate, and unsets a wrapped SOL account's close
    // authority.
    let revoked_delegate = Option::<Address>::from(state.base.delegate).filter(|_| moves_owner);
    let unset_close_authority = close_authority.filter(|_| {
        moves_owner && state.base.is_native() && !roles.contains(&AuthorityType::Close)
    });

    output.render(&TokenAccountMigrationOutput {
        token_account: address.to_string(),
        mint: mint.to_string(),
        token_program: token_program.to_string(),
        owner: owner.to_string(),
        associated,
        authority_types: roles.iter().map(|role| role.name().to_string()).collect(),
        unset_authority_types: unset.iter().map(|role| role.name().to_string()).collect(),
        revoked_delegate: revoked_delegate.map(|delegate| delegate.to_string()),
        unset_close_authority: unset_close_authority.map(|authority| authority.to_string()),
        new_authority: new_owner_programmatic_signer.to_string(),
        new_authority_signing_pubkey: new_authority_signing_pubkey.to_string(),
        required_signers: RequiredSigners::new(&execution_message, &[new_authority_signing_pubkey]),
        execution_message: BASE64_STANDARD.encode(execution_message.serialize()),
    })
}

/// Text of the memo the new authority's programmatic signer signs, such as "migrate token account
/// owner and close authority to <address>".
fn memo(roles: &[AuthorityType], new_owner_programmatic_signer: &Address) -> String {
    let descriptions = roles
        .iter()
        .map(|role| role.description())
        .collect::<Vec<_>>();
    format!(
        "migrate token account {} to {new_owner_programmatic_signer}",
        descriptions.join(" and ")
    )
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenAccountMigrationOutput {
    pub token_account: String,
    pub mint: String,
    pub token_program: String,
    /// The current owner.
    pub owner: String,
    /// Whether this is the current owner's associated token account. Moving its owner needs
    /// `--allow-ata`.
    pub associated: bool,
    pub authority_types: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unset_authority_types: Vec<String>,
    /// The delegate that changing the owner revokes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_delegate: Option<String>,
    /// The close authority of a wrapped SOL account, which changing its owner clears. The new
    /// owner can then close it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unset_close_authority: Option<String>,
    pub new_authority: String,
    pub new_authority_signing_pubkey: String,
    #[serde(flatten)]
    pub required_signers: RequiredSigners,
    pub execution_message: String,
}

impl fmt::Display for TokenAccountMigrationOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Token account: {}", self.token_account)?;
        writeln!(f, "Mint: {}", self.mint)?;
        writeln!(f, "Token program: {}", self.token_program)?;
        writeln!(f, "Owner: {}", self.owner)?;
        if self.associated
            && self
                .authority_types
                .iter()
                .any(|role| role == AuthorityType::Owner.name())
        {
            writeln!(
                f,
                "This is the owner's associated token account. Wallets won't find it under the \
                 new owner, tokens sent to {} for this mint still arrive in it, and {} can no \
                 longer create its associated token account for this mint.",
                self.owner, self.owner
            )?;
        }
        writeln!(f, "Authorities moved: {}", self.authority_types.join(", "))?;
        if !self.unset_authority_types.is_empty() {
            writeln!(
                f,
                "Not set, skipped: {}",
                self.unset_authority_types.join(", ")
            )?;
        }
        if let Some(delegate) = &self.revoked_delegate {
            writeln!(f, "Revokes delegate {delegate}, as changing the owner does")?;
        }
        if let Some(close_authority) = &self.unset_close_authority {
            writeln!(
                f,
                "Unsets close authority {close_authority}, as changing a wrapped SOL account's \
                 owner does"
            )?;
        }
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
