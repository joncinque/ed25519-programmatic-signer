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
    spl_memo_interface::instruction::build_memo,
    spl_token_2022_interface::instruction::{AuthorityType as TokenAuthorityType, set_authority},
    std::fmt,
};

#[derive(Clone, Copy, Debug, PartialEq, ValueEnum)]
enum AuthorityType {
    Mint,
    Freeze,
}

impl AuthorityType {
    fn name(self) -> &'static str {
        match self {
            Self::Mint => "mint",
            Self::Freeze => "freeze",
        }
    }

    fn token_authority_type(self) -> TokenAuthorityType {
        match self {
            Self::Mint => TokenAuthorityType::MintTokens,
            Self::Freeze => TokenAuthorityType::FreezeAccount,
        }
    }
}

#[derive(Debug, Args)]
pub(crate) struct MintCommand {
    /// Token or Token-2022 mint to migrate.
    mint: Address,

    /// Signing pubkey of the new authority. Its programmatic signer becomes the mint's authorities.
    /// Pass the signing pubkey itself, not its programmatic signer. Defaults to the current
    /// authority, which then moves to its own programmatic signer.
    #[clap(long)]
    new_authority_signing_pubkey: Option<Address>,

    /// Move only this authority. Moves the mint and freeze authorities when omitted, skipping
    /// any that are not set.
    #[clap(long, value_enum)]
    authority_type: Option<AuthorityType>,
}

pub(super) async fn run(
    command: MintCommand,
    client: &Client,
    output: OutputFormat,
) -> Result<String> {
    let (token_program, mint) = client.mint(&command.mint).await?;
    let current_authority = |role| -> Option<Address> {
        match role {
            AuthorityType::Mint => mint.mint_authority.into(),
            AuthorityType::Freeze => mint.freeze_authority.into(),
        }
    };

    // An unset authority can never be set again, so there is nothing to move.
    let (roles, unset): (Vec<_>, Vec<_>) = match command.authority_type {
        None => [AuthorityType::Mint, AuthorityType::Freeze]
            .into_iter()
            .partition(|role| current_authority(*role).is_some()),
        Some(role) => (vec![role], vec![]),
    };
    ensure!(
        !roles.is_empty(),
        "mint {} has no mint or freeze authority",
        command.mint
    );
    let current_authorities = roles
        .iter()
        .map(|role| {
            current_authority(*role)
                .with_context(|| format!("mint {} has no {} authority", command.mint, role.name()))
        })
        .collect::<Result<Vec<_>>>()?;

    let new_authority_signing_pubkey = match command.new_authority_signing_pubkey {
        Some(new_authority_signing_pubkey) => new_authority_signing_pubkey,
        None => {
            // The authorities being moved must share one to default to it.
            let current = current_authorities[0];
            ensure!(
                current_authorities
                    .iter()
                    .all(|authority| *authority == current),
                "the mint authority {current} and freeze authority {} of mint {} differ, so \
                 neither can be the default new authority signing pubkey. Pass \
                 --new-authority-signing-pubkey, or move one with --authority-type",
                current_authorities[1],
                command.mint
            );
            default_new_authority(
                format_args!("the current authority of mint {}", command.mint),
                current,
            )?
        }
    };
    let new_owner_programmatic_signer =
        new_owner_programmatic_signer(&new_authority_signing_pubkey)?;

    let mut instructions = roles
        .iter()
        .zip(&current_authorities)
        .map(|(role, current)| {
            ensure!(
                *current != new_owner_programmatic_signer,
                "the {} authority of mint {} is already {new_owner_programmatic_signer}",
                role.name(),
                command.mint
            );
            set_authority(
                &token_program,
                &command.mint,
                Some(&new_owner_programmatic_signer),
                role.token_authority_type(),
                current,
                &[],
            )
            .context("failed to build set authority instruction")
        })
        .collect::<Result<Vec<_>>>()?;
    // We add a memo instruction with the new programmatic signer as a signer
    // `SetAuthority` doesn't require the new authority as a signer
    // We want to ensure that the user of the CLI can sign for the new authority
    instructions.push(build_memo(
        &spl_memo_interface::v4::id(),
        memo(&roles, &new_owner_programmatic_signer).as_bytes(),
        &[&new_owner_programmatic_signer],
    ));
    let execution_message = execution_message(&new_owner_programmatic_signer, &instructions)?;

    output.render(&MintMigrationOutput {
        mint: command.mint.to_string(),
        token_program: token_program.to_string(),
        authority_types: roles.iter().map(|role| role.name().to_string()).collect(),
        unset_authority_types: unset.iter().map(|role| role.name().to_string()).collect(),
        new_authority: new_owner_programmatic_signer.to_string(),
        new_authority_signing_pubkey: new_authority_signing_pubkey.to_string(),
        required_signers: RequiredSigners::new(&execution_message, &[new_authority_signing_pubkey]),
        execution_message: BASE64_STANDARD.encode(execution_message.serialize()),
    })
}

/// Text of the memo the new authority's programmatic signer signs, such as "migrate mint and freeze
/// authorities to <address>".
///
fn memo(roles: &[AuthorityType], new_owner_programmatic_signer: &Address) -> String {
    let names = roles.iter().map(|role| role.name()).collect::<Vec<_>>();
    format!(
        "migrate {} authority to {new_owner_programmatic_signer}",
        names.join(" and ")
    )
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MintMigrationOutput {
    pub mint: String,
    pub token_program: String,
    pub authority_types: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unset_authority_types: Vec<String>,
    pub new_authority: String,
    pub new_authority_signing_pubkey: String,
    #[serde(flatten)]
    pub required_signers: RequiredSigners,
    pub execution_message: String,
}

impl fmt::Display for MintMigrationOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Mint: {}", self.mint)?;
        writeln!(f, "Token program: {}", self.token_program)?;
        writeln!(f, "Authorities moved: {}", self.authority_types.join(", "))?;
        if !self.unset_authority_types.is_empty() {
            writeln!(
                f,
                "Not set, skipped: {}",
                self.unset_authority_types.join(", ")
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
