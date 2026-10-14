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
    solana_loader_v3_interface::{
        instruction::set_upgrade_authority_checked, state::UpgradeableLoaderState,
    },
    std::fmt,
};

#[derive(Debug, Args)]
pub(crate) struct ProgramCommand {
    /// Program to migrate. Only programs deployed with the upgradeable loader (v3) are supported.
    program: Address,

    /// Signing pubkey of the new authority. Its programmatic signer becomes the upgrade authority.
    /// Pass the signing pubkey itself, not its programmatic signer. Defaults to the current upgrade
    /// authority, which then moves to its own programmatic signer.
    #[clap(long)]
    new_authority_signing_pubkey: Option<Address>,
}

pub(super) async fn run(
    command: ProgramCommand,
    client: &Client,
    output: OutputFormat,
) -> Result<String> {
    let UpgradeableLoaderState::Program {
        programdata_address,
    } = client
        .upgradeable_loader_account(&command.program, "program")
        .await?
    else {
        bail!(
            "account {} is not a program. Pass the program address, not its program data or a \
             buffer",
            command.program
        );
    };
    let UpgradeableLoaderState::ProgramData {
        upgrade_authority_address,
        ..
    } = client
        .upgradeable_loader_account(&programdata_address, "program data account")
        .await?
    else {
        bail!("account {programdata_address} is not program data");
    };
    let Some(upgrade_authority) = upgrade_authority_address else {
        bail!(
            "program {} is immutable, it has no upgrade authority",
            command.program
        );
    };
    let new_authority_signing_pubkey = match command.new_authority_signing_pubkey {
        Some(new_authority_signing_pubkey) => new_authority_signing_pubkey,
        None => default_new_authority(
            format_args!("the upgrade authority of program {}", command.program),
            upgrade_authority,
        )?,
    };
    let new_owner_programmatic_signer =
        new_owner_programmatic_signer(&new_authority_signing_pubkey)?;
    ensure!(
        upgrade_authority != new_owner_programmatic_signer,
        "the upgrade authority of program {} is already {new_owner_programmatic_signer}",
        command.program
    );

    let instruction = set_upgrade_authority_checked(
        &command.program,
        &upgrade_authority,
        &new_owner_programmatic_signer,
    );
    let execution_message = execution_message(&new_owner_programmatic_signer, &[instruction])?;

    output.render(&ProgramMigrationOutput {
        program: command.program.to_string(),
        program_data: programdata_address.to_string(),
        new_authority: new_owner_programmatic_signer.to_string(),
        new_authority_signing_pubkey: new_authority_signing_pubkey.to_string(),
        required_signers: RequiredSigners::new(&execution_message, &[new_authority_signing_pubkey]),
        execution_message: BASE64_STANDARD.encode(execution_message.serialize()),
    })
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProgramMigrationOutput {
    pub program: String,
    pub program_data: String,
    pub new_authority: String,
    pub new_authority_signing_pubkey: String,
    #[serde(flatten)]
    pub required_signers: RequiredSigners,
    pub execution_message: String,
}

impl fmt::Display for ProgramMigrationOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Program: {}", self.program)?;
        writeln!(f, "Program data: {}", self.program_data)?;
        writeln!(f, "Authority moved: upgrade authority")?;
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
