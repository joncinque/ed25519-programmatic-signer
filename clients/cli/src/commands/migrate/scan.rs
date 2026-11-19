use {
    super::{
        mint::AuthorityType, new_owner_programmatic_signer, stake::role_name, token_account,
        vote::authorized_withdrawer,
    },
    crate::{
        client::{
            Client, decode_mint, decode_stake_account, decode_upgradeable_loader_account,
            decode_vote_account,
        },
        output::OutputFormat,
    },
    anyhow::{Context, Result, ensure},
    clap::Args,
    serde::{Deserialize, Serialize},
    solana_account_decoder_client_types::{
        UiDataSliceConfig,
        token::{UiExtension, real_number_string_trimmed},
    },
    solana_address::Address,
    solana_loader_v3_interface::state::UpgradeableLoaderState,
    solana_native_token::Sol,
    solana_program_pack::Pack,
    solana_rpc_client_types::filter::{Memcmp, RpcFilterType},
    solana_stake_interface::state::{StakeAuthorize, StakeStateV2},
    spl_associated_token_account_interface::address::get_associated_token_address_with_program_id,
    spl_token_2022_interface::{
        extension::AccountType,
        state::{Account as TokenAccount, Mint},
    },
    std::{
        collections::BTreeMap,
        fmt::{self, Write},
        str::FromStr,
    },
};

// Stake account layout: a u32 state tag and a u64 rent-exempt reserve, then the staker and
// withdrawer.
const STAKER_OFFSET: usize = 12;
const WITHDRAWER_OFFSET: usize = 44;
// Vote account layout: a u32 version tag and the node identity, then the withdrawer.
const VOTE_WITHDRAWER_OFFSET: usize = 36;
// Program data layout: a u32 state tag and a u64 slot, then the upgrade authority as an option.
const PROGRAM_DATA_TAG: [u8; 4] = [3, 0, 0, 0];
const UPGRADE_AUTHORITY_OPTION_OFFSET: usize = 12;
const UPGRADE_AUTHORITY_OFFSET: usize = 13;
// Program layout: a u32 state tag, then the program data address.
const PROGRAM_TAG: [u8; 4] = [2, 0, 0, 0];
const PROGRAM_DATA_ADDRESS_OFFSET: usize = 4;
// Mint layout: the mint authority after its u32 option tag, then the supply, decimals and
// initialized flag, then the freeze authority after its u32 option tag.
const MINT_AUTHORITY_OFFSET: usize = 4;
const FREEZE_AUTHORITY_OFFSET: usize = 50;

#[derive(Debug, Args)]
pub(crate) struct ScanCommand {
    /// Address to list migratable accounts and balances for: the authority of stake accounts, vote
    /// accounts, programs and mints, and the owner of token accounts and SOL.
    owner: Address,

    /// Signing pubkey of the new authority, filled into the suggested migrate commands. Pass the
    /// signing pubkey itself, not its programmatic signer. When omitted, the commands default to
    /// moving to the owner's own programmatic signer.
    #[clap(long)]
    new_authority_signing_pubkey: Option<Address>,
}

pub(super) async fn run(
    command: ScanCommand,
    client: &Client,
    output: OutputFormat,
) -> Result<String> {
    let owner = &command.owner;
    let new_authority_signing_pubkey = match &command.new_authority_signing_pubkey {
        Some(new_authority_signing_pubkey) => {
            let new_owner_programmatic_signer =
                new_owner_programmatic_signer(new_authority_signing_pubkey)?;
            ensure!(
                *owner != new_owner_programmatic_signer,
                "owner {owner} is already the new authority's programmatic signer"
            );
            Some(new_authority_signing_pubkey.to_string())
        }
        // The migrate commands default to the owner, which only works if it is on curve.
        None if owner.is_on_curve() => None,
        None => Some("<NEW_AUTHORITY_SIGNING_PUBKEY>".to_string()),
    };
    let new_authority_args = match &new_authority_signing_pubkey {
        Some(new_authority_signing_pubkey) => {
            vec![
                "--new-authority-signing-pubkey",
                new_authority_signing_pubkey,
            ]
        }
        None => vec![],
    };

    // Each category is scanned and reported on its own, some RPC nodes may be limited
    // for some categories
    let (stake, vote, program, mint, token, sol) = tokio::join!(
        scan_stake(client, owner, &new_authority_args),
        scan_vote(client, owner, &new_authority_args),
        scan_program(client, owner, &new_authority_args),
        scan_mint(client, owner, &new_authority_args),
        scan_token(client, owner, &new_authority_args),
        scan_sol(client, owner, &new_authority_args),
    );
    output.render(&ScanOutput {
        owner: owner.to_string(),
        stake: stake.map_err(error_string),
        vote: vote.map_err(error_string),
        program: program.map_err(error_string),
        mint: mint.map_err(error_string),
        token: token.map_err(error_string),
        sol: sol.map_err(error_string),
    })
}

fn error_string(error: anyhow::Error) -> String {
    format!("{error:#}")
}

fn migrate_command(args: &[&str]) -> String {
    format!("spl-programmatic-signer migrate {}", args.join(" "))
}

fn memcmp(offset: usize, bytes: &[u8]) -> RpcFilterType {
    RpcFilterType::Memcmp(Memcmp::new_base58_encoded(offset, bytes))
}

fn data_size(size: usize) -> RpcFilterType {
    RpcFilterType::DataSize(size as u64)
}

async fn scan_stake(
    client: &Client,
    owner: &Address,
    new_authority_args: &[&str],
) -> Result<Vec<StakeScanItem>> {
    let mut accounts = BTreeMap::<Address, (u64, Vec<StakeAuthorize>)>::new();
    for (role, offset) in [
        (StakeAuthorize::Staker, STAKER_OFFSET),
        (StakeAuthorize::Withdrawer, WITHDRAWER_OFFSET),
    ] {
        let matches = client
            .program_accounts(
                &solana_stake_interface::program::id(),
                vec![
                    data_size(StakeStateV2::size_of()),
                    memcmp(offset, owner.as_ref()),
                ],
                None,
            )
            .await?;
        for (address, account) in matches {
            let Some(meta) = decode_stake_account(&address, &account)
                .ok()
                .and_then(|state| state.meta())
            else {
                continue;
            };
            let authority = match role {
                StakeAuthorize::Staker => meta.authorized.staker,
                StakeAuthorize::Withdrawer => meta.authorized.withdrawer,
            };
            if authority == *owner {
                accounts
                    .entry(address)
                    .or_insert((account.lamports, vec![]))
                    .1
                    .push(role);
            }
        }
    }

    Ok(accounts
        .into_iter()
        .map(|(address, (lamports, roles))| {
            let address = address.to_string();
            let mut args = vec!["stake", &address];
            args.extend(new_authority_args);
            // `migrate stake` moves both roles by default
            // if `roles` is only one, we add `--authority-type` for it
            // note that we only add an entry with a role, so this is always non-empty
            if let [role] = roles.as_slice() {
                args.extend(["--authority-type", role_name(*role)]);
            }
            StakeScanItem {
                command: migrate_command(&args),
                authority_types: roles
                    .iter()
                    .map(|role| role_name(*role).to_string())
                    .collect(),
                lamports,
                stake_account: address,
            }
        })
        .collect())
}

async fn scan_vote(
    client: &Client,
    owner: &Address,
    new_authority_args: &[&str],
) -> Result<Vec<VoteScanItem>> {
    let matches = client
        .program_accounts(
            &solana_sdk_ids::vote::id(),
            vec![memcmp(VOTE_WITHDRAWER_OFFSET, owner.as_ref())],
            None,
        )
        .await?;
    Ok(matches
        .into_iter()
        .filter(|(address, account)| {
            decode_vote_account(address, account)
                .and_then(|state| authorized_withdrawer(&state, address))
                .is_ok_and(|withdrawer| withdrawer == *owner)
        })
        .map(|(address, account)| {
            let address = address.to_string();
            VoteScanItem {
                command: migrate_command(&[&["vote", &address], new_authority_args].concat()),
                lamports: account.lamports,
                vote_account: address,
            }
        })
        .collect())
}

async fn scan_program(
    client: &Client,
    owner: &Address,
    new_authority_args: &[&str],
) -> Result<Vec<ProgramScanItem>> {
    let loader = solana_sdk_ids::bpf_loader_upgradeable::id();
    let program_data_accounts = client
        .program_accounts(
            &loader,
            vec![
                memcmp(0, &PROGRAM_DATA_TAG),
                memcmp(UPGRADE_AUTHORITY_OPTION_OFFSET, &[1]),
                memcmp(UPGRADE_AUTHORITY_OFFSET, owner.as_ref()),
            ],
            // Only fetch the program data header, not the ELF that follows it.
            Some(UiDataSliceConfig {
                offset: 0,
                length: UpgradeableLoaderState::size_of_programdata_metadata(),
            }),
        )
        .await?;

    let mut items = vec![];
    for (program_data, account) in program_data_accounts {
        let Ok(UpgradeableLoaderState::ProgramData {
            upgrade_authority_address: Some(upgrade_authority),
            ..
        }) = decode_upgradeable_loader_account(&program_data, &account)
        else {
            continue;
        };
        if upgrade_authority != *owner {
            continue;
        }
        // `migrate program` takes the program address, which can't be derived from the
        // program data address, so find the program account that points to it.
        let programs = client
            .program_accounts(
                &loader,
                vec![
                    data_size(UpgradeableLoaderState::size_of_program()),
                    memcmp(0, &PROGRAM_TAG),
                    memcmp(PROGRAM_DATA_ADDRESS_OFFSET, program_data.as_ref()),
                ],
                None,
            )
            .await?;
        for (program, _) in programs {
            let program = program.to_string();
            items.push(ProgramScanItem {
                command: migrate_command(&[&["program", &program], new_authority_args].concat()),
                program,
                program_data: program_data.to_string(),
            });
        }
    }
    Ok(items)
}

async fn scan_mint(
    client: &Client,
    owner: &Address,
    new_authority_args: &[&str],
) -> Result<Vec<MintScanItem>> {
    let token_2022 = spl_token_2022_interface::id();
    let base_mint = data_size(Mint::LEN);
    // Token-2022 mints with extensions are padded to the length of a token account, followed
    // by their account type.
    let extended_mint = memcmp(TokenAccount::LEN, &[AccountType::Mint as u8]);
    let mut queries = vec![];
    for (token_program, layout) in [
        (spl_token_2022_interface::inline_spl_token::id(), &base_mint),
        (token_2022, &base_mint),
        (token_2022, &extended_mint),
    ] {
        for (role, offset) in [
            (AuthorityType::Mint, MINT_AUTHORITY_OFFSET),
            (AuthorityType::Freeze, FREEZE_AUTHORITY_OFFSET),
        ] {
            queries.push((
                token_program,
                role,
                vec![layout.clone(), memcmp(offset, owner.as_ref())],
            ));
        }
    }

    let mut mints = BTreeMap::<Address, (Address, Vec<AuthorityType>)>::new();
    for (token_program, role, filters) in queries {
        let matches = client
            .program_accounts(
                &token_program,
                filters,
                // Skip any extensions, only the base mint is needed.
                Some(UiDataSliceConfig {
                    offset: 0,
                    length: Mint::LEN,
                }),
            )
            .await?;
        for (address, account) in matches {
            let Ok((_, mint)) = decode_mint(&address, &account) else {
                continue;
            };
            let authority: Option<Address> = match role {
                AuthorityType::Mint => mint.mint_authority.into(),
                AuthorityType::Freeze => mint.freeze_authority.into(),
            };
            if authority == Some(*owner) {
                mints
                    .entry(address)
                    .or_insert((token_program, vec![]))
                    .1
                    .push(role);
            }
        }
    }

    Ok(mints
        .into_iter()
        .map(|(address, (token_program, roles))| {
            let address = address.to_string();
            let mut args = vec!["mint", &address];
            args.extend(new_authority_args);
            // only include --authority-type if there is one role
            if let [role] = roles.as_slice() {
                args.extend(["--authority-type", role.name()]);
            }
            MintScanItem {
                command: migrate_command(&args),
                token_program: token_program.to_string(),
                authority_types: roles.iter().map(|role| role.name().to_string()).collect(),
                mint: address,
            }
        })
        .collect())
}

async fn scan_token(
    client: &Client,
    owner: &Address,
    new_authority_args: &[&str],
) -> Result<Vec<TokenScanItem>> {
    let owner_arg = owner.to_string();
    let mut items = vec![];
    for token_program in [
        spl_token_2022_interface::inline_spl_token::id(),
        spl_token_2022_interface::id(),
    ] {
        for (address, account) in client
            .token_accounts_by_owner(owner, &token_program)
            .await?
        {
            let amount = u64::from_str(&account.token_amount.amount)
                .with_context(|| format!("token account {address} has an invalid amount"))?;
            let mint = Address::from_str(&account.mint)
                .with_context(|| format!("token account {address} has an invalid mint"))?;
            let associated =
                get_associated_token_address_with_program_id(owner, &mint, &token_program)
                    == address;
            // Any other token account is passed as the source, which names its owner.
            let address_arg = address.to_string();
            let source_args = if associated {
                ["--owner", &owner_arg]
            } else {
                ["--source", &address_arg]
            };
            // Any other token account can instead keep its tokens and change owner, unless its
            // owner is immutable. Moving the owner of an associated token account needs
            // --allow-ata, which is left to the user.
            let reassign_command = (!associated
                && !account.extensions.contains(&UiExtension::ImmutableOwner))
            .then(|| {
                let mut args = vec!["token-account", &address_arg];
                args.extend(new_authority_args);
                // Add --authority-type owner if there's a close authority different to the owner, to leave close authority unchanged
                if account
                    .close_authority
                    .as_ref()
                    .is_some_and(|close_authority| *close_authority != owner_arg)
                {
                    args.extend([
                        "--authority-type",
                        token_account::AuthorityType::Owner.name(),
                    ]);
                }
                migrate_command(&args)
            });
            items.push(TokenScanItem {
                command: migrate_command(
                    &[
                        &["token", &account.mint],
                        &source_args[..],
                        new_authority_args,
                    ]
                    .concat(),
                ),
                reassign_command,
                token_account: address.to_string(),
                mint: account.mint,
                token_program: token_program.to_string(),
                // The raw balance, which `migrate token --amount` takes. The RPC node's UI amount
                // may apply an interest or scaling multiplier.
                amount: real_number_string_trimmed(amount, account.token_amount.decimals),
                associated,
            });
        }
    }
    Ok(items)
}

async fn scan_sol(
    client: &Client,
    owner: &Address,
    new_authority_args: &[&str],
) -> Result<SolScanItem> {
    let Some(account) = client.optional_account(owner).await? else {
        return Ok(SolScanItem::default());
    };
    // The System Program can only transfer from its own accounts that hold no data.
    let migratable = account.owner == solana_sdk_ids::system_program::id()
        && account.data.is_empty()
        && account.lamports > 0;
    Ok(SolScanItem {
        lamports: account.lamports,
        command: migratable
            .then(|| migrate_command(&[&["sol", &owner.to_string()], new_authority_args].concat())),
    })
}

/// Each category's scan result, or the error that stopped it being scanned.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(into = "ScanJson", from = "ScanJson")]
pub struct ScanOutput {
    pub owner: String,
    pub stake: Result<Vec<StakeScanItem>, String>,
    pub vote: Result<Vec<VoteScanItem>, String>,
    pub program: Result<Vec<ProgramScanItem>, String>,
    pub mint: Result<Vec<MintScanItem>, String>,
    pub token: Result<Vec<TokenScanItem>, String>,
    pub sol: Result<SolScanItem, String>,
}

impl ScanOutput {
    /// The categories that could not be scanned, with their errors.
    fn errors(&self) -> Vec<ScanError> {
        [
            ("stake", self.stake.as_ref().err()),
            ("vote", self.vote.as_ref().err()),
            ("program", self.program.as_ref().err()),
            ("mint", self.mint.as_ref().err()),
            ("token", self.token.as_ref().err()),
            ("sol", self.sol.as_ref().err()),
        ]
        .into_iter()
        .filter_map(|(category, error)| {
            error.map(|error| ScanError {
                category: category.to_string(),
                error: error.clone(),
            })
        })
        .collect()
    }
}

/// The JSON shape of [`ScanOutput`].
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ScanJson {
    owner: String,
    stake: Option<Vec<StakeScanItem>>,
    vote: Option<Vec<VoteScanItem>>,
    program: Option<Vec<ProgramScanItem>>,
    mint: Option<Vec<MintScanItem>>,
    token: Option<Vec<TokenScanItem>>,
    sol: Option<SolScanItem>,
    /// Categories that could not be scanned, which are null above.
    errors: Vec<ScanError>,
}

impl From<ScanOutput> for ScanJson {
    fn from(output: ScanOutput) -> Self {
        let errors = output.errors();
        Self {
            owner: output.owner,
            stake: output.stake.ok(),
            vote: output.vote.ok(),
            program: output.program.ok(),
            mint: output.mint.ok(),
            token: output.token.ok(),
            sol: output.sol.ok(),
            errors,
        }
    }
}

impl From<ScanJson> for ScanOutput {
    fn from(json: ScanJson) -> Self {
        let mut errors = json
            .errors
            .into_iter()
            .map(|error| (error.category, error.error))
            .collect::<BTreeMap<_, _>>();
        Self {
            owner: json.owner,
            stake: scan_result(&mut errors, "stake", json.stake).map(Option::unwrap_or_default),
            vote: scan_result(&mut errors, "vote", json.vote).map(Option::unwrap_or_default),
            program: scan_result(&mut errors, "program", json.program)
                .map(Option::unwrap_or_default),
            mint: scan_result(&mut errors, "mint", json.mint).map(Option::unwrap_or_default),
            token: scan_result(&mut errors, "token", json.token).map(Option::unwrap_or_default),
            sol: scan_result(&mut errors, "sol", json.sol).map(Option::unwrap_or_default),
        }
    }
}

/// The category's error if it could not be scanned, otherwise its JSON value.
fn scan_result<T>(
    errors: &mut BTreeMap<String, String>,
    category: &str,
    value: Option<T>,
) -> Result<Option<T>, String> {
    match errors.remove(category) {
        Some(error) => Err(error),
        None => Ok(value),
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StakeScanItem {
    pub stake_account: String,
    pub lamports: u64,
    /// The stake authorities the owner holds.
    pub authority_types: Vec<String>,
    pub command: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VoteScanItem {
    pub vote_account: String,
    pub lamports: u64,
    pub command: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProgramScanItem {
    pub program: String,
    pub program_data: String,
    pub command: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MintScanItem {
    pub mint: String,
    pub token_program: String,
    /// The mint authorities the owner holds.
    pub authority_types: Vec<String>,
    pub command: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenScanItem {
    pub token_account: String,
    pub mint: String,
    pub token_program: String,
    pub amount: String,
    /// Whether this is the owner's associated token account. The command passes any other token
    /// account as `--source`.
    pub associated: bool,
    /// Moves the tokens to the new authority's associated token account.
    pub command: String,
    /// Moves the token account's owner instead, leaving the tokens in place. Set for token
    /// accounts other than the owner's associated token account, unless their owner is
    /// immutable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reassign_command: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SolScanItem {
    pub lamports: u64,
    /// None when the owner holds no SOL, or its account is not a System Program account without
    /// data, so `migrate sol` can't migrate it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanError {
    pub category: String,
    pub error: String,
}

impl fmt::Display for ScanOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut out = String::new();
        writeln!(out, "Owner: {}", self.owner)?;

        if let Ok(stake) = &self.stake {
            writeln!(out)?;
            write_heading(&mut out, "Stake accounts", stake.len())?;
            for item in stake {
                writeln!(
                    out,
                    "  {} ({}), {}",
                    item.stake_account,
                    Sol(item.lamports),
                    item.authority_types.join(", ")
                )?;
                writeln!(out, "    {}", item.command)?;
            }
        }
        if let Ok(vote) = &self.vote {
            writeln!(out)?;
            write_heading(&mut out, "Vote accounts (withdrawer)", vote.len())?;
            for item in vote {
                writeln!(out, "  {} ({})", item.vote_account, Sol(item.lamports))?;
                writeln!(out, "    {}", item.command)?;
            }
        }
        if let Ok(program) = &self.program {
            writeln!(out)?;
            write_heading(&mut out, "Programs (upgrade authority)", program.len())?;
            for item in program {
                writeln!(
                    out,
                    "  {} (program data: {})",
                    item.program, item.program_data
                )?;
                writeln!(out, "    {}", item.command)?;
            }
        }
        if let Ok(mint) = &self.mint {
            writeln!(out)?;
            write_heading(&mut out, "Mints", mint.len())?;
            for item in mint {
                writeln!(out, "  {}, {}", item.mint, item.authority_types.join(", "))?;
                writeln!(out, "    {}", item.command)?;
            }
        }
        if let Ok(token) = &self.token {
            writeln!(out)?;
            write_heading(&mut out, "Token accounts", token.len())?;
            for item in token {
                writeln!(out, "  {} of mint {}", item.amount, item.mint)?;
                if !item.associated {
                    writeln!(
                        out,
                        "    In {}, not an associated token account",
                        item.token_account
                    )?;
                }
                writeln!(out, "    {}", item.command)?;
                if let Some(reassign_command) = &item.reassign_command {
                    writeln!(out, "    Or keep the tokens in place: {reassign_command}")?;
                }
            }
        }
        if let Ok(sol) = &self.sol {
            writeln!(out)?;
            if sol.lamports == 0 {
                writeln!(out, "SOL: none")?;
            } else {
                writeln!(out, "SOL: {}", Sol(sol.lamports))?;
                match &sol.command {
                    Some(command) => writeln!(out, "    {command}")?,
                    None => writeln!(
                        out,
                        "    `migrate sol` only supports System Program accounts without data"
                    )?,
                }
            }
        }

        let errors = self.errors();
        if !errors.is_empty() {
            writeln!(out)?;
            writeln!(out, "Not scanned, so there may be more:")?;
            for error in &errors {
                writeln!(out, "  {}: {}", error.category, error.error)?;
            }
        }
        f.write_str(out.trim_end())
    }
}

fn write_heading(out: &mut String, heading: &str, count: usize) -> fmt::Result {
    if count == 0 {
        writeln!(out, "{heading}: none")
    } else {
        writeln!(out, "{heading} ({count}):")
    }
}

#[cfg(test)]
mod tests {
    use {
        super::{ScanOutput, SolScanItem, VoteScanItem},
        serde_json::json,
    };

    /// An output where stake and sol failed and the rest were scanned.
    fn partly_failed() -> ScanOutput {
        ScanOutput {
            owner: "owner".to_string(),
            stake: Err("stake failed".to_string()),
            vote: Ok(vec![VoteScanItem {
                vote_account: "vote".to_string(),
                lamports: 1,
                command: "migrate vote".to_string(),
            }]),
            program: Ok(vec![]),
            mint: Ok(vec![]),
            token: Ok(vec![]),
            sol: Err("sol failed".to_string()),
        }
    }

    #[test]
    fn failed_categories_are_null_and_listed_in_errors() {
        let json = serde_json::to_value(partly_failed()).unwrap();
        assert_eq!(
            json,
            json!({
                "owner": "owner",
                "stake": null,
                "vote": [{ "voteAccount": "vote", "lamports": 1, "command": "migrate vote" }],
                "program": [],
                "mint": [],
                "token": [],
                "sol": null,
                "errors": [
                    { "category": "stake", "error": "stake failed" },
                    { "category": "sol", "error": "sol failed" },
                ],
            })
        );

        let output = serde_json::from_value::<ScanOutput>(json).unwrap();
        assert_eq!(output.stake.unwrap_err(), "stake failed");
        assert_eq!(output.sol.unwrap_err(), "sol failed");
        assert_eq!(output.vote.unwrap()[0].vote_account, "vote");
        assert!(output.program.unwrap().is_empty());
    }

    #[test]
    fn sol_without_balance_is_not_null() {
        let output = ScanOutput {
            sol: Ok(SolScanItem::default()),
            ..partly_failed()
        };
        let json = serde_json::to_value(output).unwrap();
        assert_eq!(json["sol"], json!({ "lamports": 0 }));
        assert_eq!(json["errors"].as_array().unwrap().len(), 1);

        let sol = serde_json::from_value::<ScanOutput>(json)
            .unwrap()
            .sol
            .unwrap();
        assert_eq!(sol.lamports, 0);
        assert!(sol.command.is_none());
    }

    #[test]
    fn failed_categories_are_listed_as_not_scanned() {
        let display = partly_failed().to_string();
        assert!(!display.contains("Stake accounts"), "{display}");
        assert!(!display.contains("SOL:"), "{display}");
        assert!(
            display.contains("Vote accounts (withdrawer) (1):"),
            "{display}"
        );
        assert!(
            display.ends_with(
                "Not scanned, so there may be more:\n  stake: stake failed\n  sol: sol failed"
            ),
            "{display}"
        );
    }
}
