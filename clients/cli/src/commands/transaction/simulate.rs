use {
    super::decode::read_execution_message,
    crate::{client::Client, output::OutputFormat},
    anyhow::{Context, Result, bail, ensure},
    clap::Args,
    serde::Serialize,
    serde_json::json,
    solana_account_decoder_client_types::token::real_number_string_trimmed,
    solana_address::Address,
    solana_hash::Hash,
    solana_message::legacy::Message,
    solana_native_token::Sol,
    solana_rpc_client_types::response::{RpcSimulateTransactionResult, UiTokenAmount},
    solana_transaction::Transaction,
    solana_transaction_status::UiTransactionTokenBalance,
    spl_ed25519_signer_client::ProgrammaticSigner,
    spl_message_executor_client::instruction::execute,
    std::{
        collections::{BTreeMap, BTreeSet, HashSet},
        fmt,
    },
};

#[derive(Debug, Args)]
pub(super) struct SimulateCommand {
    /// Base64-encoded v1 execution message.
    execution_message: String,

    /// SPL nonce account protecting this execution.
    nonce_account: Address,

    /// Nonce account authority. Defaults to the nonce account's authority.
    #[clap(long)]
    nonce_authority: Option<Address>,

    /// Expected nonce value, which replaces the execution message's recent blockhash.
    /// Defaults to the nonce account's current value.
    #[clap(long)]
    nonce_hash: Option<Hash>,

    /// Authority whose derived PDA signer to label in the balance changes. Repeat for each
    /// authority. Only affects the output.
    #[clap(long)]
    change_for_authority: Vec<Address>,

    /// Also print the full simulation result to stderr, including logs, inner instructions and
    /// the post-simulation state of every writable account.
    #[clap(long)]
    verbose: bool,
}

pub(super) async fn run(
    command: SimulateCommand,
    client: &Client,
    output: OutputFormat,
) -> Result<String> {
    let nonce = client.nonce_account(&command.nonce_account).await?.state;
    let nonce_authority = command.nonce_authority.unwrap_or(nonce.authority);
    let nonce_hash = command.nonce_hash.unwrap_or(nonce.nonce);
    let mut execution_message = read_execution_message(&command.execution_message)?;
    execution_message.lifetime_specifier = nonce_hash;
    ensure!(
        nonce_hash == nonce.nonce,
        "expected nonce value {nonce_hash}, but nonce account {} currently has {}",
        command.nonce_account,
        nonce.nonce
    );
    ensure!(
        nonce_authority == nonce.authority,
        "expected nonce authority {nonce_authority}, but nonce account {} has authority {}",
        command.nonce_account,
        nonce.authority
    );
    // The fee payer only needs to be funded. Signatures are not verified.
    let fee_payer = client.fee_payer()?.try_pubkey()?;

    // Submit promotes the PDA signers and forwards the other signers to the executor, so every
    // signer the Execute instruction marks is a signer when it runs. Calling the executor
    // directly with those signers mirrors that, without the authority signatures Submit checks.
    let instruction = execute(&command.nonce_account, &nonce_authority, &execution_message);
    // Compiling the message panics on more than 256 account keys.
    let account_count = instruction
        .accounts
        .iter()
        .map(|meta| meta.pubkey)
        .chain([instruction.program_id, fee_payer])
        .collect::<BTreeSet<_>>()
        .len();
    ensure!(
        account_count <= 256,
        "too many accounts for the simulated message"
    );
    let transaction = Transaction::new_unsigned(Message::new(&[instruction], Some(&fee_payer)));

    let verbose_accounts = command
        .verbose
        .then(|| writable_accounts(&transaction.message));
    let result = client
        .simulate_transaction(&transaction, verbose_accounts.as_deref())
        .await?;
    if let Some(addresses) = &verbose_accounts {
        let result = verbose_result(&result, addresses)?;
        eprintln!("Simulation result:\n{result}\n");
    }
    if let Some(error) = &result.err {
        let logs = result.logs.as_deref().unwrap_or_default().join("\n");
        bail!("simulation failed: {error}\nLogs:\n{logs}");
    }
    let fee = result.fee.unwrap_or(0);

    // Map each derived PDA signer back to its authority, to label the balance changes.
    let authorities = command
        .change_for_authority
        .iter()
        .map(|authority| {
            let pda =
                ProgrammaticSigner::derive_address(&spl_ed25519_signer_client::id(), authority);
            (pda.to_string(), authority.to_string())
        })
        .collect::<BTreeMap<_, _>>();

    output.render(&SimulateOutput {
        units_consumed: result.units_consumed,
        sol_balance_changes: sol_balance_changes(&transaction.message, &result, fee, &authorities)?,
        token_balance_changes: token_balance_changes(&transaction.message, &result, &authorities)?,
    })
}

/// Accounts the message may write to.
fn writable_accounts(message: &Message) -> Vec<Address> {
    message
        .account_keys
        .iter()
        .enumerate()
        .filter(|(index, _)| {
            message.is_maybe_writable_with_reserved_addresses(*index, None::<&HashSet<Address>>)
        })
        .map(|(_, address)| *address)
        .collect()
}

/// The full simulation result as pretty JSON, with each returned account paired with the
/// address it was requested for, since the RPC returns them by position only.
fn verbose_result(result: &RpcSimulateTransactionResult, addresses: &[Address]) -> Result<String> {
    let mut value = serde_json::to_value(result).context("failed to encode JSON")?;
    if let Some(accounts) = &result.accounts {
        ensure!(
            accounts.len() == addresses.len(),
            "the RPC node returned accounts that do not match the requested accounts"
        );
        value["accounts"] = addresses
            .iter()
            .zip(accounts)
            .map(|(address, account)| json!({ "address": address.to_string(), "account": account }))
            .collect();
    }
    serde_json::to_string_pretty(&value).context("failed to encode JSON")
}

/// Lamport changes per account. The simulation fee is added back to the fee payer, since the
/// relay transaction pays its own fee. `authorities` maps PDA signers to their authorities.
fn sol_balance_changes(
    message: &Message,
    result: &RpcSimulateTransactionResult,
    fee: u64,
    authorities: &BTreeMap<String, String>,
) -> Result<Vec<SolBalanceChange>> {
    let (Some(pre), Some(post)) = (&result.pre_balances, &result.post_balances) else {
        bail!("the RPC node did not return simulated balances");
    };
    ensure!(
        pre.len() == message.account_keys.len() && post.len() == message.account_keys.len(),
        "the RPC node returned balances that do not match the simulated accounts"
    );
    Ok(message
        .account_keys
        .iter()
        .zip(pre.iter().zip(post))
        .enumerate()
        .filter_map(|(index, (address, (pre, post)))| {
            let fee = if index == 0 { i128::from(fee) } else { 0 };
            let change = i128::from(*post)
                .saturating_sub(i128::from(*pre))
                .saturating_add(fee);
            (change != 0).then(|| {
                let address = address.to_string();
                SolBalanceChange {
                    authority: authorities.get(&address).cloned(),
                    address,
                    lamports: change,
                }
            })
        })
        .collect())
}

/// Token amount changes per token account. An account missing on one side was created or
/// closed, so its amount there is zero. `authorities` maps PDA signers to their authorities,
/// matched against the token account owner.
fn token_balance_changes(
    message: &Message,
    result: &RpcSimulateTransactionResult,
    authorities: &BTreeMap<String, String>,
) -> Result<Vec<TokenBalanceChange>> {
    let (Some(pre), Some(post)) = (&result.pre_token_balances, &result.post_token_balances) else {
        bail!("the RPC node did not return simulated token balances");
    };
    let mut balances = BTreeMap::<u8, (Option<_>, Option<_>)>::new();
    for balance in pre {
        balances.entry(balance.account_index).or_default().0 = Some(balance);
    }
    for balance in post {
        balances.entry(balance.account_index).or_default().1 = Some(balance);
    }

    let mut changes = Vec::new();
    for (index, (pre, post)) in balances {
        let amount = |balance: Option<&UiTransactionTokenBalance>| -> Result<i128> {
            balance.map_or(Ok(0), |balance| {
                balance
                    .ui_token_amount
                    .amount
                    .parse::<u64>()
                    .map(i128::from)
                    .context("the RPC node returned an invalid token amount")
            })
        };
        let change = amount(post)?.saturating_sub(amount(pre)?);
        if change == 0 {
            continue;
        }
        // Infallible: one side is present for every entry.
        // Note: currently doesn't handle these fields changing between pre/post balances.
        let UiTransactionTokenBalance {
            mint,
            owner,
            program_id,
            ui_token_amount: UiTokenAmount { decimals, .. },
            ..
        } = post.or(pre).unwrap();
        let account = message
            .account_keys
            .get(usize::from(index))
            .context("the RPC node returned a token balance for an unknown account")?;
        let owner = Option::<String>::from(owner.clone());
        changes.push(TokenBalanceChange {
            account: account.to_string(),
            mint: mint.clone(),
            authority: owner
                .as_ref()
                .and_then(|owner| authorities.get(owner).cloned()),
            owner,
            program_id: Option::from(program_id.clone()),
            amount: change,
            decimals: *decimals,
        });
    }
    Ok(changes)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SimulateOutput {
    units_consumed: Option<u64>,
    sol_balance_changes: Vec<SolBalanceChange>,
    token_balance_changes: Vec<TokenBalanceChange>,
}

#[derive(Serialize)]
struct SolBalanceChange {
    address: String,
    lamports: i128,
    /// Authority from --change-for-authority whose PDA signer is this address.
    authority: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TokenBalanceChange {
    account: String,
    mint: String,
    owner: Option<String>,
    program_id: Option<String>,
    /// Raw amount change, in base units.
    amount: i128,
    decimals: u8,
    /// Authority from --change-for-authority whose PDA signer owns this token account.
    authority: Option<String>,
}

impl fmt::Display for SimulateOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Simulation succeeded")?;
        if let Some(units) = self.units_consumed {
            write!(f, " ({units} compute units, excluding Submit)")?;
        }
        writeln!(f)?;

        writeln!(f, "\nSOL balance changes:")?;
        if self.sol_balance_changes.is_empty() {
            writeln!(f, "  none")?;
        }
        for change in &self.sol_balance_changes {
            writeln!(f, "  {change}")?;
        }

        write!(f, "\nToken balance changes:")?;
        if self.token_balance_changes.is_empty() {
            write!(f, "\n  none")?;
        }
        for change in &self.token_balance_changes {
            write!(f, "\n  {change}")?;
        }
        Ok(())
    }
}

impl fmt::Display for SolBalanceChange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sign = if self.lamports < 0 { '-' } else { '+' };
        // Infallible: the change of one u64 balance fits in a u64.
        let lamports = u64::try_from(self.lamports.unsigned_abs()).unwrap();
        write!(f, "{}  {sign}{}", self.address, Sol(lamports))?;
        if let Some(authority) = &self.authority {
            write!(f, "  (PDA of {authority})")?;
        }
        Ok(())
    }
}

impl fmt::Display for TokenBalanceChange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}  {}  mint {}",
            self.account,
            format_token_amount(self.amount, self.decimals),
            self.mint
        )?;
        if let Some(owner) = &self.owner {
            write!(f, "  owner {owner}")?;
        }
        if let Some(authority) = &self.authority {
            write!(f, "  (PDA of {authority})")?;
        }
        Ok(())
    }
}

/// Format a signed raw token amount with its decimals, e.g. `-1.5`.
fn format_token_amount(amount: i128, decimals: u8) -> String {
    let sign = if amount < 0 { '-' } else { '+' };
    // Infallible: the change of one u64 amount fits in a u64.
    let amount = u64::try_from(amount.unsigned_abs()).unwrap();
    format!("{sign}{}", real_number_string_trimmed(amount, decimals))
}

#[cfg(test)]
mod tests {
    use {super::format_token_amount, test_case::test_case};

    #[test_case(0, 0 => "+0")]
    #[test_case(-5, 0 => "-5")]
    #[test_case(1_500_000, 6 => "+1.5")]
    #[test_case(-1, 6 => "-0.000001")]
    #[test_case(2_000_000, 6 => "+2")]
    fn formats_token_amounts(amount: i128, decimals: u8) -> String {
        format_token_amount(amount, decimals)
    }
}
