//! v1 transaction helpers for simulating `Execute` and relaying `Submit`.

use {
    crate::client::{Client, SimulateConfig},
    anyhow::{Context, Result, ensure},
    base64::{Engine, prelude::BASE64_STANDARD},
    clap::Args,
    solana_address::Address,
    solana_cli_output::CliSignOnlyData,
    solana_hash::Hash,
    solana_instruction::Instruction,
    solana_message::{VersionedMessage, v1},
    solana_signature::Signature,
    solana_signer::Signer,
    solana_system_interface::instruction::advance_nonce_account,
    solana_transaction::versioned::VersionedTransaction,
};

/// Runtime maximum compute unit limit.
const MAX_COMPUTE_UNIT_LIMIT: u32 = 1_400_000;

/// Runtime maximum loaded accounts data size, in bytes.
const MAX_LOADED_ACCOUNTS_DATA_SIZE: u32 = 64 * 1024 * 1024;

/// Headroom added to simulated limits, in percent, for state that changes between the simulation
/// and the transaction landing.
const SIMULATED_LIMIT_MARGIN_PERCENT: u64 = 10;

/// Compute budget options for a v1 transaction, shared by the commands that send one.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Args)]
pub(crate) struct ComputeBudget {
    /// Compute unit limit for the transaction, up to 1,400,000. Defaults to the simulated compute
    /// units plus a 10% margin, or to the maximum for a transaction signed without a simulation.
    #[clap(
        long = "with-compute-unit-limit",
        value_name = "COMPUTE-UNIT-LIMIT",
        value_parser = clap::value_parser!(u32).range(1..=1_400_000)
    )]
    pub(crate) unit_limit: Option<u32>,

    /// Loaded accounts data size limit for the transaction, in bytes, up to 64 MiB (67,108,864).
    /// Defaults to the simulated loaded accounts data size plus a 10% margin, or to the maximum for
    /// a transaction signed without a simulation.
    #[clap(
        long = "with-loaded-accounts-data-size-limit",
        value_name = "BYTES",
        value_parser = clap::value_parser!(u32).range(1..=i64::from(MAX_LOADED_ACCOUNTS_DATA_SIZE))
    )]
    pub(crate) loaded_accounts_data_size_limit: Option<u32>,

    /// Priority fee for the transaction, in lamports. Paid on top of the base fee, whatever the
    /// compute unit limit.
    #[clap(long = "with-priority-fee", value_name = "LAMPORTS")]
    pub(crate) priority_fee: Option<u64>,
}

impl ComputeBudget {
    /// Fail if any compute budget option is set, for a command run that sends no transaction.
    /// `reason` says why, and where the options apply instead.
    pub(crate) fn ensure_unset(&self, reason: &str) -> Result<()> {
        ensure!(
            *self == Self::default(),
            "--with-compute-unit-limit, --with-loaded-accounts-data-size-limit and \
             --with-priority-fee have no effect here: {reason}"
        );
        Ok(())
    }

    /// The transaction config, with the fixed limits from these options, or else
    /// `compute_unit_limit` and `loaded_accounts_data_size_limit`.
    fn config(
        &self,
        compute_unit_limit: u32,
        loaded_accounts_data_size_limit: u32,
    ) -> v1::TransactionConfig {
        let config = v1::TransactionConfig::empty()
            .with_compute_unit_limit(self.unit_limit.unwrap_or(compute_unit_limit))
            .with_loaded_accounts_data_size_limit(
                self.loaded_accounts_data_size_limit
                    .unwrap_or(loaded_accounts_data_size_limit),
            );
        match self.priority_fee {
            Some(fee) => config.with_priority_fee(fee),
            None => config,
        }
    }
}

/// Compile and validate a v1 message for `instructions` with `budget`. Limits it does not fix are
/// the maximum, since v1 has no default limits.
pub(crate) fn compile_message(
    fee_payer: &Address,
    instructions: &[Instruction],
    blockhash: Hash,
    budget: ComputeBudget,
) -> Result<v1::Message> {
    let config = budget.config(MAX_COMPUTE_UNIT_LIMIT, MAX_LOADED_ACCOUNTS_DATA_SIZE);
    let message = v1::Message::try_compile_with_config(fee_payer, instructions, blockhash, config)
        .context("failed to compile transaction message")?;
    message.validate().context("invalid transaction message")?;
    Ok(message)
}

/// Return `message` with its maximum limits replaced by its simulated compute units and loaded
/// accounts data size, plus a margin. Limits fixed by `budget` are kept. With
/// `replace_recent_blockhash`, simulates against the latest blockhash. If the transaction fails in
/// simulation, `message` is returned unchanged so that sending it reports the error. Errors if the
/// simulation request itself fails.
pub(crate) async fn with_simulated_limits(
    client: &Client,
    mut message: v1::Message,
    budget: ComputeBudget,
    replace_recent_blockhash: bool,
) -> Result<v1::Message> {
    // Nothing to size when both limits are fixed.
    if budget.unit_limit.is_some() && budget.loaded_accounts_data_size_limit.is_some() {
        return Ok(message);
    }
    let result = client
        .simulate_transaction(
            &unsigned_transaction(message.clone()),
            &SimulateConfig {
                replace_recent_blockhash,
                ..SimulateConfig::default()
            },
        )
        .await?;
    if result.err.is_some() {
        return Ok(message);
    }
    let compute_unit_limit = result
        .units_consumed
        .map_or(MAX_COMPUTE_UNIT_LIMIT, |units| {
            with_margin(units, MAX_COMPUTE_UNIT_LIMIT)
        });
    let loaded_accounts_data_size_limit = result
        .loaded_accounts_data_size
        .map_or(MAX_LOADED_ACCOUNTS_DATA_SIZE, |size| {
            with_margin(u64::from(size), MAX_LOADED_ACCOUNTS_DATA_SIZE)
        });
    message.config = budget.config(compute_unit_limit, loaded_accounts_data_size_limit);
    Ok(message)
}

/// `value` plus [`SIMULATED_LIMIT_MARGIN_PERCENT`], rounded up and capped at `max`.
fn with_margin(value: u64, max: u32) -> u32 {
    let value = u128::from(value)
        .saturating_mul(u128::from(100 + SIMULATED_LIMIT_MARGIN_PERCENT))
        .div_ceil(100);
    u32::try_from(value).unwrap_or(max).min(max)
}

/// Wrap `message` in a transaction with an empty signature slot for each signer.
pub(crate) fn unsigned_transaction(message: v1::Message) -> VersionedTransaction {
    VersionedTransaction {
        signatures: vec![Signature::default(); usize::from(message.header.num_required_signatures)],
        message: VersionedMessage::V1(message),
    }
}

/// Build the relay transaction message that submits `authorization_message`. `signatures` has one
/// entry per authorization message signer. `submit_signers` are the authorization message signers
/// that sign the relay transaction, and have their
/// `Submit` accounts marked as signers.
pub(super) fn relay_message(
    authorization_message: &v1::Message,
    signatures: Vec<Option<Signature>>,
    submit_signers: &[Address],
    fee_payer: &Address,
    durable_nonce: Option<(Address, Address)>,
    blockhash: Hash,
    budget: ComputeBudget,
) -> Result<v1::Message> {
    let mut submit = spl_ed25519_signer_client::instruction::submit(
        signatures,
        VersionedMessage::V1(authorization_message.clone()),
    );
    for meta in &mut submit.accounts {
        meta.is_signer |= submit_signers.contains(&meta.pubkey);
    }
    // A durable nonce transaction must advance its nonce in its first instruction.
    let instructions = match durable_nonce {
        Some((address, authority)) => vec![advance_nonce_account(&address, &authority), submit],
        None => vec![submit],
    };
    compile_message(fee_payer, &instructions, blockhash, budget)
}

/// Check that a transaction for `message`, including its signatures, fits within the v1 transaction
/// size limit. `name` describes it in errors.
pub(super) fn ensure_transaction_size(name: &str, message: &v1::Message) -> Result<()> {
    let size = wincode::serialize(&unsigned_transaction(message.clone()))
        .with_context(|| format!("failed to serialize {name}"))?
        .len();
    ensure!(
        size <= v1::MAX_TRANSACTION_SIZE,
        "{name} is {size} bytes, which exceeds the v1 transaction size limit of {} bytes",
        v1::MAX_TRANSACTION_SIZE
    );
    Ok(())
}

/// The signature slot of a transaction signer.
pub(super) fn signer_index(transaction: &VersionedTransaction, address: &Address) -> Option<usize> {
    transaction.message.static_account_keys()[..transaction.signatures.len()]
        .iter()
        .position(|key| key == address)
}

/// Sign `message_data` with each signer, leaving other signature slots unchanged. The v1 stand-in
/// for `Transaction::try_partial_sign`. `message_data` is not checked against the transaction's
/// message, so it must be its serialization.
pub(crate) fn try_partial_sign(
    transaction: &mut VersionedTransaction,
    signers: &[&dyn Signer],
    message_data: &[u8],
) -> Result<()> {
    for signer in signers {
        let address = signer.try_pubkey()?;
        let index = signer_index(transaction, &address)
            .with_context(|| format!("{address} is not a relay transaction signer"))?;
        transaction.signatures[index] = signer.try_sign_message(message_data)?;
    }
    Ok(())
}

/// The v1 stand-in for `solana_cli_output::return_signers_data`, which only takes a legacy
/// transaction.
pub(super) fn return_signers_data(
    transaction: &VersionedTransaction,
    message_data: &[u8],
    dump_transaction_message: bool,
) -> CliSignOnlyData {
    let mut data = CliSignOnlyData {
        blockhash: transaction.message.recent_blockhash().to_string(),
        message: dump_transaction_message.then(|| BASE64_STANDARD.encode(message_data)),
        ..CliSignOnlyData::default()
    };
    let keys = transaction.message.static_account_keys();
    for (signature, address) in transaction.signatures.iter().zip(keys) {
        if signature.verify(address.as_ref(), message_data) {
            data.signers.push(format!("{address}={signature}"));
        } else if *signature == Signature::default() {
            data.absent.push(address.to_string());
        } else {
            data.bad_sig.push(address.to_string());
        }
    }
    data
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_sets_the_priority_fee() {
        let budget = ComputeBudget {
            priority_fee: Some(200),
            ..ComputeBudget::default()
        };
        assert_eq!(
            budget.config(100, 200),
            v1::TransactionConfig::empty()
                .with_compute_unit_limit(100)
                .with_loaded_accounts_data_size_limit(200)
                .with_priority_fee(200)
        );
        assert_eq!(
            ComputeBudget::default().config(100, 200),
            v1::TransactionConfig::empty()
                .with_compute_unit_limit(100)
                .with_loaded_accounts_data_size_limit(200)
        );
    }

    #[test]
    fn config_keeps_fixed_limits() {
        let budget = ComputeBudget {
            unit_limit: Some(10),
            loaded_accounts_data_size_limit: Some(20),
            priority_fee: None,
        };
        assert_eq!(
            budget.config(100, 200),
            v1::TransactionConfig::empty()
                .with_compute_unit_limit(10)
                .with_loaded_accounts_data_size_limit(20)
        );
    }

    #[test]
    fn with_margin_rounds_up_and_caps() {
        assert_eq!(with_margin(0, 100), 0);
        assert_eq!(with_margin(1, 100), 2);
        assert_eq!(with_margin(10, 100), 11);
        assert_eq!(with_margin(95, 100), 100);
        assert_eq!(
            with_margin(u64::MAX, MAX_COMPUTE_UNIT_LIMIT),
            MAX_COMPUTE_UNIT_LIMIT
        );
    }
}
