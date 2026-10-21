//! v1 transaction helpers for simulating `Execute` and relaying `Submit`.

use {
    anyhow::{Context, Result},
    base64::{Engine, prelude::BASE64_STANDARD},
    solana_address::Address,
    solana_cli_output::CliSignOnlyData,
    solana_hash::Hash,
    solana_instruction::Instruction,
    solana_message::v1,
    solana_signature::Signature,
    solana_signer::Signer,
    solana_transaction::versioned::VersionedTransaction,
};

/// Runtime maximum compute unit limit.
const MAX_COMPUTE_UNIT_LIMIT: u32 = 1_400_000;

/// Runtime maximum loaded accounts data size, in bytes.
const MAX_LOADED_ACCOUNTS_DATA_SIZE: u32 = 64 * 1024 * 1024;

/// Unset v1 limits are zero rather than the legacy defaults, so a transaction requests the
/// maximum. Every run must build the same relay message, including `--sign-only` runs that make no
/// RPC calls, so the limits are fixed rather than sized from a simulation.
// TODO later: Align with how other CLIs set v1 limits.
const LIMITS: v1::TransactionConfig = v1::TransactionConfig::empty()
    .with_compute_unit_limit(MAX_COMPUTE_UNIT_LIMIT)
    .with_loaded_accounts_data_size_limit(MAX_LOADED_ACCOUNTS_DATA_SIZE);

/// Compile and validate a v1 message for `instructions`.
pub(crate) fn compile_message(
    fee_payer: &Address,
    instructions: &[Instruction],
    blockhash: Hash,
) -> Result<v1::Message> {
    let message = v1::Message::try_compile_with_config(fee_payer, instructions, blockhash, LIMITS)
        .context("failed to compile transaction message")?;
    message.validate().context("invalid transaction message")?;
    Ok(message)
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
    for ((signature, address), valid) in transaction
        .signatures
        .iter()
        .zip(keys)
        .zip(transaction.verify_with_results())
    {
        if valid {
            data.signers.push(format!("{address}={signature}"));
        } else if *signature == Signature::default() {
            data.absent.push(address.to_string());
        } else {
            data.bad_sig.push(address.to_string());
        }
    }
    data
}
