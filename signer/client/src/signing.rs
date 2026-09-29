//! Signs an authorization message with [`Signers`] and assembles the on-chain submit instruction.

use {
    crate::{instruction::submit, message::authorization_message},
    solana_instruction::Instruction,
    solana_signer::{SignerError, signers::Signers},
    solana_transaction::versioned::VersionedTransaction,
};

/// Builds an authorization message for `executor_instruction`, signs it with `signers`, and returns
/// the on-chain signer-program `Submit` instruction.
pub fn sign_and_submit<S: Signers + ?Sized>(
    executor_instruction: &Instruction,
    signers: &S,
) -> Result<Instruction, SignerError> {
    let authorities = signers.try_pubkeys()?;
    let message = authorization_message(executor_instruction, &authorities);
    let VersionedTransaction {
        signatures,
        message,
    } = VersionedTransaction::try_new(message, signers)?;
    let instruction = submit(signatures, message);
    Ok(instruction)
}
