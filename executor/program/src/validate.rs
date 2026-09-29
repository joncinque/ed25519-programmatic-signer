//! Validates the wrapped message and the runtime accounts used to execute it.

use {
    pinocchio::{AccountView, error::ProgramError},
    solana_message::{VersionedMessage, v1},
    solana_sanitize::Sanitize,
    spl_message_executor_interface::error::Error,
};

pub fn validate_wrapped_message(
    wrapped_message: &VersionedMessage,
) -> Result<&v1::Message, ProgramError> {
    let VersionedMessage::V1(wrapped_message) = wrapped_message else {
        return Err(Error::UnsupportedMessageVersion.into());
    };

    // Message account privileges come from the header counts,
    // so they must agree with the key list.
    // Sanitization also rejects duplicates. The runtime's `AccountLoadedTwice` check only covers
    // top-level messages, and one account must not hold conflicting CPI privileges.
    wrapped_message
        .sanitize()
        .map_err(|_| Error::InvalidMessage)?;

    // Config fields only apply to top-level transactions. Reject them so authorities never
    // approve fees or limits that have no effect.
    if wrapped_message.config != v1::TransactionConfig::default() {
        return Err(Error::UnsupportedTransactionConfig.into());
    }

    Ok(wrapped_message)
}

/// Validates the supplied accounts against the wrapped message.
///
/// Note: The CPI runtime rejects writable and signer privilege escalation during instruction
/// execution.
pub fn validate_message_accounts(
    message_accounts: &[AccountView],
    wrapped_message: &v1::Message,
) -> Result<(), ProgramError> {
    // Compiled instructions resolve accounts by index, so message accounts
    // must mirror the message's static addresses one-to-one
    if message_accounts.len() != wrapped_message.account_keys.len() {
        return Err(Error::MessageAccountsMismatch.into());
    }

    for (account, expected_addr) in message_accounts.iter().zip(&wrapped_message.account_keys) {
        if account.address() != expected_addr {
            return Err(Error::MessageAccountsMismatch.into());
        }
    }

    Ok(())
}
