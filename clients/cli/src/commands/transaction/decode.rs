use {
    anyhow::{Context, Result, bail, ensure},
    base64::{Engine, prelude::BASE64_STANDARD},
    solana_message::{VersionedMessage, v1},
};

/// Decode and sanitize a base64-encoded message. `name` describes the message in errors.
pub(super) fn read_message(input: &str, name: &str) -> Result<VersionedMessage> {
    let bytes = BASE64_STANDARD
        .decode(input.trim())
        .with_context(|| format!("invalid base64 {name}"))?;
    let message: VersionedMessage =
        wincode::deserialize_exact(&bytes).with_context(|| format!("invalid serialized {name}"))?;
    message
        .sanitize()
        .with_context(|| format!("invalid {name}"))?;
    Ok(message)
}

/// Read an execution message the executor can invoke. Transaction config fields only apply to
/// top-level transactions, so they are rejected unless `strip_transaction_config` is set, in
/// which case they are cleared.
pub(super) fn read_execution_message(
    input: &str,
    strip_transaction_config: bool,
) -> Result<v1::Message> {
    let mut message = read_message(input, "execution message")?;
    if let (true, VersionedMessage::V1(message)) = (strip_transaction_config, &mut message) {
        message.config = v1::TransactionConfig::default();
    }
    validate_execution_message(message)
}

/// Check that a sanitized execution message is one the executor can invoke. Sanitizing a v1 message
/// already rejects duplicate account keys.
pub(super) fn validate_execution_message(message: VersionedMessage) -> Result<v1::Message> {
    let VersionedMessage::V1(message) = message else {
        bail!("the executor supports only v1 execution messages");
    };
    ensure!(
        message.config == v1::TransactionConfig::default(),
        "execution message must not set transaction config fields, which only apply to top-level \
         transactions. Pass --strip-transaction-config to remove them"
    );
    ensure!(
        !message.instructions.iter().any(|ix| {
            message.account_keys.get(usize::from(ix.program_id_index))
                == Some(&spl_message_executor_interface::ID)
        }),
        "execution message must not invoke the executor program. A nested Execute would run \
         another execution message with the same signers"
    );
    Ok(message)
}

/// Read an authorization message the signer program accepts.
pub(super) fn read_authorization_message(input: &str) -> Result<v1::Message> {
    let VersionedMessage::V1(message) = read_message(input, "authorization message")? else {
        bail!("the signer program supports only v1 authorization messages");
    };
    ensure!(
        message.config == v1::TransactionConfig::default(),
        "authorization message must not set transaction config fields"
    );
    Ok(message)
}
