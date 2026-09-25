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

/// Read an inner message the executor can invoke.
pub(super) fn read_inner_message(input: &str) -> Result<v1::Message> {
    executable_inner_message(read_message(input, "inner message")?)
}

/// Check that a sanitized inner message is one the executor can invoke. Sanitizing a v1 message
/// already rejects duplicate account keys.
pub(super) fn executable_inner_message(message: VersionedMessage) -> Result<v1::Message> {
    let VersionedMessage::V1(message) = message else {
        bail!("the executor supports only v1 inner messages");
    };
    ensure!(
        message.config == v1::TransactionConfig::default(),
        "inner message must not set transaction config fields, which only apply to top-level \
         transactions"
    );
    Ok(message)
}

/// Read an execute message the signer program accepts.
pub(super) fn read_execute_message(input: &str) -> Result<VersionedMessage> {
    let message = read_message(input, "execute message")?;
    let VersionedMessage::V1(v1_message) = &message else {
        bail!("the signer program supports only v1 execute messages");
    };
    ensure!(
        v1_message.config == v1::TransactionConfig::default(),
        "execute message must not set transaction config fields"
    );
    Ok(message)
}
