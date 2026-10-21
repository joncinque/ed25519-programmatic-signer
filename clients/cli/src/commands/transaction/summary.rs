use {
    anyhow::{Context, Result, ensure},
    indoc::formatdoc,
    solana_address::Address,
    solana_hash::Hash,
    solana_message::{VersionedMessage, v1},
    solana_signature::Signature,
    solana_signer::Signer,
    solana_transaction_status::{Encodable, UiTransactionEncoding},
    spl_ed25519_signer_client::ProgrammaticSigner,
    spl_message_executor_interface::instruction::derive_transition_commitment,
    spl_nonce_interface::state::Nonce,
    std::io,
};

/// The value the nonce account holds after the executor runs `execution_message`, whose lifetime
/// specifier is the expected nonce. Each advance commits to the exact execution message, so the
/// successor is known offline, and a message signed against it can only execute after this one.
pub(crate) fn next_nonce(nonce_account: &Address, execution_message: &v1::Message) -> Hash {
    Nonce {
        nonce: execution_message.lifetime_specifier,
        ..Nonce::default()
    }
    .derive_next_nonce(
        &spl_nonce_interface::id(),
        nonce_account,
        &derive_transition_commitment(&VersionedMessage::V1(execution_message.clone())),
    )
}

/// Describe what signing the authorization message authorizes. `closing` says what happens after
/// signing.
pub(super) fn render_signing_summary(
    execution_message: &v1::Message,
    authorization_message: &v1::Message,
    nonce_account: &Address,
    nonce_authority: &Address,
    authorities: &[Address],
    forwarded_signers: &[Address],
    closing: &str,
) -> Result<String> {
    let execution_json =
        serde_json::to_string_pretty(&execution_message.encode(UiTransactionEncoding::JsonParsed))?;
    let authorization_json =
        serde_json::to_string_pretty(&authorization_message.encode(UiTransactionEncoding::Json))?;
    let signing_keys = authorities
        .iter()
        .map(|authority| {
            let pda =
                ProgrammaticSigner::derive_address(&spl_ed25519_signer_client::id(), authority);
            format!("  {authority} (derived signer: {pda})")
        })
        .collect::<Vec<_>>()
        .join("\n");
    let forwarded_signers = forwarded_signers
        .iter()
        .map(|address| format!("  {address}"))
        .collect::<Vec<_>>();
    let forwarded_section = if forwarded_signers.is_empty() {
        String::new()
    } else {
        format!(
            "\nForwarded signers (sign at submission):\n{}\n",
            forwarded_signers.join("\n")
        )
    };
    let message_hash = VersionedMessage::hash_raw_message(&authorization_message.serialize());
    let expected_nonce = execution_message.lifetime_specifier;
    let next_nonce = next_nonce(nonce_account, execution_message);
    Ok(formatdoc! {"
        === Signing ===
        Message hash: {message_hash}
        PDA promotion authorities:
        {signing_keys}
        {forwarded_section}
        === Replay protection ===
        SPL nonce account address: {nonce_account}
        Nonce authority: {nonce_authority}
        Expected nonce value (execution message's recent blockhash): {expected_nonce}
        Next nonce value (after this message executes): {next_nonce}

        === Authorization message ===
        Your signatures authorize this Execute call, including its accounts, permissions,
        and the execution message.

        v1 message:
        {authorization_json}

        === Execution message (what the executor program invokes via CPI) ===
        v1 message:
        {execution_json}

        {closing}"
    })
}

/// Confirm once before signing if any signer has no approval step of its own.
pub(super) fn confirm_signing(
    signers: &[(Address, Box<dyn Signer>)],
    skip_confirmation: bool,
) -> Result<()> {
    if skip_confirmation || signers.iter().all(|(_, signer)| signer.is_interactive()) {
        return Ok(());
    }
    let addresses = signers
        .iter()
        .map(|(address, _)| address.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    eprint!("Sign this message for {addresses}? [y/N] ");
    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .context("failed to read signing confirmation")?;
    let answer = answer.trim();
    ensure!(
        answer.eq_ignore_ascii_case("y") || answer.eq_ignore_ascii_case("yes"),
        "signing cancelled"
    );
    Ok(())
}

/// Sign the authorization message with each signer.
pub(super) fn sign_authorization_message(
    authorization_message: &v1::Message,
    signers: &[(Address, Box<dyn Signer>)],
) -> Result<Vec<(Address, Signature)>> {
    let message_bytes = authorization_message.serialize();
    signers
        .iter()
        .map(|(authority, signer)| {
            let signature = signer.try_sign_message(&message_bytes).with_context(|| {
                format!("failed to sign authorization message with {authority}")
            })?;
            Ok((*authority, signature))
        })
        .collect()
}
