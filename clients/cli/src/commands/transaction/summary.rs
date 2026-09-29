use {
    anyhow::{Context, Result, ensure},
    indoc::formatdoc,
    solana_address::Address,
    solana_message::{VersionedMessage, v1},
    solana_signature::Signature,
    solana_signer::Signer,
    solana_transaction_status::{Encodable, EncodableWithMeta, UiTransactionEncoding},
    spl_ed25519_signer_client::ProgrammaticSigner,
    std::io,
};

/// Describe what signing the execute message authorizes. `closing` says what happens after
/// signing.
pub(super) fn render_signing_summary(
    inner: &v1::Message,
    outer: &VersionedMessage,
    nonce_account: &Address,
    nonce_authority: &Address,
    authorities: &[Address],
    forwarded_signers: &[Address],
    closing: &str,
) -> Result<String> {
    let inner_json =
        serde_json::to_string_pretty(&inner.encode(UiTransactionEncoding::JsonParsed))?;
    let (outer_version, outer_ui_message) = match outer {
        VersionedMessage::Legacy(message) => {
            ("Legacy", message.encode(UiTransactionEncoding::Json))
        }
        VersionedMessage::V0(message) => ("v0", message.json_encode()),
        VersionedMessage::V1(message) => ("v1", message.encode(UiTransactionEncoding::Json)),
    };
    let outer_json = serde_json::to_string_pretty(&outer_ui_message)?;
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
    let message_hash = outer.hash();
    let expected_nonce = inner.lifetime_specifier;
    Ok(formatdoc! {"
        === Authorization ===
        Message hash: {message_hash}
        PDA promotion authorities:
        {signing_keys}
        {forwarded_section}
        === Replay protection ===
        SPL nonce account address: {nonce_account}
        Nonce authority: {nonce_authority}
        Expected nonce value (inner message's recent blockhash): {expected_nonce}

        === Outer message ===
        Your signatures authorize this Execute call, including its accounts, permissions,
        and the inner message.

        {outer_version} message:
        {outer_json}

        === Inner message (what the executor program invokes via CPI) ===
        v1 message:
        {inner_json}

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

/// Sign the execute message with each signer.
pub(super) fn sign_outer_message(
    outer_message: &VersionedMessage,
    signers: &[(Address, Box<dyn Signer>)],
) -> Result<Vec<(Address, Signature)>> {
    let message_bytes = outer_message.serialize();
    signers
        .iter()
        .map(|(authority, signer)| {
            let signature = signer
                .try_sign_message(&message_bytes)
                .with_context(|| format!("failed to sign outer message with {authority}"))?;
            Ok((*authority, signature))
        })
        .collect()
}
