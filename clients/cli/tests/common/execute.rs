use {
    base64::{Engine, prelude::BASE64_STANDARD},
    solana_address::Address,
    solana_message::{VersionedMessage, v1},
    solana_signer::Signer,
    spl_ed25519_signer_client::{ProgrammaticSigner, message::authorization_message},
    spl_message_executor_client::instruction::execute,
    std::collections::BTreeSet,
};

pub fn programmatic_signer(authority: &Address) -> Address {
    ProgrammaticSigner::derive_address(&spl_ed25519_signer_client::id(), authority)
}

/// Build the authorization message the way `transaction sign` does. Its signers are the
/// authorities plus every execution message signer and the nonce authority that is not one of
/// their derived signers.
pub fn build_authorization_message(
    execution_message: &v1::Message,
    nonce_account: &Address,
    nonce_authority: &Address,
    authorities: &[Address],
) -> VersionedMessage {
    let derived_signers = authorities
        .iter()
        .map(programmatic_signer)
        .collect::<BTreeSet<_>>();
    let execution_signers = &execution_message.account_keys
        [..usize::from(execution_message.header.num_required_signatures)];
    let signers = execution_signers
        .iter()
        .chain([nonce_authority])
        .filter(|address| !derived_signers.contains(*address))
        .chain(authorities)
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    authorization_message(
        &execute(nonce_account, nonce_authority, execution_message),
        &signers,
    )
}

pub fn encode(message: &VersionedMessage) -> String {
    BASE64_STANDARD.encode(message.serialize())
}

/// An `ADDRESS=SIGNATURE` pair for `message`, as printed by `transaction sign`.
pub fn signature_entry(signer: &impl Signer, message: &VersionedMessage) -> String {
    format!(
        "{}={}",
        signer.pubkey(),
        signer.sign_message(&message.serialize())
    )
}
