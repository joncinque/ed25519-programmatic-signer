use {
    base64::{Engine, prelude::BASE64_STANDARD},
    solana_address::Address,
    solana_message::{VersionedMessage, legacy::Message},
    solana_signer::Signer,
    spl_ed25519_signer_client::{ProgrammaticSigner, message::wrapped_message},
    spl_message_executor_client::instruction::execute,
    std::collections::BTreeSet,
};

pub fn programmatic_signer(authority: &Address) -> Address {
    ProgrammaticSigner::derive_address(&spl_ed25519_signer_client::id(), authority)
}

/// Build the execute message the way `transaction sign` does. The wrapped message's signers are
/// the authorities plus every inner signer and the nonce authority that is not one of their
/// derived signers.
pub fn execute_message(
    inner: &Message,
    nonce_account: &Address,
    nonce_authority: &Address,
    authorities: &[Address],
) -> VersionedMessage {
    let derived_signers = authorities
        .iter()
        .map(programmatic_signer)
        .collect::<BTreeSet<_>>();
    let inner_signers = &inner.account_keys[..usize::from(inner.header.num_required_signatures)];
    let signers = inner_signers
        .iter()
        .chain([nonce_authority])
        .filter(|address| !derived_signers.contains(*address))
        .chain(authorities)
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    wrapped_message(&execute(nonce_account, nonce_authority, inner), &signers)
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
