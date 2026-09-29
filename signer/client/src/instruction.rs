//! Builder for the on-chain `Submit` instruction.

use {
    alloc::{collections::BTreeSet, vec::Vec},
    solana_instruction::{AccountMeta, Instruction},
    solana_message::VersionedMessage,
    solana_signature::Signature,
    spl_ed25519_signer_interface::instruction::Instruction as SignerInstruction,
};

/// Builds the `Submit` instruction from authority signatures and their authorization message.
pub fn submit(signatures: Vec<Signature>, message: VersionedMessage) -> Instruction {
    let accounts = message
        .static_account_keys()
        .iter()
        .enumerate()
        .map(|(index, key)| AccountMeta {
            pubkey: *key,
            is_signer: false,
            is_writable: message
                .is_maybe_writable_with_reserved_addresses(index, None::<&BTreeSet<_>>),
        })
        .collect();
    Instruction::new_with_wincode(
        spl_ed25519_signer_interface::id(),
        &SignerInstruction::Submit {
            signatures,
            message,
        },
        accounts,
    )
}
