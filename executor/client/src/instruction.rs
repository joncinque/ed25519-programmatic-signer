use {
    alloc::{collections::BTreeSet, vec::Vec},
    solana_address::Address,
    solana_instruction::{AccountMeta, Instruction},
    solana_message::legacy,
    spl_message_executor_interface::instruction::Instruction as MessageExecutorInstruction,
};

/// Creates an `Execute` instruction for a legacy message.
pub fn execute(
    nonce_account: &Address,
    nonce_authority: &Address,
    message: &legacy::Message,
) -> Instruction {
    // Fixed accounts for consuming the nonce, followed by the wrapped message's accounts
    let mut accounts = Vec::with_capacity(message.account_keys.len().saturating_add(3));
    accounts.push(AccountMeta::new_readonly(*nonce_authority, true));
    accounts.push(AccountMeta::new(*nonce_account, false));
    accounts.push(AccountMeta::new_readonly(spl_nonce_interface::id(), false));

    for (index, address) in message.account_keys.iter().enumerate() {
        accounts.push(AccountMeta {
            pubkey: *address,
            is_signer: message.is_signer(index),
            is_writable: message
                .is_maybe_writable_with_reserved_addresses(index, None::<&BTreeSet<_>>),
        });
    }

    Instruction::new_with_wincode(
        spl_message_executor_interface::id(),
        &MessageExecutorInstruction::Execute(message.clone()),
        accounts,
    )
}
