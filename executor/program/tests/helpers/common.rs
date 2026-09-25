use {
    crate::helpers::nonce_account_builder::NonceAccountBuilder, mollusk_svm::Mollusk,
    solana_account::Account, solana_address::Address, spl_nonce_client::instruction::initialize,
    spl_nonce_interface::state::Nonce,
};

pub fn init_mollusk() -> Mollusk {
    let mut mollusk = Mollusk::new(
        &spl_message_executor_interface::id(),
        "spl_message_executor_program",
    );
    mollusk.add_program(&spl_nonce_interface::id(), "spl_nonce_program");
    mollusk
}

pub fn decode_state(account: &Account) -> Nonce {
    wincode::deserialize_exact(&account.data).unwrap()
}

pub fn initialize_nonce_account(mollusk: &Mollusk, authority: &Address) -> (Address, Account) {
    let (nonce_address, nonce_account) = NonceAccountBuilder::new()
        .address(Address::new_unique())
        .build();
    let instruction = initialize(&nonce_address, authority);
    let result = mollusk.process_and_validate_instruction(
        &instruction,
        &[
            (nonce_address, nonce_account),
            (
                *authority,
                Account::new(0, 0, &solana_system_interface::program::id()),
            ),
            mollusk.sysvars.keyed_account_for_slot_hashes_sysvar(),
        ],
        &[mollusk_svm::result::Check::success()],
    );

    (
        nonce_address,
        result.get_account(&nonce_address).unwrap().clone(),
    )
}
