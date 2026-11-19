use {
    crate::helpers::{
        common::{decode_state, init_mollusk},
        initialize_builder::InitializeBuilder,
        nonce_account_builder::NonceAccountBuilder,
    },
    mollusk_svm::result::Check,
    solana_account::Account,
    solana_address::Address,
    solana_instruction::AccountMeta,
    solana_program_error::ProgramError,
    solana_rent::Rent,
    spl_nonce_client::instruction::{create_account, initialize},
    spl_nonce_interface::state::{NONCE_INIT_TAG, Nonce},
};

pub mod helpers;

#[test]
fn initialize_rejects_unknown_instruction_discriminator() {
    let invalid_discriminator = 9;
    InitializeBuilder::default()
        .instruction_data(vec![invalid_discriminator])
        .check(Check::err(ProgramError::InvalidInstructionData))
        .execute();
}

#[test]
fn initialize_rejects_trailing_instruction_data() {
    let mut data_with_trailing_byte =
        initialize(&Address::new_unique(), &Address::new_unique()).data;
    data_with_trailing_byte.push(0);

    InitializeBuilder::default()
        .instruction_data(data_with_trailing_byte)
        .check(Check::err(ProgramError::InvalidInstructionData))
        .execute();
}

#[test]
fn initialize_rejects_missing_accounts() {
    let nonce_account = NonceAccountBuilder::new().build();
    let authority = (Address::new_unique(), Account::default());
    let mut instruction = initialize(&nonce_account.0, &authority.0);
    instruction.accounts.pop(); // drop the SlotHashes account meta

    init_mollusk().process_and_validate_instruction(
        &instruction,
        &[nonce_account, authority],
        &[Check::err(ProgramError::NotEnoughAccountKeys)],
    );
}

#[test]
fn initialize_rejects_account_owned_by_another_program() {
    let wrong_owner = Address::new_unique();
    InitializeBuilder::default()
        .nonce_account(NonceAccountBuilder::new().owner(wrong_owner).build())
        .check(Check::err(ProgramError::IllegalOwner))
        .execute();
}

#[test]
fn initialize_rejects_wrong_slot_hashes_account() {
    let nonce_account = NonceAccountBuilder::new().build();
    let authority = (Address::new_unique(), Account::default());
    let wrong_slot_hashes = (Address::new_unique(), Account::default());

    let mut instruction = initialize(&nonce_account.0, &authority.0);
    instruction.accounts.pop(); // drop the real SlotHashes meta
    instruction
        .accounts
        .push(AccountMeta::new_readonly(wrong_slot_hashes.0, false));

    init_mollusk().process_and_validate_instruction(
        &instruction,
        &[nonce_account, authority, wrong_slot_hashes],
        &[Check::err(ProgramError::InvalidArgument)],
    );
}

#[test]
fn initialize_rejects_wrong_account_data_size() {
    for wrong_space in [
        Nonce::LEN.checked_sub(1).unwrap(),
        Nonce::LEN.checked_add(1).unwrap(),
    ] {
        InitializeBuilder::default()
            .nonce_account(
                NonceAccountBuilder::new()
                    .data(vec![0; wrong_space])
                    .build(),
            )
            .check(Check::err(ProgramError::InvalidAccountData))
            .execute();
    }
}

#[test]
fn initialize_rejects_underfunded_account() {
    let underfunded = Rent::default()
        .minimum_balance(Nonce::LEN)
        .saturating_sub(1);

    InitializeBuilder::default()
        .nonce_account(NonceAccountBuilder::new().lamports(underfunded).build())
        .check(Check::err(ProgramError::AccountNotRentExempt))
        .execute();
}

#[test]
fn initialize_rejects_reinitialization() {
    let nonce_account_address = Address::new_unique();
    let initialized = InitializeBuilder::default()
        .nonce_account(
            NonceAccountBuilder::new()
                .key(Address::from(&nonce_account_address))
                .build(),
        )
        .execute()
        .get_account(&nonce_account_address)
        .unwrap()
        .clone();

    InitializeBuilder::default()
        .nonce_account((nonce_account_address, initialized))
        .check(Check::err(ProgramError::AccountAlreadyInitialized))
        .execute();
}

#[test]
fn initialize_writes_expected_state() {
    let nonce_account_address = Address::new_unique();
    let authority_address = Address::new_unique();
    let result = InitializeBuilder::default()
        .slot(42)
        .nonce_account(
            NonceAccountBuilder::new()
                .key(Address::from(&nonce_account_address))
                .build(),
        )
        .authority_address(Address::from(&authority_address))
        .execute();
    let state = decode_state(result.get_account(&nonce_account_address).unwrap());

    let slot_hash = init_mollusk().sysvars.slot_hashes.first().unwrap().hash;
    let program_id = spl_nonce_interface::id().to_bytes();
    let nonce_account_address = nonce_account_address.to_bytes();
    let slot_hash = slot_hash.to_bytes();
    assert_eq!(
        state.nonce,
        solana_sha256_hasher::hashv(&[
            NONCE_INIT_TAG,
            &program_id,
            &nonce_account_address,
            &slot_hash,
        ])
    );
    assert_eq!(state.authority, authority_address);
    assert_eq!(u64::from(state.initialize_slot), 42);
}

#[test]
fn create_account_creates_and_initializes_nonce_account() {
    let mollusk = init_mollusk();
    let payer_address = Address::new_unique();
    let nonce_account_address = Address::new_unique();
    let authority_address = Address::new_unique();
    let rent_lamports = mollusk.sysvars.rent.minimum_balance(Nonce::LEN);
    let expected_account = NonceAccountBuilder::new()
        .key(nonce_account_address)
        .lamports(rent_lamports)
        .initialized(
            authority_address,
            &mollusk.sysvars.slot_hashes.first().unwrap().hash,
            mollusk.sysvars.clock.slot,
        )
        .build()
        .1;

    mollusk.process_and_validate_transaction_instructions(
        &create_account(
            &payer_address,
            &nonce_account_address,
            &authority_address,
            rent_lamports,
        ),
        &[
            (
                payer_address,
                Account {
                    lamports: rent_lamports,
                    ..Account::default()
                },
            ),
            (nonce_account_address, Account::default()),
            (authority_address, Account::default()),
            mollusk.sysvars.keyed_account_for_slot_hashes_sysvar(),
        ],
        &[
            Check::success(),
            Check::account(&payer_address).lamports(0).build(),
            Check::account(&nonce_account_address)
                .owner(&expected_account.owner)
                .lamports(expected_account.lamports)
                .space(Nonce::LEN)
                .data(&expected_account.data)
                .build(),
        ],
        Some(&payer_address),
    );
}

#[test]
fn initialize_nonce_is_unique_per_nonce_account() {
    let first_nonce_account_address = Address::new_unique();
    let second_nonce_account_address = Address::new_unique();
    let first = InitializeBuilder::default()
        .nonce_account(
            NonceAccountBuilder::new()
                .key(Address::from(&first_nonce_account_address))
                .build(),
        )
        .execute();
    let first_state = decode_state(first.get_account(&first_nonce_account_address).unwrap());

    let second = InitializeBuilder::default()
        .nonce_account(
            NonceAccountBuilder::new()
                .key(Address::from(&second_nonce_account_address))
                .build(),
        )
        .execute();
    let second_state = decode_state(second.get_account(&second_nonce_account_address).unwrap());

    assert_eq!(first_state.authority, second_state.authority);
    assert_ne!(first_state.nonce, second_state.nonce);
}
