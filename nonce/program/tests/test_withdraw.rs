use {
    crate::helpers::{
        advance_builder::AdvanceBuilder,
        common::{init_mollusk, initialize_nonce_account},
        nonce_account_builder::NonceAccountBuilder,
        withdraw_builder::WithdrawBuilder,
    },
    mollusk_svm::result::Check,
    solana_account::Account,
    solana_address::Address,
    solana_hash::Hash,
    solana_program_error::ProgramError,
    solana_rent::Rent,
    spl_nonce_interface::{error::Error, state::Nonce},
    test_case::test_case,
};

pub mod helpers;

#[test_case(0; "no accounts")]
#[test_case(1; "authority only")]
#[test_case(2; "missing destination")]
fn withdraw_rejects_missing_accounts(count: usize) {
    WithdrawBuilder::default()
        .account_count(count)
        .check(Check::err(ProgramError::NotEnoughAccountKeys))
        .execute();
}

#[test]
fn withdraw_rejects_wrong_owner() {
    WithdrawBuilder::default()
        .initialization_slot(42)
        .nonce_account(
            NonceAccountBuilder::new()
                .owner(Address::new_unique())
                .build(),
        )
        .check(Check::err(ProgramError::IllegalOwner))
        .execute();
}

#[test]
fn withdraw_rejects_self_destination() {
    WithdrawBuilder::default()
        .destination_is_nonce()
        .check(Check::err(ProgramError::InvalidArgument))
        .execute();
}

#[test_case(Nonce::LEN; "zeroed")]
#[test_case(Nonce::LEN - 1; "too short")]
#[test_case(Nonce::LEN + 1; "too long")]
#[test_case(0; "empty")]
fn uninitialized_withdraw_rejects_authority_other_than_nonce_account(len: usize) {
    WithdrawBuilder::default()
        .nonce_account(NonceAccountBuilder::new().data(vec![0; len]).build())
        .check(Check::err(Error::InvalidNonceAccount.into()))
        .execute();
}

#[test]
fn uninitialized_withdraw_requires_nonce_account_signature() {
    let (nonce_address, nonce_account) = NonceAccountBuilder::new().build();
    WithdrawBuilder::default()
        .nonce_account((nonce_address, nonce_account))
        .withdraw_authority(nonce_address)
        .authority_not_signer()
        .withdraw_all()
        .check(Check::err(ProgramError::MissingRequiredSignature))
        .execute();
}

#[test]
fn initialized_withdraw_rejects_nonce_account_signature() {
    let authority = Address::from([2; 32]);
    let (nonce_address, nonce_account) = initialize_nonce_account(&init_mollusk(), &authority);
    WithdrawBuilder::default()
        .nonce_account((nonce_address, nonce_account))
        .withdraw_authority(nonce_address)
        .withdrawal_slot(1)
        .withdraw_all()
        .check(Check::err(Error::AuthorityMismatch.into()))
        .execute();
}

#[test_case(Nonce::LEN; "zeroed")]
#[test_case(Nonce::LEN - 1; "too short")]
#[test_case(Nonce::LEN + 1; "too long")]
#[test_case(0; "empty")]
fn uninitialized_full_withdraw_closes_account_in_same_slot(len: usize) {
    let (nonce_address, nonce_account) = NonceAccountBuilder::new().data(vec![0; len]).build();
    let balance = nonce_account.lamports;
    let destination = Address::new_unique();
    WithdrawBuilder::default()
        .nonce_account((nonce_address, nonce_account))
        .withdraw_authority(nonce_address)
        .destination_account((
            destination,
            Account {
                lamports: 1_000_000,
                ..Account::default()
            },
        ))
        .withdraw_all()
        .check(Check::success())
        .check(Check::account(&nonce_address).closed().build())
        .check(
            Check::account(&destination)
                .lamports(balance.checked_add(1_000_000).unwrap())
                .build(),
        )
        .execute();
}

#[test_case(Nonce::LEN - 1; "too short")]
#[test_case(Nonce::LEN + 1; "too long")]
fn uninitialized_partial_withdraw_uses_actual_size_for_rent(len: usize) {
    let rent_minimum = Rent::default().minimum_balance(len);
    let (nonce_address, nonce_account) = NonceAccountBuilder::new()
        .data(vec![0; len])
        .lamports(rent_minimum.checked_add(100).unwrap())
        .build();

    WithdrawBuilder::default()
        .nonce_account((nonce_address, nonce_account.clone()))
        .withdraw_authority(nonce_address)
        .amount(100)
        .check(Check::success())
        .check(
            Check::account(&nonce_address)
                .lamports(rent_minimum)
                .build(),
        )
        .execute();
    WithdrawBuilder::default()
        .nonce_account((nonce_address, nonce_account))
        .withdraw_authority(nonce_address)
        .amount(101)
        .check(Check::err(ProgramError::AccountNotRentExempt))
        .execute();
}

#[test]
fn withdraw_rejects_wrong_authority() {
    WithdrawBuilder::default()
        .initialization_slot(42)
        .withdraw_authority(Address::new_unique())
        .check(Check::err(Error::AuthorityMismatch.into()))
        .execute();
}

#[test_case(false; "partial")]
#[test_case(true; "full")]
fn withdraw_requires_authority_signature(full: bool) {
    let builder = WithdrawBuilder::default()
        .initialization_slot(42)
        .excess_lamports(100)
        .withdrawal_slot(43)
        .authority_not_signer()
        .check(Check::err(ProgramError::MissingRequiredSignature));

    if full {
        builder.withdraw_all()
    } else {
        builder.amount(100)
    }
    .execute();
}

#[test]
fn withdraw_rejects_overdraw() {
    let amount = Rent::default()
        .minimum_balance(Nonce::LEN)
        .checked_add(100)
        .unwrap()
        .checked_add(1)
        .unwrap();
    WithdrawBuilder::default()
        .excess_lamports(100)
        .amount(amount)
        .check(Check::err(ProgramError::InsufficientFunds))
        .execute();
}

#[test_case(41; "earlier slot")]
#[test_case(42; "initialization slot")]
fn close_rejects_slot_not_after_initialization(slot: u64) {
    WithdrawBuilder::default()
        .initialization_slot(42)
        .withdrawal_slot(slot)
        .withdraw_all()
        .check(Check::err(Error::CloseSameSlot.into()))
        .execute();
}

#[test]
fn advance_does_not_bypass_same_slot_close_guard() {
    let nonce_address = Address::new_unique();
    let advanced = AdvanceBuilder::default()
        .nonce_address(nonce_address)
        .initialization_slot(42)
        .excess_lamports(100)
        .transition_commitment(Hash::default())
        .execute();
    WithdrawBuilder::default()
        .nonce_account((
            nonce_address,
            advanced.get_account(&nonce_address).unwrap().clone(),
        ))
        .withdrawal_slot(42)
        .withdraw_all()
        .check(Check::err(Error::CloseSameSlot.into()))
        .execute();
}

#[test_case(101; "one below rent minimum")]
#[test_case(
    Rent::default().minimum_balance(Nonce::LEN).checked_add(99).unwrap();
    "one lamport remaining"
)]
fn withdraw_rejects_balance_below_rent_minimum(amount: u64) {
    WithdrawBuilder::default()
        .excess_lamports(100)
        .amount(amount)
        .check(Check::err(ProgramError::AccountNotRentExempt))
        .execute();
}

#[test]
fn withdraw_rejects_destination_overflow() {
    WithdrawBuilder::default()
        .initialization_slot(42)
        .destination_account((
            Address::new_unique(),
            Account {
                lamports: u64::MAX,
                ..Account::default()
            },
        ))
        .check(Check::err(ProgramError::ArithmeticOverflow))
        .execute();
}

#[test]
fn full_withdraw_closes_account_in_later_slot() {
    let nonce_address = Address::new_unique();
    let balance = Rent::default()
        .minimum_balance(Nonce::LEN)
        .checked_add(100)
        .unwrap();
    let destination = Address::new_unique();
    WithdrawBuilder::default()
        .nonce_address(nonce_address)
        .initialization_slot(42)
        .excess_lamports(100)
        .destination_account((
            destination,
            Account {
                lamports: 1_000_000,
                ..Account::default()
            },
        ))
        .withdrawal_slot(43)
        .withdraw_all()
        .check(Check::success())
        .check(Check::account(&nonce_address).closed().build())
        .check(
            Check::account(&destination)
                .lamports(balance.checked_add(1_000_000).unwrap())
                .build(),
        )
        .execute();
}

#[test_case(0; "zero")]
#[test_case(99; "above rent minimum")]
#[test_case(100; "exact rent minimum")]
fn partial_withdraw_preserves_state_in_initialization_slot(amount: u64) {
    let authority = Address::from([2; 32]);
    let mut mollusk = init_mollusk();
    mollusk.sysvars.clock.slot = 42;
    let (nonce_address, mut original) = initialize_nonce_account(&mollusk, &authority);
    original.lamports = original.lamports.checked_add(100).unwrap();
    let destination = Address::new_unique();
    WithdrawBuilder::default()
        .nonce_account((nonce_address, original.clone()))
        .destination_account((
            destination,
            Account {
                lamports: 1_000_000,
                ..Account::default()
            },
        ))
        .amount(amount)
        .withdrawal_slot(42)
        .check(Check::success())
        .check(
            Check::account(&nonce_address)
                .data(&original.data)
                .owner(&original.owner)
                .lamports(original.lamports.checked_sub(amount).unwrap())
                .build(),
        )
        .check(
            Check::account(&destination)
                .lamports(amount.checked_add(1_000_000).unwrap())
                .build(),
        )
        .execute();
}

#[test]
fn withdraw_to_authority_is_allowed() {
    let authority = Address::from([2; 32]);
    let amount = Rent::default().minimum_balance(0);
    WithdrawBuilder::default()
        .destination_is_authority()
        .excess_lamports(amount)
        .amount(amount)
        .check(Check::success())
        .check(Check::account(&authority).lamports(amount).build())
        .execute();
}
