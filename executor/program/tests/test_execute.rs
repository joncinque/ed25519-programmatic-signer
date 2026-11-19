extern crate alloc;

use {
    crate::helpers::{
        common::{
            decode_state, init_mollusk, initialize_nonce_account, rent_exempt_system_account,
        },
        execute_builder::{DEFAULT_AUTHORITY, ExecuteBuilder},
        nonce_account_builder::NonceAccountBuilder,
    },
    mollusk_svm::result::Check,
    solana_account::Account,
    solana_address::Address,
    solana_hash::Hash,
    solana_instruction::AccountMeta,
    solana_instruction_error::InstructionError,
    solana_message::{
        MessageHeader, VersionedMessage, compiled_instruction::CompiledInstruction, legacy, v0, v1,
    },
    solana_program_error::ProgramError,
    solana_system_interface::instruction::transfer,
    spl_message_executor_interface::{
        error::Error as MessageExecutorError,
        instruction::{Instruction as MessageExecutorInstruction, derive_transition_commitment},
        pda::TransitionSigner,
    },
    spl_nonce_client::instruction::advance,
    spl_nonce_interface::{error::Error as NonceError, state::Nonce},
    test_case::test_case,
};

pub mod helpers;

#[test]
fn execute_rejects_missing_fixed_accounts() {
    ExecuteBuilder::default()
        .mutate_execute_ix(|ix| ix.accounts.truncate(2))
        .check_err(ProgramError::NotEnoughAccountKeys)
        .execute();
}

#[test]
fn execute_requires_transition_signer_account() {
    ExecuteBuilder::default()
        .mutate_execute_ix(|ix| ix.accounts.truncate(3))
        .check_err(ProgramError::NotEnoughAccountKeys)
        .execute();
}

#[test]
fn execute_rejects_wrong_nonce_program_account() {
    let wrong_nonce_program = Address::new_unique();
    ExecuteBuilder::default()
        .mutate_execute_ix(move |ix| ix.accounts[2].pubkey = wrong_nonce_program)
        .check_err(ProgramError::IncorrectProgramId)
        .execute();
}

#[test]
fn execute_rejects_nonce_account_owned_by_another_program() {
    let (nonce_address, nonce_account) = NonceAccountBuilder::new()
        .owner(Address::new_unique())
        .build();

    ExecuteBuilder::default()
        .nonce_account(nonce_address, nonce_account)
        .check_err(ProgramError::IllegalOwner)
        .execute();
}

#[test]
fn execute_rejects_malformed_nonce_account() {
    // Program owned but with truncated data that cannot parse as nonce state
    let (nonce_address, nonce_account) = NonceAccountBuilder::new().data(vec![0; 1]).build();

    ExecuteBuilder::default()
        .nonce_account(nonce_address, nonce_account)
        .check_err(MessageExecutorError::InvalidNonceAccount)
        .execute();
}

#[test]
fn execute_cannot_manufacture_approval_when_authority_is_transition_signer() {
    let nonce_address = Address::new_unique();
    let transition_signer = TransitionSigner::ADDRESS;
    let nonce = Nonce {
        nonce: Hash::new_from_array([7; 32]),
        authority: transition_signer,
        initialize_slot: 0.into(),
    };
    let (_, nonce_account) = NonceAccountBuilder::new()
        .address(nonce_address)
        .data(wincode::serialize(&nonce).unwrap())
        .build();

    ExecuteBuilder::default()
        .authority(transition_signer)
        .payer(Address::new_unique())
        .nonce_account(nonce_address, nonce_account)
        .mutate_execute_ix(|ix| ix.accounts[0].is_signer = false)
        .check_err(ProgramError::MissingRequiredSignature)
        .execute();
}

#[test]
fn execute_rejects_wrong_transition_signer() {
    let authority = Address::new_unique();
    ExecuteBuilder::default()
        .authority(authority)
        .mutate_execute_ix(move |ix| {
            ix.accounts[3] = AccountMeta::new_readonly(authority, true);
        })
        .check_err(MessageExecutorError::InvalidTransitionSigner)
        .execute();
}

#[test]
fn execute_rejects_message_that_fails_sanitization() {
    ExecuteBuilder::default()
        .mutate_message(|message| {
            message.header.num_required_signatures = 2;
        })
        .check_err(MessageExecutorError::InvalidMessage)
        .execute();
}

#[test]
fn execute_rejects_duplicate_message_addresses() {
    ExecuteBuilder::default()
        .mutate_message(|message| {
            message.header.num_readonly_unsigned_accounts = 1;
            message.account_keys.push(DEFAULT_AUTHORITY);
        })
        .check_err(MessageExecutorError::InvalidMessage)
        .execute();
}

#[test_case(VersionedMessage::Legacy(legacy::Message::default()) ; "legacy")]
#[test_case(VersionedMessage::V0(v0::Message::default()) ; "v0")]
fn execute_rejects_non_v1_message(message: VersionedMessage) {
    ExecuteBuilder::default()
        .mutate_execute_ix(move |ix| {
            ix.data = wincode::serialize(&MessageExecutorInstruction::Execute(message)).unwrap();
        })
        .check_err(MessageExecutorError::UnsupportedMessageVersion)
        .execute();
}

#[test_case(v1::TransactionConfig::default().with_priority_fee(1) ; "priority fee")]
#[test_case(v1::TransactionConfig::default().with_compute_unit_limit(1) ; "compute unit limit")]
#[test_case(
    v1::TransactionConfig::default().with_loaded_accounts_data_size_limit(1)
    ; "loaded accounts data size limit"
)]
#[test_case(v1::TransactionConfig::default().with_heap_size(v1::MIN_HEAP_SIZE) ; "heap size")]
fn execute_rejects_transaction_config(config: v1::TransactionConfig) {
    ExecuteBuilder::default()
        .mutate_message(move |message| message.config = config)
        .check_err(MessageExecutorError::UnsupportedTransactionConfig)
        .execute();
}

#[test]
fn execute_rejects_recent_blockhash_mismatch() {
    ExecuteBuilder::default()
        .recent_blockhash(Hash::new_from_array([9; 32]))
        .check_err(MessageExecutorError::NonceMismatch)
        .execute();
}

#[test]
fn nonce_authority_cannot_unlock_successor_without_executing_predecessor() {
    let mollusk = init_mollusk();
    let (nonce_address, nonce_account) = initialize_nonce_account(&mollusk, &DEFAULT_AUTHORITY);
    let initial_state = decode_state(&nonce_account);
    let predecessor = v1::Message::try_compile_with_config(
        &DEFAULT_AUTHORITY,
        &[transfer(&DEFAULT_AUTHORITY, &Address::new_unique(), 1)],
        initial_state.nonce,
        v1::TransactionConfig::empty(),
    )
    .unwrap();
    let commitment = derive_transition_commitment(&VersionedMessage::V1(predecessor));
    let expected_successor = initial_state.derive_next_nonce(
        &spl_nonce_interface::id(),
        &nonce_address,
        &TransitionSigner::ADDRESS,
        &commitment,
    );
    let forged_step = advance(
        &DEFAULT_AUTHORITY,
        &DEFAULT_AUTHORITY,
        &nonce_address,
        initial_state.nonce,
        commitment,
    );
    let advanced = mollusk.process_and_validate_instruction(
        &forged_step,
        &[
            (DEFAULT_AUTHORITY, Account::default()),
            (nonce_address, nonce_account),
        ],
        &[Check::success()],
    );
    assert_ne!(
        decode_state(advanced.get_account(&nonce_address).unwrap()).nonce,
        expected_successor,
    );

    ExecuteBuilder::new(mollusk)
        .nonce_account(
            nonce_address,
            advanced.get_account(&nonce_address).unwrap().clone(),
        )
        .recent_blockhash(expected_successor)
        .check_err(MessageExecutorError::NonceMismatch)
        .execute();
}

#[test]
fn execute_rejects_message_reuse_after_nonce_advances() {
    let first = ExecuteBuilder::default().execute();

    ExecuteBuilder::default()
        .nonce_account(first.nonce_address, first.nonce_account)
        .message(first.message)
        .check_err(MessageExecutorError::NonceMismatch)
        .execute();
}

#[test]
fn execute_supports_precomputed_nonce_chain() {
    let mollusk = init_mollusk();
    let (nonce_address, nonce_account) = initialize_nonce_account(&mollusk, &DEFAULT_AUTHORITY);
    let initial_state = decode_state(&nonce_account);

    let first_recipient = Address::new_unique();
    let first_message = v1::Message::try_compile_with_config(
        &DEFAULT_AUTHORITY,
        &[transfer(&DEFAULT_AUTHORITY, &first_recipient, 1)],
        initial_state.nonce,
        v1::TransactionConfig::empty(),
    )
    .unwrap();
    let first_nonce = initial_state.derive_next_nonce(
        &spl_nonce_interface::id(),
        &nonce_address,
        &TransitionSigner::ADDRESS,
        &derive_transition_commitment(&VersionedMessage::V1(first_message.clone())),
    );

    let second_recipient = Address::new_unique();
    let second_message = v1::Message::try_compile_with_config(
        &DEFAULT_AUTHORITY,
        &[transfer(&DEFAULT_AUTHORITY, &second_recipient, 1)],
        first_nonce,
        v1::TransactionConfig::empty(),
    )
    .unwrap();
    let second_nonce = Nonce {
        nonce: first_nonce,
        authority: initial_state.authority,
        initialize_slot: initial_state.initialize_slot,
    }
    .derive_next_nonce(
        &spl_nonce_interface::id(),
        &nonce_address,
        &TransitionSigner::ADDRESS,
        &derive_transition_commitment(&VersionedMessage::V1(second_message.clone())),
    );

    let first = ExecuteBuilder::new(mollusk)
        .nonce_account(nonce_address, nonce_account)
        .message(first_message)
        .account(first_recipient, rent_exempt_system_account(0))
        .execute();
    assert_eq!(decode_state(&first.nonce_account).nonce, first_nonce);

    let second = ExecuteBuilder::default()
        .nonce_account(nonce_address, first.nonce_account)
        .message(second_message)
        .account(second_recipient, rent_exempt_system_account(0))
        .execute();
    assert_eq!(decode_state(&second.nonce_account).nonce, second_nonce);
}

#[test]
fn tampered_message_invalidates_precomputed_successor() {
    let mollusk = init_mollusk();
    let (nonce_address, nonce_account) = initialize_nonce_account(&mollusk, &DEFAULT_AUTHORITY);
    let initial_state = decode_state(&nonce_account);

    let planned_message = v1::Message::try_compile_with_config(
        &DEFAULT_AUTHORITY,
        &[transfer(&DEFAULT_AUTHORITY, &Address::new_unique(), 1)],
        initial_state.nonce,
        v1::TransactionConfig::empty(),
    )
    .unwrap();
    let planned_successor = initial_state.derive_next_nonce(
        &spl_nonce_interface::id(),
        &nonce_address,
        &TransitionSigner::ADDRESS,
        &derive_transition_commitment(&VersionedMessage::V1(planned_message.clone())),
    );

    let tampered_recipient = Address::new_unique();
    let tampered_message = v1::Message::try_compile_with_config(
        &DEFAULT_AUTHORITY,
        &[transfer(&DEFAULT_AUTHORITY, &tampered_recipient, 2)],
        initial_state.nonce,
        v1::TransactionConfig::empty(),
    )
    .unwrap();
    let tampered = ExecuteBuilder::new(mollusk)
        .nonce_account(nonce_address, nonce_account)
        .message(tampered_message)
        .account(tampered_recipient, rent_exempt_system_account(0))
        .execute();
    assert_ne!(
        decode_state(&tampered.nonce_account).nonce,
        planned_successor
    );

    ExecuteBuilder::default()
        .nonce_account(nonce_address, tampered.nonce_account)
        .recent_blockhash(planned_successor)
        .check_err(MessageExecutorError::NonceMismatch)
        .execute();
}

#[test]
fn execute_rejects_account_count_mismatch() {
    ExecuteBuilder::default()
        .mutate_execute_ix(|ix| {
            ix.accounts
                .push(AccountMeta::new_readonly(Address::new_unique(), false));
        })
        .check_err(MessageExecutorError::MessageAccountsMismatch)
        .execute();
}

#[test]
fn execute_rejects_account_order_mismatch() {
    ExecuteBuilder::default()
        .message_instruction(transfer(&DEFAULT_AUTHORITY, &Address::new_unique(), 1))
        .mutate_execute_ix(|ix| ix.accounts.swap(4, 5))
        .check_err(MessageExecutorError::MessageAccountsMismatch)
        .execute();
}

#[test]
fn execute_rejects_readonly_message_writable_account() {
    ExecuteBuilder::default()
        .message_instruction(transfer(&DEFAULT_AUTHORITY, &Address::new_unique(), 1))
        .mutate_execute_ix(|ix| ix.accounts[5].is_writable = false)
        .check(Check::instruction_err(
            InstructionError::PrivilegeEscalation,
        ))
        .execute();
}

#[test]
fn execute_rejects_missing_required_signer_privilege() {
    let payer = Address::new_unique();

    ExecuteBuilder::default()
        // Make it the 5th account (1st in the execution message accounts) and a signer on an instruction
        .payer(payer)
        .message_instruction(transfer(&payer, &Address::new_unique(), 0))
        .mutate_execute_ix(|ix| ix.accounts[4].is_signer = false)
        .check(Check::instruction_err(
            InstructionError::PrivilegeEscalation,
        ))
        .execute();
}

#[test]
fn execute_rejects_missing_nonce_authority_signer_privilege() {
    ExecuteBuilder::default()
        // Keep the message payer distinct so it cannot grant the authority signer privilege.
        .payer(Address::new_unique())
        .mutate_execute_ix(|ix| ix.accounts[0].is_signer = false)
        .check_err(ProgramError::MissingRequiredSignature)
        .execute();
}

#[test]
fn execute_rejects_wrong_nonce_authority() {
    let wrong_signer = Address::new_unique();
    let mut mollusk = init_mollusk();
    mollusk.logger = Some(std::rc::Rc::default());
    let logger = mollusk.logger.as_ref().unwrap().clone();

    ExecuteBuilder::new(mollusk)
        .mutate_execute_ix(move |ix| ix.accounts[0].pubkey = wrong_signer)
        .check_err(NonceError::AuthorityMismatch)
        .execute();

    // Both Nonce's AuthorityMismatch and Executor's InvalidMessage use `AuthorityMismatch`.
    // Check the logs so an unrelated Executor failure cannot make this test pass.
    let logs = logger.borrow();
    let nonce_program = spl_nonce_interface::ID;
    assert!(
        logs.get_recorded_content()
            .contains(&format!("Program {nonce_program} invoke [2]")),
    );
    assert!(logs.get_recorded_content().contains(&format!(
        "Program {nonce_program} failed: custom program error: 0x1"
    )));
}

#[test]
fn nonce_authority_cannot_forge_executor_transition_signature() {
    let mollusk = init_mollusk();
    let (nonce_address, nonce_account) = initialize_nonce_account(&mollusk, &DEFAULT_AUTHORITY);
    let old_nonce = decode_state(&nonce_account).nonce;
    let transition_signer = TransitionSigner::ADDRESS;
    let mut instruction = advance(
        &DEFAULT_AUTHORITY,
        &transition_signer,
        &nonce_address,
        old_nonce,
        Hash::default(),
    );
    instruction.accounts[1].is_signer = false;
    let result = mollusk.process_and_validate_instruction(
        &instruction,
        &[
            (DEFAULT_AUTHORITY, Account::default()),
            (nonce_address, nonce_account.clone()),
            (transition_signer, Account::default()),
        ],
        &[Check::err(ProgramError::MissingRequiredSignature)],
    );
    assert_eq!(result.get_account(&nonce_address), Some(&nonce_account));
}

#[test]
fn execute_rejects_readonly_nonce_account() {
    ExecuteBuilder::default()
        .mutate_execute_ix(|ix| ix.accounts[1].is_writable = false)
        .check(Check::instruction_err(
            InstructionError::PrivilegeEscalation,
        ))
        .execute();
}

#[test]
fn execute_rejects_uninitialized_nonce_account() {
    let (nonce_address, nonce_account) = NonceAccountBuilder::new().build();

    ExecuteBuilder::default()
        .authority(Address::default())
        .nonce_account(nonce_address, nonce_account)
        .check_err(NonceError::InvalidNonceAccount)
        .execute();
}

#[test]
fn execute_never_forwards_transition_signer_signature_to_payload() {
    let mollusk = init_mollusk();
    let (nonce_address, nonce_account) = initialize_nonce_account(&mollusk, &DEFAULT_AUTHORITY);
    let old_nonce = decode_state(&nonce_account).nonce;
    let transition_signer = TransitionSigner::ADDRESS;
    let result = ExecuteBuilder::new(mollusk)
        .nonce_account(nonce_address, nonce_account)
        .message_instruction(advance(
            &DEFAULT_AUTHORITY,
            &transition_signer,
            &nonce_address,
            old_nonce,
            Hash::default(),
        ))
        .mutate_execute_ix(move |ix| {
            // The transaction cannot sign for this PDA. Only the nonce CPI receives its privilege.
            for account in &mut ix.accounts {
                if account.pubkey == transition_signer {
                    account.is_signer = false;
                }
            }
        })
        .check(Check::instruction_err(
            InstructionError::PrivilegeEscalation,
        ))
        .execute();
    assert_eq!(decode_state(&result.nonce_account).nonce, old_nonce);
}

#[test]
fn execute_downgrades_extra_writable_privilege_for_message_cpi() {
    // Verifies extra writable privilege on the Execute instruction
    // does not leak into the execution message CPI
    let recipient = Address::new_unique();

    ExecuteBuilder::default()
        .message_instruction(transfer(&DEFAULT_AUTHORITY, &recipient, 1))
        .mutate_message(|message| {
            // makes the recipient readonly in the execution message
            message.header.num_readonly_unsigned_accounts = 2;
        })
        // gives recipient extra writable privilege on the Execute ix
        .mutate_execute_ix(|ix| ix.accounts[5].is_writable = true)
        .check(Check::instruction_err(
            InstructionError::ReadonlyLamportChange,
        ))
        .execute();
}

#[test]
fn execute_downgrades_extra_signer_privilege_for_message_cpi() {
    // Verifies extra signer privilege on the Execute instruction
    // does not leak into the execution message CPI
    let source = Address::new_unique();
    let recipient = Address::new_unique();

    ExecuteBuilder::default()
        .message_instruction(transfer(&source, &recipient, 1))
        .mutate_message(|message| {
            // makes the source a nonsigner in the execution message
            message.header.num_required_signatures = 1;
        })
        // gives source extra signer privilege on the Execute ix
        .mutate_execute_ix(|ix| ix.accounts[5].is_signer = true)
        .account(
            source,
            Account::empty(1, &solana_system_interface::program::id()),
        )
        .check_err(ProgramError::MissingRequiredSignature)
        .execute();
}

#[test]
fn execute_rolls_back_nonce_when_message_instruction_fails() {
    let recipient = Address::new_unique();

    let overdraft = 1_000_000_000;
    let result = ExecuteBuilder::default()
        .message_instruction(transfer(&DEFAULT_AUTHORITY, &recipient, overdraft))
        .check_err(ProgramError::Custom(1))
        .execute();

    assert_eq!(
        decode_state(&result.nonce_account).nonce,
        result.message.lifetime_specifier
    );
}

#[test]
fn execute_rejects_message_that_consumes_its_own_nonce() {
    let mollusk = init_mollusk();
    let (nonce_address, nonce_account) = initialize_nonce_account(&mollusk, &DEFAULT_AUTHORITY);
    let old_nonce = decode_state(&nonce_account).nonce;

    ExecuteBuilder::new(mollusk)
        .nonce_account(nonce_address, nonce_account)
        .message_instruction(advance(
            &DEFAULT_AUTHORITY,
            &DEFAULT_AUTHORITY,
            &nonce_address,
            old_nonce,
            Hash::default(),
        ))
        .check_err(NonceError::NonceMismatch)
        .execute();
}

#[test]
fn execute_accepts_nonce_authority_as_readonly_nonpayer_signer() {
    let payer = Address::new_unique();

    ExecuteBuilder::default()
        .mutate_message(move |message| {
            // Insert a writable payer before the authority,
            // making the authority the second, readonly signer
            message.header.num_required_signatures = 2;
            message.header.num_readonly_signed_accounts = 1;
            message.account_keys.insert(0, payer);
        })
        .execute();
}

#[test]
fn execute_accepts_static_v1_message() {
    let recipient = Address::new_unique();
    let transfer_lamports = 1_000_000;
    let mollusk = init_mollusk();
    let (nonce_address, nonce_account) = initialize_nonce_account(&mollusk, &DEFAULT_AUTHORITY);
    let old_nonce = decode_state(&nonce_account).nonce;
    let transfer_ix = transfer(&DEFAULT_AUTHORITY, &recipient, transfer_lamports);
    let message = v1::Message {
        header: MessageHeader {
            num_required_signatures: 1,
            num_readonly_signed_accounts: 0,
            num_readonly_unsigned_accounts: 1,
        },
        config: v1::TransactionConfig::default(),
        lifetime_specifier: old_nonce,
        account_keys: vec![
            DEFAULT_AUTHORITY,
            recipient,
            solana_system_interface::program::id(),
        ],
        instructions: vec![CompiledInstruction::new_from_raw_parts(
            2,
            transfer_ix.data,
            vec![0, 1],
        )],
    };

    let result = ExecuteBuilder::new(mollusk)
        .nonce_account(nonce_address, nonce_account)
        .message(message)
        .execute();

    assert_eq!(
        result.account(&recipient).unwrap().lamports,
        transfer_lamports
    );
    assert_ne!(decode_state(&result.nonce_account).nonce, old_nonce);
}

#[test]
fn execute_empty_message_advances_nonce() {
    // An empty message must still consume the nonce
    let mollusk = init_mollusk();
    let (nonce_address, nonce_account) = initialize_nonce_account(&mollusk, &DEFAULT_AUTHORITY);
    let old_nonce = decode_state(&nonce_account).nonce;

    let result = ExecuteBuilder::new(mollusk)
        .nonce_account(nonce_address, nonce_account)
        .execute();

    assert_ne!(decode_state(&result.nonce_account).nonce, old_nonce);
}

#[test]
fn execute_batches_instructions_from_multiple_signers() {
    let second_signer = Address::new_unique();
    let first_recipient = Address::new_unique();
    let second_recipient = Address::new_unique();

    let result = ExecuteBuilder::default()
        .message_instruction(transfer(&DEFAULT_AUTHORITY, &first_recipient, 100))
        .message_instruction(transfer(&second_signer, &second_recipient, 200))
        .account(first_recipient, rent_exempt_system_account(0))
        .account(second_recipient, rent_exempt_system_account(0))
        .account(
            second_signer,
            Account::empty(1_000_000, &solana_system_interface::program::id()),
        )
        .execute();

    assert_eq!(
        result.account(&first_recipient).unwrap().lamports,
        rent_exempt_system_account(100).lamports
    );
    assert_eq!(
        result.account(&second_recipient).unwrap().lamports,
        rent_exempt_system_account(200).lamports
    );
}

#[test]
fn execute_accepts_duplicate_instruction_account_indices() {
    let result = ExecuteBuilder::default()
        .message_instruction(transfer(&DEFAULT_AUTHORITY, &DEFAULT_AUTHORITY, 1))
        .execute();

    assert_eq!(result.message.instructions[0].accounts, [0, 0]);
}

#[test]
fn execute_accepts_nonce_authority_absent_from_message() {
    let source = Address::new_unique();
    let recipient = Address::new_unique();
    let result = ExecuteBuilder::default()
        .payer(source)
        .message_instruction(transfer(&source, &recipient, 1))
        .account(source, rent_exempt_system_account(10))
        .account(recipient, rent_exempt_system_account(0))
        .execute();
    assert!(!result.message.account_keys.contains(&DEFAULT_AUTHORITY));
    assert_eq!(
        result.account(&recipient).unwrap().lamports,
        rent_exempt_system_account(1).lamports
    );
    assert_ne!(
        decode_state(&result.nonce_account).nonce,
        result.message.lifetime_specifier
    );
}

#[test]
fn execute_accepts_nonce_authority_as_message_nonsigner() {
    let source = Address::new_unique();
    let result = ExecuteBuilder::default()
        .payer(source)
        .message_instruction(transfer(&source, &DEFAULT_AUTHORITY, 1))
        .account(source, rent_exempt_system_account(10))
        .execute();
    let authority_index = result
        .message
        .account_keys
        .iter()
        .position(|address| address == &DEFAULT_AUTHORITY)
        .unwrap();
    assert!(!result.message.is_signer(authority_index));
    assert_eq!(
        result.account(&DEFAULT_AUTHORITY).unwrap().lamports,
        100_000_001
    );
}

#[test]
fn execute_downgrades_nonce_authority_signer_privilege_for_message_cpi() {
    let recipient = Address::new_unique();
    let mut instruction = transfer(&DEFAULT_AUTHORITY, &recipient, 1);
    // The authority signs the Execute instruction, but not the transfer in the execution message.
    instruction.accounts[0].is_signer = false;

    ExecuteBuilder::default()
        .payer(Address::new_unique())
        .message_instruction(instruction)
        .check_err(ProgramError::MissingRequiredSignature)
        .execute();
}
