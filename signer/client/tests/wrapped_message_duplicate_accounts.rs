use {
    solana_address::Address,
    solana_instruction::{AccountMeta, Instruction},
    spl_ed25519_signer_client::message::wrapped_message,
    std::collections::BTreeSet,
    test_case::test_case,
};

#[test]
fn repeated_account_preserves_writable_privilege_and_instruction_positions() {
    let authority = Address::new_from_array([1; 32]);
    let program_id = Address::new_from_array([2; 32]);
    let shared_account = Address::new_from_array([3; 32]);
    let instruction = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(shared_account, false),
            AccountMeta::new_readonly(shared_account, false),
        ],
        data: vec![],
    };

    let message = wrapped_message(&instruction, &[authority]);
    message.sanitize().unwrap();
    let compiled = &message.instructions()[0];

    // Both instruction positions must survive, referencing the same account key.
    assert_eq!(compiled.accounts.len(), 2);
    assert_eq!(compiled.accounts[0], compiled.accounts[1]);
    let index = usize::from(compiled.accounts[0]);
    assert_eq!(message.static_account_keys()[index], shared_account);
    assert!(
        message.is_maybe_writable_with_reserved_addresses(index, None::<&BTreeSet<Address>>),
        "a readonly occurrence must not erase another occurrence's writable privilege"
    );
    assert_eq!(
        message
            .static_account_keys()
            .iter()
            .filter(|key| **key == shared_account)
            .count(),
        1,
        "repeated instruction accounts should share one message account-key entry"
    );
}

#[test_case([true, false]; "writable then readonly")]
#[test_case([false, true]; "readonly then writable")]
#[test_case([true, true]; "both writable")]
#[test_case([false, false]; "both readonly")]
fn duplicate_privileges_are_merged_in_either_order(privileges: [bool; 2]) {
    let authority = Address::new_from_array([1; 32]);
    let program_id = Address::new_from_array([2; 32]);
    let shared = Address::new_from_array([3; 32]);
    let other = Address::new_from_array([4; 32]);

    let instruction = Instruction {
        program_id,
        accounts: vec![
            AccountMeta {
                pubkey: shared,
                is_signer: true,
                is_writable: privileges[0],
            },
            AccountMeta::new(other, false),
            AccountMeta {
                pubkey: shared,
                is_signer: false,
                is_writable: privileges[1],
            },
        ],
        data: vec![7, 8],
    };
    let message = wrapped_message(&instruction, &[authority]);
    message.sanitize().unwrap();
    let compiled = &message.instructions()[0];
    assert_eq!(compiled.accounts.len(), 3);
    assert_eq!(compiled.accounts[0], compiled.accounts[2]);
    assert_eq!(
        message.static_account_keys()[usize::from(compiled.accounts[1])],
        other
    );
    assert_eq!(compiled.data, instruction.data);
    assert_eq!(message.static_account_keys().len(), 4);
    let index = usize::from(compiled.accounts[0]);
    assert_eq!(message.static_account_keys()[index], shared);
    assert!(
        !message.is_signer(index),
        "input signer flags must not grant outer signer privilege"
    );
    let should_be_writable = privileges.into_iter().any(|writable| writable);
    assert_eq!(
        message.is_maybe_writable_with_reserved_addresses(index, None::<&BTreeSet<Address>>),
        should_be_writable,
    );
}

#[test]
fn authority_and_program_references_reuse_existing_account_keys() {
    let readonly_authority = Address::new_from_array([1; 32]);
    let writable_authority = Address::new_from_array([2; 32]);
    let program_id = Address::new_from_array([3; 32]);
    let instruction = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new_readonly(writable_authority, false),
            AccountMeta::new_readonly(program_id, true),
            AccountMeta::new_readonly(readonly_authority, false),
            AccountMeta::new(writable_authority, false),
            AccountMeta::new(program_id, true),
        ],
        data: vec![],
    };
    let message = wrapped_message(&instruction, &[readonly_authority, writable_authority]);
    message.sanitize().unwrap();
    assert_eq!(
        message.static_account_keys(),
        &[writable_authority, readonly_authority, program_id]
    );
    assert_eq!(message.instructions()[0].accounts, [0, 2, 1, 0, 2]);
    assert_eq!(message.instructions()[0].program_id_index, 2);
    assert_eq!(message.header().num_required_signatures, 2);
    assert_eq!(message.header().num_readonly_signed_accounts, 1);
    assert_eq!(message.header().num_readonly_unsigned_accounts, 1);
    assert!(message.is_signer(0));
    assert!(message.is_signer(1));
    assert!(!message.is_signer(2));
}

#[test]
fn unaffected_message_without_authority_writes_preserves_serialized_bytes() {
    use {
        solana_hash::Hash,
        solana_message::{
            MessageHeader, VersionedMessage, compiled_instruction::CompiledInstruction, v1,
        },
    };

    // Deliberately use non-sorted keys and interleave privilege groups.
    let [
        first_authority,
        second_authority,
        program_id,
        writable1,
        writable2,
        readonly1,
        readonly2,
    ] = [9, 8, 7, 6, 5, 4, 3].map(|byte| Address::new_from_array([byte; 32]));
    let instruction = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new_readonly(readonly1, true),
            AccountMeta::new(writable1, true),
            AccountMeta::new_readonly(readonly2, false),
            AccountMeta::new(writable2, false),
        ],
        data: vec![11, 12],
    };
    // With no authority writes, the first authority is the writable fee-payer placeholder.
    let expected = VersionedMessage::V1(v1::Message::new(
        MessageHeader {
            num_required_signatures: 2,
            num_readonly_signed_accounts: 1,
            num_readonly_unsigned_accounts: 3,
        },
        v1::TransactionConfig::default(),
        Hash::default(),
        vec![
            first_authority,
            second_authority,
            writable1,
            writable2,
            program_id,
            readonly1,
            readonly2,
        ],
        vec![CompiledInstruction {
            program_id_index: 4,
            accounts: vec![5, 2, 6, 3],
            data: vec![11, 12],
        }],
    ));
    let actual = wrapped_message(&instruction, &[first_authority, second_authority]);
    actual.sanitize().unwrap();
    assert_eq!(actual.serialize(), expected.serialize());
}

#[test]
fn unaffected_message_with_authority_writes_preserves_serialized_bytes() {
    use {
        solana_hash::Hash,
        solana_message::{
            MessageHeader, VersionedMessage, compiled_instruction::CompiledInstruction, v1,
        },
    };

    // Deliberately use non-sorted keys and interleave privilege groups.
    let [
        first_authority,
        second_authority,
        program_id,
        writable1,
        writable2,
        readonly1,
        readonly2,
    ] = [9, 8, 7, 6, 5, 4, 3].map(|byte| Address::new_from_array([byte; 32]));
    let instruction = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new_readonly(readonly1, true),
            AccountMeta::new(writable1, true),
            AccountMeta::new_readonly(readonly2, false),
            AccountMeta::new(writable2, false),
            AccountMeta::new(second_authority, false),
        ],
        data: vec![11, 12],
    };
    // The written authority moves ahead of the readonly authority.
    let expected = VersionedMessage::V1(v1::Message::new(
        MessageHeader {
            num_required_signatures: 2,
            num_readonly_signed_accounts: 1,
            num_readonly_unsigned_accounts: 3,
        },
        v1::TransactionConfig::default(),
        Hash::default(),
        vec![
            second_authority,
            first_authority,
            writable1,
            writable2,
            program_id,
            readonly1,
            readonly2,
        ],
        vec![CompiledInstruction {
            program_id_index: 4,
            accounts: vec![5, 2, 6, 3, 0],
            data: vec![11, 12],
        }],
    ));
    let actual = wrapped_message(&instruction, &[first_authority, second_authority]);
    actual.sanitize().unwrap();
    assert_eq!(actual.serialize(), expected.serialize());
}

#[test]
fn interleaved_duplicates_recompile_all_indices_and_preserve_privilege_order() {
    // Non-sorted addresses ensure sorting cannot accidentally satisfy the ordering checks.
    let [
        authority,
        program_id,
        mixed1,
        mixed2,
        writable,
        readonly1,
        readonly2,
    ] = [9, 8, 7, 6, 5, 4, 3].map(|byte| Address::new_from_array([byte; 32]));
    let instruction = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new_readonly(mixed1, false),
            AccountMeta::new_readonly(readonly1, false),
            AccountMeta::new(mixed2, false),
            AccountMeta::new(writable, false),
            AccountMeta::new_readonly(mixed2, false),
            AccountMeta::new_readonly(readonly2, false),
            AccountMeta::new(mixed1, false),
            AccountMeta::new_readonly(readonly1, false),
            AccountMeta::new(writable, false),
            AccountMeta::new_readonly(mixed1, false),
            AccountMeta::new_readonly(readonly2, false),
            AccountMeta::new(mixed2, false),
        ],
        data: vec![42],
    };
    let message = wrapped_message(&instruction, &[authority]);
    message.sanitize().unwrap();

    // Writable keys retain first-writable-occurrence order, including a key first seen readonly.
    // Surviving readonly keys retain their relative order after overlapping keys are removed.
    let keys = message.static_account_keys();
    assert_eq!(
        keys,
        &[
            authority, mixed2, writable, mixed1, program_id, readonly1, readonly2
        ]
    );
    assert_eq!(keys.iter().collect::<BTreeSet<_>>().len(), keys.len());
    assert_eq!(message.header().num_required_signatures, 1);
    assert_eq!(message.header().num_readonly_signed_accounts, 0);
    assert_eq!(message.header().num_readonly_unsigned_accounts, 3);

    let compiled = &message.instructions()[0];
    assert_eq!(compiled.program_id_index, 4);
    assert_eq!(keys[usize::from(compiled.program_id_index)], program_id);
    assert_eq!(compiled.accounts, [3, 5, 1, 2, 1, 6, 3, 5, 2, 3, 6, 1]);
    assert_eq!(compiled.data, instruction.data);
    // Check every original position against the final key table, including the later readonly
    // occurrences and accounts shifted by removal of preceding duplicate entries.
    for (index, meta) in compiled.accounts.iter().zip(&instruction.accounts) {
        assert_eq!(keys[usize::from(*index)], meta.pubkey);
    }
    for index in 0..keys.len() {
        assert_eq!(message.is_signer(index), index == 0);
        assert_eq!(
            message.is_maybe_writable_with_reserved_addresses(index, None::<&BTreeSet<Address>>),
            index < 4,
        );
    }
}
