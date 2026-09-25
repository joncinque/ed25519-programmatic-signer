use {
    crate::helpers::{
        common::init_mollusk,
        stub_executor,
        submit_builder::{DEFAULT_TRANSFER_LAMPORTS, SubmitBuilder, funded_account},
    },
    mollusk_svm::result::Check,
    solana_account::Account,
    solana_address::Address,
    solana_hash::Hash,
    solana_instruction::{AccountMeta, error::InstructionError},
    solana_keypair::Keypair,
    solana_message::{
        MessageHeader, VersionedMessage, compiled_instruction::CompiledInstruction,
        legacy::Message, v0, v1,
    },
    solana_program_error::ProgramError,
    solana_signer::Signer as _,
    solana_system_interface::instruction::{create_account, transfer},
    solana_transaction::versioned::VersionedTransaction,
    spl_ed25519_signer_client::{instruction::submit, signing::sign_and_submit},
    spl_ed25519_signer_interface::{error::Error, pda::ProgrammaticSigner},
    test_case::test_case,
};

pub mod helpers;

#[test]
fn submit_rejects_no_required_signatures() {
    let ix = submit(vec![], VersionedMessage::Legacy(Message::default()));

    init_mollusk().process_and_validate_instruction(
        &ix,
        &[],
        &[Check::err(Error::InvalidWrappedMessage.into())],
    );
}

#[test_case(|tx| tx.signatures.clear(); "missing")]
#[test_case(|tx| tx.signatures.push(Keypair::new().sign_message(&[0])); "extra")]
fn submit_rejects_mismatched_signature_count(mutation: fn(&mut VersionedTransaction)) {
    SubmitBuilder::default_transfer()
        .tamper_transaction(mutation)
        .check_err(Error::InvalidSignatureCount)
        .execute();
}

#[test_case(|msg| msg.instructions[0].program_id_index = u8::MAX; "program index")]
#[test_case(|msg| msg.instructions[0].accounts[0] = u8::MAX; "executor account index")]
fn submit_rejects_out_of_bounds_instruction_index(mutation: fn(&mut Message)) {
    SubmitBuilder::default_transfer()
        .mutate_message(mutation)
        .check_err(Error::InvalidWrappedMessage)
        .execute();
}

#[test_case(|msg| msg.instructions.clear(); "none")]
#[test_case(|msg| msg.instructions.push(msg.instructions[0].clone()); "multiple")]
fn submit_rejects_wrong_executor_instruction_count(mutation: fn(&mut Message)) {
    SubmitBuilder::default_transfer()
        .mutate_message(mutation)
        .check_err(Error::InvalidExecutorInstructionCount)
        .execute();
}

#[test]
fn submit_rejects_missing_accounts() {
    SubmitBuilder::default_transfer()
        .mutate_submit_ix(|ix| {
            ix.accounts.pop();
        })
        .check_err(ProgramError::NotEnoughAccountKeys)
        .execute();
}

#[test]
fn submit_rejects_extra_accounts() {
    SubmitBuilder::default_transfer()
        .mutate_submit_ix(|ix| {
            ix.accounts
                .push(AccountMeta::new_readonly(Address::new_unique(), false));
        })
        .check_err(Error::AccountKeyMismatch)
        .execute();
}

#[test]
fn submit_rejects_account_key_mismatch() {
    SubmitBuilder::default_transfer()
        .mutate_submit_ix(|ix| {
            ix.accounts[1].pubkey = Address::new_unique();
        })
        .check_err(Error::AccountKeyMismatch)
        .execute();
}

// Any post-signing change to the signed message must fail signature verification
#[test_case(|msg| *msg.account_keys.last_mut().unwrap() = Address::new_unique(); "account key")]
#[test_case(|msg| msg.recent_blockhash = Hash::new_from_array([99; 32]); "recent blockhash")]
#[test_case(|msg| msg.instructions[0].accounts[1] = msg.instructions[0].accounts[0]; "executor account index")]
#[test_case(|msg| msg.instructions[0].data[1] ^= 1; "executor instruction data")]
fn submit_rejects_post_sign_message_change(post_sign_change: fn(&mut Message)) {
    SubmitBuilder::default_transfer()
        .tamper_message(post_sign_change)
        .check_err(Error::InvalidSignature)
        .execute();
}

#[test]
fn submit_rejects_wrong_authority_signature() {
    let wrong_authority = Keypair::new();
    SubmitBuilder::default_transfer()
        .tamper_transaction(move |transaction| {
            transaction.signatures[0] =
                wrong_authority.sign_message(&transaction.message.serialize());
        })
        .check_err(Error::InvalidSignature)
        .execute();
}

#[test]
fn submit_verifies_every_signature() {
    // The first signature is valid but the second slot is signed by the wrong key,
    // which fails the whole submit.
    let wrong_authority = Keypair::new();
    SubmitBuilder::default_transfer()
        .additional_authority(Keypair::new())
        .tamper_transaction(move |transaction| {
            transaction.signatures[1] =
                wrong_authority.sign_message(&transaction.message.serialize());
        })
        .check_err(Error::InvalidSignature)
        .execute();
}

#[test]
fn submit_rejects_v0_loaded_executor_account_index() {
    // The executor instruction references an account index in the lookup-table range,
    // which the program never resolves.
    let authority = Keypair::new();
    let message = VersionedMessage::V0(v0::Message {
        header: MessageHeader {
            num_required_signatures: 1,
            num_readonly_signed_accounts: 0,
            num_readonly_unsigned_accounts: 0,
        },
        account_keys: vec![authority.pubkey(), spl_message_executor_interface::id()],
        recent_blockhash: Hash::default(),
        instructions: vec![CompiledInstruction::new_from_raw_parts(1, vec![0], vec![2])],
        address_table_lookups: vec![v0::MessageAddressTableLookup {
            account_key: Address::new_unique(),
            writable_indexes: vec![],
            readonly_indexes: vec![0],
        }],
    });

    SubmitBuilder::default_transfer_with_authority(authority)
        .message(message)
        .check_err(Error::InvalidExecutorAccountIndex)
        .execute();
}

#[test]
fn submit_rejects_disallowed_executor_program() {
    let fake_executor = Address::new_unique();
    SubmitBuilder::default_transfer()
        .mutate_executor_instruction(move |ix| {
            ix.program_id = fake_executor;
        })
        .check_err(Error::DisallowedExecutorInstruction)
        .execute();
}

#[test]
fn submit_rejects_disallowed_executor_instruction() {
    SubmitBuilder::default_transfer()
        .mutate_executor_instruction(|ix| {
            ix.data[0] = ix.data[0].wrapping_add(1);
        })
        .check_err(Error::DisallowedExecutorInstruction)
        .execute();
}

#[test]
fn submit_rejects_outer_writable_undergrant() {
    // The relayer demotes the promoted programmatic signer to readonly in the outer
    // accounts. The CPI still needs it writable, so the runtime blocks the escalation.
    let authority = Keypair::new();
    let programmatic_signer = ProgrammaticSigner::derive_address(
        &spl_ed25519_signer_interface::id(),
        &authority.pubkey(),
    );
    SubmitBuilder::default_transfer_with_authority(authority)
        .mutate_submit_ix(move |ix| {
            let writable_index = ix
                .accounts
                .iter()
                .position(|meta| meta.pubkey == programmatic_signer)
                .unwrap();
            ix.accounts[writable_index].is_writable = false;
        })
        .check(Check::instruction_err(
            InstructionError::PrivilegeEscalation,
        ))
        .execute();
}

#[test]
fn submit_does_not_promote_unrelated_accounts() {
    // The transfer spends from a PDA that belongs to no signing authority. The program
    // forwards it unsigned, so the system program rejects the transfer.
    let unrelated_authority = Keypair::new();
    let unrelated = ProgrammaticSigner::derive_address(
        &spl_ed25519_signer_interface::id(),
        &unrelated_authority.pubkey(),
    );
    let recipient = Address::new_unique();
    let mut executor_instruction = transfer(&unrelated, &recipient, DEFAULT_TRANSFER_LAMPORTS);
    executor_instruction.accounts[0].is_signer = false;

    SubmitBuilder::default_transfer()
        .recipient(recipient)
        .executor_instruction(executor_instruction)
        .account(unrelated, funded_account())
        .check_err(ProgramError::MissingRequiredSignature)
        .execute();
}

#[test]
fn submit_does_not_forward_unrequired_outer_signer_privilege() {
    // Outer signer privilege is forwarded only when the wrapped message also marks that
    // account as a required signer.
    let real_signer = Keypair::new();
    let real_signer_key = real_signer.pubkey();
    let recipient = Address::new_unique();
    let mut executor_instruction =
        transfer(&real_signer_key, &recipient, DEFAULT_TRANSFER_LAMPORTS);
    executor_instruction.accounts[0].is_signer = false;

    SubmitBuilder::default_transfer()
        .recipient(recipient)
        .executor_instruction(executor_instruction)
        .account(real_signer_key, funded_account())
        .mutate_submit_ix(move |ix| {
            let real_signer_index = ix
                .accounts
                .iter()
                .position(|meta| meta.pubkey == real_signer_key)
                .unwrap();
            ix.accounts[real_signer_index].is_signer = true;
        })
        .check_err(ProgramError::MissingRequiredSignature)
        .execute();
}

#[test]
fn submit_does_not_forward_outer_writable_overgrant() {
    // The signed message marks the recipient readonly. A relayer granting it writable in
    // the outer accounts must not leak that privilege into the CPI.
    let recipient = Address::new_unique();
    SubmitBuilder::default_transfer()
        .recipient(recipient)
        .mutate_message(|msg| {
            // The recipient is the last unsigned key, so adding one readonly unsigned account
            // marks it readonly in the signed message.
            msg.header.num_readonly_unsigned_accounts =
                msg.header.num_readonly_unsigned_accounts.saturating_add(1);
        })
        .mutate_submit_ix(move |ix| {
            let recipient_index = ix
                .accounts
                .iter()
                .position(|meta| meta.pubkey == recipient)
                .unwrap();
            ix.accounts[recipient_index].is_writable = true;
        })
        .check(Check::instruction_err(
            InstructionError::PrivilegeEscalation,
        ))
        .execute();
}

#[test]
fn submit_promotes_programmatic_signer() {
    let result = SubmitBuilder::default_transfer().execute();

    // Success comes from PDA promotion, not outer signer privilege
    let programmatic_signer_meta = result
        .instruction
        .accounts
        .iter()
        .find(|meta| meta.pubkey == result.programmatic_signer)
        .unwrap();
    assert!(!programmatic_signer_meta.is_signer);

    assert_eq!(
        result.account(&result.recipient).unwrap().lamports,
        DEFAULT_TRANSFER_LAMPORTS
    );
    assert_eq!(
        result
            .account(&result.programmatic_signer)
            .unwrap()
            .lamports,
        funded_account().lamports - DEFAULT_TRANSFER_LAMPORTS
    );
}

#[test]
fn submit_promotes_multiple_authorities() {
    // `create_account` needs both programmatic signers to sign, the funder and the new
    // account. Success proves both authorities were promoted in one submit.
    let first_authority = Keypair::new();
    let second_authority = Keypair::new();
    let first_programmatic_signer = ProgrammaticSigner::derive_address(
        &spl_ed25519_signer_interface::id(),
        &first_authority.pubkey(),
    );
    let second_programmatic_signer = ProgrammaticSigner::derive_address(
        &spl_ed25519_signer_interface::id(),
        &second_authority.pubkey(),
    );
    let executor_instruction = create_account(
        &first_programmatic_signer,
        &second_programmatic_signer,
        DEFAULT_TRANSFER_LAMPORTS,
        0,
        &solana_system_interface::program::id(),
    );

    let result = SubmitBuilder::default_transfer_with_authority(first_authority)
        .additional_authority(second_authority)
        .executor_instruction(executor_instruction)
        .execute();

    assert_eq!(
        result
            .account(&second_programmatic_signer)
            .unwrap()
            .lamports,
        DEFAULT_TRANSFER_LAMPORTS
    );
}

#[test]
fn submit_forwards_required_outer_signer_privilege() {
    // The authority signs the wrapped message and the outer transaction, so its signer
    // privilege forwards into the executor CPI.
    let authority = Keypair::new();
    let authority_key = authority.pubkey();
    let recipient = Address::new_unique();
    let executor_instruction = transfer(&authority_key, &recipient, DEFAULT_TRANSFER_LAMPORTS);

    let result = SubmitBuilder::default_transfer_with_authority(authority)
        .recipient(recipient)
        .executor_instruction(executor_instruction)
        .account(authority_key, funded_account())
        .mutate_submit_ix(move |ix| {
            let authority_index = ix
                .accounts
                .iter()
                .position(|meta| meta.pubkey == authority_key)
                .unwrap();
            // mollusk simulates an outer transaction signature with the account meta signer flag
            ix.accounts[authority_index].is_signer = true;
        })
        .execute();

    assert_eq!(
        result.account(&recipient).unwrap().lamports,
        DEFAULT_TRANSFER_LAMPORTS
    );
}

#[test]
fn submit_treats_recent_blockhash_as_signed_opaque_bytes() {
    let result = SubmitBuilder::default_transfer()
        .mutate_message(|msg| {
            msg.recent_blockhash = Hash::new_from_array([42; 32]); // not default blockhash
        })
        .execute();

    assert_eq!(
        result.account(&result.recipient).unwrap().lamports,
        DEFAULT_TRANSFER_LAMPORTS
    );
}

#[test]
fn submit_allows_authority_as_normal_executor_account() {
    let authority = Keypair::new();
    let authority_key = authority.pubkey();
    let result = SubmitBuilder::default_transfer_with_authority(authority)
        .recipient(authority_key)
        .execute();

    assert_eq!(
        result.account(&authority_key).unwrap().lamports,
        DEFAULT_TRANSFER_LAMPORTS
    );
}

#[test]
fn submit_allows_second_authority_key_as_writable_executor_account() {
    // The executor writes to the second authority, so the client must order it into the
    // header's writable-signer range.
    let first_authority = Keypair::new();
    let second_authority = Keypair::new();
    let second_authority_key = second_authority.pubkey();
    let result = SubmitBuilder::default_transfer_with_authority(first_authority)
        .additional_authority(second_authority)
        .recipient(second_authority_key)
        .execute();

    assert_eq!(
        result.account(&second_authority_key).unwrap().lamports,
        DEFAULT_TRANSFER_LAMPORTS
    );
}

#[test]
fn submit_allows_multiple_writable_authorities() {
    // The executor writes to both authorities, so both land in the writable-signer range.
    let first_authority = Keypair::new();
    let second_authority = Keypair::new();
    let first_authority_key = first_authority.pubkey();
    let second_authority_key = second_authority.pubkey();
    let executor_instruction = transfer(
        &second_authority_key,
        &first_authority_key,
        DEFAULT_TRANSFER_LAMPORTS,
    );

    let result = SubmitBuilder::default_transfer_with_authority(first_authority)
        .additional_authority(second_authority)
        .executor_instruction(executor_instruction)
        .account(second_authority_key, funded_account())
        .mutate_submit_ix(move |ix| {
            let second_authority_index = ix
                .accounts
                .iter()
                .position(|meta| meta.pubkey == second_authority_key)
                .unwrap();
            ix.accounts[second_authority_index].is_signer = true;
        })
        .execute();

    assert_eq!(
        result.account(&first_authority_key).unwrap().lamports,
        DEFAULT_TRANSFER_LAMPORTS
    );
}

#[test]
fn submit_accepts_static_legacy_message() {
    assert_static_message_executes(|header, account_keys, recent_blockhash, instructions| {
        VersionedMessage::Legacy(Message {
            header,
            account_keys,
            recent_blockhash,
            instructions,
        })
    });
}

#[test]
fn submit_accepts_static_v0_message() {
    assert_static_message_executes(|header, account_keys, recent_blockhash, instructions| {
        VersionedMessage::V0(v0::Message {
            header,
            account_keys,
            recent_blockhash,
            instructions,
            address_table_lookups: vec![],
        })
    });
}

#[test]
fn submit_accepts_static_v1_message() {
    assert_static_message_executes(|header, account_keys, recent_blockhash, instructions| {
        VersionedMessage::V1(v1::Message::new(
            header,
            v1::TransactionConfig::empty(),
            recent_blockhash,
            account_keys,
            instructions,
        ))
    });
}

fn assert_static_message_executes(
    build_message: impl FnOnce(
        MessageHeader,
        Vec<Address>,
        Hash,
        Vec<CompiledInstruction>,
    ) -> VersionedMessage,
) {
    let authority = Keypair::new();
    let programmatic_signer = ProgrammaticSigner::derive_address(
        &spl_ed25519_signer_interface::id(),
        &authority.pubkey(),
    );
    let recipient = Address::new_unique();
    let executor_instruction = stub_executor::wrap(transfer(
        &programmatic_signer,
        &recipient,
        DEFAULT_TRANSFER_LAMPORTS,
    ));
    let message = build_message(
        MessageHeader {
            num_required_signatures: 1,
            num_readonly_signed_accounts: 0,
            num_readonly_unsigned_accounts: 2,
        },
        vec![
            authority.pubkey(),
            programmatic_signer,
            recipient,
            spl_message_executor_interface::id(),
            solana_system_interface::program::id(),
        ],
        Hash::default(),
        vec![CompiledInstruction::new_from_raw_parts(
            3,
            executor_instruction.data,
            vec![1, 2, 4],
        )],
    );

    let result = SubmitBuilder::default_transfer_with_authority(authority)
        .message(message)
        .execute();

    assert_eq!(
        result.account(&recipient).unwrap().lamports,
        DEFAULT_TRANSFER_LAMPORTS
    );
}

#[test]
fn submit_accepts_v0_unused_address_table_lookups() {
    let authority = Keypair::new();
    let programmatic_signer = ProgrammaticSigner::derive_address(
        &spl_ed25519_signer_interface::id(),
        &authority.pubkey(),
    );
    let recipient = Address::new_unique();
    let executor_instruction = stub_executor::wrap(transfer(
        &programmatic_signer,
        &recipient,
        DEFAULT_TRANSFER_LAMPORTS,
    ));
    let message = VersionedMessage::V0(v0::Message {
        header: MessageHeader {
            num_required_signatures: 1,
            num_readonly_signed_accounts: 0,
            num_readonly_unsigned_accounts: 2,
        },
        account_keys: vec![
            authority.pubkey(),
            programmatic_signer,
            recipient,
            spl_message_executor_interface::id(),
            solana_system_interface::program::id(),
        ],
        recent_blockhash: Hash::default(),
        instructions: vec![CompiledInstruction::new_from_raw_parts(
            3,
            executor_instruction.data,
            vec![1, 2, 4],
        )],
        // Unused lookups are allowed if executor account indexes still resolve to static keys
        address_table_lookups: vec![v0::MessageAddressTableLookup {
            account_key: Address::new_unique(),
            writable_indexes: vec![],
            readonly_indexes: vec![0],
        }],
    });

    let result = SubmitBuilder::default_transfer_with_authority(authority)
        .message(message)
        .execute();

    assert_eq!(
        result.account(&recipient).unwrap().lamports,
        DEFAULT_TRANSFER_LAMPORTS
    );
}

#[test]
fn sign_and_submit_builds_and_executes() {
    let authority = Keypair::new();
    let programmatic_signer = ProgrammaticSigner::derive_address(
        &spl_ed25519_signer_interface::id(),
        &authority.pubkey(),
    );
    let recipient = Address::new_unique();
    let executor_instruction = stub_executor::wrap(transfer(
        &programmatic_signer,
        &recipient,
        DEFAULT_TRANSFER_LAMPORTS,
    ));
    let ix = sign_and_submit(&executor_instruction, &[&authority]).unwrap();

    let result = init_mollusk().process_and_validate_instruction(
        &ix,
        &[
            (authority.pubkey(), Account::default()),
            mollusk_svm::program::keyed_account_for_system_program(),
            (programmatic_signer, funded_account()),
            (recipient, Account::default()),
            stub_executor::keyed_account(),
        ],
        &[Check::success()],
    );

    assert_eq!(
        result.get_account(&recipient).unwrap().lamports,
        DEFAULT_TRANSFER_LAMPORTS
    );
}
