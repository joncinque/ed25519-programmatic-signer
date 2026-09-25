//! Verifies authority signatures over a wrapped message, then invokes its executor instruction
//! while signing for explicitly authorized programmatic signers.

use {
    crate::executor_policy,
    alloc::{collections::BTreeSet, vec::Vec},
    brine_ed25519::hasher::Sha512,
    pinocchio::{
        AccountView, Address, ProgramResult,
        cpi::{Seed, Signer, invoke_signed_with_slice},
        error::ProgramError,
        instruction::{InstructionAccount, InstructionView},
    },
    solana_message::{VersionedMessage, compiled_instruction::CompiledInstruction, v1},
    solana_signature::Signature,
    spl_ed25519_signer_interface::{error::Error, pda::ProgrammaticSigner},
};

/// A verified authority whose `ProgrammaticSigner` is referenced by the executor instruction.
struct AuthorizedSigner {
    authority: Address,
    programmatic_signer_index: usize,
    bump_seed: [u8; 1],
}

/// Processes the signatures and signed message, then executes its single executor instruction.
pub fn process_submit(
    program_id: &Address,
    accounts: &[AccountView],
    signatures: &[Signature],
    message: &VersionedMessage,
) -> ProgramResult {
    let VersionedMessage::V1(message) = message else {
        return Err(Error::UnsupportedMessageVersion.into());
    };

    // Validation also rejects duplicate account keys, so each key has one set of privileges.
    message
        .validate()
        .map_err(|_| Error::InvalidWrappedMessage)?;

    // The wrapped message is only an authorization envelope. Reject config fields so
    // authorities never approve fees or limits that have no effect.
    if message.config != v1::TransactionConfig::default() {
        return Err(Error::UnsupportedTransactionConfig.into());
    }

    // Exactly one executor instruction is expected
    let [executor_instruction] = message.instructions.as_slice() else {
        return Err(Error::InvalidExecutorInstructionCount.into());
    };

    let executor_instruction =
        CheckedExecutorInstruction::try_new(accounts, message, executor_instruction)?;

    let authorities = verify_authority_signatures(signatures, message)?;

    let authorized_signers =
        collect_authorized_signers(program_id, &executor_instruction, authorities);

    invoke_executor_instruction(message, &executor_instruction, &authorized_signers)
}

/// The executor instruction resolved against outer `Submit` accounts proven to mirror the
/// wrapped message's static account keys.
struct CheckedExecutorInstruction<'a> {
    program_id: &'a Address,
    accounts: Vec<ExecutorAccount<'a>>,
    data: &'a [u8],
}

/// An executor account resolved to its outer `Submit` account and its signed message index.
struct ExecutorAccount<'a> {
    account: &'a AccountView,
    index: usize,
}

impl<'a> CheckedExecutorInstruction<'a> {
    fn try_new(
        outer_accounts: &'a [AccountView],
        message: &'a v1::Message,
        executor_instruction: &'a CompiledInstruction,
    ) -> Result<Self, ProgramError> {
        let wrapped_account_keys = &message.account_keys;

        // The relayer must supply the wrapped message's account keys in signed order, so
        // executor account indexes resolve to the accounts the authorities signed.
        if outer_accounts.len() < wrapped_account_keys.len() {
            return Err(ProgramError::NotEnoughAccountKeys);
        }

        if outer_accounts.len() > wrapped_account_keys.len() {
            return Err(Error::AccountKeyMismatch.into());
        }

        for (outer_account, wrapped_key) in outer_accounts.iter().zip(wrapped_account_keys) {
            if outer_account.address() != wrapped_key {
                return Err(Error::AccountKeyMismatch.into());
            }
        }

        // The executor program is selected by the signed message, not by a separate `Submit`
        // account. Infallible: validation guarantees the index is within the account keys.
        let program_id = wrapped_account_keys
            .get(usize::from(executor_instruction.program_id_index))
            .unwrap();

        // Only allow trusted executor entrypoints to receive promoted signers.
        executor_policy::validate(program_id, &executor_instruction.data)?;

        // Infallible: validation guarantees every executor account index is within the account
        // keys, which the outer accounts mirror one-to-one.
        let accounts = executor_instruction
            .accounts
            .iter()
            .map(|account_index| {
                let index = usize::from(*account_index);
                let account = outer_accounts.get(index).unwrap();
                ExecutorAccount { account, index }
            })
            .collect();

        Ok(Self {
            program_id,
            accounts,
            data: &executor_instruction.data,
        })
    }
}

fn verify_authority_signatures<'a>(
    signatures: &[Signature],
    message: &'a v1::Message,
) -> Result<&'a [Address], ProgramError> {
    let required_signatures = usize::from(message.header.num_required_signatures);
    if signatures.len() != required_signatures {
        return Err(Error::InvalidSignatureCount.into());
    }

    // Required signers occupy the leading account key slots. Signatures use the same indexes.
    // Infallible: message validation guarantees an account key for every required signer.
    let authorities = message.account_keys.get(..required_signatures).unwrap();

    let message_bytes = message.serialize();

    // Verify each authority signed the wrapped transaction message
    for (authority, signature) in authorities.iter().zip(signatures) {
        brine_ed25519::verify::<Sha512>(
            authority,
            signature.as_array(),
            &[message_bytes.as_slice()],
        )
        .map_err(|_| Error::InvalidSignature)?;
    }

    Ok(authorities)
}

fn collect_authorized_signers(
    program_id: &Address,
    executor_instruction: &CheckedExecutorInstruction,
    authorities: &[Address],
) -> Vec<AuthorizedSigner> {
    let mut authorized = Vec::<AuthorizedSigner>::with_capacity(authorities.len());

    // Cold authorities sign as normal Ed25519 keys. PDA signer promotion is allowed only for a
    // matching ProgrammaticSigner PDA that appears in the executor's signed account index list.
    for authority in authorities {
        let (programmatic_signer, bump) =
            ProgrammaticSigner::derive_address_and_bump(program_id, authority);

        for executor_account in &executor_instruction.accounts {
            if executor_account.account.address() == &programmatic_signer {
                authorized.push(AuthorizedSigner {
                    authority: *authority,
                    programmatic_signer_index: executor_account.index,
                    bump_seed: [bump],
                });
            }
        }
    }

    authorized
}

fn invoke_executor_instruction(
    message: &v1::Message,
    executor_instruction: &CheckedExecutorInstruction,
    authorized_signers: &[AuthorizedSigner],
) -> ProgramResult {
    // The PDA seeds that authorize `invoke_signed` to sign as each programmatic signer.
    let signer_seeds: Vec<[Seed; 3]> = authorized_signers
        .iter()
        .map(|signer| {
            [
                Seed::from(ProgrammaticSigner::SEED_PREFIX),
                Seed::from(signer.authority.as_ref()),
                Seed::from(&signer.bump_seed),
            ]
        })
        .collect();
    let cpi_signers: Vec<Signer> = signer_seeds.iter().map(Signer::from).collect();

    // The CPI receives only the accounts named by the executor instruction, in signed index order.
    let mut instruction_accounts = Vec::with_capacity(executor_instruction.accounts.len());
    let mut account_views = Vec::with_capacity(executor_instruction.accounts.len());

    for executor_account in &executor_instruction.accounts {
        let is_promoted = authorized_signers
            .iter()
            .any(|signer| signer.programmatic_signer_index == executor_account.index);

        // Real outer signers, such as a relayer co-signer, can be forwarded to the executor
        let is_forwarded_outer_signer =
            message.is_signer(executor_account.index) && executor_account.account.is_signer();

        let is_writable = message.is_maybe_writable_with_reserved_addresses(
            executor_account.index,
            None::<&BTreeSet<_>>,
        );

        // CPI privileges come from the wrapped message plus authorized PDA promotion.
        // Outer over-grants are not forwarded. Under-grants fail runtime privilege checks.
        instruction_accounts.push(InstructionAccount::new(
            executor_account.account.address(),
            is_writable,
            is_promoted || is_forwarded_outer_signer,
        ));
        account_views.push(executor_account.account);
    }

    let view = InstructionView {
        program_id: executor_instruction.program_id,
        accounts: &instruction_accounts,
        data: executor_instruction.data,
    };
    invoke_signed_with_slice::<&AccountView>(&view, &account_views, &cpi_signers)?;

    Ok(())
}
