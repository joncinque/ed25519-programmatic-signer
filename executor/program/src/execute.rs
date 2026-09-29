use {
    crate::{
        cpi::invoke_instructions,
        validate::{validate_message_accounts, validate_wrapped_message},
    },
    pinocchio::{AccountView, ProgramResult, error::ProgramError},
    solana_message::VersionedMessage,
    spl_message_executor_interface::{error::Error, instruction::derive_transition_commitment},
    spl_nonce_interface::state::Nonce,
};

pub fn process_execute(
    accounts: &mut [AccountView],
    wrapped_message: VersionedMessage,
) -> ProgramResult {
    let [
        nonce_authority_account,
        nonce_account,
        nonce_program,
        message_accounts @ ..,
    ] = accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if nonce_program.address() != &spl_nonce_interface::ID {
        return Err(ProgramError::IncorrectProgramId);
    }
    if !nonce_account.owned_by(&spl_nonce_interface::ID) {
        return Err(ProgramError::IllegalOwner);
    }
    let nonce_data = nonce_account.try_borrow()?;
    let Nonce { nonce, .. } = Nonce::view(&nonce_data).map_err(|_| Error::InvalidNonceAccount)?;

    let message = validate_wrapped_message(&wrapped_message)?;

    if &message.lifetime_specifier != nonce {
        return Err(Error::NonceMismatch.into());
    }

    validate_message_accounts(message_accounts, message)?;

    // The advance ix requires an owned nonce
    let current_nonce = *nonce;
    drop(nonce_data);

    // Consume the nonce before invoking the message instructions to prevent recursive execution.
    // The advance rolls back if any instruction invocation fails.
    spl_nonce_client::cpi::advance(
        nonce_authority_account,
        nonce_account,
        current_nonce,
        derive_transition_commitment(&wrapped_message),
    )?;

    invoke_instructions(message_accounts, message)
}
