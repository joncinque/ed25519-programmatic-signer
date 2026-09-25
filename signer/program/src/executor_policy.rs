//! Hard-coded policy for executor entrypoints allowed to receive promoted signers.

use {pinocchio::Address, spl_ed25519_signer_interface::error::Error};

const EXECUTE_DISCRIMINATOR: u8 = 0;

/// Executor entrypoints allowed to receive promoted signers.
/// Each entry is `(program ID, instruction discriminator)`.
const ALLOWED_EXECUTOR_INSTRUCTIONS: &[(Address, u8)] =
    &[(spl_message_executor_interface::ID, EXECUTE_DISCRIMINATOR)];

/// Admits only executor entrypoints that guarantee replay protection before using promoted
/// signers. Without this allow list, accidentally signing an instruction for a malicious executor
/// could let it use the promoted signer indefinitely because the signer program is stateless.
///
/// Note: Expanding this policy can make a previously rejected, already-signed envelope executable.
#[inline(always)]
pub(crate) fn validate(program_id: &Address, instruction_data: &[u8]) -> Result<(), Error> {
    let discriminator = *instruction_data
        .first()
        .ok_or(Error::DisallowedExecutorInstruction)?;

    if !ALLOWED_EXECUTOR_INSTRUCTIONS.contains(&(*program_id, discriminator)) {
        return Err(Error::DisallowedExecutorInstruction);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use {
        super::{EXECUTE_DISCRIMINATOR, validate},
        pinocchio::Address,
        solana_message::legacy::Message,
        spl_ed25519_signer_interface::error::Error,
        spl_message_executor_interface::instruction::Instruction as ExecutorInstruction,
    };

    #[test]
    fn accepts_message_executor_execute_wire_format() {
        let instruction_data =
            wincode::serialize(&ExecutorInstruction::Execute(Message::default())).unwrap();

        assert_eq!(
            validate(&spl_message_executor_interface::ID, &instruction_data,),
            Ok(())
        );
    }

    #[test]
    fn rejects_unknown_program() {
        assert_eq!(
            validate(&Address::new_unique(), &[EXECUTE_DISCRIMINATOR]),
            Err(Error::DisallowedExecutorInstruction)
        );
    }

    #[test]
    fn rejects_empty_instruction_data() {
        assert_eq!(
            validate(&spl_message_executor_interface::ID, &[]),
            Err(Error::DisallowedExecutorInstruction)
        );
    }

    #[test]
    fn rejects_unknown_instruction_discriminator() {
        assert_eq!(
            validate(
                &spl_message_executor_interface::ID,
                &[EXECUTE_DISCRIMINATOR + 1],
            ),
            Err(Error::DisallowedExecutorInstruction)
        );
    }
}
