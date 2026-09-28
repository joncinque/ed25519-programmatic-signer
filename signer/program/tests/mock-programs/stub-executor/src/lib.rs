#![no_std]

extern crate alloc;

use {
    alloc::vec::Vec,
    pinocchio::{
        AccountView, Address, ProgramResult,
        cpi::invoke_with_slice,
        default_allocator,
        error::ProgramError,
        instruction::{InstructionAccount, InstructionView},
        nostd_panic_handler, program_entrypoint,
    },
    solana_instruction::Instruction,
};

const EXECUTE_DISCRIMINATOR: u8 = 0;

program_entrypoint!(process_instruction);
default_allocator!();
nostd_panic_handler!();

/// Test-only executor used by the signer program's tests.
///
/// The first instruction-data byte is the allowed executor discriminator. The remaining bytes
/// encode a single Solana instruction, which this program invokes through CPI.
/// For simplicity, there's no replay protection.
fn process_instruction(
    _program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let (discriminator, instruction_data) = data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;
    if *discriminator != EXECUTE_DISCRIMINATOR {
        return Err(ProgramError::InvalidInstructionData);
    }

    let instruction: Instruction = wincode::deserialize_exact(instruction_data)
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    let account_views = accounts
        .get(..instruction.accounts.len())
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let instruction_accounts = instruction
        .accounts
        .iter()
        .map(|account| {
            InstructionAccount::new(&account.pubkey, account.is_writable, account.is_signer)
        })
        .collect::<Vec<_>>();
    let instruction = InstructionView {
        program_id: &instruction.program_id,
        accounts: &instruction_accounts,
        data: &instruction.data,
    };

    invoke_with_slice::<AccountView>(&instruction, account_views)
}
