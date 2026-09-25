use {
    mollusk_svm::{Mollusk, program::create_program_account_loader_v3},
    solana_account::Account,
    solana_address::Address,
    solana_instruction::{AccountMeta, Instruction},
};

const NAME: &str = "stub_executor";

pub fn install(mollusk: &mut Mollusk) {
    mollusk.add_program(&spl_message_executor_interface::id(), NAME);
}

/// Wraps an inner instruction in the stub format: discriminator, instruction, and program account.
pub fn wrap(instruction: Instruction) -> Instruction {
    let mut data = vec![0];
    data.extend(wincode::serialize(&instruction).unwrap());

    let mut accounts = instruction.accounts;
    accounts.push(AccountMeta::new_readonly(instruction.program_id, false));

    Instruction {
        program_id: spl_message_executor_interface::id(),
        accounts,
        data,
    }
}

pub fn keyed_account() -> (Address, Account) {
    let program_id = spl_message_executor_interface::id();
    (program_id, create_program_account_loader_v3(&program_id))
}
