use {
    crate::execute::process_execute,
    pinocchio::{
        AccountView, Address, ProgramResult, default_allocator, nostd_panic_handler,
        program_entrypoint,
    },
    spl_message_executor_interface::instruction::Instruction,
};

program_entrypoint!(process_instruction);
default_allocator!();
nostd_panic_handler!();

#[inline(always)]
fn process_instruction(
    _program_id: &Address,
    accounts: &mut [AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    match Instruction::try_from_bytes(instruction_data)? {
        Instruction::Execute(message) => process_execute(accounts, message),
    }
}
