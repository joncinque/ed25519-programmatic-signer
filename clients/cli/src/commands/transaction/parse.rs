use {
    serde_json::json,
    solana_address::Address,
    solana_message::{compiled_instruction::CompiledInstruction, v1},
    solana_transaction_status::{
        Encodable, UiInstruction, UiMessage, UiParsedInstruction, UiTransactionEncoding,
        parse_instruction::ParsedInstruction,
    },
    spl_nonce_interface::instruction::Instruction as NonceInstruction,
};

/// Encode an execution message as parsed JSON. On top of the programs `jsonParsed` decodes, this
/// decodes SPL Nonce instructions. Instructions for any other program stay partially decoded.
pub(super) fn encode_execution_message(message: &v1::Message) -> UiMessage {
    let mut encoded = message.encode(UiTransactionEncoding::JsonParsed);
    if let UiMessage::Parsed(parsed) = &mut encoded {
        for (ui_instruction, instruction) in
            parsed.instructions.iter_mut().zip(&message.instructions)
        {
            let UiInstruction::Parsed(UiParsedInstruction::PartiallyDecoded(partial)) =
                ui_instruction
            else {
                continue;
            };
            if let Some(parsed) = parse_nonce(message, instruction, partial.stack_height) {
                *ui_instruction = UiInstruction::Parsed(UiParsedInstruction::Parsed(parsed));
            }
        }
    }
    encoded
}

/// Indexes of the instructions `encoded` leaves partially decoded.
pub(super) fn undecoded_instructions(encoded: &UiMessage) -> Vec<usize> {
    let UiMessage::Parsed(parsed) = encoded else {
        return vec![];
    };
    parsed
        .instructions
        .iter()
        .enumerate()
        .filter(|(_, instruction)| {
            matches!(
                instruction,
                UiInstruction::Parsed(UiParsedInstruction::PartiallyDecoded(_))
            )
        })
        .map(|(index, _)| index)
        .collect()
}

/// Decode an SPL Nonce instruction in the shape `jsonParsed` uses for builtin programs, or `None`
/// if the instruction is for another program or is malformed.
fn parse_nonce(
    message: &v1::Message,
    instruction: &CompiledInstruction,
    stack_height: Option<u32>,
) -> Option<ParsedInstruction> {
    let account = |position: usize| -> Option<&Address> {
        let index = instruction.accounts.get(position)?;
        message.account_keys.get(usize::from(*index))
    };
    let program_id = message
        .account_keys
        .get(usize::from(instruction.program_id_index))?;
    if *program_id != spl_nonce_interface::ID {
        return None;
    }
    let parsed = match NonceInstruction::try_from_bytes(&instruction.data).ok()? {
        NonceInstruction::Initialize => json!({
            "type": "initialize",
            "info": {
                "nonceAccount": account(0)?.to_string(),
                "authority": account(1)?.to_string(),
                "slotHashesSysvar": account(2)?.to_string(),
            },
        }),
        NonceInstruction::Advance {
            current_nonce,
            transition_commitment,
        } => json!({
            "type": "advance",
            "info": {
                "authority": account(0)?.to_string(),
                "transitionSigner": account(1)?.to_string(),
                "nonceAccount": account(2)?.to_string(),
                "currentNonce": current_nonce.to_string(),
                "transitionCommitment": transition_commitment.to_string(),
            },
        }),
        NonceInstruction::Withdraw { lamports } => json!({
            "type": "withdraw",
            "info": {
                "authority": account(0)?.to_string(),
                "nonceAccount": account(1)?.to_string(),
                "destination": account(2)?.to_string(),
                "lamports": lamports,
            },
        }),
    };
    Some(ParsedInstruction {
        program: "spl-nonce".into(),
        program_id: program_id.to_string(),
        parsed,
        stack_height,
    })
}
