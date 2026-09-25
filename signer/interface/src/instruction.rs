#[cfg(feature = "codama")]
use codama_macros::CodamaInstructions;
use {
    alloc::vec::Vec,
    solana_message::VersionedMessage,
    solana_program_error::ProgramError,
    solana_signature::Signature,
    wincode::{SchemaRead, SchemaWrite, containers},
};

/// Instructions supported by the SPL Ed25519 Signer program.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
#[wincode(tag_encoding = "u8")]
#[cfg_attr(
    feature = "codama",
    derive(CodamaInstructions),
    codama(enum_discriminator(size = number(u8)))
)]
pub enum Instruction {
    /// Verifies authority signatures over a Solana [`VersionedMessage`], then CPIs to the program
    /// of its single executor instruction, promoting `ProgrammaticSigner` PDAs to a signer.
    ///
    /// Only [`v1::Message`](solana_message::v1::Message) is supported. It is encoded with its
    /// version prefix and must leave every transaction config field unset.
    ///
    /// Instruction data: instruction discriminator followed by signatures and message.
    ///
    /// On success, the program:
    /// 1. Verifies the message contains exactly one executor instruction.
    /// 2. Verifies the executor program and instruction discriminator are present in the allow list.
    /// 3. Verifies each `signatures[i]` is `account_keys[i]`'s Ed25519 signature over that message.
    /// 4. Verifies submitted account keys match the message's account keys in order.
    /// 5. CPIs to the executor instruction's program using exactly the accounts referenced by the
    ///    executor instruction's account index list, promoting any referenced authority-derived
    ///    `ProgrammaticSigner` PDAs to a signer.
    ///
    /// Trust assumptions:
    /// - This program validates authority signatures, accounts, flags, and executor identity.
    /// - The inner signed message is an authorization envelope. Only its single executor
    ///   instruction is invoked.
    /// - Except for its discriminator, executor instruction data is opaque to this program.
    /// - This program is stateless. Replay protection belongs to the executor program.
    ///
    /// Accounts required:
    /// - One account for each key in the wrapped message's `account_keys` list, in the same order.
    ///   At every index, the submitted account key and writable flag must match the wrapped message.
    #[cfg_attr(
        feature = "codama",
        codama(display(intent = "Verify wrapped message and invoke its executor"))
    )]
    Submit {
        #[wincode(with = "containers::Vec<Signature, u8>")]
        #[cfg_attr(
            feature = "codama",
            codama(type = array(fixed_size(bytes, 64), prefixed_count(number(u8)))),
            codama(display(label = "Authority signatures"))
        )]
        signatures: Vec<Signature>,
        #[cfg_attr(
            feature = "codama",
            codama(type = bytes),
            codama(display(label = "Signed message"))
        )]
        message: VersionedMessage,
    },
}

impl Instruction {
    #[inline(always)]
    pub fn try_from_bytes(instruction_data: &[u8]) -> Result<Self, ProgramError> {
        wincode::deserialize_exact(instruction_data)
            .map_err(|_| ProgramError::InvalidInstructionData)
    }
}

#[cfg(test)]
mod tests {
    use {
        super::Instruction,
        alloc::vec,
        solana_message::{VersionedMessage, v1},
        solana_program_error::ProgramError,
        solana_signature::Signature,
    };

    #[test]
    fn instruction_tags_match_wire_format() {
        let instruction = Instruction::Submit {
            signatures: vec![],
            message: VersionedMessage::V1(v1::Message::default()),
        };
        assert_eq!(wincode::serialize(&instruction).unwrap()[0], 0);
    }

    #[test]
    fn submit_round_trips() {
        let instruction = Instruction::Submit {
            signatures: vec![Signature::from([7; 64])],
            message: VersionedMessage::V1(v1::Message::default()),
        };
        let bytes = wincode::serialize(&instruction).unwrap();
        assert_eq!(Instruction::try_from_bytes(&bytes).unwrap(), instruction);
    }

    #[test]
    fn submit_rejects_trailing_data() {
        let mut bytes = wincode::serialize(&Instruction::Submit {
            signatures: vec![],
            message: VersionedMessage::V1(v1::Message::default()),
        })
        .unwrap();
        bytes.extend_from_slice(&[1, 2, 3]);

        assert_eq!(
            Instruction::try_from_bytes(&bytes),
            Err(ProgramError::InvalidInstructionData)
        );
    }

    #[test]
    fn try_from_bytes_rejects_unknown() {
        assert_eq!(
            Instruction::try_from_bytes(&[1]),
            Err(ProgramError::InvalidInstructionData)
        );
        assert_eq!(
            Instruction::try_from_bytes(&[255]),
            Err(ProgramError::InvalidInstructionData)
        );
    }
}
