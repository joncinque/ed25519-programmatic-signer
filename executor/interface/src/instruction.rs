#[cfg(feature = "codama")]
use codama_macros::CodamaInstructions;
use {
    solana_hash::Hash,
    solana_message::VersionedMessage,
    solana_program_error::ProgramError,
    wincode::{SchemaRead, SchemaWrite},
};

/// Instructions supported by the SPL Message Executor program.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
#[wincode(tag_encoding = "u8")]
#[cfg_attr(
    feature = "codama",
    derive(CodamaInstructions),
    codama(enum_discriminator(size = number(u8)))
)]
pub enum Instruction {
    /// Executes a wrapped message by invoking each of its instructions via CPI, consuming a nonce
    /// for replay protection. This program is intended to be invoked after a signer program has
    /// verified signatures and promoted any authorized PDAs to signer.
    ///
    /// Instruction data: the discriminator followed by a serialized [`VersionedMessage`], including
    /// its version prefix. Only [`v1::Message`](solana_message::v1::Message) is supported.
    ///
    /// On success, the program:
    /// 1. Deserializes the wrapped message and verifies that it is a sanitized v1 message with an
    ///    empty transaction config, since config fields only apply to top-level transactions.
    /// 2. Verifies that the message's recent blockhash matches the nonce account's stored nonce.
    /// 3. Verifies that each supplied account matches the message account at the same index.
    /// 4. Advances the nonce via CPI to the Nonce program, which validates the authority signer.
    /// 5. Executes each message instruction via CPI. All changes roll back on failure.
    ///
    /// Accounts required:
    /// - `[signer]` Nonce authority, independent of the wrapped message accounts
    /// - `[writable]` Nonce account to advance
    /// - `[]` SPL Nonce program
    /// - Message accounts referenced by the wrapped message, in order
    #[cfg_attr(
        feature = "codama",
        codama(display(intent = "Execute all instructions in a wrapped message")),
        codama(account(
            name = "nonce_authority",
            signer,
            docs = "Authority signer for the nonce account",
            display(label = "Nonce authority")
        )),
        codama(account(
            name = "nonce_account",
            writable,
            docs = "Nonce account consumed for replay protection",
            display(label = "Nonce account to advance")
        )),
        codama(account(
            name = "nonce_program",
            docs = "SPL Nonce program",
            default_value = public_key("Noncediea1fH12usShuQAz28UhgAeuE5Maf32LsMUQB"),
            display(skip = always)
        ))
    )]
    Execute(
        #[cfg_attr(
            feature = "codama",
            codama(name = "message"),
            codama(type = bytes),
            codama(display(label = "Wrapped message"))
        )]
        VersionedMessage,
    ),
}

/// Derives the transition commitment for a wrapped message as SHA-256 of its wire encoding.
/// Each nonce advancement commits to the exact message executed, so altering a message
/// invalidates every successor precomputed from the original.
pub fn derive_transition_commitment(message: &VersionedMessage) -> Hash {
    solana_sha256_hasher::hash(&message.serialize())
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
        super::{Instruction, derive_transition_commitment},
        solana_hash::Hash,
        solana_message::{VersionedMessage, v1},
        solana_program_error::ProgramError,
    };

    #[test]
    fn instruction_tags_match_wire_format() {
        assert_eq!(
            wincode::serialize(&Instruction::Execute(VersionedMessage::V1(
                v1::Message::default()
            )))
            .unwrap()[0],
            0
        );
    }

    #[test]
    fn execute_message_keeps_version_prefix() {
        // Clients decode the message bytes as a standard wire message, which needs the prefix.
        let bytes = wincode::serialize(&Instruction::Execute(VersionedMessage::V1(
            v1::Message::default(),
        )))
        .unwrap();
        assert_eq!(bytes[1], v1::V1_PREFIX);
    }

    #[test]
    fn execute_round_trips() {
        let instruction = Instruction::Execute(VersionedMessage::V1(v1::Message::default()));
        let bytes = wincode::serialize(&instruction).unwrap();
        assert_eq!(Instruction::try_from_bytes(&bytes).unwrap(), instruction);
    }

    #[test]
    fn execute_rejects_trailing_data() {
        let mut bytes = wincode::serialize(&Instruction::Execute(VersionedMessage::V1(
            v1::Message::default(),
        )))
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

    #[test]
    fn transition_commitment_matches_snapshot() {
        let message = VersionedMessage::V1(v1::Message::default());
        assert_eq!(
            derive_transition_commitment(&message),
            "CBg3iVEh1d3hGJDQQ7eQxEJhZ9txvkCeeMDSMaVTWZwc"
                .parse::<Hash>()
                .unwrap()
        );
    }
}
