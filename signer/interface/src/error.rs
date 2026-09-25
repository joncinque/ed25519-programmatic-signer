//! Error types for the SPL Ed25519 Signer program.

#[cfg(feature = "codama")]
use codama_macros::CodamaErrors;
use solana_program_error::ProgramError;

/// Errors that may be returned by the SPL Ed25519 Signer program.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
#[cfg_attr(feature = "codama", derive(CodamaErrors))]
pub enum Error {
    /// The wrapped message failed sanitization.
    #[cfg_attr(
        feature = "codama",
        codama(error(message = "The wrapped message failed sanitization"))
    )]
    InvalidWrappedMessage = 0,
    /// The wrapped message must contain exactly one executor instruction.
    #[cfg_attr(
        feature = "codama",
        codama(error(
            message = "The wrapped message must contain exactly one executor instruction"
        ))
    )]
    InvalidExecutorInstructionCount = 1,
    /// A Submit account differs from the wrapped message key at the same index.
    #[cfg_attr(
        feature = "codama",
        codama(error(
            message = "A Submit account differs from the wrapped message key at the same index"
        ))
    )]
    AccountKeyMismatch = 2,
    /// An authority signature failed verification against the wrapped message.
    #[cfg_attr(
        feature = "codama",
        codama(error(
            message = "An authority signature failed verification against the wrapped message"
        ))
    )]
    InvalidSignature = 3,
    /// The executor program and instruction pair is not permitted by this signer program.
    #[cfg_attr(
        feature = "codama",
        codama(error(
            message = "The executor program and instruction pair is not permitted by this signer \
                       program"
        ))
    )]
    DisallowedExecutorInstruction = 4,
    /// The authority signature count does not match the wrapped message.
    #[cfg_attr(
        feature = "codama",
        codama(error(
            message = "The authority signature count does not match the wrapped message."
        ))
    )]
    InvalidSignatureCount = 5,
    /// The wrapped message is not a v1 message.
    #[cfg_attr(
        feature = "codama",
        codama(error(message = "The wrapped message is not a v1 message"))
    )]
    UnsupportedMessageVersion = 6,
    /// The wrapped message sets transaction config fields. The wrapped message is never
    /// executed as a transaction, so they would have no effect.
    #[cfg_attr(
        feature = "codama",
        codama(error(message = "The wrapped message sets transaction config fields"))
    )]
    UnsupportedTransactionConfig = 7,
}

impl From<Error> for ProgramError {
    fn from(error: Error) -> Self {
        ProgramError::Custom(error as u32)
    }
}
