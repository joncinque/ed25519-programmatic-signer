#[cfg(feature = "codama")]
use codama_macros::CodamaErrors;
use solana_program_error::ProgramError;

/// Custom errors returned by the SPL Message Executor program.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
#[cfg_attr(feature = "codama", derive(CodamaErrors))]
pub enum Error {
    /// The nonce account data could not be decoded as nonce state.
    #[cfg_attr(
        feature = "codama",
        codama(error(message = "The nonce account data could not be decoded as nonce state"))
    )]
    InvalidNonceAccount = 0,
    /// The legacy message fails sanitization or contains duplicate keys.
    #[cfg_attr(
        feature = "codama",
        codama(error(
            message = "The legacy message fails sanitization or contains duplicate keys"
        ))
    )]
    InvalidMessage = 1,
    /// The passed accounts do not match the wrapped message's account keys.
    #[cfg_attr(
        feature = "codama",
        codama(error(
            message = "The passed accounts do not match the wrapped message's account keys"
        ))
    )]
    MessageAccountsMismatch = 2,
    /// The message's recent blockhash does not match the stored nonce.
    #[cfg_attr(
        feature = "codama",
        codama(error(message = "The message's recent blockhash does not match the stored nonce"))
    )]
    NonceMismatch = 3,
}

impl From<Error> for ProgramError {
    fn from(error: Error) -> Self {
        ProgramError::Custom(error as u32)
    }
}
