#[cfg(feature = "codama")]
use codama_macros::CodamaPda;
use solana_address::Address;

/// Programmatic signer for an authority.
///
/// Program-owned runtime signer. `Submit` promotes it to `is_signer=true` via
/// `invoke_signed` wherever the executor CPI references it, after the corresponding
/// authority has signed the authorization message.
///
/// Seeds: `["programmatic-signer", authority, bump]`
#[cfg_attr(
    feature = "codama",
    derive(CodamaPda),
    codama(seed(type = string(utf8), value = "programmatic-signer")),
    codama(seed(name = "authority", type = public_key))
)]
pub struct ProgrammaticSigner;

impl ProgrammaticSigner {
    pub const SEED_PREFIX: &[u8] = b"programmatic-signer";

    #[inline(always)]
    pub fn derive_address_and_bump(program_id: &Address, authority: &Address) -> (Address, u8) {
        Address::derive_program_address(&[Self::SEED_PREFIX, authority.as_ref()], program_id)
            .expect("failed to derive ProgrammaticSigner from authority")
    }

    #[inline(always)]
    pub fn derive_address(program_id: &Address, authority: &Address) -> Address {
        let (address, _bump) = Self::derive_address_and_bump(program_id, authority);
        address
    }
}
