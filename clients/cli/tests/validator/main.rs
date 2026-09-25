use {
    self::{
        common::helpers::setup_test_env,
        nonce_create::{
            creates_and_shows_nonce_account, creates_nonce_account_with_cold_authority,
            creates_nonce_account_with_generated_keypair,
        },
        test_transaction_simulate::{
            prints_verbose_simulation_result, rejects_stale_nonce_hash,
            reports_failed_simulation_logs, simulates_promoted_and_forwarded_signers,
            simulates_token_transfer,
        },
        test_transaction_submit::{
            cancels_when_forwarded_signer_declines, rejects_nonce_authority_mismatch,
            submits_authority_signatures_in_any_order,
            submits_authority_signed_transfer_and_rejects_replay,
            submits_quietly_without_confirmation, submits_with_authority_as_inner_non_signer,
            submits_with_fee_payer_as_forwarded_signer, submits_with_forwarded_authority,
            submits_with_forwarded_ordinary_signer, submits_with_plain_key_nonce_authority,
        },
    },
    libtest_mimic::{Arguments, Trial},
    std::{process::ExitCode, sync::Arc},
};

#[path = "../common/mod.rs"]
pub mod common;
mod nonce_create;
mod test_transaction_simulate;
mod test_transaction_submit;

macro_rules! async_trial {
    ($test:ident, $env:ident, $runtime:ident) => {{
        let test_env = Arc::clone(&$env);
        let handle = $runtime.clone();
        Trial::test(stringify!($test), move || {
            handle.block_on($test(&test_env));
            Ok(())
        })
    }};
}

fn main() -> ExitCode {
    let arguments = Arguments::from_args();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let env = Arc::new(runtime.block_on(setup_test_env()));
    let runtime_handle = runtime.handle().clone();
    let tests = vec![
        async_trial!(creates_and_shows_nonce_account, env, runtime_handle),
        async_trial!(
            creates_nonce_account_with_generated_keypair,
            env,
            runtime_handle
        ),
        async_trial!(
            creates_nonce_account_with_cold_authority,
            env,
            runtime_handle
        ),
        async_trial!(
            submits_authority_signed_transfer_and_rejects_replay,
            env,
            runtime_handle
        ),
        async_trial!(submits_with_forwarded_ordinary_signer, env, runtime_handle),
        async_trial!(cancels_when_forwarded_signer_declines, env, runtime_handle),
        async_trial!(submits_quietly_without_confirmation, env, runtime_handle),
        async_trial!(submits_with_plain_key_nonce_authority, env, runtime_handle),
        async_trial!(
            submits_with_fee_payer_as_forwarded_signer,
            env,
            runtime_handle
        ),
        async_trial!(
            submits_authority_signatures_in_any_order,
            env,
            runtime_handle
        ),
        async_trial!(submits_with_forwarded_authority, env, runtime_handle),
        async_trial!(
            submits_with_authority_as_inner_non_signer,
            env,
            runtime_handle
        ),
        async_trial!(rejects_nonce_authority_mismatch, env, runtime_handle),
        async_trial!(
            simulates_promoted_and_forwarded_signers,
            env,
            runtime_handle
        ),
        async_trial!(simulates_token_transfer, env, runtime_handle),
        async_trial!(prints_verbose_simulation_result, env, runtime_handle),
        async_trial!(reports_failed_simulation_logs, env, runtime_handle),
        async_trial!(rejects_stale_nonce_hash, env, runtime_handle),
    ];
    libtest_mimic::run(&arguments, tests).exit_code()
}
