use {
    self::{
        common::helpers::setup_test_env,
        nonce_create::{
            creates_and_shows_nonce_account, creates_nonce_account_with_cold_authority,
            creates_nonce_account_with_generated_keypair,
        },
        test_migrate_mint::{
            migrates_mint_authorities_between_programmatic_signers,
            migrates_mint_without_freeze_authority, migrates_token_2022_mint_authorities,
            migrates_token_2022_mint_authorities_one_at_a_time, migrates_token_mint_authorities,
            migrates_token_mint_authorities_one_at_a_time, rejects_invalid_mint_migrations,
        },
        test_migrate_program::{
            migrates_program_upgrade_authority_between_programmatic_signers,
            migrates_program_upgrade_authority_to_new_owner, rejects_invalid_program_migrations,
        },
        test_migrate_stake::{
            migrates_stake_authorities_one_at_a_time, migrates_stake_between_programmatic_signers,
            migrates_stake_to_new_owner, migrates_stake_with_lockup_custodian,
            rejects_invalid_stake_migrations,
        },
        test_migrate_vote::{
            migrates_vote_withdrawer_between_programmatic_signers,
            migrates_vote_withdrawer_held_by_identity, migrates_vote_withdrawer_to_new_owner,
            rejects_invalid_vote_migrations,
        },
        test_nonce_advance::{
            advances_nonce_with_cold_authority, advances_nonce_with_external_cold_authority,
            advances_nonce_with_plain_key_authority, rejects_offline_plain_key_authority,
            rejects_unrelated_nonce_authority,
        },
        test_transaction_simulate::{
            prints_verbose_simulation_result, rejects_stale_nonce_hash,
            reports_failed_simulation_logs, simulates_promoted_and_forwarded_signers,
            simulates_token_transfer,
        },
        test_transaction_submit::{
            cancels_when_forwarded_signer_declines, rejects_durable_nonce_authority_mismatch,
            rejects_nonce_authority_mismatch, rejects_stale_durable_nonce_value,
            submits_authority_signatures_in_any_order,
            submits_authority_signed_transfer_and_rejects_replay,
            submits_chain_signed_offline_with_next_nonce, submits_quietly_without_confirmation,
            submits_unsigned_message_with_external_signature,
            submits_with_authority_as_execution_message_non_signer, submits_with_blockhash,
            submits_with_durable_nonce, submits_with_fee_payer_as_forwarded_signer,
            submits_with_forwarded_authority, submits_with_forwarded_ordinary_signer,
            submits_with_offline_relay_signatures, submits_with_plain_key_nonce_authority,
        },
    },
    libtest_mimic::{Arguments, Trial},
    std::{process::ExitCode, sync::Arc},
};

#[path = "../common/mod.rs"]
pub mod common;
mod migration;
mod nonce_create;
mod test_migrate_mint;
mod test_migrate_program;
mod test_migrate_stake;
mod test_migrate_vote;
mod test_nonce_advance;
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
        async_trial!(advances_nonce_with_plain_key_authority, env, runtime_handle),
        async_trial!(advances_nonce_with_cold_authority, env, runtime_handle),
        async_trial!(
            advances_nonce_with_external_cold_authority,
            env,
            runtime_handle
        ),
        async_trial!(rejects_offline_plain_key_authority, env, runtime_handle),
        async_trial!(rejects_unrelated_nonce_authority, env, runtime_handle),
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
            submits_with_authority_as_execution_message_non_signer,
            env,
            runtime_handle
        ),
        async_trial!(rejects_nonce_authority_mismatch, env, runtime_handle),
        async_trial!(submits_with_blockhash, env, runtime_handle),
        async_trial!(submits_with_durable_nonce, env, runtime_handle),
        async_trial!(submits_with_offline_relay_signatures, env, runtime_handle),
        async_trial!(rejects_stale_durable_nonce_value, env, runtime_handle),
        async_trial!(
            rejects_durable_nonce_authority_mismatch,
            env,
            runtime_handle
        ),
        async_trial!(
            simulates_promoted_and_forwarded_signers,
            env,
            runtime_handle
        ),
        async_trial!(simulates_token_transfer, env, runtime_handle),
        async_trial!(prints_verbose_simulation_result, env, runtime_handle),
        async_trial!(reports_failed_simulation_logs, env, runtime_handle),
        async_trial!(rejects_stale_nonce_hash, env, runtime_handle),
        async_trial!(migrates_stake_to_new_owner, env, runtime_handle),
        async_trial!(
            migrates_stake_between_programmatic_signers,
            env,
            runtime_handle
        ),
        async_trial!(
            migrates_stake_authorities_one_at_a_time,
            env,
            runtime_handle
        ),
        async_trial!(migrates_stake_with_lockup_custodian, env, runtime_handle),
        async_trial!(rejects_invalid_stake_migrations, env, runtime_handle),
        async_trial!(migrates_vote_withdrawer_to_new_owner, env, runtime_handle),
        async_trial!(
            migrates_vote_withdrawer_between_programmatic_signers,
            env,
            runtime_handle
        ),
        async_trial!(
            migrates_vote_withdrawer_held_by_identity,
            env,
            runtime_handle
        ),
        async_trial!(rejects_invalid_vote_migrations, env, runtime_handle),
        async_trial!(
            migrates_program_upgrade_authority_to_new_owner,
            env,
            runtime_handle
        ),
        async_trial!(
            migrates_program_upgrade_authority_between_programmatic_signers,
            env,
            runtime_handle
        ),
        async_trial!(rejects_invalid_program_migrations, env, runtime_handle),
        async_trial!(migrates_token_mint_authorities, env, runtime_handle),
        async_trial!(migrates_token_2022_mint_authorities, env, runtime_handle),
        async_trial!(
            migrates_token_mint_authorities_one_at_a_time,
            env,
            runtime_handle
        ),
        async_trial!(
            migrates_token_2022_mint_authorities_one_at_a_time,
            env,
            runtime_handle
        ),
        async_trial!(
            migrates_mint_authorities_between_programmatic_signers,
            env,
            runtime_handle
        ),
        async_trial!(migrates_mint_without_freeze_authority, env, runtime_handle),
        async_trial!(rejects_invalid_mint_migrations, env, runtime_handle),
        async_trial!(
            submits_chain_signed_offline_with_next_nonce,
            env,
            runtime_handle
        ),
        async_trial!(
            submits_unsigned_message_with_external_signature,
            env,
            runtime_handle
        ),
    ];
    libtest_mimic::run(&arguments, tests).exit_code()
}
