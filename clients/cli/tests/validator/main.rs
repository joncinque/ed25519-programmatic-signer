use {
    self::{
        common::helpers::setup_test_env,
        nonce_create::{
            creates_and_shows_nonce_account, creates_nonce_account_with_cold_authority,
            creates_nonce_account_with_compute_budget_flags,
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
        test_migrate_scan::{rejects_invalid_scans, scans_owner_for_migrations},
        test_migrate_sol::{
            migrates_sol_between_programmatic_signers, migrates_sol_to_new_owner,
            rejects_invalid_sol_migrations,
        },
        test_migrate_stake::{
            dry_runs_stake_migration, migrates_stake_authorities_one_at_a_time,
            migrates_stake_between_programmatic_signers, migrates_stake_to_new_owner,
            migrates_stake_with_lockup_custodian, rejects_invalid_stake_migrations,
        },
        test_migrate_token::{
            migrates_token_2022_balance, migrates_token_2022_balance_from_source,
            migrates_token_2022_balance_to_destination, migrates_token_balance,
            migrates_token_balance_from_source, migrates_token_balance_to_destination,
            migrates_tokens_between_programmatic_signers,
            migrates_tokens_from_reassigned_associated_account,
            migrates_tokens_past_reassigned_destination, migrates_tokens_with_close_authority,
            migrates_tokens_with_funder, migrates_tokens_with_transfer_fee,
            rejects_invalid_token_destinations, rejects_invalid_token_migrations,
            rejects_invalid_token_sources, rejects_unsupported_token_2022_migrations,
            warns_of_scheduled_token_transfer_fee,
        },
        test_migrate_vote::{
            migrates_vote_withdrawer_between_programmatic_signers,
            migrates_vote_withdrawer_held_by_identity, migrates_vote_withdrawer_to_new_owner,
            rejects_invalid_vote_migrations, simulates_vote_identity_change,
            simulates_vote_voter_change, simulates_vote_withdrawer_migration,
        },
        test_nonce_advance::{
            advances_nonce_with_cold_authority, advances_nonce_with_compute_budget_flags,
            advances_nonce_with_external_cold_authority, advances_nonce_with_plain_key_authority,
            rejects_advance_compute_budget_flags_for_address_authority,
            rejects_offline_plain_key_authority, rejects_unrelated_nonce_authority,
        },
        test_nonce_withdraw::{
            recovers_uninitialized_nonce_account, rejects_invalid_withdrawals,
            rejects_withdraw_compute_budget_flags_for_address_authority,
            withdraws_with_cold_authority, withdraws_with_compute_budget_flags,
            withdraws_with_external_cold_authority, withdraws_with_plain_key_authority,
        },
        test_transaction_simulate::{
            parses_scaled_ui_amount_token_accounts, prints_verbose_simulation_result,
            rejects_stale_nonce_hash, rejects_transaction_over_transaction_size,
            reports_created_and_closed_accounts, reports_failed_simulation_logs,
            simulates_at_relay_cpi_depth, simulates_promoted_and_forwarded_signers,
            simulates_token_transfer,
        },
        test_transaction_submit::{
            cancels_when_forwarded_signer_declines, dry_run_reports_failed_simulation,
            dry_run_requires_authority_signatures, dry_runs_with_durable_nonce,
            dry_runs_without_relay_signers, rejects_durable_nonce_authority_mismatch,
            rejects_expired_execution_message, rejects_limits_below_usage,
            rejects_nonce_authority_mismatch, rejects_nonce_chain_skips_through_submit,
            rejects_stale_durable_nonce_value, submits_authority_signatures_in_any_order,
            submits_authority_signed_transfer_and_rejects_replay,
            submits_chain_signed_offline_with_next_nonce, submits_quietly_without_confirmation,
            submits_unsigned_message_with_external_signature,
            submits_with_all_compute_budget_flags,
            submits_with_authority_as_execution_message_non_signer, submits_with_blockhash,
            submits_with_compute_unit_limit, submits_with_durable_nonce,
            submits_with_fee_payer_as_forwarded_signer, submits_with_forwarded_authority,
            submits_with_forwarded_ordinary_signer, submits_with_loaded_accounts_data_size_limit,
            submits_with_offline_durable_nonce_authority, submits_with_offline_relay_signatures,
            submits_with_plain_key_nonce_authority, submits_with_priority_fee,
            submits_with_required_relay_signer, suggests_nonce_advance_after_failed_submission,
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
mod test_migrate_scan;
mod test_migrate_sol;
mod test_migrate_stake;
mod test_migrate_token;
mod test_migrate_vote;
mod test_nonce_advance;
mod test_nonce_withdraw;
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
            creates_nonce_account_with_compute_budget_flags,
            env,
            runtime_handle
        ),
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
            advances_nonce_with_compute_budget_flags,
            env,
            runtime_handle
        ),
        async_trial!(
            rejects_advance_compute_budget_flags_for_address_authority,
            env,
            runtime_handle
        ),
        async_trial!(withdraws_with_plain_key_authority, env, runtime_handle),
        async_trial!(withdraws_with_cold_authority, env, runtime_handle),
        async_trial!(withdraws_with_external_cold_authority, env, runtime_handle),
        async_trial!(rejects_invalid_withdrawals, env, runtime_handle),
        async_trial!(withdraws_with_compute_budget_flags, env, runtime_handle),
        async_trial!(
            rejects_withdraw_compute_budget_flags_for_address_authority,
            env,
            runtime_handle
        ),
        async_trial!(recovers_uninitialized_nonce_account, env, runtime_handle),
        async_trial!(
            submits_authority_signed_transfer_and_rejects_replay,
            env,
            runtime_handle
        ),
        async_trial!(rejects_expired_execution_message, env, runtime_handle),
        async_trial!(submits_with_forwarded_ordinary_signer, env, runtime_handle),
        async_trial!(cancels_when_forwarded_signer_declines, env, runtime_handle),
        async_trial!(
            suggests_nonce_advance_after_failed_submission,
            env,
            runtime_handle
        ),
        async_trial!(submits_quietly_without_confirmation, env, runtime_handle),
        async_trial!(submits_with_plain_key_nonce_authority, env, runtime_handle),
        async_trial!(submits_with_required_relay_signer, env, runtime_handle),
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
        async_trial!(submits_with_priority_fee, env, runtime_handle),
        async_trial!(submits_with_compute_unit_limit, env, runtime_handle),
        async_trial!(
            submits_with_loaded_accounts_data_size_limit,
            env,
            runtime_handle
        ),
        async_trial!(submits_with_all_compute_budget_flags, env, runtime_handle),
        async_trial!(rejects_limits_below_usage, env, runtime_handle),
        async_trial!(
            submits_with_offline_durable_nonce_authority,
            env,
            runtime_handle
        ),
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
        async_trial!(reports_created_and_closed_accounts, env, runtime_handle),
        async_trial!(parses_scaled_ui_amount_token_accounts, env, runtime_handle),
        async_trial!(simulates_at_relay_cpi_depth, env, runtime_handle),
        async_trial!(prints_verbose_simulation_result, env, runtime_handle),
        async_trial!(reports_failed_simulation_logs, env, runtime_handle),
        async_trial!(rejects_stale_nonce_hash, env, runtime_handle),
        async_trial!(
            rejects_transaction_over_transaction_size,
            env,
            runtime_handle
        ),
        async_trial!(migrates_stake_to_new_owner, env, runtime_handle),
        async_trial!(dry_runs_stake_migration, env, runtime_handle),
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
        async_trial!(simulates_vote_withdrawer_migration, env, runtime_handle),
        async_trial!(simulates_vote_voter_change, env, runtime_handle),
        async_trial!(simulates_vote_identity_change, env, runtime_handle),
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
        async_trial!(migrates_token_balance, env, runtime_handle),
        async_trial!(migrates_token_2022_balance, env, runtime_handle),
        async_trial!(migrates_token_balance_from_source, env, runtime_handle),
        async_trial!(migrates_token_2022_balance_from_source, env, runtime_handle),
        async_trial!(
            migrates_tokens_from_reassigned_associated_account,
            env,
            runtime_handle
        ),
        async_trial!(rejects_invalid_token_sources, env, runtime_handle),
        async_trial!(migrates_token_balance_to_destination, env, runtime_handle),
        async_trial!(
            migrates_token_2022_balance_to_destination,
            env,
            runtime_handle
        ),
        async_trial!(rejects_invalid_token_destinations, env, runtime_handle),
        async_trial!(
            migrates_tokens_past_reassigned_destination,
            env,
            runtime_handle
        ),
        async_trial!(migrates_tokens_with_funder, env, runtime_handle),
        async_trial!(migrates_tokens_with_close_authority, env, runtime_handle),
        async_trial!(
            migrates_tokens_between_programmatic_signers,
            env,
            runtime_handle
        ),
        async_trial!(migrates_tokens_with_transfer_fee, env, runtime_handle),
        async_trial!(warns_of_scheduled_token_transfer_fee, env, runtime_handle),
        async_trial!(rejects_invalid_token_migrations, env, runtime_handle),
        async_trial!(
            rejects_unsupported_token_2022_migrations,
            env,
            runtime_handle
        ),
        async_trial!(migrates_sol_to_new_owner, env, runtime_handle),
        async_trial!(
            migrates_sol_between_programmatic_signers,
            env,
            runtime_handle
        ),
        async_trial!(rejects_invalid_sol_migrations, env, runtime_handle),
        async_trial!(scans_owner_for_migrations, env, runtime_handle),
        async_trial!(rejects_invalid_scans, env, runtime_handle),
        async_trial!(
            submits_chain_signed_offline_with_next_nonce,
            env,
            runtime_handle
        ),
        async_trial!(
            rejects_nonce_chain_skips_through_submit,
            env,
            runtime_handle
        ),
        async_trial!(
            submits_unsigned_message_with_external_signature,
            env,
            runtime_handle
        ),
        async_trial!(dry_runs_without_relay_signers, env, runtime_handle),
        async_trial!(dry_runs_with_durable_nonce, env, runtime_handle),
        async_trial!(dry_run_reports_failed_simulation, env, runtime_handle),
        async_trial!(dry_run_requires_authority_signatures, env, runtime_handle),
    ];
    let exit_code = libtest_mimic::run(&arguments, tests).exit_code();
    // Agave's validator shutdown calls Handle::current(), which panics outside a Tokio context.
    runtime.block_on(async { drop(env) });
    exit_code
}
