use {
    crate::{
        common::{
            execute::programmatic_signer,
            helpers::{TestEnv, run_psigner},
        },
        migration::{
            assert_signers, authorization, create_nonce, decode_execution_message,
            execute_as_new_owner, migrate, migrate_error,
        },
    },
    base64::{Engine, prelude::BASE64_STANDARD},
    solana_address::Address,
    solana_hash::Hash,
    solana_keypair::Keypair,
    solana_message::v1,
    solana_signer::Signer,
    solana_transaction::Transaction,
    solana_vote_interface::{
        instruction::{
            CreateVoteAccountConfig, authorize, create_account_with_config,
            update_validator_identity, withdraw,
        },
        state::{VoteAuthorize, VoteInit, VoteStateV4, VoteStateVersions},
    },
    spl_programmatic_signer_cli::{Authorization, VoteMigrationOutput},
};

/// Lamports above the rent-exempt minimum, which the withdrawer can take out.
const WITHDRAWABLE_LAMPORTS: u64 = 1_000_000_000;

pub async fn create_vote_account(
    env: &TestEnv,
    identity: &Keypair,
    withdrawer: &Address,
) -> Address {
    let vote = Keypair::new();
    let rent = env
        .rpc
        .get_minimum_balance_for_rent_exemption(VoteStateV4::size_of())
        .await
        .unwrap();
    let transaction = Transaction::new_signed_with_payer(
        &create_account_with_config(
            &env.payer.pubkey(),
            &vote.pubkey(),
            &VoteInit {
                node_pubkey: identity.pubkey(),
                authorized_voter: identity.pubkey(),
                authorized_withdrawer: *withdrawer,
                commission: 0,
            },
            rent.checked_add(WITHDRAWABLE_LAMPORTS).unwrap(),
            CreateVoteAccountConfig::default(),
        ),
        Some(&env.payer.pubkey()),
        &[&env.payer, &vote, identity],
        env.rpc.get_latest_blockhash().await.unwrap(),
    );
    env.rpc
        .send_and_confirm_transaction(&transaction)
        .await
        .unwrap();
    vote.pubkey()
}

async fn vote_withdrawer(env: &TestEnv, vote: &Address) -> Address {
    let data = env.rpc.get_account_data(vote).await.unwrap();
    match wincode::deserialize::<VoteStateVersions>(&data).unwrap() {
        VoteStateVersions::V3(state) => state.authorized_withdrawer,
        VoteStateVersions::V4(state) => state.authorized_withdrawer,
        state => panic!("unexpected vote state {state:?}"),
    }
}

pub async fn migrates_vote_withdrawer_to_new_owner(env: &TestEnv) {
    let identity = Keypair::new();
    let old_withdrawer = Keypair::new();
    let new_owner = Keypair::new();
    let new_owner_programmatic_signer = programmatic_signer(&new_owner.pubkey());
    let vote = create_vote_account(env, &identity, &old_withdrawer.pubkey()).await;
    let nonce_account = create_nonce(env, &new_owner.pubkey());

    let migration: VoteMigrationOutput =
        migrate(env, "vote", &vote, Some(&new_owner.pubkey()), &[]);
    assert_eq!(migration.vote_account, vote.to_string());
    assert_eq!(
        migration.new_authority,
        new_owner_programmatic_signer.to_string()
    );
    assert_eq!(
        migration.new_authority_signing_pubkey,
        new_owner.pubkey().to_string()
    );
    // Only the current withdrawer signs. The identity and voter are untouched.
    assert_signers(
        &migration.required_signers,
        &[authorization(&new_owner.pubkey())],
        &[old_withdrawer.pubkey()],
    );
    let message = decode_execution_message(&migration.execution_message);
    assert_eq!(message.account_keys[0], new_owner_programmatic_signer);
    assert_eq!(message.lifetime_specifier, Hash::default());

    execute_as_new_owner(
        env,
        &migration.execution_message,
        &nonce_account,
        &new_owner,
        &[],
        &[&old_withdrawer],
    )
    .await;
    assert_eq!(
        vote_withdrawer(env, &vote).await,
        new_owner_programmatic_signer
    );

    let stderr = migrate_error(env, "vote", &vote, Some(&new_owner.pubkey()), &[]);
    assert!(
        stderr.contains(&format!(
            "the withdrawer of vote account {vote} is already {new_owner_programmatic_signer}"
        )),
        "{stderr}"
    );

    // The withdrawer is now a programmatic signer, which can't be the default new authority.
    let stderr = migrate_error(env, "vote", &vote, None, &[]);
    assert!(
        stderr.contains(&format!(
            "the withdrawer of vote account {vote} is {new_owner_programmatic_signer}, which is \
             not an on-curve address"
        )),
        "{stderr}"
    );

    // The programmatic signer can now withdraw, with no forwarded signers.
    let recipient = Address::new_unique();
    let withdraw = v1::Message::try_compile_with_config(
        &new_owner_programmatic_signer,
        &[withdraw(
            &vote,
            &new_owner_programmatic_signer,
            WITHDRAWABLE_LAMPORTS,
            &recipient,
        )],
        Hash::default(),
        v1::TransactionConfig::empty(),
    )
    .unwrap();
    execute_as_new_owner(
        env,
        &BASE64_STANDARD.encode(withdraw.serialize()),
        &nonce_account,
        &new_owner,
        &[],
        &[],
    )
    .await;
    assert_eq!(
        env.rpc.get_balance(&recipient).await.unwrap(),
        WITHDRAWABLE_LAMPORTS
    );
}

/// Simulate `execution_message` against `nonce_account`, returning the JSON summary.
fn simulate(
    env: &TestEnv,
    execution_message: &str,
    nonce_account: &Address,
    extra: &[&str],
) -> serde_json::Value {
    let mut args = vec![
        "-C",
        &env.config_file_path,
        "--output",
        "json-compact",
        "transaction",
        "simulate",
        execution_message,
    ];
    let nonce_account = nonce_account.to_string();
    args.push(&nonce_account);
    args.extend_from_slice(extra);
    let output = run_psigner(&args);
    serde_json::from_slice(&output.stdout).unwrap()
}

/// Simulating a vote migration reports the withdrawer change, but no voter change, labelling the
/// new withdrawer with its signing pubkey.
pub async fn simulates_vote_withdrawer_migration(env: &TestEnv) {
    let withdrawer_change = |vote: &Address, before: &Address, signing_pubkey: &Address| {
        serde_json::json!([{
            "account": vote.to_string(),
            "kind": "vote",
            "role": "withdrawer",
            "before": { "address": before.to_string() },
            "after": {
                "address": programmatic_signer(signing_pubkey).to_string(),
                "signingPubkey": signing_pubkey.to_string(),
            },
        }])
    };

    // To a new owner. Only its programmatic signer is in the transaction, so its signing pubkey
    // needs --signing-pubkey.
    let identity = Keypair::new();
    let old_withdrawer = Keypair::new();
    let new_owner = Keypair::new();
    let vote = create_vote_account(env, &identity, &old_withdrawer.pubkey()).await;
    let nonce_account = create_nonce(env, &new_owner.pubkey());
    let migration: VoteMigrationOutput =
        migrate(env, "vote", &vote, Some(&new_owner.pubkey()), &[]);
    let new_owner_signing_pubkey = new_owner.pubkey().to_string();
    let value = simulate(
        env,
        &migration.execution_message,
        &nonce_account,
        &["--signing-pubkey", &new_owner_signing_pubkey],
    );
    assert_eq!(value["accountChanges"], serde_json::json!([]));
    assert_eq!(
        value["authorityChanges"],
        withdrawer_change(&vote, &old_withdrawer.pubkey(), &new_owner.pubkey())
    );
    // Nothing is submitted.
    assert_eq!(vote_withdrawer(env, &vote).await, old_withdrawer.pubkey());

    // To the current withdrawer's own programmatic signer. The current withdrawer signs the
    // execution message, so it is labelled without --signing-pubkey.
    let vote = create_vote_account(env, &identity, &old_withdrawer.pubkey()).await;
    let nonce_account = create_nonce(env, &old_withdrawer.pubkey());
    let migration: VoteMigrationOutput = migrate(env, "vote", &vote, None, &[]);
    let value = simulate(env, &migration.execution_message, &nonce_account, &[]);
    assert_eq!(
        value["authorityChanges"],
        withdrawer_change(&vote, &old_withdrawer.pubkey(), &old_withdrawer.pubkey())
    );
}

/// Simulating a voter change reports the epoch each voter applies from, since a new voter only
/// takes effect after the current leader schedule epoch.
pub async fn simulates_vote_voter_change(env: &TestEnv) {
    let identity = Keypair::new();
    let withdrawer = Keypair::new();
    let new_voter = Address::new_unique();
    let vote = create_vote_account(env, &identity, &withdrawer.pubkey()).await;
    let nonce_account = create_nonce(env, &withdrawer.pubkey());
    let execution_message = v1::Message::try_compile_with_config(
        &withdrawer.pubkey(),
        &[authorize(
            &vote,
            &withdrawer.pubkey(),
            &new_voter,
            VoteAuthorize::Voter,
        )],
        Hash::default(),
        v1::TransactionConfig::empty(),
    )
    .unwrap();

    let epoch_schedule = env.rpc.get_epoch_schedule().await.unwrap();
    let target_epoch = |slot| {
        epoch_schedule
            .get_leader_schedule_epoch(slot)
            .checked_add(1)
            .unwrap()
    };
    let slot_before = env.rpc.get_slot().await.unwrap();
    let output = run_psigner(&[
        "-C",
        &env.config_file_path,
        "--output",
        "json-compact",
        "transaction",
        "simulate",
        &BASE64_STANDARD.encode(execution_message.serialize()),
        &nonce_account.to_string(),
    ]);
    let slot_after = env.rpc.get_slot().await.unwrap();
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let changes = value["authorityChanges"].as_array().unwrap();
    assert_eq!(changes.len(), 1, "{value}");
    let change = &changes[0];
    assert_eq!(change["account"], vote.to_string());
    assert_eq!(change["kind"], "vote");
    assert_eq!(change["role"], "voter");
    assert_eq!(change["before"]["address"], identity.pubkey().to_string());
    assert_eq!(change["after"]["address"], new_voter.to_string());
    assert!(change["after"].get("signingPubkey").is_none(), "{change}");
    // The identity has been the voter since the account was created. The new voter applies from
    // the epoch after the leader schedule epoch at the simulation's slot, which may have advanced
    // while running it.
    let before_epoch = change["before"]["effectiveEpoch"].as_u64().unwrap();
    let after_epoch = change["after"]["effectiveEpoch"].as_u64().unwrap();
    assert!(
        before_epoch <= epoch_schedule.get_epoch(slot_before),
        "{change}"
    );
    assert!(
        (target_epoch(slot_before)..=target_epoch(slot_after)).contains(&after_epoch),
        "{change}"
    );
}

/// Simulating a validator identity change reports it as an identity change.
pub async fn simulates_vote_identity_change(env: &TestEnv) {
    let identity = Keypair::new();
    let withdrawer = Keypair::new();
    let new_identity = Address::new_unique();
    let vote = create_vote_account(env, &identity, &withdrawer.pubkey()).await;
    let nonce_account = create_nonce(env, &withdrawer.pubkey());
    let execution_message = v1::Message::try_compile_with_config(
        &withdrawer.pubkey(),
        &[update_validator_identity(
            &vote,
            &withdrawer.pubkey(),
            &new_identity,
        )],
        Hash::default(),
        v1::TransactionConfig::empty(),
    )
    .unwrap();

    let value = simulate(
        env,
        &BASE64_STANDARD.encode(execution_message.serialize()),
        &nonce_account,
        &[],
    );
    assert_eq!(value["accountChanges"], serde_json::json!([]));
    assert_eq!(
        value["authorityChanges"],
        serde_json::json!([{
            "account": vote.to_string(),
            "kind": "vote",
            "role": "identity",
            "before": { "address": identity.pubkey().to_string() },
            "after": { "address": new_identity.to_string() },
        }])
    );
}

pub async fn migrates_vote_withdrawer_between_programmatic_signers(env: &TestEnv) {
    let identity = Keypair::new();
    let old_owner = Keypair::new();
    let old_owner_programmatic_signer = programmatic_signer(&old_owner.pubkey());
    let new_owner = Keypair::new();
    let new_owner_programmatic_signer = programmatic_signer(&new_owner.pubkey());
    let vote = create_vote_account(env, &identity, &old_owner_programmatic_signer).await;
    let nonce_account = create_nonce(env, &new_owner.pubkey());

    // The current withdrawer is a programmatic signer, which can't be traced back to its signing
    // pubkey, and nothing signs the relay transaction for it.
    let migration: VoteMigrationOutput =
        migrate(env, "vote", &vote, Some(&new_owner.pubkey()), &[]);
    assert_signers(
        &migration.required_signers,
        &[
            authorization(&new_owner.pubkey()),
            Authorization {
                programmatic_signer: old_owner_programmatic_signer.to_string(),
                signer_pubkey: None,
            },
        ],
        &[],
    );

    // Whoever holds the old signing pubkey authorizes its programmatic signer alongside the new one.
    execute_as_new_owner(
        env,
        &migration.execution_message,
        &nonce_account,
        &new_owner,
        &[&old_owner],
        &[],
    )
    .await;
    assert_eq!(
        vote_withdrawer(env, &vote).await,
        new_owner_programmatic_signer
    );
}

pub async fn migrates_vote_withdrawer_held_by_identity(env: &TestEnv) {
    // The identity moves the withdrawer to its own programmatic signer, the default new authority.
    let identity = Keypair::new();
    let vote = create_vote_account(env, &identity, &identity.pubkey()).await;
    let nonce_account = create_nonce(env, &identity.pubkey());

    let migration: VoteMigrationOutput = migrate(env, "vote", &vote, None, &[]);
    assert_eq!(
        migration.new_authority_signing_pubkey,
        identity.pubkey().to_string()
    );
    assert_signers(
        &migration.required_signers,
        &[authorization(&identity.pubkey())],
        &[identity.pubkey()],
    );
    execute_as_new_owner(
        env,
        &migration.execution_message,
        &nonce_account,
        &identity,
        &[],
        &[&identity],
    )
    .await;
    assert_eq!(
        vote_withdrawer(env, &vote).await,
        programmatic_signer(&identity.pubkey())
    );
}

pub async fn rejects_invalid_vote_migrations(env: &TestEnv) {
    let identity = Keypair::new();
    let owner = Keypair::new();
    let vote = create_vote_account(env, &identity, &owner.pubkey()).await;

    // Passing the programmatic signer in place of its authority.
    let owner_signer = programmatic_signer(&owner.pubkey());
    let stderr = migrate_error(env, "vote", &vote, Some(&owner_signer), &[]);
    assert!(
        stderr.contains(&format!(
            "new authority signing pubkey {owner_signer} is not an on-curve address"
        )),
        "{stderr}"
    );

    let stderr = migrate_error(env, "vote", &env.payer.pubkey(), Some(&owner.pubkey()), &[]);
    assert!(
        stderr.contains(&format!(
            "account {} is owned by 11111111111111111111111111111111, not the Vote Program",
            env.payer.pubkey()
        )),
        "{stderr}"
    );
}
