use {
    crate::{
        common::{execute::programmatic_signer, helpers::TestEnv},
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
        instruction::{CreateVoteAccountConfig, create_account_with_config, withdraw},
        state::{VoteInit, VoteStateV4, VoteStateVersions},
    },
    spl_programmatic_signer_cli::{Authorization, VoteMigrationOutput},
};

/// Lamports above the rent-exempt minimum, which the withdrawer can take out.
const WITHDRAWABLE_LAMPORTS: u64 = 1_000_000_000;

async fn create_vote_account(env: &TestEnv, identity: &Keypair, withdrawer: &Address) -> Address {
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
    let withdraw = v1::Message::try_compile(
        &new_owner_programmatic_signer,
        &[withdraw(
            &vote,
            &new_owner_programmatic_signer,
            WITHDRAWABLE_LAMPORTS,
            &recipient,
        )],
        Hash::default(),
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
