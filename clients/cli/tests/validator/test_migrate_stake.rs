use {
    crate::common::{
        execute::programmatic_signer,
        helpers::{TestEnv, run_psigner, run_psigner_with_input},
    },
    base64::{Engine, prelude::BASE64_STANDARD},
    serde::Deserialize,
    solana_address::Address,
    solana_hash::Hash,
    solana_keypair::{Keypair, write_keypair_file},
    solana_message::{VersionedMessage, v1},
    solana_signer::Signer,
    solana_stake_interface::{
        instruction::create_account,
        state::{Authorized, Lockup, StakeStateV2},
    },
    solana_transaction::Transaction,
    spl_nonce_interface::state::Nonce,
    spl_programmatic_signer_cli::{
        Authorization, NonceCreateOutput, RequiredSigners, StakeMigrationOutput,
    },
    tempfile::NamedTempFile,
};

const STAKE_LAMPORTS: u64 = 1_000_000_000;

/// The authorization an authority gives for its programmatic signer.
fn authorization(authority: &Address) -> Authorization {
    Authorization {
        programmatic_signer: programmatic_signer(authority).to_string(),
        signer_pubkey: Some(authority.to_string()),
    }
}

fn decode_execution_message(execution_message: &str) -> v1::Message {
    let bytes = BASE64_STANDARD.decode(execution_message).unwrap();
    let VersionedMessage::V1(message) = wincode::deserialize_exact(&bytes).unwrap() else {
        panic!("expected a v1 execution message");
    };
    message
}

/// Forwarded signers are compared in any order.
fn assert_signers(
    signers: &RequiredSigners,
    authorizations: &[Authorization],
    forwarded_signers: &[Address],
) {
    assert_eq!(signers.authorizations, authorizations);
    let mut actual = signers.forwarded_signers.clone();
    actual.sort();
    let mut expected = forwarded_signers
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    expected.sort();
    assert_eq!(actual, expected);
}

#[derive(Deserialize)]
struct SignOutput {
    authorization_message: String,
    signatures: Vec<SignatureEntry>,
}

#[derive(Deserialize)]
struct SignatureEntry {
    address: String,
    signature: String,
}

async fn create_stake_account(env: &TestEnv, authorized: &Authorized, lockup: &Lockup) -> Address {
    let stake = Keypair::new();
    let transaction = Transaction::new_signed_with_payer(
        &create_account(
            &env.payer.pubkey(),
            &stake.pubkey(),
            authorized,
            lockup,
            STAKE_LAMPORTS,
        ),
        Some(&env.payer.pubkey()),
        &[&env.payer, &stake],
        env.rpc.get_latest_blockhash().await.unwrap(),
    );
    env.rpc
        .send_and_confirm_transaction(&transaction)
        .await
        .unwrap();
    stake.pubkey()
}

async fn stake_authorized(env: &TestEnv, stake: &Address) -> Authorized {
    let data = env.rpc.get_account_data(stake).await.unwrap();
    wincode::deserialize::<StakeStateV2>(&data)
        .unwrap()
        .authorized()
        .unwrap()
}

/// An SPL nonce account whose authority is `authority`'s programmatic signer.
fn create_nonce(env: &TestEnv, authority: &Address) -> Address {
    let create = run_psigner(&[
        "-C",
        &env.config_file_path,
        "--output",
        "json-compact",
        "nonce",
        "create",
        "--cold-authority",
        &authority.to_string(),
    ]);
    let create: NonceCreateOutput = serde_json::from_slice(&create.stdout).unwrap();
    create.nonce_account.parse().unwrap()
}

async fn current_nonce(env: &TestEnv, nonce_account: &Address) -> Hash {
    let data = env.rpc.get_account_data(nonce_account).await.unwrap();
    Nonce::view(&data).unwrap().nonce
}

fn keypair_file(keypair: &Keypair) -> NamedTempFile {
    let file = NamedTempFile::new().unwrap();
    write_keypair_file(keypair, &file).unwrap();
    file
}

/// Without `new_owner`, the migration defaults to the current authority.
fn migrate(
    env: &TestEnv,
    stake: &Address,
    new_owner: Option<&Address>,
    extra: &[&str],
) -> StakeMigrationOutput {
    let stake = stake.to_string();
    let new_owner = new_owner.map(ToString::to_string);
    let mut args = vec![
        "-C",
        &env.config_file_path,
        "--output",
        "json",
        "migrate",
        "stake",
        &stake,
    ];
    if let Some(new_owner) = &new_owner {
        args.extend(["--new-authority-signing-pubkey", new_owner]);
    }
    args.extend_from_slice(extra);
    serde_json::from_slice(&run_psigner(&args).stdout).unwrap()
}

fn migrate_error(
    env: &TestEnv,
    stake: &Address,
    new_owner: Option<&Address>,
    extra: &[&str],
) -> String {
    let stake = stake.to_string();
    let new_owner = new_owner.map(ToString::to_string);
    let mut args = vec!["-C", &env.config_file_path, "migrate", "stake", &stake];
    if let Some(new_owner) = &new_owner {
        args.extend(["--new-authority-signing-pubkey", new_owner]);
    }
    args.extend_from_slice(extra);
    let output = run_psigner_with_input(&args, "");
    assert!(!output.status.success());
    String::from_utf8(output.stderr).unwrap()
}

/// Sign the migration with the new authority, whose programmatic signer is the nonce authority,
/// and any other authorities whose programmatic signers the migration needs. Then submit it with
/// the forwarded signers signing the relay transaction.
async fn execute_migration(
    env: &TestEnv,
    migration: &StakeMigrationOutput,
    nonce_account: &Address,
    new_owner: &Keypair,
    other_authorities: &[&Keypair],
    relay_signers: &[&Keypair],
) {
    let nonce_account_arg = nonce_account.to_string();
    let nonce_authority = programmatic_signer(&new_owner.pubkey()).to_string();
    let nonce_hash = current_nonce(env, nonce_account).await.to_string();
    let authorities = std::iter::once(new_owner)
        .chain(other_authorities.iter().copied())
        .collect::<Vec<_>>();
    let authority_args = authorities
        .iter()
        .map(|authority| authority.pubkey().to_string())
        .collect::<Vec<_>>();
    let authority_files = authorities
        .iter()
        .map(|authority| keypair_file(authority))
        .collect::<Vec<_>>();
    let mut args = vec![
        "-C",
        &env.config_file_path,
        "--output",
        "json",
        "transaction",
        "sign",
        "--execution-message",
        &migration.execution_message,
        "--nonce-account",
        &nonce_account_arg,
        "--nonce-authority",
        &nonce_authority,
        "--nonce-hash",
        &nonce_hash,
        "--quiet",
        "--yes",
    ];
    for (authority, file) in authority_args.iter().zip(&authority_files) {
        args.extend([
            "--authority",
            authority,
            "--signer",
            file.path().to_str().unwrap(),
        ]);
    }
    let sign: SignOutput = serde_json::from_slice(&run_psigner(&args).stdout).unwrap();
    assert_eq!(sign.signatures.len(), authorities.len());
    let signatures = sign
        .signatures
        .iter()
        .map(|signature| format!("{}={}", signature.address, signature.signature))
        .collect::<Vec<_>>();

    let relay_signer_files = relay_signers
        .iter()
        .map(|signer| keypair_file(signer))
        .collect::<Vec<_>>();
    let mut args = vec![
        "-C",
        &env.config_file_path,
        "transaction",
        "submit",
        "--authorization-message",
        &sign.authorization_message,
        "--quiet",
        "--yes",
    ];
    for signature in &signatures {
        args.extend(["--signer", signature]);
    }
    for file in &relay_signer_files {
        args.extend(["--relay-signer", file.path().to_str().unwrap()]);
    }
    run_psigner(&args);
}

pub async fn migrates_stake_to_new_owner(env: &TestEnv) {
    let old_owner = Keypair::new();
    let new_owner = Keypair::new();
    let new_owner_programmatic_signer = programmatic_signer(&new_owner.pubkey());
    let stake = create_stake_account(
        env,
        &Authorized::auto(&old_owner.pubkey()),
        &Lockup::default(),
    )
    .await;
    let nonce_account = create_nonce(env, &new_owner.pubkey());

    let migration = migrate(env, &stake, Some(&new_owner.pubkey()), &[]);
    assert_eq!(migration.authority_types, ["staker", "withdrawer"]);
    assert_eq!(
        migration.new_authority,
        new_owner_programmatic_signer.to_string()
    );
    assert_eq!(
        migration.new_authority_signing_pubkey,
        new_owner.pubkey().to_string()
    );
    assert_eq!(migration.custodian, None);
    assert_signers(
        &migration.required_signers,
        &[authorization(&new_owner.pubkey())],
        &[old_owner.pubkey()],
    );
    // The new authority's programmatic signer stands in as the fee payer, and `transaction sign`
    // sets the lifetime.
    let message = decode_execution_message(&migration.execution_message);
    assert_eq!(message.account_keys[0], new_owner_programmatic_signer);
    assert_eq!(message.lifetime_specifier, Hash::default());

    execute_migration(
        env,
        &migration,
        &nonce_account,
        &new_owner,
        &[],
        &[&old_owner],
    )
    .await;
    assert_eq!(
        stake_authorized(env, &stake).await,
        Authorized::auto(&new_owner_programmatic_signer)
    );
}

pub async fn migrates_stake_between_programmatic_signers(env: &TestEnv) {
    let old_owner = Keypair::new();
    let old_owner_programmatic_signer = programmatic_signer(&old_owner.pubkey());
    let new_owner = Keypair::new();
    let new_owner_programmatic_signer = programmatic_signer(&new_owner.pubkey());
    let stake = create_stake_account(
        env,
        &Authorized::auto(&old_owner_programmatic_signer),
        &Lockup::default(),
    )
    .await;
    let nonce_account = create_nonce(env, &new_owner.pubkey());

    // The current authority is a programmatic signer, which signs at `transaction sign`
    let migration = migrate(env, &stake, Some(&new_owner.pubkey()), &[]);
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
    execute_migration(
        env,
        &migration,
        &nonce_account,
        &new_owner,
        &[&old_owner],
        &[],
    )
    .await;
    assert_eq!(
        stake_authorized(env, &stake).await,
        Authorized::auto(&new_owner_programmatic_signer)
    );
}

pub async fn migrates_stake_authorities_one_at_a_time(env: &TestEnv) {
    // The owner moves the stake account to its own programmatic signer, the default new authority.
    let owner = Keypair::new();
    let owner_signer = programmatic_signer(&owner.pubkey());
    let stake =
        create_stake_account(env, &Authorized::auto(&owner.pubkey()), &Lockup::default()).await;
    let nonce_account = create_nonce(env, &owner.pubkey());

    let staker = migrate(env, &stake, None, &["--authority-type", "staker"]);
    assert_eq!(staker.authority_types, ["staker"]);
    assert_eq!(
        staker.new_authority_signing_pubkey,
        owner.pubkey().to_string()
    );
    assert_signers(
        &staker.required_signers,
        &[authorization(&owner.pubkey())],
        &[owner.pubkey()],
    );
    execute_migration(env, &staker, &nonce_account, &owner, &[], &[&owner]).await;
    assert_eq!(
        stake_authorized(env, &stake).await,
        Authorized {
            staker: owner_signer,
            withdrawer: owner.pubkey(),
        }
    );

    let stderr = migrate_error(
        env,
        &stake,
        Some(&owner.pubkey()),
        &["--authority-type", "staker"],
    );
    assert!(
        stderr.contains(&format!(
            "the staker of stake account {stake} is already {owner_signer}"
        )),
        "{stderr}"
    );

    // The staker already moved, so moving both is rejected too.
    let stderr = migrate_error(env, &stake, Some(&owner.pubkey()), &[]);
    assert!(stderr.contains("is already"), "{stderr}");

    // The staker is now a programmatic signer, which can't be the default new authority.
    let stderr = migrate_error(env, &stake, None, &["--authority-type", "staker"]);
    assert!(
        stderr.contains(&format!(
            "the current authority of stake account {stake} is {owner_signer}, which is not an \
             on-curve address"
        )),
        "{stderr}"
    );

    // The staker and withdrawer differ, so neither is the default for moving both.
    let stderr = migrate_error(env, &stake, None, &[]);
    assert!(
        stderr.contains(&format!(
            "the staker {owner_signer} and withdrawer {} of stake account {stake} differ",
            owner.pubkey()
        )),
        "{stderr}"
    );

    let withdrawer = migrate(env, &stake, None, &["--authority-type", "withdrawer"]);
    execute_migration(env, &withdrawer, &nonce_account, &owner, &[], &[&owner]).await;
    assert_eq!(
        stake_authorized(env, &stake).await,
        Authorized::auto(&owner_signer)
    );
}

pub async fn migrates_stake_with_lockup_custodian(env: &TestEnv) {
    let staker = Keypair::new();
    let withdrawer = Keypair::new();
    let custodian = Keypair::new();
    let new_owner = Keypair::new();
    let new_owner_programmatic_signer = programmatic_signer(&new_owner.pubkey());
    let stake = create_stake_account(
        env,
        &Authorized {
            staker: staker.pubkey(),
            withdrawer: withdrawer.pubkey(),
        },
        &Lockup {
            unix_timestamp: 0,
            epoch: u64::MAX,
            custodian: custodian.pubkey(),
        },
    )
    .await;
    let nonce_account = create_nonce(env, &new_owner.pubkey());

    // Only moving the withdrawer needs the custodian.
    let staker_only = migrate(
        env,
        &stake,
        Some(&new_owner.pubkey()),
        &["--authority-type", "staker"],
    );
    assert_eq!(staker_only.custodian, None);

    let migration = migrate(env, &stake, Some(&new_owner.pubkey()), &[]);
    assert_eq!(migration.custodian, Some(custodian.pubkey().to_string()));
    assert_signers(
        &migration.required_signers,
        &[authorization(&new_owner.pubkey())],
        &[staker.pubkey(), withdrawer.pubkey(), custodian.pubkey()],
    );

    execute_migration(
        env,
        &migration,
        &nonce_account,
        &new_owner,
        &[],
        &[&staker, &withdrawer, &custodian],
    )
    .await;
    assert_eq!(
        stake_authorized(env, &stake).await,
        Authorized::auto(&new_owner_programmatic_signer)
    );
}

pub async fn rejects_invalid_stake_migrations(env: &TestEnv) {
    let owner = Keypair::new();
    let stake =
        create_stake_account(env, &Authorized::auto(&owner.pubkey()), &Lockup::default()).await;

    // Passing the programmatic signer in place of its authority.
    let owner_signer = programmatic_signer(&owner.pubkey());
    let stderr = migrate_error(env, &stake, Some(&owner_signer), &[]);
    assert!(
        stderr.contains(&format!(
            "new authority signing pubkey {owner_signer} is not an on-curve address"
        )),
        "{stderr}"
    );

    let stderr = migrate_error(env, &env.payer.pubkey(), Some(&owner.pubkey()), &[]);
    assert!(
        stderr.contains(&format!(
            "account {} is owned by 11111111111111111111111111111111, not the Stake Program",
            env.payer.pubkey()
        )),
        "{stderr}"
    );
}
