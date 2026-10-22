use {
    crate::{
        common::{execute::programmatic_signer, helpers::TestEnv},
        migration::{
            assert_signers, authorization, create_nonce, decode_execution_message,
            execute_as_new_owner, migrate, migrate_error, send,
        },
    },
    solana_address::Address,
    solana_hash::Hash,
    solana_keypair::Keypair,
    solana_native_token::{LAMPORTS_PER_SOL, Sol},
    solana_signer::Signer,
    solana_system_interface::instruction::{create_account, transfer},
    spl_programmatic_signer_cli::{Authorization, SolMigrationOutput},
};

fn migrate_sol(
    env: &TestEnv,
    owner: &Address,
    new_owner: Option<&Address>,
    extra: &[&str],
) -> SolMigrationOutput {
    migrate(env, "sol", owner, new_owner, extra)
}

fn migrate_sol_error(
    env: &TestEnv,
    owner: &Address,
    new_owner: Option<&Address>,
    extra: &[&str],
) -> String {
    migrate_error(env, "sol", owner, new_owner, extra)
}

/// Give `address` `lamports` from the test payer.
async fn fund(env: &TestEnv, address: &Address, lamports: u64) {
    send(
        env,
        &[transfer(&env.payer.pubkey(), address, lamports)],
        &[],
    )
    .await;
}

pub async fn migrates_sol_to_new_owner(env: &TestEnv) {
    let owner = Keypair::new();
    let new_owner = Keypair::new();
    let new_owner_programmatic_signer = programmatic_signer(&new_owner.pubkey());
    fund(env, &owner.pubkey(), 2 * LAMPORTS_PER_SOL).await;
    let nonce_account = create_nonce(env, &new_owner.pubkey());

    // Without a new authority, the SOL moves to the owner's own programmatic signer.
    let default = migrate_sol(env, &owner.pubkey(), None, &["--amount", "0.5"]);
    assert_eq!(
        default.new_authority_signing_pubkey,
        owner.pubkey().to_string()
    );

    let migration = migrate_sol(
        env,
        &owner.pubkey(),
        Some(&new_owner.pubkey()),
        &["--amount", "0.5"],
    );
    assert_eq!(migration.owner, owner.pubkey().to_string());
    assert_eq!(migration.lamports, LAMPORTS_PER_SOL / 2);
    assert!(!migration.closes_account);
    assert_eq!(
        migration.new_authority,
        new_owner_programmatic_signer.to_string()
    );
    assert_eq!(
        migration.new_authority_signing_pubkey,
        new_owner.pubkey().to_string()
    );
    assert_signers(
        &migration.required_signers,
        &[authorization(&new_owner.pubkey())],
        &[owner.pubkey()],
    );

    let message = decode_execution_message(&migration.execution_message);
    assert_eq!(message.account_keys[0], new_owner_programmatic_signer);
    assert_eq!(message.lifetime_specifier, Hash::default());
    let program_ids = message
        .instructions
        .iter()
        .map(|instruction| message.account_keys[usize::from(instruction.program_id_index)])
        .collect::<Vec<_>>();
    assert_eq!(
        program_ids,
        [
            solana_sdk_ids::system_program::id(),
            spl_memo_interface::v4::id()
        ]
    );
    // The transfer doesn't list the new authority as a signer, so the memo must, or nothing onchain
    // would require the new authority's approval.
    let memo = message.instructions.last().unwrap();
    assert_eq!(memo.accounts, [0]);
    assert_eq!(memo.data, b"migrate sol");

    execute_as_new_owner(
        env,
        &migration.execution_message,
        &nonce_account,
        &new_owner,
        &[],
        &[&owner],
    )
    .await;
    assert_eq!(
        env.rpc.get_balance(&owner.pubkey()).await.unwrap(),
        3 * LAMPORTS_PER_SOL / 2
    );
    assert_eq!(
        env.rpc
            .get_balance(&new_owner_programmatic_signer)
            .await
            .unwrap(),
        LAMPORTS_PER_SOL / 2
    );

    // Without an amount, the whole balance moves and the owner's account closes.
    let migration = migrate_sol(env, &owner.pubkey(), Some(&new_owner.pubkey()), &[]);
    assert_eq!(migration.lamports, 3 * LAMPORTS_PER_SOL / 2);
    assert!(migration.closes_account);
    execute_as_new_owner(
        env,
        &migration.execution_message,
        &nonce_account,
        &new_owner,
        &[],
        &[&owner],
    )
    .await;
    assert_eq!(env.rpc.get_balance(&owner.pubkey()).await.unwrap(), 0);
    assert_eq!(
        env.rpc
            .get_balance(&new_owner_programmatic_signer)
            .await
            .unwrap(),
        2 * LAMPORTS_PER_SOL
    );

    let stderr = migrate_sol_error(env, &owner.pubkey(), Some(&new_owner.pubkey()), &[]);
    assert!(
        stderr.contains(&format!("account {} was not found", owner.pubkey())),
        "{stderr}"
    );
}

pub async fn migrates_sol_between_programmatic_signers(env: &TestEnv) {
    let old_owner = Keypair::new();
    let old_owner_programmatic_signer = programmatic_signer(&old_owner.pubkey());
    let new_owner = Keypair::new();
    let new_owner_programmatic_signer = programmatic_signer(&new_owner.pubkey());
    fund(env, &old_owner_programmatic_signer, LAMPORTS_PER_SOL).await;
    let nonce_account = create_nonce(env, &new_owner.pubkey());

    // The owner is a programmatic signer, which can't be traced back to its signing pubkey, and
    // nothing signs the relay transaction for it.
    let migration = migrate_sol(
        env,
        &old_owner_programmatic_signer,
        Some(&new_owner.pubkey()),
        &[],
    );
    assert_eq!(migration.lamports, LAMPORTS_PER_SOL);
    assert!(migration.closes_account);
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
        env.rpc
            .get_balance(&old_owner_programmatic_signer)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        env.rpc
            .get_balance(&new_owner_programmatic_signer)
            .await
            .unwrap(),
        LAMPORTS_PER_SOL
    );
}

pub async fn rejects_invalid_sol_migrations(env: &TestEnv) {
    let owner = Keypair::new();
    let new_owner = Keypair::new();
    let rent = env
        .rpc
        .get_minimum_balance_for_rent_exemption(0)
        .await
        .unwrap();
    fund(env, &owner.pubkey(), LAMPORTS_PER_SOL).await;

    let new_owner_programmatic_signer = programmatic_signer(&new_owner.pubkey());
    let stderr = migrate_sol_error(
        env,
        &new_owner_programmatic_signer,
        Some(&new_owner.pubkey()),
        &[],
    );
    assert!(
        stderr.contains(&format!(
            "funds must be migrated to a different account. The destination wallet \
             {new_owner_programmatic_signer} matches the current wallet \
             {new_owner_programmatic_signer}"
        )),
        "{stderr}"
    );

    // An owner that is a programmatic signer can't be the default new authority.
    let stderr = migrate_sol_error(env, &new_owner_programmatic_signer, None, &[]);
    assert!(
        stderr.contains(&format!(
            "the owner is {new_owner_programmatic_signer}, which is not an on-curve address"
        )),
        "{stderr}"
    );

    let nonce_account = create_nonce(env, &owner.pubkey());
    let stderr = migrate_sol_error(env, &nonce_account, Some(&new_owner.pubkey()), &[]);
    assert!(
        stderr.contains(&format!(
            "account {nonce_account} is owned by {}, not the System Program",
            spl_nonce_interface::id()
        )),
        "{stderr}"
    );

    // The System Program can't transfer from an account it owns that holds data.
    let data_account = Keypair::new();
    let lamports = env
        .rpc
        .get_minimum_balance_for_rent_exemption(8)
        .await
        .unwrap();
    send(
        env,
        &[create_account(
            &env.payer.pubkey(),
            &data_account.pubkey(),
            lamports,
            8,
            &solana_sdk_ids::system_program::id(),
        )],
        &[&data_account],
    )
    .await;
    let stderr = migrate_sol_error(env, &data_account.pubkey(), Some(&new_owner.pubkey()), &[]);
    assert!(
        stderr.contains(&format!(
            "account {} holds data, so the System Program can't transfer from it",
            data_account.pubkey()
        )),
        "{stderr}"
    );

    let rent_exempt_error = format!(
        "account {} holds {}. Move all of it, or at most {} to leave it rent exempt",
        owner.pubkey(),
        Sol(LAMPORTS_PER_SOL),
        Sol(LAMPORTS_PER_SOL.checked_sub(rent).unwrap())
    );
    for amount in ["0.9999999", "2"] {
        let stderr = migrate_sol_error(
            env,
            &owner.pubkey(),
            Some(&new_owner.pubkey()),
            &["--amount", amount],
        );
        assert!(stderr.contains(&rent_exempt_error), "{stderr}");
    }

    let stderr = migrate_sol_error(
        env,
        &owner.pubkey(),
        Some(&new_owner.pubkey()),
        &["--amount", "0.000001"],
    );
    assert!(
        stderr.contains(&format!(
            "the new wallet's programmatic signer {new_owner_programmatic_signer} must end up \
             rent exempt, so move at least {}",
            Sol(rent)
        )),
        "{stderr}"
    );

    let stderr = migrate_sol_error(
        env,
        &owner.pubkey(),
        Some(&new_owner.pubkey()),
        &["--amount", "0"],
    );
    assert!(
        stderr.contains("amount must be greater than zero"),
        "{stderr}"
    );

    let stderr = migrate_sol_error(
        env,
        &owner.pubkey(),
        Some(&new_owner.pubkey()),
        &["--amount", "one"],
    );
    assert!(stderr.contains("invalid amount one"), "{stderr}");
}
