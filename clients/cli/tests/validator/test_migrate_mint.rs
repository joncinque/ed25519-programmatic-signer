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
    solana_signer::Signer,
    solana_system_interface::instruction::create_account,
    spl_programmatic_signer_cli::{Authorization, MintMigrationOutput},
    spl_token_2022_interface::{
        extension::{ExtensionType, StateWithExtensions},
        instruction::{
            AuthorityType, initialize_mint2, initialize_non_transferable_mint, set_authority,
        },
        state::Mint,
    },
};

/// Create a mint. Token-2022 mints get an extension, so decoding has to handle the extended
/// layout most Token-2022 mints use.
async fn create_mint(
    env: &TestEnv,
    token_program: &Address,
    mint_authority: &Address,
    freeze_authority: Option<&Address>,
) -> Address {
    let mint = Keypair::new();
    let is_token_2022 = *token_program == spl_token_2022_interface::id();
    let extensions: &[ExtensionType] = if is_token_2022 {
        &[ExtensionType::NonTransferable]
    } else {
        &[]
    };
    let space = ExtensionType::try_calculate_account_len::<Mint>(extensions).unwrap();
    let lamports = env
        .rpc
        .get_minimum_balance_for_rent_exemption(space)
        .await
        .unwrap();
    let mut instructions = vec![create_account(
        &env.payer.pubkey(),
        &mint.pubkey(),
        lamports,
        space.try_into().unwrap(),
        token_program,
    )];
    if is_token_2022 {
        instructions.push(initialize_non_transferable_mint(token_program, &mint.pubkey()).unwrap());
    }
    instructions.push(
        initialize_mint2(
            token_program,
            &mint.pubkey(),
            mint_authority,
            freeze_authority,
            0,
        )
        .unwrap(),
    );
    send(env, &instructions, &[&mint]).await;
    mint.pubkey()
}

/// The mint's mint and freeze authorities.
async fn mint_authorities(env: &TestEnv, mint: &Address) -> (Option<Address>, Option<Address>) {
    let data = env.rpc.get_account_data(mint).await.unwrap();
    let mint = StateWithExtensions::<Mint>::unpack(&data).unwrap().base;
    (mint.mint_authority.into(), mint.freeze_authority.into())
}

async fn migrates_mint_authorities(env: &TestEnv, token_program: &Address) {
    let mint_authority = Keypair::new();
    let freeze_authority = Keypair::new();
    let new_owner = Keypair::new();
    let new_owner_programmatic_signer = programmatic_signer(&new_owner.pubkey());
    let mint = create_mint(
        env,
        token_program,
        &mint_authority.pubkey(),
        Some(&freeze_authority.pubkey()),
    )
    .await;
    let nonce_account = create_nonce(env, &new_owner.pubkey());

    let migration: MintMigrationOutput =
        migrate(env, "mint", &mint, Some(&new_owner.pubkey()), &[]);
    assert_eq!(migration.mint, mint.to_string());
    assert_eq!(migration.token_program, token_program.to_string());
    assert_eq!(migration.authority_types, ["mint", "freeze"]);
    assert!(migration.unset_authority_types.is_empty());
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
        &[mint_authority.pubkey(), freeze_authority.pubkey()],
    );

    let message = decode_execution_message(&migration.execution_message);
    assert_eq!(message.account_keys[0], new_owner_programmatic_signer);
    assert_eq!(message.lifetime_specifier, Hash::default());
    // `SetAuthority` doesn't list the new authority, so the memo must, or nothing onchain would
    // require the new authority's approval.
    let memo = message.instructions.last().unwrap();
    assert_eq!(
        message.account_keys[usize::from(memo.program_id_index)],
        spl_memo_interface::v4::id()
    );
    assert_eq!(memo.accounts, [0]);
    assert_eq!(
        memo.data,
        format!("migrate mint and freeze authority to {new_owner_programmatic_signer}").as_bytes()
    );

    execute_as_new_owner(
        env,
        &migration.execution_message,
        &nonce_account,
        &new_owner,
        &[],
        &[&mint_authority, &freeze_authority],
    )
    .await;
    assert_eq!(
        mint_authorities(env, &mint).await,
        (
            Some(new_owner_programmatic_signer),
            Some(new_owner_programmatic_signer)
        )
    );
}

pub async fn migrates_token_mint_authorities(env: &TestEnv) {
    migrates_mint_authorities(env, &spl_token_interface::id()).await;
}

pub async fn migrates_token_2022_mint_authorities(env: &TestEnv) {
    migrates_mint_authorities(env, &spl_token_2022_interface::id()).await;
}

async fn migrates_mint_authorities_one_at_a_time(env: &TestEnv, token_program: &Address) {
    // The owner holds both authorities and moves them to its own programmatic signer, the default
    // new authority.
    let owner = Keypair::new();
    let owner_signer = programmatic_signer(&owner.pubkey());
    let mint = create_mint(env, token_program, &owner.pubkey(), Some(&owner.pubkey())).await;
    let nonce_account = create_nonce(env, &owner.pubkey());

    let freeze: MintMigrationOutput =
        migrate(env, "mint", &mint, None, &["--authority-type", "freeze"]);
    assert_eq!(freeze.authority_types, ["freeze"]);
    assert_eq!(
        freeze.new_authority_signing_pubkey,
        owner.pubkey().to_string()
    );
    let message = decode_execution_message(&freeze.execution_message);
    assert_eq!(
        message.instructions.last().unwrap().data,
        format!("migrate freeze authority to {owner_signer}").as_bytes()
    );
    assert_signers(
        &freeze.required_signers,
        &[authorization(&owner.pubkey())],
        &[owner.pubkey()],
    );
    execute_as_new_owner(
        env,
        &freeze.execution_message,
        &nonce_account,
        &owner,
        &[],
        &[&owner],
    )
    .await;
    assert_eq!(
        mint_authorities(env, &mint).await,
        (Some(owner.pubkey()), Some(owner_signer))
    );

    let stderr = migrate_error(
        env,
        "mint",
        &mint,
        Some(&owner.pubkey()),
        &["--authority-type", "freeze"],
    );
    assert!(
        stderr.contains(&format!(
            "the freeze authority of mint {mint} is already {owner_signer}"
        )),
        "{stderr}"
    );
    // The freeze authority already moved, so moving both is rejected too.
    let stderr = migrate_error(env, "mint", &mint, Some(&owner.pubkey()), &[]);
    assert!(stderr.contains("is already"), "{stderr}");

    // The freeze authority is now a programmatic signer, which can't be the default new authority.
    let stderr = migrate_error(env, "mint", &mint, None, &["--authority-type", "freeze"]);
    assert!(
        stderr.contains(&format!(
            "the current authority of mint {mint} is {owner_signer}, which is not an on-curve \
             address"
        )),
        "{stderr}"
    );

    // The mint and freeze authorities differ, so neither is the default for moving both.
    let stderr = migrate_error(env, "mint", &mint, None, &[]);
    assert!(
        stderr.contains(&format!(
            "the mint authority {} and freeze authority {owner_signer} of mint {mint} differ",
            owner.pubkey()
        )),
        "{stderr}"
    );

    let mint_only: MintMigrationOutput =
        migrate(env, "mint", &mint, None, &["--authority-type", "mint"]);
    execute_as_new_owner(
        env,
        &mint_only.execution_message,
        &nonce_account,
        &owner,
        &[],
        &[&owner],
    )
    .await;
    assert_eq!(
        mint_authorities(env, &mint).await,
        (Some(owner_signer), Some(owner_signer))
    );
}

pub async fn migrates_token_mint_authorities_one_at_a_time(env: &TestEnv) {
    migrates_mint_authorities_one_at_a_time(env, &spl_token_interface::id()).await;
}

pub async fn migrates_token_2022_mint_authorities_one_at_a_time(env: &TestEnv) {
    migrates_mint_authorities_one_at_a_time(env, &spl_token_2022_interface::id()).await;
}

pub async fn migrates_mint_authorities_between_programmatic_signers(env: &TestEnv) {
    let old_owner = Keypair::new();
    let old_owner_programmatic_signer = programmatic_signer(&old_owner.pubkey());
    let new_owner = Keypair::new();
    let new_owner_programmatic_signer = programmatic_signer(&new_owner.pubkey());
    let mint = create_mint(
        env,
        &spl_token_interface::id(),
        &old_owner_programmatic_signer,
        Some(&old_owner_programmatic_signer),
    )
    .await;
    let nonce_account = create_nonce(env, &new_owner.pubkey());

    // The current authorities are a programmatic signer, which can't be traced back to its signing
    // pubkey, and nothing signs the relay transaction for it.
    let migration: MintMigrationOutput =
        migrate(env, "mint", &mint, Some(&new_owner.pubkey()), &[]);
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
        mint_authorities(env, &mint).await,
        (
            Some(new_owner_programmatic_signer),
            Some(new_owner_programmatic_signer)
        )
    );
}

pub async fn migrates_mint_without_freeze_authority(env: &TestEnv) {
    let mint_authority = Keypair::new();
    let new_owner = Keypair::new();
    let mint = create_mint(
        env,
        &spl_token_interface::id(),
        &mint_authority.pubkey(),
        None,
    )
    .await;
    let nonce_account = create_nonce(env, &new_owner.pubkey());

    // An unset authority is skipped when moving both.
    let migration: MintMigrationOutput =
        migrate(env, "mint", &mint, Some(&new_owner.pubkey()), &[]);
    assert_eq!(migration.authority_types, ["mint"]);
    assert_eq!(migration.unset_authority_types, ["freeze"]);
    execute_as_new_owner(
        env,
        &migration.execution_message,
        &nonce_account,
        &new_owner,
        &[],
        &[&mint_authority],
    )
    .await;
    assert_eq!(
        mint_authorities(env, &mint).await,
        (Some(programmatic_signer(&new_owner.pubkey())), None)
    );

    // Asking for it explicitly is an error.
    let stderr = migrate_error(
        env,
        "mint",
        &mint,
        Some(&new_owner.pubkey()),
        &["--authority-type", "freeze"],
    );
    assert!(
        stderr.contains(&format!("mint {mint} has no freeze authority")),
        "{stderr}"
    );
}

pub async fn rejects_invalid_mint_migrations(env: &TestEnv) {
    let authority = Keypair::new();
    let owner = Keypair::new();
    let token_program = spl_token_interface::id();
    let mint = create_mint(env, &token_program, &authority.pubkey(), None).await;

    // Passing the programmatic signer in place of its authority.
    let owner_signer = programmatic_signer(&owner.pubkey());
    let stderr = migrate_error(env, "mint", &mint, Some(&owner_signer), &[]);
    assert!(
        stderr.contains(&format!(
            "new authority signing pubkey {owner_signer} is not an on-curve address"
        )),
        "{stderr}"
    );

    let stderr = migrate_error(env, "mint", &env.payer.pubkey(), Some(&owner.pubkey()), &[]);
    assert!(
        stderr.contains(&format!(
            "account {} is owned by 11111111111111111111111111111111, not the Token or Token-2022 \
             Program",
            env.payer.pubkey()
        )),
        "{stderr}"
    );

    // With the mint authority revoked as well, nothing is left to move.
    send(
        env,
        &[set_authority(
            &token_program,
            &mint,
            None,
            AuthorityType::MintTokens,
            &authority.pubkey(),
            &[],
        )
        .unwrap()],
        &[&authority],
    )
    .await;
    let stderr = migrate_error(env, "mint", &mint, Some(&owner.pubkey()), &[]);
    assert!(
        stderr.contains(&format!("mint {mint} has no mint or freeze authority")),
        "{stderr}"
    );
}
