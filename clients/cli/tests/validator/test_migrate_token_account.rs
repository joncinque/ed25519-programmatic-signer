use {
    crate::{
        common::{
            execute::programmatic_signer,
            helpers::{TestEnv, run_psigner},
        },
        migration::{
            assert_signers, authorization, create_nonce, decode_execution_message,
            execute_as_new_owner, migrate, migrate_error, send,
        },
        test_migrate_token::{DECIMALS, create_mint, mint_tokens},
    },
    solana_address::Address,
    solana_keypair::Keypair,
    solana_native_token::LAMPORTS_PER_SOL,
    solana_program_pack::Pack,
    solana_signer::Signer,
    solana_system_interface::instruction::create_account,
    spl_programmatic_signer_cli::TokenAccountMigrationOutput,
    spl_token_2022_interface::{
        extension::{ExtensionType, StateWithExtensions, cpi_guard::instruction::enable_cpi_guard},
        instruction::{
            AuthorityType, approve, freeze_account, initialize_account3,
            initialize_immutable_owner, mint_to_checked, reallocate, set_authority,
        },
        state::Account as TokenAccount,
    },
};

/// Create a token account for `owner` at a new address, not its associated token account, with
/// the given Token-2022 extensions, of which only `ImmutableOwner` is supported, and mint `amount`
/// to it.
pub async fn create_token_account(
    env: &TestEnv,
    token_program: &Address,
    mint: &Address,
    owner: &Address,
    extensions: &[ExtensionType],
    amount: u64,
) -> Address {
    let account = Keypair::new();
    let payer = env.payer.pubkey();
    let space = ExtensionType::try_calculate_account_len::<TokenAccount>(extensions).unwrap();
    let lamports = env
        .rpc
        .get_minimum_balance_for_rent_exemption(space)
        .await
        .unwrap();
    let mut instructions = vec![create_account(
        &payer,
        &account.pubkey(),
        lamports,
        space.try_into().unwrap(),
        token_program,
    )];
    for extension in extensions {
        assert_eq!(*extension, ExtensionType::ImmutableOwner);
        instructions.push(initialize_immutable_owner(token_program, &account.pubkey()).unwrap());
    }
    instructions.extend([
        initialize_account3(token_program, &account.pubkey(), mint, owner).unwrap(),
        mint_to_checked(
            token_program,
            mint,
            &account.pubkey(),
            &payer,
            &[],
            amount,
            DECIMALS,
        )
        .unwrap(),
    ]);
    send(env, &instructions, &[&account]).await;
    account.pubkey()
}

/// Create a wrapped SOL token account for `owner` holding one SOL.
async fn create_wrapped_sol_account(env: &TestEnv, owner: &Address) -> Address {
    let account = Keypair::new();
    let token_program = spl_token_interface::id();
    let lamports = env
        .rpc
        .get_minimum_balance_for_rent_exemption(TokenAccount::LEN)
        .await
        .unwrap();
    send(
        env,
        &[
            create_account(
                &env.payer.pubkey(),
                &account.pubkey(),
                lamports.checked_add(LAMPORTS_PER_SOL).unwrap(),
                TokenAccount::LEN.try_into().unwrap(),
                &token_program,
            ),
            initialize_account3(
                &token_program,
                &account.pubkey(),
                &spl_token_interface::native_mint::id(),
                owner,
            )
            .unwrap(),
        ],
        &[&account],
    )
    .await;
    account.pubkey()
}

/// Set the token account's close authority, signed by `owner` as the current one.
async fn set_close_authority(
    env: &TestEnv,
    token_program: &Address,
    account: &Address,
    owner: &Keypair,
    close_authority: &Address,
) {
    send(
        env,
        &[set_authority(
            token_program,
            account,
            Some(close_authority),
            AuthorityType::CloseAccount,
            &owner.pubkey(),
            &[],
        )
        .unwrap()],
        &[owner],
    )
    .await;
}

async fn token_account(env: &TestEnv, account: &Address) -> TokenAccount {
    let data = env.rpc.get_account_data(account).await.unwrap();
    StateWithExtensions::<TokenAccount>::unpack(&data)
        .unwrap()
        .base
}

async fn migrates_token_account_authorities(env: &TestEnv, token_program: &Address) {
    let owner = Keypair::new();
    let delegate = Address::new_unique();
    let new_owner = Keypair::new();
    let new_owner_programmatic_signer = programmatic_signer(&new_owner.pubkey());
    let mint = create_mint(env, token_program, &[]).await;
    let account =
        create_token_account(env, token_program, &mint, &owner.pubkey(), &[], 1_000).await;
    set_close_authority(env, token_program, &account, &owner, &owner.pubkey()).await;
    send(
        env,
        &[approve(
            token_program,
            &account,
            &delegate,
            &owner.pubkey(),
            &[],
            100,
        )
        .unwrap()],
        &[&owner],
    )
    .await;
    let nonce_account = create_nonce(env, &new_owner.pubkey());

    // Without a new authority, the account moves to the owner's own programmatic signer.
    let default: TokenAccountMigrationOutput = migrate(env, "token-account", &account, None, &[]);
    assert_eq!(
        default.new_authority_signing_pubkey,
        owner.pubkey().to_string()
    );

    let migration: TokenAccountMigrationOutput = migrate(
        env,
        "token-account",
        &account,
        Some(&new_owner.pubkey()),
        &[],
    );
    assert_eq!(migration.token_account, account.to_string());
    assert_eq!(migration.mint, mint.to_string());
    assert_eq!(migration.token_program, token_program.to_string());
    assert_eq!(migration.owner, owner.pubkey().to_string());
    assert!(!migration.associated);
    assert_eq!(migration.authority_types, ["owner", "close"]);
    assert!(migration.unset_authority_types.is_empty());
    assert_eq!(migration.revoked_delegate, Some(delegate.to_string()));
    assert_eq!(migration.unset_close_authority, None);
    assert_eq!(
        migration.new_authority,
        new_owner_programmatic_signer.to_string()
    );
    assert_signers(
        &migration.required_signers,
        &[authorization(&new_owner.pubkey())],
        &[owner.pubkey()],
    );

    let message = decode_execution_message(&migration.execution_message);
    // `SetAuthority` data is its tag then the authority type. The close authority moves first.
    let authority_types = message.instructions[..2]
        .iter()
        .map(|instruction| instruction.data[1])
        .collect::<Vec<_>>();
    assert_eq!(
        authority_types,
        [
            AuthorityType::CloseAccount as u8,
            AuthorityType::AccountOwner as u8
        ]
    );
    // `SetAuthority` doesn't list the new authority, so the memo must.
    let memo = message.instructions.last().unwrap();
    assert_eq!(
        message.account_keys[usize::from(memo.program_id_index)],
        spl_memo_interface::v4::id()
    );
    assert_eq!(memo.accounts, [0]);
    assert_eq!(
        memo.data,
        format!(
            "migrate token account owner and close authority to {new_owner_programmatic_signer}"
        )
        .as_bytes()
    );

    execute_as_new_owner(
        env,
        &migration.execution_message,
        &nonce_account,
        &new_owner,
        &[],
        &[&owner],
    )
    .await;
    let state = token_account(env, &account).await;
    assert_eq!(state.owner, new_owner_programmatic_signer);
    assert_eq!(
        Option::<Address>::from(state.close_authority),
        Some(new_owner_programmatic_signer)
    );
    assert_eq!(Option::<Address>::from(state.delegate), None);
    assert_eq!(state.amount, 1_000);
}

pub async fn migrates_token_account(env: &TestEnv) {
    migrates_token_account_authorities(env, &spl_token_interface::id()).await;
}

pub async fn migrates_token_2022_account(env: &TestEnv) {
    migrates_token_account_authorities(env, &spl_token_2022_interface::id()).await;
}

pub async fn migrates_token_account_authorities_one_at_a_time(env: &TestEnv) {
    let owner = Keypair::new();
    let close_authority = Keypair::new();
    let new_owner = Keypair::new();
    let new_owner_programmatic_signer = programmatic_signer(&new_owner.pubkey());
    let token_program = spl_token_interface::id();
    let mint = create_mint(env, &token_program, &[]).await;
    let account =
        create_token_account(env, &token_program, &mint, &owner.pubkey(), &[], 1_000).await;
    set_close_authority(
        env,
        &token_program,
        &account,
        &owner,
        &close_authority.pubkey(),
    )
    .await;
    let nonce_account = create_nonce(env, &new_owner.pubkey());

    let stderr = migrate_error(env, "token-account", &account, None, &[]);
    assert!(
        stderr.contains(&format!(
            "the owner {} and close authority {} of token account {account} differ",
            owner.pubkey(),
            close_authority.pubkey()
        )),
        "{stderr}"
    );

    let migration: TokenAccountMigrationOutput = migrate(
        env,
        "token-account",
        &account,
        Some(&new_owner.pubkey()),
        &["--authority-type", "owner"],
    );
    assert_eq!(migration.authority_types, ["owner"]);
    assert!(migration.unset_authority_types.is_empty());
    assert_signers(
        &migration.required_signers,
        &[authorization(&new_owner.pubkey())],
        &[owner.pubkey()],
    );
    execute_as_new_owner(
        env,
        &migration.execution_message,
        &nonce_account,
        &new_owner,
        &[],
        &[&owner],
    )
    .await;
    let state = token_account(env, &account).await;
    assert_eq!(state.owner, new_owner_programmatic_signer);
    assert_eq!(
        Option::<Address>::from(state.close_authority),
        Some(close_authority.pubkey())
    );

    let migration: TokenAccountMigrationOutput = migrate(
        env,
        "token-account",
        &account,
        Some(&new_owner.pubkey()),
        &["--authority-type", "close"],
    );
    assert_eq!(migration.authority_types, ["close"]);
    assert_eq!(migration.revoked_delegate, None);
    assert_signers(
        &migration.required_signers,
        &[authorization(&new_owner.pubkey())],
        &[close_authority.pubkey()],
    );
    execute_as_new_owner(
        env,
        &migration.execution_message,
        &nonce_account,
        &new_owner,
        &[],
        &[&close_authority],
    )
    .await;
    let state = token_account(env, &account).await;
    assert_eq!(
        Option::<Address>::from(state.close_authority),
        Some(new_owner_programmatic_signer)
    );

    // Without a close authority, the owner has it and it changes with the owner.
    let account =
        create_token_account(env, &token_program, &mint, &owner.pubkey(), &[], 1_000).await;
    let migration: TokenAccountMigrationOutput = migrate(
        env,
        "token-account",
        &account,
        Some(&new_owner.pubkey()),
        &[],
    );
    assert_eq!(migration.authority_types, ["owner"]);
    assert_eq!(migration.unset_authority_types, ["close"]);
    let stderr = migrate_error(
        env,
        "token-account",
        &account,
        Some(&new_owner.pubkey()),
        &["--authority-type", "close"],
    );
    assert!(
        stderr.contains(&format!(
            "token account {account} has no close authority, so its owner can close it"
        )),
        "{stderr}"
    );
}

pub async fn migrates_associated_token_account_with_allow_ata(env: &TestEnv) {
    let owner = Keypair::new();
    let new_owner = Keypair::new();
    let new_owner_programmatic_signer = programmatic_signer(&new_owner.pubkey());
    let token_program = spl_token_interface::id();
    let mint = create_mint(env, &token_program, &[]).await;
    let account = mint_tokens(env, &token_program, &mint, &owner.pubkey(), 1_000).await;
    let nonce_account = create_nonce(env, &new_owner.pubkey());

    let stderr = migrate_error(
        env,
        "token-account",
        &account,
        Some(&new_owner.pubkey()),
        &[],
    );
    assert!(
        stderr.contains(&format!(
            "token account {account} is {}'s associated token account. Use `migrate token`",
            owner.pubkey()
        )),
        "{stderr}"
    );
    assert!(stderr.contains("Pass --allow-ata"), "{stderr}");

    let migration: TokenAccountMigrationOutput = migrate(
        env,
        "token-account",
        &account,
        Some(&new_owner.pubkey()),
        &["--allow-ata"],
    );
    assert!(migration.associated);
    assert_eq!(migration.authority_types, ["owner"]);
    let display = String::from_utf8(
        run_psigner(&[
            "-C",
            &env.config_file_path,
            "migrate",
            "token-account",
            &account.to_string(),
            "--new-authority-signing-pubkey",
            &new_owner.pubkey().to_string(),
            "--allow-ata",
        ])
        .stdout,
    )
    .unwrap();
    assert!(
        display.contains("This is the owner's associated token account."),
        "{display}"
    );

    execute_as_new_owner(
        env,
        &migration.execution_message,
        &nonce_account,
        &new_owner,
        &[],
        &[&owner],
    )
    .await;
    let state = token_account(env, &account).await;
    assert_eq!(state.owner, new_owner_programmatic_signer);
    assert_eq!(state.amount, 1_000);

    // A Token-2022 associated token account's owner is immutable, but its close authority can
    // still move.
    let token_program = spl_token_2022_interface::id();
    let mint = create_mint(env, &token_program, &[]).await;
    let account = mint_tokens(env, &token_program, &mint, &owner.pubkey(), 1_000).await;
    let stderr = migrate_error(
        env,
        "token-account",
        &account,
        Some(&new_owner.pubkey()),
        &["--allow-ata"],
    );
    assert!(
        stderr.contains(&format!(
            "token account {account} has an immutable owner, so its owner can't change"
        )),
        "{stderr}"
    );
    set_close_authority(env, &token_program, &account, &owner, &owner.pubkey()).await;
    let migration: TokenAccountMigrationOutput = migrate(
        env,
        "token-account",
        &account,
        Some(&new_owner.pubkey()),
        &["--authority-type", "close"],
    );
    assert!(migration.associated);
    execute_as_new_owner(
        env,
        &migration.execution_message,
        &nonce_account,
        &new_owner,
        &[],
        &[&owner],
    )
    .await;
    let state = token_account(env, &account).await;
    assert_eq!(state.owner, owner.pubkey());
    assert_eq!(
        Option::<Address>::from(state.close_authority),
        Some(new_owner_programmatic_signer)
    );
}

pub async fn migrates_wrapped_sol_token_account(env: &TestEnv) {
    let owner = Keypair::new();
    let close_authority = Address::new_unique();
    let new_owner = Keypair::new();
    let new_owner_programmatic_signer = programmatic_signer(&new_owner.pubkey());
    let token_program = spl_token_interface::id();
    let nonce_account = create_nonce(env, &new_owner.pubkey());

    // Changing the owner unsets a wrapped SOL account's close authority.
    let account = create_wrapped_sol_account(env, &owner.pubkey()).await;
    set_close_authority(env, &token_program, &account, &owner, &close_authority).await;
    let migration: TokenAccountMigrationOutput = migrate(
        env,
        "token-account",
        &account,
        Some(&new_owner.pubkey()),
        &["--authority-type", "owner"],
    );
    assert_eq!(
        migration.unset_close_authority,
        Some(close_authority.to_string())
    );
    execute_as_new_owner(
        env,
        &migration.execution_message,
        &nonce_account,
        &new_owner,
        &[],
        &[&owner],
    )
    .await;
    let state = token_account(env, &account).await;
    assert_eq!(state.owner, new_owner_programmatic_signer);
    assert_eq!(Option::<Address>::from(state.close_authority), None);

    // Moving both works because the close authority moves before the owner change unsets it.
    let account = create_wrapped_sol_account(env, &owner.pubkey()).await;
    set_close_authority(env, &token_program, &account, &owner, &owner.pubkey()).await;
    let migration: TokenAccountMigrationOutput = migrate(
        env,
        "token-account",
        &account,
        Some(&new_owner.pubkey()),
        &[],
    );
    assert_eq!(migration.authority_types, ["owner", "close"]);
    assert_eq!(migration.unset_close_authority, None);
    execute_as_new_owner(
        env,
        &migration.execution_message,
        &nonce_account,
        &new_owner,
        &[],
        &[&owner],
    )
    .await;
    let state = token_account(env, &account).await;
    assert_eq!(state.owner, new_owner_programmatic_signer);
    assert_eq!(Option::<Address>::from(state.close_authority), None);
}

pub async fn rejects_invalid_token_account_migrations(env: &TestEnv) {
    let owner = Keypair::new();
    let new_owner = Keypair::new();
    let new_owner_programmatic_signer = programmatic_signer(&new_owner.pubkey());
    let token_program = spl_token_interface::id();
    let token_2022_program = spl_token_2022_interface::id();
    let mint = create_mint(env, &token_program, &[]).await;
    let mint_2022 = create_mint(env, &token_2022_program, &[]).await;
    let migrate_error = |account: &Address| {
        migrate_error(
            env,
            "token-account",
            account,
            Some(&new_owner.pubkey()),
            &[],
        )
    };

    let missing = Address::new_unique();
    let stderr = migrate_error(&missing);
    assert!(
        stderr.contains(&format!("token account {missing} was not found")),
        "{stderr}"
    );

    let stderr = migrate_error(&mint);
    assert!(
        stderr.contains(&format!("account {mint} is not a token account")),
        "{stderr}"
    );

    let account = create_token_account(
        env,
        &token_program,
        &mint,
        &new_owner_programmatic_signer,
        &[],
        1_000,
    )
    .await;
    let stderr = migrate_error(&account);
    assert!(
        stderr.contains(&format!(
            "the owner of token account {account} is already {new_owner_programmatic_signer}"
        )),
        "{stderr}"
    );

    let account =
        create_token_account(env, &token_program, &mint, &owner.pubkey(), &[], 1_000).await;
    send(
        env,
        &[freeze_account(&token_program, &account, &mint, &env.payer.pubkey(), &[]).unwrap()],
        &[],
    )
    .await;
    let stderr = migrate_error(&account);
    assert!(
        stderr.contains(&format!(
            "token account {account} is frozen, so its authorities can't change"
        )),
        "{stderr}"
    );

    let account = create_token_account(
        env,
        &token_2022_program,
        &mint_2022,
        &owner.pubkey(),
        &[ExtensionType::ImmutableOwner],
        1_000,
    )
    .await;
    let stderr = migrate_error(&account);
    assert!(
        stderr.contains(&format!(
            "token account {account} has an immutable owner, so its owner can't change"
        )),
        "{stderr}"
    );

    let account = create_token_account(
        env,
        &token_2022_program,
        &mint_2022,
        &owner.pubkey(),
        &[],
        1_000,
    )
    .await;
    send(
        env,
        &[
            reallocate(
                &token_2022_program,
                &account,
                &env.payer.pubkey(),
                &owner.pubkey(),
                &[],
                &[ExtensionType::CpiGuard],
            )
            .unwrap(),
            enable_cpi_guard(&token_2022_program, &account, &owner.pubkey(), &[]).unwrap(),
        ],
        &[&owner],
    )
    .await;
    let stderr = migrate_error(&account);
    assert!(
        stderr.contains(&format!(
            "token account {account} has the CPI guard enabled"
        )),
        "{stderr}"
    );
}
