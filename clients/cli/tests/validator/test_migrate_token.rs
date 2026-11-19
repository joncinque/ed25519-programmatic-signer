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
    },
    base64::{Engine, prelude::BASE64_STANDARD},
    solana_address::Address,
    solana_hash::Hash,
    solana_keypair::Keypair,
    solana_message::v1,
    solana_native_token::LAMPORTS_PER_SOL,
    solana_program_pack::Pack,
    solana_signer::Signer,
    solana_system_interface::instruction::{create_account, transfer},
    spl_associated_token_account_interface::{
        address::get_associated_token_address_with_program_id,
        instruction::create_associated_token_account_idempotent,
    },
    spl_programmatic_signer_cli::{Authorization, TokenMigrationOutput},
    spl_token_2022_interface::{
        extension::{
            ExtensionType, StateWithExtensions,
            cpi_guard::instruction::enable_cpi_guard,
            default_account_state::instruction::initialize_default_account_state,
            scaled_ui_amount,
            transfer_fee::instruction::{
                harvest_withheld_tokens_to_mint, initialize_transfer_fee_config, set_transfer_fee,
                transfer_checked_with_fee,
            },
            transfer_hook,
        },
        instruction::{
            AuthorityType, close_account, freeze_account, initialize_account3, initialize_mint2,
            initialize_non_transferable_mint, mint_to_checked, reallocate, set_authority,
            thaw_account, transfer_checked,
        },
        state::{Account as TokenAccount, AccountState, Mint},
    },
};

pub const DECIMALS: u8 = 2;
/// The UI amount multiplier of mints created with the `ScaledUiAmount` extension.
pub const SCALED_UI_AMOUNT_MULTIPLIER: f64 = 2.0;

/// Create a mint with the test payer as its mint and freeze authority, and the given Token-2022
/// extensions.
pub async fn create_mint(
    env: &TestEnv,
    token_program: &Address,
    extensions: &[ExtensionType],
) -> Address {
    let mint = Keypair::new();
    let payer = env.payer.pubkey();
    let space = ExtensionType::try_calculate_account_len::<Mint>(extensions).unwrap();
    let lamports = env
        .rpc
        .get_minimum_balance_for_rent_exemption(space)
        .await
        .unwrap();
    let mut instructions = vec![create_account(
        &payer,
        &mint.pubkey(),
        lamports,
        space.try_into().unwrap(),
        token_program,
    )];
    for extension in extensions {
        instructions.push(
            match extension {
                ExtensionType::NonTransferable => {
                    initialize_non_transferable_mint(token_program, &mint.pubkey())
                }
                ExtensionType::TransferHook => transfer_hook::instruction::initialize(
                    token_program,
                    &mint.pubkey(),
                    None,
                    Some(Address::new_unique()),
                ),
                ExtensionType::DefaultAccountState => initialize_default_account_state(
                    token_program,
                    &mint.pubkey(),
                    &AccountState::Frozen,
                ),
                ExtensionType::ScaledUiAmount => scaled_ui_amount::instruction::initialize(
                    token_program,
                    &mint.pubkey(),
                    None,
                    SCALED_UI_AMOUNT_MULTIPLIER,
                ),
                ExtensionType::TransferFeeConfig => initialize_transfer_fee_config(
                    token_program,
                    &mint.pubkey(),
                    Some(&payer),
                    None,
                    100, // transfer fee basis points
                    u64::MAX,
                ),
                extension => panic!("unsupported extension {extension:?}"),
            }
            .unwrap(),
        );
    }
    instructions.push(
        initialize_mint2(
            token_program,
            &mint.pubkey(),
            &payer,
            Some(&payer),
            DECIMALS,
        )
        .unwrap(),
    );
    send(env, &instructions, &[&mint]).await;
    mint.pubkey()
}

/// Mint `amount` to `owner`'s associated token account, creating it, and return the account.
pub async fn mint_tokens(
    env: &TestEnv,
    token_program: &Address,
    mint: &Address,
    owner: &Address,
    amount: u64,
) -> Address {
    let payer = env.payer.pubkey();
    let account = get_associated_token_address_with_program_id(owner, mint, token_program);
    send(
        env,
        &[
            create_associated_token_account_idempotent(&payer, owner, mint, token_program),
            mint_to_checked(token_program, mint, &account, &payer, &[], amount, DECIMALS).unwrap(),
        ],
        &[],
    )
    .await;
    account
}

/// Create a token account for `owner` at a new address, not its associated token account, and
/// mint `amount` to it.
pub async fn mint_to_new_account(
    env: &TestEnv,
    token_program: &Address,
    mint: &Address,
    owner: &Address,
    amount: u64,
) -> Address {
    let account = Keypair::new();
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
                lamports,
                TokenAccount::LEN.try_into().unwrap(),
                token_program,
            ),
            initialize_account3(token_program, &account.pubkey(), mint, owner).unwrap(),
            mint_to_checked(
                token_program,
                mint,
                &account.pubkey(),
                &env.payer.pubkey(),
                &[],
                amount,
                DECIMALS,
            )
            .unwrap(),
        ],
        &[&account],
    )
    .await;
    account.pubkey()
}

/// Give `address` SOL, to pay rent for the new authority's token account.
async fn fund(env: &TestEnv, address: &Address) {
    send(
        env,
        &[transfer(&env.payer.pubkey(), address, LAMPORTS_PER_SOL)],
        &[],
    )
    .await;
}

async fn token_balance(env: &TestEnv, account: &Address) -> u64 {
    let data = env.rpc.get_account_data(account).await.unwrap();
    StateWithExtensions::<TokenAccount>::unpack(&data)
        .unwrap()
        .base
        .amount
}

async fn assert_closed(env: &TestEnv, account: &Address) {
    let account = env
        .rpc
        .get_account_with_commitment(account, env.rpc.commitment())
        .await;
    assert_eq!(account.unwrap().value, None);
}

async fn migrates_tokens(env: &TestEnv, token_program: &Address) {
    let owner = Keypair::new();
    let owner_arg = owner.pubkey().to_string();
    let new_owner = Keypair::new();
    let new_owner_programmatic_signer = programmatic_signer(&new_owner.pubkey());
    fund(env, &owner.pubkey()).await;
    let mint = create_mint(env, token_program, &[]).await;
    let source = mint_tokens(env, token_program, &mint, &owner.pubkey(), 1_000).await;
    let destination = get_associated_token_address_with_program_id(
        &new_owner_programmatic_signer,
        &mint,
        token_program,
    );
    let nonce_account = create_nonce(env, &new_owner.pubkey());

    // Without a new authority, the tokens move to the owner's own programmatic signer.
    let default: TokenMigrationOutput = migrate(
        env,
        "token",
        &mint,
        None,
        &["--owner", &owner_arg, "--amount", "2.5"],
    );
    assert_eq!(default.new_authority_signing_pubkey, owner_arg);

    // Without an owner, the tokens move from the configured keypair's token account.
    let payer_source = mint_tokens(env, token_program, &mint, &env.payer.pubkey(), 1).await;
    let default_owner: TokenMigrationOutput = migrate(env, "token", &mint, None, &[]);
    assert_eq!(default_owner.source, payer_source.to_string());
    assert_eq!(
        default_owner.new_authority_signing_pubkey,
        env.payer_address
    );

    // The new authority has no token account yet, so the migration creates it, paid for by the
    // owner.
    let migration: TokenMigrationOutput = migrate(
        env,
        "token",
        &mint,
        Some(&new_owner.pubkey()),
        &["--owner", &owner_arg, "--amount", "2.5"],
    );
    assert_eq!(migration.mint, mint.to_string());
    assert_eq!(migration.token_program, token_program.to_string());
    assert_eq!(migration.amount, "2.5");
    assert_eq!(migration.source, source.to_string());
    assert_eq!(migration.destination, destination.to_string());
    assert_eq!(migration.funder, Some(owner_arg.clone()));
    assert_eq!(migration.transfer_fee, None);
    // Tokens are left behind, so the source stays open.
    assert_eq!(migration.rent_recipient, None);
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
            spl_associated_token_account_interface::program::id(),
            *token_program,
            spl_memo_interface::v4::id(),
        ]
    );
    // The transfer doesn't list the new authority, so the memo must, or nothing onchain would
    // require the new authority's approval.
    let memo = message.instructions.last().unwrap();
    assert_eq!(memo.accounts, [0]);
    assert_eq!(memo.data, b"migrate tokens");

    execute_as_new_owner(
        env,
        &migration.execution_message,
        &nonce_account,
        &new_owner,
        &[],
        &[&owner],
    )
    .await;
    assert_eq!(token_balance(env, &source).await, 750);
    assert_eq!(token_balance(env, &destination).await, 250);

    // The new authority's token account exists now, and without an amount the rest moves. The
    // emptied source stays open, as asked.
    let migration: TokenMigrationOutput = migrate(
        env,
        "token",
        &mint,
        Some(&new_owner.pubkey()),
        &["--owner", &owner_arg, "--no-close"],
    );
    assert_eq!(migration.amount, "7.5");
    assert_eq!(migration.funder, None);
    assert_eq!(migration.rent_recipient, None);
    let message = decode_execution_message(&migration.execution_message);
    assert_eq!(message.instructions.len(), 2);
    execute_as_new_owner(
        env,
        &migration.execution_message,
        &nonce_account,
        &new_owner,
        &[],
        &[&owner],
    )
    .await;
    assert_eq!(token_balance(env, &source).await, 0);
    assert_eq!(token_balance(env, &destination).await, 1_000);

    // Zero balance left and --no-close, error
    let stderr = migrate_error(
        env,
        "token",
        &mint,
        Some(&new_owner.pubkey()),
        &["--owner", &owner_arg, "--no-close"],
    );
    assert!(
        stderr.contains(&format!(
            "token account {source} has no balance, remove --no-close to close it"
        )),
        "{stderr}"
    );

    // We can close the empty token account, even when it's frozen
    send(
        env,
        &[freeze_account(token_program, &source, &mint, &env.payer.pubkey(), &[]).unwrap()],
        &[],
    )
    .await;
    let rent_recipient = Address::new_unique();
    let migration: TokenMigrationOutput = migrate(
        env,
        "token",
        &mint,
        Some(&new_owner.pubkey()),
        &[
            "--owner",
            &owner_arg,
            "--rent-recipient",
            &rent_recipient.to_string(),
        ],
    );
    assert_eq!(migration.amount, "0");
    assert_eq!(migration.funder, None);
    assert_eq!(migration.rent_recipient, Some(rent_recipient.to_string()));
    assert_signers(
        &migration.required_signers,
        &[authorization(&new_owner.pubkey())],
        &[owner.pubkey()],
    );
    let message = decode_execution_message(&migration.execution_message);
    let program_ids = message
        .instructions
        .iter()
        .map(|instruction| message.account_keys[usize::from(instruction.program_id_index)])
        .collect::<Vec<_>>();
    assert_eq!(program_ids, [*token_program, spl_memo_interface::v4::id()]);
    let rent = env.rpc.get_balance(&source).await.unwrap();
    execute_as_new_owner(
        env,
        &migration.execution_message,
        &nonce_account,
        &new_owner,
        &[],
        &[&owner],
    )
    .await;
    assert_closed(env, &source).await;
    assert_eq!(env.rpc.get_balance(&rent_recipient).await.unwrap(), rent);
    assert_eq!(token_balance(env, &destination).await, 1_000);

    let stderr = migrate_error(
        env,
        "token",
        &mint,
        Some(&new_owner.pubkey()),
        &["--owner", &owner_arg],
    );
    assert!(
        stderr.contains(&format!("associated token account {source} was not found")),
        "{stderr}"
    );
}

pub async fn migrates_token_balance(env: &TestEnv) {
    migrates_tokens(env, &spl_token_interface::id()).await;
}

pub async fn migrates_token_2022_balance(env: &TestEnv) {
    migrates_tokens(env, &spl_token_2022_interface::id()).await;
}

/// Move tokens out of a token account that isn't the owner's associated token account.
async fn migrates_tokens_from_source(env: &TestEnv, token_program: &Address) {
    let owner = Keypair::new();
    let new_owner_programmatic_signer = programmatic_signer(&owner.pubkey());
    fund(env, &owner.pubkey()).await;
    let mint = create_mint(env, token_program, &[]).await;
    let source = mint_to_new_account(env, token_program, &mint, &owner.pubkey(), 1_000).await;
    let source_arg = source.to_string();
    let destination = get_associated_token_address_with_program_id(
        &new_owner_programmatic_signer,
        &mint,
        token_program,
    );
    let nonce_account = create_nonce(env, &owner.pubkey());

    // The owner is read from the source, and stands in for the owner in the other defaults: the
    // new authority, the funder and the rent recipient.
    let migration: TokenMigrationOutput =
        migrate(env, "token", &mint, None, &["--source", &source_arg]);
    assert_eq!(migration.source, source_arg);
    assert_eq!(migration.destination, destination.to_string());
    assert_eq!(migration.amount, "10");
    assert_eq!(
        migration.new_authority_signing_pubkey,
        owner.pubkey().to_string()
    );
    assert_eq!(migration.funder, Some(owner.pubkey().to_string()));
    assert_eq!(migration.rent_recipient, Some(owner.pubkey().to_string()));
    assert_signers(
        &migration.required_signers,
        &[authorization(&owner.pubkey())],
        &[owner.pubkey()],
    );
    let rent = env.rpc.get_balance(&source).await.unwrap();
    let owner_balance = env.rpc.get_balance(&owner.pubkey()).await.unwrap();
    execute_as_new_owner(
        env,
        &migration.execution_message,
        &nonce_account,
        &owner,
        &[],
        &[&owner],
    )
    .await;
    assert_closed(env, &source).await;
    assert_eq!(token_balance(env, &destination).await, 1_000);
    // The owner gets the source's rent back, less the destination's rent it paid.
    let destination_rent = env.rpc.get_balance(&destination).await.unwrap();
    assert_eq!(
        env.rpc.get_balance(&owner.pubkey()).await.unwrap(),
        owner_balance
            .checked_add(rent)
            .and_then(|balance| balance.checked_sub(destination_rent))
            .unwrap()
    );

    // An associated token account can be passed as the source too.
    let associated = mint_tokens(env, token_program, &mint, &owner.pubkey(), 100).await;
    let from_source: TokenMigrationOutput = migrate(
        env,
        "token",
        &mint,
        None,
        &["--source", &associated.to_string()],
    );
    let from_owner: TokenMigrationOutput = migrate(
        env,
        "token",
        &mint,
        None,
        &["--owner", &owner.pubkey().to_string()],
    );
    assert_eq!(from_source.execution_message, from_owner.execution_message);
}

pub async fn migrates_token_balance_from_source(env: &TestEnv) {
    migrates_tokens_from_source(env, &spl_token_interface::id()).await;
}

pub async fn migrates_token_2022_balance_from_source(env: &TestEnv) {
    migrates_tokens_from_source(env, &spl_token_2022_interface::id()).await;
}

/// A Token Program associated token account can be given a new owner, which then moves its tokens
/// with --source.
pub async fn migrates_tokens_from_reassigned_associated_account(env: &TestEnv) {
    let owner = Keypair::new();
    let account_owner = Keypair::new();
    let new_owner = Keypair::new();
    let token_program = spl_token_interface::id();
    fund(env, &account_owner.pubkey()).await;
    let mint = create_mint(env, &token_program, &[]).await;
    let source = mint_tokens(env, &token_program, &mint, &owner.pubkey(), 1_000).await;
    send(
        env,
        &[set_authority(
            &token_program,
            &source,
            Some(&account_owner.pubkey()),
            AuthorityType::AccountOwner,
            &owner.pubkey(),
            &[],
        )
        .unwrap()],
        &[&owner],
    )
    .await;
    let nonce_account = create_nonce(env, &new_owner.pubkey());

    let stderr = migrate_error(
        env,
        "token",
        &mint,
        Some(&new_owner.pubkey()),
        &["--owner", &owner.pubkey().to_string()],
    );
    assert!(
        stderr.contains(&format!(
            "token account {source} is owned by {}, not {}. Pass --source {source} to move its \
             tokens as {}",
            account_owner.pubkey(),
            owner.pubkey(),
            account_owner.pubkey()
        )),
        "{stderr}"
    );

    let migration: TokenMigrationOutput = migrate(
        env,
        "token",
        &mint,
        Some(&new_owner.pubkey()),
        &["--source", &source.to_string()],
    );
    assert_signers(
        &migration.required_signers,
        &[authorization(&new_owner.pubkey())],
        &[account_owner.pubkey()],
    );
    execute_as_new_owner(
        env,
        &migration.execution_message,
        &nonce_account,
        &new_owner,
        &[],
        &[&account_owner],
    )
    .await;
    assert_closed(env, &source).await;
    let destination = get_associated_token_address_with_program_id(
        &programmatic_signer(&new_owner.pubkey()),
        &mint,
        &token_program,
    );
    assert_eq!(token_balance(env, &destination).await, 1_000);
}

pub async fn rejects_invalid_token_sources(env: &TestEnv) {
    let owner = Keypair::new();
    let new_owner = Keypair::new();
    let token_program = spl_token_interface::id();
    let mint = create_mint(env, &token_program, &[]).await;
    let other_mint = create_mint(env, &token_program, &[]).await;
    let mint_2022 = create_mint(env, &spl_token_2022_interface::id(), &[]).await;
    let source = mint_to_new_account(env, &token_program, &mint, &owner.pubkey(), 1_000).await;
    let source_arg = source.to_string();
    let migrate_error = |mint: &Address, extra: &[&str]| {
        migrate_error(env, "token", mint, Some(&new_owner.pubkey()), extra)
    };

    let stderr = migrate_error(
        &mint,
        &[
            "--source",
            &source_arg,
            "--owner",
            &owner.pubkey().to_string(),
        ],
    );
    assert!(stderr.contains("cannot be used with"), "{stderr}");

    let stderr = migrate_error(&other_mint, &["--source", &source_arg]);
    assert!(
        stderr.contains(&format!(
            "token account {source} holds mint {mint}, not {other_mint}"
        )),
        "{stderr}"
    );

    let stderr = migrate_error(&mint_2022, &["--source", &source_arg]);
    assert!(
        stderr.contains(&format!(
            "token account {source} is owned by {token_program}, but mint {mint_2022} is owned by \
             {}",
            spl_token_2022_interface::id()
        )),
        "{stderr}"
    );

    // A mint isn't a token account.
    let stderr = migrate_error(&mint, &["--source", &mint.to_string()]);
    assert!(
        stderr.contains(&format!("account {mint} is not a token account")),
        "{stderr}"
    );

    let missing = Address::new_unique();
    let stderr = migrate_error(&mint, &["--source", &missing.to_string()]);
    assert!(
        stderr.contains(&format!("token account {missing} was not found")),
        "{stderr}"
    );

    // The new authority's associated token account, reassigned to the owner, would be both the
    // source and the destination.
    let new_owner_programmatic_signer = programmatic_signer(&new_owner.pubkey());
    let destination = mint_tokens(
        env,
        &token_program,
        &mint,
        &new_owner_programmatic_signer,
        1_000,
    )
    .await;
    let reassign = v1::Message::try_compile_with_config(
        &new_owner_programmatic_signer,
        &[set_authority(
            &token_program,
            &destination,
            Some(&owner.pubkey()),
            AuthorityType::AccountOwner,
            &new_owner_programmatic_signer,
            &[],
        )
        .unwrap()],
        Hash::default(),
        v1::TransactionConfig::empty(),
    )
    .unwrap();
    let nonce_account = create_nonce(env, &new_owner.pubkey());
    execute_as_new_owner(
        env,
        &BASE64_STANDARD.encode(reassign.serialize()),
        &nonce_account,
        &new_owner,
        &[],
        &[],
    )
    .await;
    let stderr = migrate_error(&mint, &["--source", &destination.to_string()]);
    assert!(
        stderr.contains(&format!(
            "token account {destination} is both the source and the destination"
        )),
        "{stderr}"
    );
}

/// Move tokens into a token account that isn't the new authority's associated token account.
async fn migrates_tokens_to_destination(env: &TestEnv, token_program: &Address) {
    let owner = Keypair::new();
    let new_owner = Keypair::new();
    let new_owner_programmatic_signer = programmatic_signer(&new_owner.pubkey());
    let mint = create_mint(env, token_program, &[]).await;
    let source = mint_tokens(env, token_program, &mint, &owner.pubkey(), 1_000).await;
    let destination = mint_to_new_account(
        env,
        token_program,
        &mint,
        &new_owner_programmatic_signer,
        100,
    )
    .await;
    let destination_arg = destination.to_string();
    let associated = get_associated_token_address_with_program_id(
        &new_owner_programmatic_signer,
        &mint,
        token_program,
    );
    let nonce_account = create_nonce(env, &new_owner.pubkey());

    // The destination already exists, so nothing is created and no funder is needed.
    let migration: TokenMigrationOutput = migrate(
        env,
        "token",
        &mint,
        Some(&new_owner.pubkey()),
        &[
            "--owner",
            &owner.pubkey().to_string(),
            "--destination",
            &destination_arg,
        ],
    );
    assert_eq!(migration.source, source.to_string());
    assert_eq!(migration.destination, destination_arg);
    assert_eq!(migration.funder, None);
    assert_eq!(
        migration.new_authority,
        new_owner_programmatic_signer.to_string()
    );
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
    assert_closed(env, &source).await;
    assert_eq!(token_balance(env, &destination).await, 1_100);
    assert!(env.rpc.get_account(&associated).await.is_err());

    // The new authority's associated token account can be passed as the destination too.
    mint_tokens(env, token_program, &mint, &owner.pubkey(), 100).await;
    mint_tokens(env, token_program, &mint, &new_owner_programmatic_signer, 0).await;
    let owner_arg = owner.pubkey().to_string();
    let to_destination: TokenMigrationOutput = migrate(
        env,
        "token",
        &mint,
        Some(&new_owner.pubkey()),
        &[
            "--owner",
            &owner_arg,
            "--destination",
            &associated.to_string(),
        ],
    );
    let to_associated: TokenMigrationOutput = migrate(
        env,
        "token",
        &mint,
        Some(&new_owner.pubkey()),
        &["--owner", &owner_arg],
    );
    assert_eq!(
        to_destination.execution_message,
        to_associated.execution_message
    );
}

pub async fn migrates_token_balance_to_destination(env: &TestEnv) {
    migrates_tokens_to_destination(env, &spl_token_interface::id()).await;
}

pub async fn migrates_token_2022_balance_to_destination(env: &TestEnv) {
    migrates_tokens_to_destination(env, &spl_token_2022_interface::id()).await;
}

pub async fn rejects_invalid_token_destinations(env: &TestEnv) {
    let owner = Keypair::new();
    let new_owner = Keypair::new();
    let new_owner_programmatic_signer = programmatic_signer(&new_owner.pubkey());
    let token_program = spl_token_interface::id();
    let mint = create_mint(env, &token_program, &[]).await;
    let other_mint = create_mint(env, &token_program, &[]).await;
    let mint_2022 = create_mint(env, &spl_token_2022_interface::id(), &[]).await;
    let source = mint_tokens(env, &token_program, &mint, &owner.pubkey(), 1_000).await;
    let owner_arg = owner.pubkey().to_string();
    let migrate_error = |mint: &Address, destination: &Address, extra: &[&str]| {
        let destination = destination.to_string();
        let mut args = vec!["--owner", &owner_arg, "--destination", &destination];
        args.extend_from_slice(extra);
        migrate_error(env, "token", mint, Some(&new_owner.pubkey()), &args)
    };

    let destination = mint_to_new_account(
        env,
        &token_program,
        &mint,
        &new_owner_programmatic_signer,
        0,
    )
    .await;
    let stderr = migrate_error(
        &mint,
        &destination,
        &["--funder", &Address::new_unique().to_string()],
    );
    assert!(stderr.contains("cannot be used with"), "{stderr}");

    // Only an associated token account is created, so the destination must exist.
    let missing = Address::new_unique();
    let stderr = migrate_error(&mint, &missing, &[]);
    assert!(
        stderr.contains(&format!("token account {missing} was not found")),
        "{stderr}"
    );

    let stderr = migrate_error(&mint, &mint, &[]);
    assert!(
        stderr.contains(&format!("account {mint} is not a token account")),
        "{stderr}"
    );

    let stderr = migrate_error(&mint, &source, &[]);
    assert!(
        stderr.contains(&format!(
            "token account {source} is both the source and the destination"
        )),
        "{stderr}"
    );

    let other_mint_destination = mint_to_new_account(
        env,
        &token_program,
        &other_mint,
        &new_owner_programmatic_signer,
        0,
    )
    .await;
    let stderr = migrate_error(&mint, &other_mint_destination, &[]);
    assert!(
        stderr.contains(&format!(
            "token account {other_mint_destination} holds mint {other_mint}, not {mint}"
        )),
        "{stderr}"
    );

    let destination_2022 = mint_to_new_account(
        env,
        &spl_token_2022_interface::id(),
        &mint_2022,
        &new_owner_programmatic_signer,
        0,
    )
    .await;
    let stderr = migrate_error(&mint, &destination_2022, &[]);
    assert!(
        stderr.contains(&format!(
            "token account {destination_2022} is owned by {}, but mint {mint} is owned by \
             {token_program}",
            spl_token_2022_interface::id()
        )),
        "{stderr}"
    );

    // The destination must belong to the new authority's programmatic signer, not its signing
    // pubkey.
    let signing_pubkey_destination =
        mint_to_new_account(env, &token_program, &mint, &new_owner.pubkey(), 0).await;
    let stderr = migrate_error(&mint, &signing_pubkey_destination, &[]);
    assert!(
        stderr.contains(&format!(
            "token account {signing_pubkey_destination} is owned by {}, not the new authority's \
             programmatic signer {new_owner_programmatic_signer}",
            new_owner.pubkey()
        )),
        "{stderr}"
    );

    send(
        env,
        &[freeze_account(
            &token_program,
            &destination,
            &mint,
            &env.payer.pubkey(),
            &[],
        )
        .unwrap()],
        &[],
    )
    .await;
    let stderr = migrate_error(&mint, &destination, &[]);
    assert!(
        stderr.contains(&format!("token account {destination} is frozen")),
        "{stderr}"
    );
}

/// A Token Program associated token account can be given a new owner. If the new authority's
/// associated token account is reassigned away, the tokens move with --destination instead.
pub async fn migrates_tokens_past_reassigned_destination(env: &TestEnv) {
    let owner = Keypair::new();
    let new_owner = Keypair::new();
    let account_owner = Address::new_unique();
    let new_owner_programmatic_signer = programmatic_signer(&new_owner.pubkey());
    let token_program = spl_token_interface::id();
    let mint = create_mint(env, &token_program, &[]).await;
    let source = mint_tokens(env, &token_program, &mint, &owner.pubkey(), 1_000).await;
    let associated = mint_tokens(
        env,
        &token_program,
        &mint,
        &new_owner_programmatic_signer,
        0,
    )
    .await;
    let reassign = v1::Message::try_compile_with_config(
        &new_owner_programmatic_signer,
        &[set_authority(
            &token_program,
            &associated,
            Some(&account_owner),
            AuthorityType::AccountOwner,
            &new_owner_programmatic_signer,
            &[],
        )
        .unwrap()],
        Hash::default(),
        v1::TransactionConfig::empty(),
    )
    .unwrap();
    let nonce_account = create_nonce(env, &new_owner.pubkey());
    execute_as_new_owner(
        env,
        &BASE64_STANDARD.encode(reassign.serialize()),
        &nonce_account,
        &new_owner,
        &[],
        &[],
    )
    .await;
    let owner_arg = owner.pubkey().to_string();

    let stderr = migrate_error(
        env,
        "token",
        &mint,
        Some(&new_owner.pubkey()),
        &["--owner", &owner_arg],
    );
    assert!(
        stderr.contains(&format!(
            "token account {associated} is owned by {account_owner}, not the new authority's \
             programmatic signer {new_owner_programmatic_signer}. Pass --destination with a token \
             account owned by {new_owner_programmatic_signer}"
        )),
        "{stderr}"
    );

    let destination = mint_to_new_account(
        env,
        &token_program,
        &mint,
        &new_owner_programmatic_signer,
        0,
    )
    .await;
    let migration: TokenMigrationOutput = migrate(
        env,
        "token",
        &mint,
        Some(&new_owner.pubkey()),
        &[
            "--owner",
            &owner_arg,
            "--destination",
            &destination.to_string(),
        ],
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
    assert_closed(env, &source).await;
    assert_eq!(token_balance(env, &destination).await, 1_000);
    assert_eq!(token_balance(env, &associated).await, 0);
}

pub async fn migrates_tokens_with_funder(env: &TestEnv) {
    // The owner holds no SOL, so only the funder can pay rent for the new token account.
    let owner = Keypair::new();
    let funder = Keypair::new();
    let new_owner = Keypair::new();
    let token_program = spl_token_interface::id();
    fund(env, &funder.pubkey()).await;
    let mint = create_mint(env, &token_program, &[]).await;
    let source = mint_tokens(env, &token_program, &mint, &owner.pubkey(), 1_000).await;
    let nonce_account = create_nonce(env, &new_owner.pubkey());

    let migration: TokenMigrationOutput = migrate(
        env,
        "token",
        &mint,
        Some(&new_owner.pubkey()),
        &[
            "--owner",
            &owner.pubkey().to_string(),
            "--funder",
            &funder.pubkey().to_string(),
        ],
    );
    assert_eq!(migration.funder, Some(funder.pubkey().to_string()));
    // The rent goes to the new authority's signing pubkey by default
    assert_eq!(
        migration.rent_recipient,
        Some(new_owner.pubkey().to_string())
    );
    let message = decode_execution_message(&migration.execution_message);
    let close = message
        .instructions
        .iter()
        .find(|instruction| {
            message.account_keys[usize::from(instruction.program_id_index)] == token_program
                && instruction.data
                    == close_account(
                        &token_program,
                        &source,
                        &new_owner.pubkey(),
                        &owner.pubkey(),
                        &[],
                    )
                    .unwrap()
                    .data
        })
        .expect("the source is closed");
    assert_eq!(
        message.account_keys[usize::from(close.accounts[1])],
        new_owner.pubkey()
    );
    assert_signers(
        &migration.required_signers,
        &[authorization(&new_owner.pubkey())],
        &[owner.pubkey(), funder.pubkey()],
    );
    let rent = env.rpc.get_balance(&source).await.unwrap();
    execute_as_new_owner(
        env,
        &migration.execution_message,
        &nonce_account,
        &new_owner,
        &[],
        &[&owner, &funder],
    )
    .await;
    assert_closed(env, &source).await;
    assert_eq!(
        env.rpc.get_balance(&new_owner.pubkey()).await.unwrap(),
        rent
    );
    let destination = get_associated_token_address_with_program_id(
        &programmatic_signer(&new_owner.pubkey()),
        &mint,
        &token_program,
    );
    assert_eq!(token_balance(env, &destination).await, 1_000);
}

pub async fn migrates_tokens_between_programmatic_signers(env: &TestEnv) {
    let old_owner = Keypair::new();
    let old_owner_programmatic_signer = programmatic_signer(&old_owner.pubkey());
    let new_owner = Keypair::new();
    let new_owner_programmatic_signer = programmatic_signer(&new_owner.pubkey());
    let token_program = spl_token_interface::id();
    // The owner pays rent for the new token account, as the default funder.
    fund(env, &old_owner_programmatic_signer).await;
    let mint = create_mint(env, &token_program, &[]).await;
    let source = mint_tokens(
        env,
        &token_program,
        &mint,
        &old_owner_programmatic_signer,
        1_000,
    )
    .await;
    let nonce_account = create_nonce(env, &new_owner.pubkey());

    // The owner is a programmatic signer, which can't be traced back to its signing pubkey, and
    // nothing signs the relay transaction for it.
    let migration: TokenMigrationOutput = migrate(
        env,
        "token",
        &mint,
        Some(&new_owner.pubkey()),
        &["--owner", &old_owner_programmatic_signer.to_string()],
    );
    assert_eq!(
        migration.funder,
        Some(old_owner_programmatic_signer.to_string())
    );
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
    assert_closed(env, &source).await;
    let destination = get_associated_token_address_with_program_id(
        &new_owner_programmatic_signer,
        &mint,
        &token_program,
    );
    assert_eq!(token_balance(env, &destination).await, 1_000);
}

pub async fn migrates_tokens_with_transfer_fee(env: &TestEnv) {
    let owner = Keypair::new();
    let new_owner = Keypair::new();
    let token_program = spl_token_2022_interface::id();
    fund(env, &owner.pubkey()).await;
    let mint = create_mint(env, &token_program, &[ExtensionType::TransferFeeConfig]).await;
    // The owner receives its tokens through a transfer, so its token account holds withheld fees,
    // which must be harvested before it can close.
    let payer = env.payer.pubkey();
    let payer_account = mint_tokens(env, &token_program, &mint, &payer, 1_000).await;
    let source =
        get_associated_token_address_with_program_id(&owner.pubkey(), &mint, &token_program);
    send(
        env,
        &[
            create_associated_token_account_idempotent(
                &payer,
                &owner.pubkey(),
                &mint,
                &token_program,
            ),
            transfer_checked(
                &token_program,
                &payer_account,
                &mint,
                &source,
                &payer,
                &[],
                1_000,
                DECIMALS,
            )
            .unwrap(),
        ],
        &[],
    )
    .await;
    assert_eq!(token_balance(env, &source).await, 990);
    let nonce_account = create_nonce(env, &new_owner.pubkey());

    let migration: TokenMigrationOutput = migrate(
        env,
        "token",
        &mint,
        Some(&new_owner.pubkey()),
        &["--owner", &owner.pubkey().to_string()],
    );
    assert_eq!(migration.amount, "9.9");
    // 1% of 990, rounded up.
    assert_eq!(migration.transfer_fee, Some("0.1".to_string()));
    assert_eq!(
        migration.rent_recipient,
        Some(new_owner.pubkey().to_string())
    );
    let destination = get_associated_token_address_with_program_id(
        &programmatic_signer(&new_owner.pubkey()),
        &mint,
        &token_program,
    );
    let message = decode_execution_message(&migration.execution_message);
    let data = message
        .instructions
        .iter()
        .filter(|instruction| {
            message.account_keys[usize::from(instruction.program_id_index)] == token_program
        })
        .map(|instruction| instruction.data.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        data,
        [
            transfer_checked_with_fee(
                &token_program,
                &source,
                &mint,
                &destination,
                &owner.pubkey(),
                &[],
                990,
                DECIMALS,
                10
            )
            .unwrap()
            .data,
            harvest_withheld_tokens_to_mint(&token_program, &mint, &[&source])
                .unwrap()
                .data,
            close_account(
                &token_program,
                &source,
                &new_owner.pubkey(),
                &owner.pubkey(),
                &[]
            )
            .unwrap()
            .data,
        ]
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
    assert_closed(env, &source).await;
    // The fee is withheld in the new authority's token account.
    assert_eq!(token_balance(env, &destination).await, 980);
}

/// A scheduled fee change is warned about, but the message pins the current fee.
pub async fn warns_of_scheduled_token_transfer_fee(env: &TestEnv) {
    let owner = Keypair::new();
    let token_program = spl_token_2022_interface::id();
    fund(env, &owner.pubkey()).await;
    let mint = create_mint(env, &token_program, &[ExtensionType::TransferFeeConfig]).await;
    mint_tokens(env, &token_program, &mint, &owner.pubkey(), 1_000).await;
    let payer = env.payer.pubkey();
    // Takes effect two epochs from now.
    send(
        env,
        &[set_transfer_fee(&token_program, &mint, &payer, &[], 200, u64::MAX).unwrap()],
        &[],
    )
    .await;

    let owner_arg = owner.pubkey().to_string();
    let output = run_psigner(&[
        "-C",
        &env.config_file_path,
        "--output",
        "json",
        "migrate",
        "token",
        &mint.to_string(),
        "--owner",
        &owner_arg,
    ]);
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains(&format!(
            "Warning: mint {mint} changes its transfer fee at epoch"
        )),
        "{stderr}"
    );
    let migration: TokenMigrationOutput = serde_json::from_slice(&output.stdout).unwrap();
    // 1% of 1,000, not the scheduled 2%.
    assert_eq!(migration.transfer_fee, Some("0.1".to_string()));
}

/// An account with a close authority other than its owner needs that authority to close it.
pub async fn migrates_tokens_with_close_authority(env: &TestEnv) {
    let owner = Keypair::new();
    let close_authority = Keypair::new();
    let new_owner = Keypair::new();
    let token_program = spl_token_interface::id();
    fund(env, &owner.pubkey()).await;
    let mint = create_mint(env, &token_program, &[]).await;
    let source = mint_tokens(env, &token_program, &mint, &owner.pubkey(), 1_000).await;
    send(
        env,
        &[set_authority(
            &token_program,
            &source,
            Some(&close_authority.pubkey()),
            AuthorityType::CloseAccount,
            &owner.pubkey(),
            &[],
        )
        .unwrap()],
        &[&owner],
    )
    .await;
    let nonce_account = create_nonce(env, &new_owner.pubkey());

    // Moving part of the balance leaves the account open, so the close authority doesn't sign.
    let migration: TokenMigrationOutput = migrate(
        env,
        "token",
        &mint,
        Some(&new_owner.pubkey()),
        &["--owner", &owner.pubkey().to_string(), "--amount", "1"],
    );
    assert_signers(
        &migration.required_signers,
        &[authorization(&new_owner.pubkey())],
        &[owner.pubkey()],
    );

    // Migrating the remaining balance, and closing, requires the close authority
    let migration: TokenMigrationOutput = migrate(
        env,
        "token",
        &mint,
        Some(&new_owner.pubkey()),
        &["--owner", &owner.pubkey().to_string()],
    );
    assert_signers(
        &migration.required_signers,
        &[authorization(&new_owner.pubkey())],
        &[owner.pubkey(), close_authority.pubkey()],
    );
    execute_as_new_owner(
        env,
        &migration.execution_message,
        &nonce_account,
        &new_owner,
        &[],
        &[&owner, &close_authority],
    )
    .await;
    assert_closed(env, &source).await;
}

pub async fn rejects_invalid_token_migrations(env: &TestEnv) {
    let owner = Keypair::new();
    let owner_arg = owner.pubkey().to_string();
    let new_owner = Keypair::new();
    let token_program = spl_token_interface::id();
    let mint = create_mint(env, &token_program, &[]).await;
    let source =
        get_associated_token_address_with_program_id(&owner.pubkey(), &mint, &token_program);

    let new_owner_programmatic_signer = programmatic_signer(&new_owner.pubkey()).to_string();
    let stderr = migrate_error(
        env,
        "token",
        &mint,
        Some(&new_owner.pubkey()),
        &["--owner", &new_owner_programmatic_signer],
    );
    assert!(
        stderr.contains(&format!(
            "owner {new_owner_programmatic_signer} is already the new authority's programmatic \
             signer"
        )),
        "{stderr}"
    );

    // An owner that is a programmatic signer can't be the default new authority.
    let stderr = migrate_error(
        env,
        "token",
        &mint,
        None,
        &["--owner", &new_owner_programmatic_signer],
    );
    assert!(
        stderr.contains(&format!(
            "the owner is {new_owner_programmatic_signer}, which is not an on-curve address"
        )),
        "{stderr}"
    );

    let stderr = migrate_error(
        env,
        "token",
        &mint,
        Some(&new_owner.pubkey()),
        &["--owner", &owner_arg],
    );
    assert!(
        stderr.contains(&format!("associated token account {source} was not found")),
        "{stderr}"
    );

    mint_tokens(env, &token_program, &mint, &owner.pubkey(), 1_000).await;
    let stderr = migrate_error(
        env,
        "token",
        &mint,
        Some(&new_owner.pubkey()),
        &["--owner", &owner_arg, "--amount", "10.01"],
    );
    assert!(
        stderr.contains(&format!(
            "token account {source} holds 10, less than the amount"
        )),
        "{stderr}"
    );
    let stderr = migrate_error(
        env,
        "token",
        &mint,
        Some(&new_owner.pubkey()),
        &["--owner", &owner_arg, "--amount", "0.001"],
    );
    assert!(
        stderr.contains("amount 0.001 has more than 2 decimal places"),
        "{stderr}"
    );

    // A rent recipient is ignored when the account isn't closed.
    let rent_recipient = Address::new_unique().to_string();
    let migration: TokenMigrationOutput = migrate(
        env,
        "token",
        &mint,
        Some(&new_owner.pubkey()),
        &[
            "--owner",
            &owner_arg,
            "--amount",
            "1",
            "--rent-recipient",
            &rent_recipient,
        ],
    );
    assert_eq!(migration.rent_recipient, None);
    let stderr = migrate_error(
        env,
        "token",
        &mint,
        Some(&new_owner.pubkey()),
        &[
            "--owner",
            &owner_arg,
            "--no-close",
            "--rent-recipient",
            &rent_recipient,
        ],
    );
    assert!(stderr.contains("cannot be used with"), "{stderr}");

    send(
        env,
        &[freeze_account(&token_program, &source, &mint, &env.payer.pubkey(), &[]).unwrap()],
        &[],
    )
    .await;
    let stderr = migrate_error(
        env,
        "token",
        &mint,
        Some(&new_owner.pubkey()),
        &["--owner", &owner_arg],
    );
    assert!(
        stderr.contains(&format!("token account {source} is frozen")),
        "{stderr}"
    );
}

/// Token-2022 extensions that would make the transfer fail onchain are rejected up front.
pub async fn rejects_unsupported_token_2022_migrations(env: &TestEnv) {
    let owner = Keypair::new();
    let owner_arg = owner.pubkey().to_string();
    let new_owner = Keypair::new();
    let token_program = spl_token_2022_interface::id();
    let migrate_error = |mint: &Address| {
        migrate_error(
            env,
            "token",
            mint,
            Some(&new_owner.pubkey()),
            &["--owner", &owner_arg],
        )
    };

    // An empty account only needs closing, which the mint can't block.
    let mint = create_mint(env, &token_program, &[ExtensionType::NonTransferable]).await;
    mint_tokens(env, &token_program, &mint, &owner.pubkey(), 0).await;
    let migration: TokenMigrationOutput = migrate(
        env,
        "token",
        &mint,
        Some(&new_owner.pubkey()),
        &["--owner", &owner_arg],
    );
    assert_eq!(migration.amount, "0");
    assert_eq!(
        migration.rent_recipient,
        Some(new_owner.pubkey().to_string())
    );
    mint_tokens(env, &token_program, &mint, &owner.pubkey(), 1_000).await;
    let stderr = migrate_error(&mint);
    assert!(
        stderr.contains(&format!("mint {mint} is non-transferable")),
        "{stderr}"
    );

    let mint = create_mint(env, &token_program, &[ExtensionType::TransferHook]).await;
    mint_tokens(env, &token_program, &mint, &owner.pubkey(), 1_000).await;
    let stderr = migrate_error(&mint);
    assert!(
        stderr.contains(&format!("mint {mint} has a transfer hook")),
        "{stderr}"
    );

    // Accounts start frozen, so the owner's is thawed before minting to it, leaving only the new
    // owner's to fail.
    let mint = create_mint(env, &token_program, &[ExtensionType::DefaultAccountState]).await;
    let payer = env.payer.pubkey();
    let source =
        get_associated_token_address_with_program_id(&owner.pubkey(), &mint, &token_program);
    send(
        env,
        &[
            create_associated_token_account_idempotent(
                &payer,
                &owner.pubkey(),
                &mint,
                &token_program,
            ),
            thaw_account(&token_program, &source, &mint, &payer, &[]).unwrap(),
            mint_to_checked(&token_program, &mint, &source, &payer, &[], 1_000, DECIMALS).unwrap(),
        ],
        &[],
    )
    .await;
    let stderr = migrate_error(&mint);
    assert!(
        stderr.contains(&format!("mint {mint} creates token accounts frozen")),
        "{stderr}"
    );

    let mint = create_mint(env, &token_program, &[]).await;
    let source = mint_tokens(env, &token_program, &mint, &owner.pubkey(), 1_000).await;
    send(
        env,
        &[
            reallocate(
                &token_program,
                &source,
                &env.payer.pubkey(),
                &owner.pubkey(),
                &[],
                &[ExtensionType::CpiGuard],
            )
            .unwrap(),
            enable_cpi_guard(&token_program, &source, &owner.pubkey(), &[]).unwrap(),
        ],
        &[&owner],
    )
    .await;
    let stderr = migrate_error(&mint);
    assert!(
        stderr.contains(&format!("token account {source} has the CPI guard enabled")),
        "{stderr}"
    );
}
