use {
    crate::{
        common::{
            execute::programmatic_signer,
            helpers::{TestEnv, run_psigner},
        },
        migration::{migrate_error_with_args, migrate_with_args, send},
        test_migrate_mint::{create_mint, create_mint_with_extensions},
        test_migrate_program::deploy_program,
        test_migrate_stake::{STAKE_LAMPORTS, create_stake_account},
        test_migrate_token::{self, mint_to_new_account, mint_tokens},
        test_migrate_token_account::create_token_account,
        test_migrate_vote::create_vote_account,
    },
    solana_address::Address,
    solana_keypair::Keypair,
    solana_loader_v3_interface::get_program_data_address,
    solana_native_token::LAMPORTS_PER_SOL,
    solana_signer::Signer,
    solana_stake_interface::state::{Authorized, Lockup},
    solana_system_interface::instruction::transfer,
    spl_programmatic_signer_cli::ScanOutput,
    spl_token_2022_interface::{
        extension::ExtensionType,
        instruction::{AuthorityType, set_authority},
    },
};

/// Run `migrate scan <owner> [extra]` and parse its JSON output.
fn scan(env: &TestEnv, owner: &Address, extra: &[&str]) -> ScanOutput {
    let owner = owner.to_string();
    let mut args = vec!["scan", &owner];
    args.extend_from_slice(extra);
    migrate_with_args(env, &args)
}

pub async fn scans_owner_for_migrations(env: &TestEnv) {
    let owner = Keypair::new();
    let other = Keypair::new();
    let new_owner = Keypair::new().pubkey();
    let new_owner_arg = new_owner.to_string();
    let token = spl_token_2022_interface::inline_spl_token::id();
    let token_2022 = spl_token_2022_interface::id();

    // Nothing to migrate yet.
    let output = scan(
        env,
        &owner.pubkey(),
        &["--new-authority-signing-pubkey", &new_owner_arg],
    );
    assert_eq!(output.owner, owner.pubkey().to_string());
    assert!(output.stake.unwrap().is_empty());
    assert!(output.vote.unwrap().is_empty());
    assert!(output.program.unwrap().is_empty());
    assert!(output.mint.unwrap().is_empty());
    assert!(output.token.unwrap().is_empty());
    let sol = output.sol.unwrap();
    assert_eq!(sol.lamports, 0);
    assert!(sol.command.is_none());

    let both_roles =
        create_stake_account(env, &Authorized::auto(&owner.pubkey()), &Lockup::default()).await;
    let staker_only = create_stake_account(
        env,
        &Authorized {
            staker: owner.pubkey(),
            withdrawer: other.pubkey(),
        },
        &Lockup::default(),
    )
    .await;
    // Owned by someone else entirely.
    create_stake_account(env, &Authorized::auto(&other.pubkey()), &Lockup::default()).await;

    let vote = create_vote_account(env, &Keypair::new(), &owner.pubkey()).await;
    // The owner is the voter and node identity here, which don't migrate.
    create_vote_account(env, &owner, &other.pubkey()).await;

    // Pays the program's write transactions, which the owner signs.
    send(
        env,
        &[transfer(
            &env.payer.pubkey(),
            &owner.pubkey(),
            LAMPORTS_PER_SOL,
        )],
        &[],
    )
    .await;
    let program = deploy_program(env, &owner).await;

    let token_mint = create_mint(env, &token, &owner.pubkey(), Some(&owner.pubkey())).await;
    let token_2022_mint =
        create_mint(env, &token_2022, &owner.pubkey(), Some(&other.pubkey())).await;
    let freeze_only_mint =
        create_mint(env, &token_2022, &other.pubkey(), Some(&owner.pubkey())).await;
    // Without extensions, a Token-2022 mint has the base layout rather than the extended one.
    let base_2022_mint =
        create_mint_with_extensions(env, &token_2022, &owner.pubkey(), None, &[]).await;

    let held_mint = test_migrate_token::create_mint(env, &token, &[]).await;
    let held_account = mint_tokens(env, &token, &held_mint, &owner.pubkey(), 150).await;
    let held_2022_mint = test_migrate_token::create_mint(env, &token_2022, &[]).await;
    let held_2022_account =
        mint_tokens(env, &token_2022, &held_2022_mint, &owner.pubkey(), 5).await;
    let other_account = mint_to_new_account(env, &token, &held_mint, &owner.pubkey(), 1_000).await;
    // Someone else's close authority leaves only the owner to move.
    let closable_account = mint_to_new_account(env, &token, &held_mint, &owner.pubkey(), 300).await;
    send(
        env,
        &[set_authority(
            &token,
            &closable_account,
            Some(&other.pubkey()),
            AuthorityType::CloseAccount,
            &owner.pubkey(),
            &[],
        )
        .unwrap()],
        &[&owner],
    )
    .await;
    // An immutable owner can't change, so only its tokens can move.
    let immutable_account = create_token_account(
        env,
        &token_2022,
        &held_2022_mint,
        &owner.pubkey(),
        &[ExtensionType::ImmutableOwner],
        7,
    )
    .await;
    // An empty account is listed, since `migrate token` closes it.
    let empty_mint = test_migrate_token::create_mint(env, &token, &[]).await;
    let empty_account = mint_tokens(env, &token, &empty_mint, &owner.pubkey(), 0).await;

    let output = scan(
        env,
        &owner.pubkey(),
        &["--new-authority-signing-pubkey", &new_owner_arg],
    );
    let command = |args: &str| format!("spl-programmatic-signer migrate {args}");

    let mut stake = output
        .stake
        .expect("stake was scanned")
        .iter()
        .map(|item| {
            (
                item.stake_account.clone(),
                item.lamports,
                item.authority_types.clone(),
                item.command.clone(),
            )
        })
        .collect::<Vec<_>>();
    stake.sort();
    let mut expected_stake = vec![
        (
            both_roles.to_string(),
            STAKE_LAMPORTS,
            vec!["staker".to_string(), "withdrawer".to_string()],
            command(&format!(
                "stake {both_roles} --new-authority-signing-pubkey {new_owner}"
            )),
        ),
        (
            staker_only.to_string(),
            STAKE_LAMPORTS,
            vec!["staker".to_string()],
            command(&format!(
                "stake {staker_only} --new-authority-signing-pubkey {new_owner} --authority-type \
                 staker"
            )),
        ),
    ];
    expected_stake.sort();
    assert_eq!(stake, expected_stake);

    let Ok([vote_item]) = output.vote.as_deref() else {
        panic!("expected one vote account, found {:?}", output.vote);
    };
    assert_eq!(vote_item.vote_account, vote.to_string());
    assert_eq!(
        vote_item.command,
        command(&format!(
            "vote {vote} --new-authority-signing-pubkey {new_owner}"
        ))
    );

    let Ok([program_item]) = output.program.as_deref() else {
        panic!("expected one program, found {:?}", output.program);
    };
    assert_eq!(program_item.program, program.to_string());
    assert_eq!(
        program_item.program_data,
        get_program_data_address(&program).to_string()
    );
    assert_eq!(
        program_item.command,
        command(&format!(
            "program {program} --new-authority-signing-pubkey {new_owner}"
        ))
    );

    let mut mints = output
        .mint
        .expect("mint was scanned")
        .iter()
        .map(|item| {
            (
                item.mint.clone(),
                item.token_program.clone(),
                item.authority_types.clone(),
                item.command.clone(),
            )
        })
        .collect::<Vec<_>>();
    mints.sort();
    let mut expected_mints = vec![
        (
            token_mint.to_string(),
            token.to_string(),
            vec!["mint".to_string(), "freeze".to_string()],
            command(&format!(
                "mint {token_mint} --new-authority-signing-pubkey {new_owner}"
            )),
        ),
        (
            token_2022_mint.to_string(),
            token_2022.to_string(),
            vec!["mint".to_string()],
            command(&format!(
                "mint {token_2022_mint} --new-authority-signing-pubkey {new_owner} \
                 --authority-type mint"
            )),
        ),
        (
            freeze_only_mint.to_string(),
            token_2022.to_string(),
            vec!["freeze".to_string()],
            command(&format!(
                "mint {freeze_only_mint} --new-authority-signing-pubkey {new_owner} \
                 --authority-type freeze"
            )),
        ),
        (
            base_2022_mint.to_string(),
            token_2022.to_string(),
            vec!["mint".to_string()],
            command(&format!(
                "mint {base_2022_mint} --new-authority-signing-pubkey {new_owner} \
                 --authority-type mint"
            )),
        ),
    ];
    expected_mints.sort();
    assert_eq!(mints, expected_mints);

    let owner_arg = owner.pubkey();
    let mut tokens = output
        .token
        .expect("token was scanned")
        .iter()
        .map(|item| {
            (
                item.token_account.clone(),
                item.mint.clone(),
                item.token_program.clone(),
                item.amount.clone(),
                item.associated,
                item.command.clone(),
                item.reassign_command.clone(),
            )
        })
        .collect::<Vec<_>>();
    tokens.sort();
    let mut expected_tokens = vec![
        (
            held_account.to_string(),
            held_mint.to_string(),
            token.to_string(),
            "1.5".to_string(),
            true,
            command(&format!(
                "token {held_mint} --owner {owner_arg} --new-authority-signing-pubkey {new_owner}"
            )),
            None,
        ),
        (
            held_2022_account.to_string(),
            held_2022_mint.to_string(),
            token_2022.to_string(),
            "0.05".to_string(),
            true,
            command(&format!(
                "token {held_2022_mint} --owner {owner_arg} --new-authority-signing-pubkey \
                 {new_owner}"
            )),
            None,
        ),
        (
            other_account.to_string(),
            held_mint.to_string(),
            token.to_string(),
            "10".to_string(),
            false,
            command(&format!(
                "token {held_mint} --source {other_account} --new-authority-signing-pubkey \
                 {new_owner}"
            )),
            Some(command(&format!(
                "token-account {other_account} --new-authority-signing-pubkey {new_owner}"
            ))),
        ),
        (
            closable_account.to_string(),
            held_mint.to_string(),
            token.to_string(),
            "3".to_string(),
            false,
            command(&format!(
                "token {held_mint} --source {closable_account} --new-authority-signing-pubkey \
                 {new_owner}"
            )),
            Some(command(&format!(
                "token-account {closable_account} --new-authority-signing-pubkey {new_owner} \
                 --authority-type owner"
            ))),
        ),
        (
            immutable_account.to_string(),
            held_2022_mint.to_string(),
            token_2022.to_string(),
            "0.07".to_string(),
            false,
            command(&format!(
                "token {held_2022_mint} --source {immutable_account} \
                 --new-authority-signing-pubkey {new_owner}"
            )),
            None,
        ),
        (
            empty_account.to_string(),
            empty_mint.to_string(),
            token.to_string(),
            "0".to_string(),
            true,
            command(&format!(
                "token {empty_mint} --owner {owner_arg} --new-authority-signing-pubkey {new_owner}"
            )),
            None,
        ),
    ];
    expected_tokens.sort();
    assert_eq!(tokens, expected_tokens);

    let sol = output.sol.expect("sol was scanned");
    assert_eq!(
        sol.lamports,
        env.rpc.get_balance(&owner.pubkey()).await.unwrap()
    );
    assert_eq!(
        sol.command,
        Some(command(&format!(
            "sol {owner_arg} --new-authority-signing-pubkey {new_owner}"
        )))
    );

    // An owner account the System Program doesn't own has its balance listed without a command.
    let sol = scan(env, &both_roles, &[]).sol.unwrap();
    assert_eq!(sol.lamports, STAKE_LAMPORTS);
    assert!(sol.command.is_none());

    // Without a new authority, the commands leave it out, so they default to the owner.
    let output = scan(env, &owner.pubkey(), &[]);
    assert_eq!(
        output.program.unwrap()[0].command,
        command(&format!("program {program}"))
    );

    let display = String::from_utf8(
        run_psigner(&[
            "-C",
            &env.config_file_path,
            "migrate",
            "scan",
            &owner.pubkey().to_string(),
        ])
        .stdout,
    )
    .unwrap();
    assert!(display.contains("Stake accounts (2):"), "{display}");
    assert!(
        display.contains("Vote accounts (withdrawer) (1):"),
        "{display}"
    );
    assert!(display.contains("Mints (4):"), "{display}");
    assert!(display.contains("Token accounts (6):"), "{display}");
    assert!(!display.contains("Not scanned"), "{display}");

    // Each item is listed under its heading, followed by details such as its command.
    let lines = display.lines().collect::<Vec<_>>();
    assert!(lines[0].starts_with("Owner: "), "{display}");
    let is_item = |line: &str| line.starts_with("  ") && !line.starts_with("    ");
    let is_detail = |line: &str| line.starts_with("    ");
    assert!(!lines.last().is_some_and(|line| is_item(line)), "{display}");
    for pair in lines.windows(2) {
        let [line, next] = pair else { unreachable!() };
        assert_eq!(
            is_item(line) || is_detail(line) && is_detail(next) || line.starts_with("SOL: ◎"),
            is_detail(next),
            "{line:?} then {next:?}\n{display}"
        );
    }
    // The line following the line equal to `line`.
    let following = |line: &str| {
        lines
            .windows(2)
            .find(|pair| pair[0] == line)
            .unwrap_or_else(|| panic!("{line:?} not listed\n{display}"))[1]
    };
    assert_eq!(
        following(&format!(
            "  {program} (program data: {})",
            get_program_data_address(&program)
        )),
        format!("    {}", command(&format!("program {program}"))),
    );
    assert_eq!(
        following(&format!("  10 of mint {held_mint}")),
        format!("    In {other_account}, not an associated token account"),
    );
    assert_eq!(
        following(&format!(
            "    In {other_account}, not an associated token account"
        )),
        format!(
            "    {}",
            command(&format!("token {held_mint} --source {other_account}"))
        ),
    );
    assert_eq!(
        following(&format!(
            "    {}",
            command(&format!("token {held_mint} --source {other_account}"))
        )),
        format!(
            "    Or keep the tokens in place: {}",
            command(&format!("token-account {other_account}"))
        ),
    );

    // An owner that is a programmatic signer can't be the default, so the commands hold a
    // placeholder.
    let owner_signer = programmatic_signer(&owner.pubkey());
    let stake =
        create_stake_account(env, &Authorized::auto(&owner_signer), &Lockup::default()).await;
    let output = scan(env, &owner_signer, &[]);
    assert_eq!(
        output.stake.unwrap()[0].command,
        command(&format!(
            "stake {stake} --new-authority-signing-pubkey <NEW_AUTHORITY_SIGNING_PUBKEY>"
        ))
    );
}

pub async fn rejects_invalid_scans(env: &TestEnv) {
    let new_owner = Keypair::new().pubkey();
    let new_owner_programmatic_signer = programmatic_signer(&new_owner);
    let stderr = migrate_error_with_args(
        env,
        &[
            "scan",
            &new_owner_programmatic_signer.to_string(),
            "--new-authority-signing-pubkey",
            &new_owner.to_string(),
        ],
    );
    assert!(
        stderr.contains(&format!(
            "owner {new_owner_programmatic_signer} is already the new authority's programmatic \
             signer"
        )),
        "{stderr}"
    );

    let stderr = migrate_error_with_args(
        env,
        &[
            "scan",
            &new_owner.to_string(),
            "--new-authority-signing-pubkey",
            &new_owner_programmatic_signer.to_string(),
        ],
    );
    assert!(
        stderr.contains(&format!(
            "new authority signing pubkey {new_owner_programmatic_signer} is not an on-curve \
             address"
        )),
        "{stderr}"
    );
}
