use {
    crate::{
        common::{
            execute::programmatic_signer,
            helpers::{TestEnv, run_psigner, run_psigner_with_input},
        },
        test_migrate_token::{self as token, create_mint, mint_tokens},
        test_transaction_submit::{SubmitTest, TRANSFER_AMOUNT, fund},
    },
    base64::{Engine, prelude::BASE64_STANDARD},
    solana_address::Address,
    solana_hash::Hash,
    solana_keypair::Keypair,
    solana_message::v1,
    solana_program_pack::Pack,
    solana_signer::Signer,
    solana_system_interface::instruction::{create_account, transfer},
    solana_transaction::Transaction,
    spl_token_2022_interface::extension::ExtensionType,
    spl_token_interface::{
        instruction::{initialize_account3, initialize_mint2, mint_to, transfer_checked},
        state::{Account as TokenAccount, Mint},
    },
    std::{
        collections::{BTreeMap, BTreeSet},
        process::Output,
    },
};

const DECIMALS: u8 = 6;
const MINTED: u64 = 100_000_000;

/// Create a mint and two token accounts, owned by `sender` and `recipient`, minting to the
/// sender's account. Returns the mint, sender account, and recipient account.
async fn create_token_accounts(
    env: &TestEnv,
    sender: &Address,
    recipient: &Address,
) -> (Address, Address, Address) {
    let [mint, source, destination] = [Keypair::new(), Keypair::new(), Keypair::new()];
    let payer = env.payer.pubkey();
    let token_program = spl_token_interface::id();
    let mint_rent = env
        .rpc
        .get_minimum_balance_for_rent_exemption(Mint::LEN)
        .await
        .unwrap();
    let account_rent = env
        .rpc
        .get_minimum_balance_for_rent_exemption(TokenAccount::LEN)
        .await
        .unwrap();
    let mut instructions = vec![
        create_account(
            &payer,
            &mint.pubkey(),
            mint_rent,
            Mint::LEN as u64,
            &token_program,
        ),
        initialize_mint2(&token_program, &mint.pubkey(), &payer, None, DECIMALS).unwrap(),
    ];
    for (account, owner) in [(&source, sender), (&destination, recipient)] {
        instructions.push(create_account(
            &payer,
            &account.pubkey(),
            account_rent,
            TokenAccount::LEN as u64,
            &token_program,
        ));
        instructions.push(
            initialize_account3(&token_program, &account.pubkey(), &mint.pubkey(), owner).unwrap(),
        );
    }
    instructions.push(
        mint_to(
            &token_program,
            &mint.pubkey(),
            &source.pubkey(),
            &payer,
            &[],
            MINTED,
        )
        .unwrap(),
    );
    let transaction = Transaction::new_signed_with_payer(
        &instructions,
        Some(&payer),
        &[&env.payer, &mint, &source, &destination],
        env.rpc.get_latest_blockhash().await.unwrap(),
    );
    env.rpc
        .send_and_confirm_transaction(&transaction)
        .await
        .unwrap();
    (mint.pubkey(), source.pubkey(), destination.pubkey())
}

fn simulate(
    env: &TestEnv,
    test: &SubmitTest,
    execution_message: &v1::Message,
    extra: &[&str],
) -> Output {
    let encoded = BASE64_STANDARD.encode(execution_message.serialize());
    let nonce_account = test.nonce_account.to_string();
    let mut args = vec![
        "-C",
        &env.config_file_path,
        "--output",
        "json-compact",
        "transaction",
        "simulate",
        &encoded,
        &nonce_account,
    ];
    args.extend_from_slice(extra);
    run_psigner_with_input(&args, "")
}

pub async fn simulates_promoted_and_forwarded_signers(env: &TestEnv) {
    let authority = Keypair::new();
    let signer = programmatic_signer(&authority.pubkey());
    let ordinary = Keypair::new();
    fund(env, &[signer, ordinary.pubkey()]).await;
    let test = SubmitTest::new(env, &signer).await;
    let execution_message = test.execution_message(&[signer, ordinary.pubkey()]);

    let for_authority = authority.pubkey().to_string();
    let output = simulate(
        env,
        &test,
        &execution_message,
        &["--signing-pubkey", &for_authority],
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let transfer = i64::try_from(TRANSFER_AMOUNT).unwrap();
    let sent = transfer.checked_neg().unwrap();
    let mut changes = value["solBalanceChanges"].as_array().unwrap().clone();
    changes.sort_by_key(|change| change["address"].as_str().unwrap().to_owned());
    let mut expected = vec![
        serde_json::json!({
            "address": signer.to_string(),
            "lamports": sent,
            "signingPubkey": for_authority,
        }),
        serde_json::json!({
            "address": ordinary.pubkey().to_string(),
            "lamports": sent,
        }),
        serde_json::json!({
            "address": test.recipient.to_string(),
            "lamports": transfer.checked_mul(2).unwrap(),
        }),
    ];
    expected.sort_by_key(|change| change["address"].as_str().unwrap().to_owned());
    // The fee payer's simulation fee is excluded, so it has no balance change.
    assert_eq!(changes, expected);
    assert_eq!(value["tokenBalanceChanges"], serde_json::json!([]));
    assert!(value["unitsConsumed"].as_u64().unwrap() > 0);

    // Nothing is submitted, so the nonce can still be used.
    test.assert_received(env, 0).await;
    let show = run_psigner(&[
        "-C",
        &env.config_file_path,
        "--output",
        "json-compact",
        "nonce",
        "show",
        &test.nonce_account.to_string(),
    ]);
    let show: serde_json::Value = serde_json::from_slice(&show.stdout).unwrap();
    assert_eq!(show["nonce"], test.nonce.to_string());
}

pub async fn prints_verbose_simulation_result(env: &TestEnv) {
    let authority = Keypair::new();
    let signer = programmatic_signer(&authority.pubkey());
    fund(env, &[signer]).await;
    let test = SubmitTest::new(env, &signer).await;
    let balance = |address| async move { env.rpc.get_balance(&address).await.unwrap() };
    let (signer_balance, recipient_balance) =
        (balance(signer).await, balance(test.recipient).await);

    let output = simulate(
        env,
        &test,
        &test.execution_message(&[signer]),
        &["--verbose"],
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    // The summary on stdout is unchanged.
    let summary: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        summary.as_object().unwrap().keys().collect::<Vec<_>>(),
        [
            "accountChanges",
            "authorityChanges",
            "solBalanceChanges",
            "tokenBalanceChanges",
            "unitsConsumed"
        ]
    );

    let result = stderr
        .strip_prefix("Simulation result:\n")
        .unwrap_or_else(|| panic!("{stderr}"));
    let result: serde_json::Value = serde_json::from_str(result).unwrap();
    assert!(result["err"].is_null());
    assert!(!result["logs"].as_array().unwrap().is_empty());
    assert!(!result["innerInstructions"].as_array().unwrap().is_empty());
    // Only the writable accounts are returned, each labelled with its address.
    let accounts = result["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            let address = entry["address"]
                .as_str()
                .unwrap()
                .parse::<Address>()
                .unwrap();
            (address, entry["account"].clone())
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        accounts.keys().copied().collect::<BTreeSet<_>>(),
        BTreeSet::from([
            env.payer.pubkey(),
            test.nonce_account,
            signer,
            test.recipient
        ])
    );
    let lamports = |address| accounts[&address]["lamports"].as_u64().unwrap();
    assert_eq!(
        lamports(signer),
        signer_balance.checked_sub(TRANSFER_AMOUNT).unwrap()
    );
    assert_eq!(
        lamports(test.recipient),
        recipient_balance.checked_add(TRANSFER_AMOUNT).unwrap()
    );
    assert_eq!(
        accounts[&test.nonce_account]["owner"],
        spl_nonce_interface::id().to_string()
    );
}

pub async fn reports_failed_simulation_logs(env: &TestEnv) {
    let authority = Keypair::new();
    // The derived signer is unfunded, so its transfer fails.
    let signer = programmatic_signer(&authority.pubkey());
    let test = SubmitTest::new(env, &signer).await;

    let output = simulate(env, &test, &test.execution_message(&[signer]), &[]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "unexpected success: {stderr}");
    assert!(output.stdout.is_empty());
    assert!(stderr.contains("simulation failed: "), "{stderr}");
    assert!(stderr.contains("Logs:\nProgram "), "{stderr}");

    // With --verbose, the logs are only in the simulation result, not repeated in the error.
    let output = simulate(
        env,
        &test,
        &test.execution_message(&[signer]),
        &["--verbose"],
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "unexpected success: {stderr}");
    let (result, error) = stderr
        .strip_prefix("Simulation result:\n")
        .and_then(|stderr| stderr.split_once("\n\n"))
        .unwrap_or_else(|| panic!("{stderr}"));
    let result: serde_json::Value = serde_json::from_str(result).unwrap();
    assert!(!result["logs"].as_array().unwrap().is_empty());
    assert!(
        error.contains("See the logs in the simulation result above."),
        "{stderr}"
    );
    assert!(!error.contains("Logs:"), "{stderr}");
}

pub async fn rejects_stale_nonce_hash(env: &TestEnv) {
    let authority = Keypair::new();
    let signer = programmatic_signer(&authority.pubkey());
    let test = SubmitTest::new(env, &signer).await;
    let stale = Hash::new_unique().to_string();

    let output = simulate(
        env,
        &test,
        &test.execution_message(&[signer]),
        &["--nonce-hash", &stale],
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "unexpected success: {stderr}");
    assert!(
        stderr.contains(&format!(
            "expected nonce value {stale}, but nonce account {} currently has {}",
            test.nonce_account, test.nonce
        )),
        "{stderr}"
    );
}

pub async fn rejects_transaction_over_transaction_size(env: &TestEnv) {
    let authority = Keypair::new();
    let signer = programmatic_signer(&authority.pubkey());
    let test = SubmitTest::new(env, &signer).await;
    let mut execution_message = test.execution_message(&[signer]);
    // The execution message alone is over the limit, so the simulated transaction is too.
    execution_message.instructions[0]
        .data
        .resize(v1::MAX_TRANSACTION_SIZE, 0);

    let output = simulate(env, &test, &execution_message, &[]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "unexpected success: {stderr}");
    assert!(output.stdout.is_empty());
    assert!(stderr.contains("simulated transaction is "), "{stderr}");
    assert!(
        stderr.contains(&format!(
            "bytes, which exceeds the v1 transaction size limit of {} bytes",
            v1::MAX_TRANSACTION_SIZE
        )),
        "{stderr}"
    );
}

pub async fn reports_created_and_closed_accounts(env: &TestEnv) {
    let authority = Keypair::new();
    let signer = programmatic_signer(&authority.pubkey());
    let closing = Keypair::new().pubkey();
    let created = Keypair::new().pubkey();
    fund(env, &[signer, closing]).await;
    let test = SubmitTest::new(env, &signer).await;
    let balance = env.rpc.get_balance(&closing).await.unwrap();
    let owner = Address::new_unique();
    let space = 42;
    let rent = env
        .rpc
        .get_minimum_balance_for_rent_exemption(space)
        .await
        .unwrap();
    let execution_message = v1::Message::try_compile_with_config(
        &signer,
        &[
            create_account(&signer, &created, rent, space as u64, &owner),
            transfer(&closing, &test.recipient, balance),
        ],
        test.nonce,
        v1::TransactionConfig::empty(),
    )
    .unwrap();

    let output = simulate(env, &test, &execution_message, &[]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let mut changes = value["accountChanges"].as_array().unwrap().clone();
    changes.sort_by_key(|change| change["address"].as_str().unwrap().to_owned());
    let mut expected = vec![
        serde_json::json!({
            "address": created.to_string(),
            "before": null,
            "after": { "owner": owner.to_string(), "size": space },
        }),
        serde_json::json!({
            "address": closing.to_string(),
            "before": {
                "owner": solana_system_interface::program::id().to_string(),
                "size": 0,
            },
            "after": null,
        }),
    ];
    expected.sort_by_key(|change| change["address"].as_str().unwrap().to_owned());
    assert_eq!(changes, expected);
    assert_eq!(value["authorityChanges"], serde_json::json!([]));
}

/// The verbose result parses Token-2022 accounts with their mint's display configs, as the RPC
/// node would.
pub async fn parses_scaled_ui_amount_token_accounts(env: &TestEnv) {
    let authority = Keypair::new();
    let signer = programmatic_signer(&authority.pubkey());
    let recipient = Keypair::new().pubkey();
    let token_program = spl_token_2022_interface::id();
    let mint = create_mint(env, &token_program, &[ExtensionType::ScaledUiAmount]).await;
    let source = mint_tokens(env, &token_program, &mint, &signer, 1_000).await;
    let destination = mint_tokens(env, &token_program, &mint, &recipient, 0).await;
    let test = SubmitTest::new(env, &signer).await;
    let execution_message = v1::Message::try_compile_with_config(
        &signer,
        &[spl_token_2022_interface::instruction::transfer_checked(
            &token_program,
            &source,
            &mint,
            &destination,
            &signer,
            &[],
            100,
            token::DECIMALS,
        )
        .unwrap()],
        test.nonce,
        v1::TransactionConfig::empty(),
    )
    .unwrap();

    let output = simulate(env, &test, &execution_message, &["--verbose"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    let result = stderr
        .strip_prefix("Simulation result:\n")
        .unwrap_or_else(|| panic!("{stderr}"));
    let result: serde_json::Value = serde_json::from_str(result).unwrap();
    let parsed = result["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["address"] == destination.to_string())
        .unwrap()["account"]["data"]["parsed"]
        .clone();
    assert_eq!(parsed["type"], "account", "{parsed}");
    // 100 base units with 2 decimals is 1, which the multiplier doubles.
    let amount = &parsed["info"]["tokenAmount"];
    assert_eq!(amount["amount"], "100", "{parsed}");
    assert_eq!(amount["uiAmountString"], "2", "{parsed}");
}

pub async fn simulates_token_transfer(env: &TestEnv) {
    let authority = Keypair::new();
    // The derived signer owns the source token account and needs no SOL of its own.
    let signer = programmatic_signer(&authority.pubkey());
    let recipient = Keypair::new().pubkey();
    let (mint, source, destination) = create_token_accounts(env, &signer, &recipient).await;
    let test = SubmitTest::new(env, &signer).await;
    let amount = 1_500_000;
    let execution_message = v1::Message::try_compile_with_config(
        &signer,
        &[transfer_checked(
            &spl_token_interface::id(),
            &source,
            &mint,
            &destination,
            &signer,
            &[],
            amount,
            DECIMALS,
        )
        .unwrap()],
        test.nonce,
        v1::TransactionConfig::empty(),
    )
    .unwrap();

    let output = simulate(env, &test, &execution_message, &[]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["solBalanceChanges"], serde_json::json!([]));
    let amount = i64::try_from(amount).unwrap();
    let mut changes = value["tokenBalanceChanges"].as_array().unwrap().clone();
    changes.sort_by_key(|change| change["account"].as_str().unwrap().to_owned());
    let token_change = |account: &Address, owner: &Address, amount: i64| {
        serde_json::json!({
            "account": account.to_string(),
            "mint": mint.to_string(),
            "owner": owner.to_string(),
            "programId": spl_token_interface::id().to_string(),
            "amount": amount,
            "decimals": DECIMALS,
        })
    };
    let mut expected = vec![
        token_change(&source, &signer, amount.checked_neg().unwrap()),
        token_change(&destination, &recipient, amount),
    ];
    expected.sort_by_key(|change| change["account"].as_str().unwrap().to_owned());
    assert_eq!(changes, expected);

    // The verbose result parses the token accounts, using the decimals from the token balances.
    let output = simulate(env, &test, &execution_message, &["--verbose"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    let result = stderr
        .strip_prefix("Simulation result:\n")
        .unwrap_or_else(|| panic!("{stderr}"));
    let result: serde_json::Value = serde_json::from_str(result).unwrap();
    let parsed = |address: &Address| {
        result["accounts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["address"] == address.to_string())
            .unwrap()["account"]["data"]["parsed"]
            .clone()
    };
    for (account, amount) in [(&source, MINTED - 1_500_000), (&destination, 1_500_000)] {
        let parsed = parsed(account);
        assert_eq!(parsed["type"], "account", "{parsed}");
        assert_eq!(parsed["info"]["tokenAmount"]["amount"], amount.to_string());
        assert_eq!(parsed["info"]["tokenAmount"]["decimals"], DECIMALS);
    }

    // The display output shows the amounts with their decimals, and labels the token account
    // owned by the authority's derived signer.
    let encoded = BASE64_STANDARD.encode(execution_message.serialize());
    let nonce_account = test.nonce_account.to_string();
    let for_authority = authority.pubkey().to_string();
    let display = run_psigner(&[
        "-C",
        &env.config_file_path,
        "transaction",
        "simulate",
        &encoded,
        &nonce_account,
        "--signing-pubkey",
        &for_authority,
    ]);
    let display = String::from_utf8(display.stdout).unwrap();
    assert!(
        display.contains(&format!(
            "  {source}  -1.5  mint {mint}  owner {signer}  (PDA of {for_authority})\n"
        )),
        "{display}"
    );
    assert!(
        display.contains(&format!(
            "  {destination}  +1.5  mint {mint}  owner {recipient}"
        )),
        "{display}"
    );
}

pub async fn simulates_at_relay_cpi_depth(env: &TestEnv) {
    let authority = Keypair::new();
    let signer = programmatic_signer(&authority.pubkey());
    fund(env, &[signer]).await;
    let test = SubmitTest::new(env, &signer).await;

    let output = simulate(
        env,
        &test,
        &test.execution_message(&[signer]),
        &["--verbose"],
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    let result = stderr
        .strip_prefix("Simulation result:\n")
        .unwrap_or_else(|| panic!("{stderr}"));
    let result: serde_json::Value = serde_json::from_str(result).unwrap();
    let invocations = result["logs"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|log| {
            let log = log.as_str().unwrap();
            log.contains(" invoke [").then_some(log)
        })
        .collect::<Vec<_>>();
    // The relay transaction's Submit invokes Execute, which advances the nonce and then runs the
    // execution message, so its instructions run at the same depth as in a real submission.
    assert_eq!(
        invocations,
        [
            format!("Program {} invoke [1]", spl_ed25519_signer_client::id()),
            format!(
                "Program {} invoke [2]",
                spl_message_executor_interface::id()
            ),
            format!("Program {} invoke [3]", spl_nonce_interface::id()),
            format!(
                "Program {} invoke [3]",
                solana_system_interface::program::id()
            ),
        ]
    );
}
