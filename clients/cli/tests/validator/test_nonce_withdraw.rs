use {
    crate::{
        common::helpers::{TestEnv, run_psigner, run_psigner_with_input},
        test_transaction_submit::fund,
    },
    base64::{Engine, prelude::BASE64_STANDARD},
    solana_address::Address,
    solana_keypair::{Keypair, write_keypair_file},
    solana_signer::Signer,
    spl_programmatic_signer_cli::{
        NonceCreateOutput, NonceShowOutput, NonceWithdrawAuthorizationOutput, NonceWithdrawOutput,
    },
    std::str::FromStr,
    tempfile::NamedTempFile,
};

/// Amount withdrawn by partial withdrawals, in SOL and lamports.
const PARTIAL_SOL: &str = "0.001";
const PARTIAL_LAMPORTS: u64 = 1_000_000;

/// Create a nonce account and fund it beyond its rent-exempt minimum, so partial withdrawals
/// leave it rent-exempt.
async fn create_funded_nonce(
    env: &TestEnv,
    authority_arg: &str,
    authority: &str,
) -> NonceCreateOutput {
    let create = run_psigner(&[
        "-C",
        &env.config_file_path,
        "--output",
        "json-compact",
        "nonce",
        "create",
        authority_arg,
        authority,
    ]);
    let create: NonceCreateOutput = serde_json::from_slice(&create.stdout).unwrap();
    fund(env, &[Address::from_str(&create.nonce_account).unwrap()]).await;
    create
}

fn show_nonce(env: &TestEnv, nonce_account: &str) -> NonceShowOutput {
    let show = run_psigner(&[
        "-C",
        &env.config_file_path,
        "--output",
        "json-compact",
        "nonce",
        "show",
        nonce_account,
    ]);
    serde_json::from_slice(&show.stdout).unwrap()
}

fn withdraw_args<'a>(
    env: &'a TestEnv,
    nonce_account: &'a str,
    destination: &'a str,
    amount: &'a str,
    extra: &[&'a str],
) -> Vec<&'a str> {
    let mut args = vec![
        "-C",
        &env.config_file_path,
        "--output",
        "json-compact",
        "nonce",
        "withdraw",
        nonce_account,
        destination,
        amount,
    ];
    args.extend(extra);
    args
}

fn withdraw(
    env: &TestEnv,
    nonce_account: &str,
    destination: &str,
    amount: &str,
    nonce_authority: Option<&str>,
) -> NonceWithdrawOutput {
    let mut extra = vec![];
    if let Some(nonce_authority) = nonce_authority {
        extra.extend(["--nonce-authority", nonce_authority]);
    }
    let output = run_psigner(&withdraw_args(
        env,
        nonce_account,
        destination,
        amount,
        &extra,
    ));
    let output: NonceWithdrawOutput = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(output.nonce_account, nonce_account);
    assert_eq!(output.destination, destination);
    assert!(!output.signature.is_empty());
    output
}

async fn balance(env: &TestEnv, address: &str) -> u64 {
    env.rpc
        .get_balance(&Address::from_str(address).unwrap())
        .await
        .unwrap()
}

async fn assert_closed(env: &TestEnv, nonce_account: &str) {
    let account = env
        .rpc
        .get_account_with_commitment(
            &Address::from_str(nonce_account).unwrap(),
            env.rpc.commitment(),
        )
        .await
        .unwrap()
        .value;
    assert!(account.is_none(), "{nonce_account} was not closed");
}

/// Withdraw part of the balance and then the rest, checking the nonce after each. A plain key
/// authority leaves the nonce unchanged, while a PDA authority's execution message advances it.
async fn withdraw_partial_then_all(
    env: &TestEnv,
    create: &NonceCreateOutput,
    nonce_authority: Option<&str>,
    advances: bool,
) {
    let destination = Keypair::new().pubkey().to_string();
    let initial_balance = balance(env, &create.nonce_account).await;

    let partial = withdraw(
        env,
        &create.nonce_account,
        &destination,
        PARTIAL_SOL,
        nonce_authority,
    );
    assert_eq!(partial.lamports, PARTIAL_LAMPORTS);
    let nonce = partial.nonce.unwrap();
    assert_eq!(nonce != create.nonce, advances);
    let show = show_nonce(env, &create.nonce_account);
    assert_eq!(show.nonce, nonce);
    assert_eq!(
        show.lamports,
        initial_balance.checked_sub(PARTIAL_LAMPORTS).unwrap()
    );
    assert_eq!(balance(env, &destination).await, PARTIAL_LAMPORTS);

    let all = withdraw(
        env,
        &create.nonce_account,
        &destination,
        "ALL",
        nonce_authority,
    );
    assert_eq!(
        all.lamports,
        initial_balance.checked_sub(PARTIAL_LAMPORTS).unwrap()
    );
    assert_eq!(all.nonce, None);
    assert_closed(env, &create.nonce_account).await;
    assert_eq!(balance(env, &destination).await, initial_balance);
}

pub async fn withdraws_with_plain_key_authority(env: &TestEnv) {
    // The configured keypair is both the nonce authority and the fee payer.
    let create = create_funded_nonce(env, "--nonce-authority", &env.payer_address).await;
    withdraw_partial_then_all(env, &create, None, false).await;

    // A separate nonce authority signs alongside the fee payer.
    let authority = Keypair::new();
    let authority_file = NamedTempFile::new().unwrap();
    write_keypair_file(&authority, &authority_file).unwrap();
    let create =
        create_funded_nonce(env, "--nonce-authority", &authority.pubkey().to_string()).await;
    withdraw_partial_then_all(
        env,
        &create,
        Some(authority_file.path().to_str().unwrap()),
        false,
    )
    .await;
}

pub async fn withdraws_with_cold_authority(env: &TestEnv) {
    // The configured keypair is both the cold authority and the fee payer.
    let create = create_funded_nonce(env, "--cold-authority", &env.payer_address).await;
    withdraw_partial_then_all(env, &create, None, true).await;

    // An unfunded cold authority signs only the authorization message.
    let cold_authority = Keypair::new();
    let cold_authority_file = NamedTempFile::new().unwrap();
    write_keypair_file(&cold_authority, &cold_authority_file).unwrap();
    let create = create_funded_nonce(
        env,
        "--cold-authority",
        &cold_authority.pubkey().to_string(),
    )
    .await;
    withdraw_partial_then_all(
        env,
        &create,
        Some(cold_authority_file.path().to_str().unwrap()),
        true,
    )
    .await;
}

pub async fn withdraws_with_external_cold_authority(env: &TestEnv) {
    let cold_authority = Keypair::new();
    let cold_authority_address = cold_authority.pubkey().to_string();
    let create = create_funded_nonce(env, "--cold-authority", &cold_authority_address).await;
    let destination = Keypair::new().pubkey().to_string();
    let initial_balance = balance(env, &create.nonce_account).await;

    let dump = |amount| {
        let dump = run_psigner(&withdraw_args(
            env,
            &create.nonce_account,
            &destination,
            amount,
            &["--nonce-authority", &cold_authority_address],
        ));
        serde_json::from_slice::<NonceWithdrawAuthorizationOutput>(&dump.stdout).unwrap()
    };
    // The external signer, e.g. an HSM, signs the decoded message bytes as-is, and the
    // signature goes through the usual submit flow.
    let submit = |unsigned: &NonceWithdrawAuthorizationOutput| {
        let signature = cold_authority.sign_message(
            &BASE64_STANDARD
                .decode(&unsigned.authorization_message)
                .unwrap(),
        );
        run_psigner(&[
            "-C",
            &env.config_file_path,
            "--output",
            "json-compact",
            "transaction",
            "submit",
            "--authorization-message",
            &unsigned.authorization_message,
            "--signer",
            &format!("{cold_authority_address}={signature}"),
        ]);
    };

    let partial = dump(PARTIAL_SOL);
    // The authorization message depends only on the arguments and the current nonce.
    assert_eq!(partial, dump(PARTIAL_SOL));
    assert_eq!(partial.nonce_account, create.nonce_account);
    assert_eq!(partial.current_nonce, create.nonce);
    assert_eq!(partial.destination, destination);
    assert_eq!(partial.lamports, PARTIAL_LAMPORTS);
    assert_eq!(partial.signer, cold_authority_address);
    // Printing the message signs and submits nothing.
    assert_eq!(balance(env, &create.nonce_account).await, initial_balance);
    submit(&partial);
    assert_eq!(
        Some(show_nonce(env, &create.nonce_account).nonce),
        partial.next_nonce
    );
    assert_eq!(balance(env, &destination).await, PARTIAL_LAMPORTS);

    let all = dump("ALL");
    assert_eq!(all.current_nonce, partial.next_nonce.unwrap());
    assert_eq!(
        all.lamports,
        initial_balance.checked_sub(PARTIAL_LAMPORTS).unwrap()
    );
    assert_eq!(all.next_nonce, None);
    submit(&all);
    assert_closed(env, &create.nonce_account).await;
    assert_eq!(balance(env, &destination).await, initial_balance);
}

pub async fn rejects_invalid_withdrawals(env: &TestEnv) {
    let plain_authority = Keypair::new().pubkey().to_string();
    let create = create_funded_nonce(env, "--nonce-authority", &env.payer_address).await;
    let plain = create_funded_nonce(env, "--nonce-authority", &plain_authority).await;
    let unrelated = create_funded_nonce(env, "--nonce-authority", &plain_authority).await;
    let destination = Keypair::new().pubkey().to_string();
    let initial_balance = balance(env, &create.nonce_account).await;
    let too_much = sol(initial_balance.checked_add(1).unwrap());
    let below_rent = sol(initial_balance.checked_sub(1).unwrap());

    for (nonce_account, destination, amount, extra, expected) in [
        (
            &plain.nonce_account,
            &destination,
            PARTIAL_SOL,
            vec!["--nonce-authority", plain_authority.as_str()],
            format!(
                "nonce authority {plain_authority} signs the relay transaction directly, so it \
                 must be passed as a signer"
            ),
        ),
        (
            &unrelated.nonce_account,
            &destination,
            PARTIAL_SOL,
            vec![],
            format!(
                "nonce account {} has authority {plain_authority}, but the nonce authority given \
                 is {}",
                unrelated.nonce_account, env.payer_address
            ),
        ),
        (
            &create.nonce_account,
            &create.nonce_account,
            PARTIAL_SOL,
            vec![],
            format!(
                "destination must differ from nonce account {}",
                create.nonce_account
            ),
        ),
        (
            &create.nonce_account,
            &destination,
            &too_much,
            vec![],
            format!("nonce account {} has", create.nonce_account),
        ),
        (
            &create.nonce_account,
            &destination,
            &below_rent,
            vec![],
            "below its rent-exempt minimum".to_string(),
        ),
        (
            &create.nonce_account,
            &destination,
            "0",
            vec![],
            "withdrawal amount must be greater than zero".to_string(),
        ),
        (
            &create.nonce_account,
            &destination,
            "all",
            vec![],
            "expected a SOL amount or ALL".to_string(),
        ),
    ] {
        let output = run_psigner_with_input(
            &withdraw_args(env, nonce_account, destination, amount, &extra),
            "",
        );
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(&expected), "{stderr}");
    }
    // Nothing was withdrawn.
    assert_eq!(
        show_nonce(env, &create.nonce_account).lamports,
        initial_balance
    );
}

/// Format lamports as an exact SOL amount.
fn sol(lamports: u64) -> String {
    format!(
        "{}.{:09}",
        lamports / 1_000_000_000,
        lamports % 1_000_000_000
    )
}
