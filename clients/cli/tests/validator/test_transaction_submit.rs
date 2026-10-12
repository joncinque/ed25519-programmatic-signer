use {
    crate::common::{
        execute::{build_authorization_message, encode, programmatic_signer, signature_entry},
        helpers::{TestEnv, run_psigner, run_psigner_with_input},
    },
    base64::{Engine, prelude::BASE64_STANDARD},
    solana_address::Address,
    solana_hash::Hash,
    solana_keypair::{Keypair, write_keypair_file},
    solana_message::{VersionedMessage, v1},
    solana_nonce::{state::State, versions::Versions},
    solana_signer::Signer,
    solana_system_interface::instruction::{create_nonce_account, transfer},
    solana_transaction::Transaction,
    spl_nonce_interface::state::Nonce,
    spl_programmatic_signer_cli::NonceCreateOutput,
    std::process::Output,
    tempfile::NamedTempFile,
};

const INITIAL_BALANCE: u64 = 10_000_000;
pub(crate) const TRANSFER_AMOUNT: u64 = 1_000_000;

/// A funded recipient and a nonce account whose value the execution message uses as its blockhash.
pub(crate) struct SubmitTest {
    pub(crate) recipient: Address,
    pub(crate) nonce_account: Address,
    pub(crate) nonce: Hash,
}

impl SubmitTest {
    pub(crate) async fn new(env: &TestEnv, nonce_authority: &Address) -> Self {
        let recipient = Keypair::new().pubkey();
        fund(env, &[recipient]).await;
        let create = run_psigner(&[
            "-C",
            &env.config_file_path,
            "--output",
            "json-compact",
            "nonce",
            "create",
            "--nonce-authority",
            &nonce_authority.to_string(),
        ]);
        let create: NonceCreateOutput = serde_json::from_slice(&create.stdout).unwrap();
        Self {
            recipient,
            nonce_account: create.nonce_account.parse().unwrap(),
            nonce: create.nonce.parse().unwrap(),
        }
    }

    /// An execution message transferring from each sender to the recipient.
    pub(crate) fn execution_message(&self, senders: &[Address]) -> v1::Message {
        let transfers = senders
            .iter()
            .map(|sender| transfer(sender, &self.recipient, TRANSFER_AMOUNT))
            .collect::<Vec<_>>();
        v1::Message::try_compile(&senders[0], &transfers, self.nonce).unwrap()
    }

    async fn current_nonce(&self, env: &TestEnv) -> Hash {
        let data = env.rpc.get_account_data(&self.nonce_account).await.unwrap();
        Nonce::view(&data).unwrap().nonce
    }

    pub(crate) async fn assert_received(&self, env: &TestEnv, transfers: u64) {
        assert_eq!(
            env.rpc.get_balance(&self.recipient).await.unwrap(),
            INITIAL_BALANCE
                .checked_add(TRANSFER_AMOUNT.checked_mul(transfers).unwrap())
                .unwrap()
        );
    }
}

pub(crate) async fn fund(env: &TestEnv, addresses: &[Address]) {
    let instructions = addresses
        .iter()
        .map(|address| transfer(&env.payer.pubkey(), address, INITIAL_BALANCE))
        .collect::<Vec<_>>();
    let transaction = Transaction::new_signed_with_payer(
        &instructions,
        Some(&env.payer.pubkey()),
        &[&env.payer],
        env.rpc.get_latest_blockhash().await.unwrap(),
    );
    env.rpc
        .send_and_confirm_transaction(&transaction)
        .await
        .unwrap();
}

/// Create a System Program nonce account for the relay transaction's durable nonce.
async fn create_durable_nonce(env: &TestEnv, authority: &Address) -> Address {
    let nonce = Keypair::new();
    let lamports = env
        .rpc
        .get_minimum_balance_for_rent_exemption(State::size())
        .await
        .unwrap();
    let transaction = Transaction::new_signed_with_payer(
        &create_nonce_account(&env.payer.pubkey(), &nonce.pubkey(), authority, lamports),
        Some(&env.payer.pubkey()),
        &[&env.payer, &nonce],
        env.rpc.get_latest_blockhash().await.unwrap(),
    );
    env.rpc
        .send_and_confirm_transaction(&transaction)
        .await
        .unwrap();
    nonce.pubkey()
}

async fn durable_nonce_value(env: &TestEnv, address: &Address) -> Hash {
    let account = env.rpc.get_account(address).await.unwrap();
    let versions = wincode::deserialize::<Versions>(&account.data).unwrap();
    let State::Initialized(data) = versions.state() else {
        panic!("durable nonce account {address} is not initialized");
    };
    data.blockhash()
}

fn keypair_file(keypair: &Keypair) -> NamedTempFile {
    let file = NamedTempFile::new().unwrap();
    write_keypair_file(keypair, &file).unwrap();
    file
}

fn submit(env: &TestEnv, message: &VersionedMessage, extra: &[&str], input: &str) -> Output {
    let encoded = encode(message);
    let mut args = vec![
        "-C",
        &env.config_file_path,
        "transaction",
        "submit",
        "--authorization-message",
        &encoded,
    ];
    args.extend_from_slice(extra);
    run_psigner_with_input(&args, input)
}

/// The signing summary shown to local signers on the authorization message.
struct Summary<'a> {
    authorities: &'a [Address],
    forwarded_signers: &'a [Address],
    confirmed_by: &'a [Address],
}

/// Local signers on the authorization message see the signing summary and confirm; a fee payer that
/// only signs the relay transaction does not.
fn assert_submitted(output: &Output, summary: Option<Summary>) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    match summary {
        None => assert!(stderr.is_empty(), "{stderr}"),
        Some(summary) => assert_summary(&stderr, &summary),
    }
    let signature = String::from_utf8(output.stdout.clone()).unwrap();
    signature
        .trim()
        .parse::<solana_signature::Signature>()
        .unwrap();
}

fn assert_summary(stderr: &str, summary: &Summary) {
    assert!(stderr.starts_with("=== Signing ==="), "{stderr}");
    let authorities = summary
        .authorities
        .iter()
        .map(|authority| {
            format!(
                "  {authority} (derived signer: {})",
                programmatic_signer(authority)
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let forwarded_signers = if summary.forwarded_signers.is_empty() {
        String::new()
    } else {
        let lines = summary
            .forwarded_signers
            .iter()
            .map(|address| format!("  {address}"))
            .collect::<Vec<_>>()
            .join("\n");
        format!("\nForwarded signers (sign at submission):\n{lines}\n")
    };
    assert!(
        stderr.contains(&format!(
            "PDA promotion authorities:\n{authorities}\n{forwarded_signers}\n=== Replay \
             protection ==="
        )),
        "{stderr}"
    );
    assert!(
        stderr.contains("Signing submits this Execute call immediately."),
        "{stderr}"
    );
    let addresses = summary
        .confirmed_by
        .iter()
        .map(Address::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    assert!(
        stderr.ends_with(&format!("Sign this message for {addresses}? [y/N] ")),
        "{stderr}"
    );
}

fn assert_failure(output: &Output, expected: &str) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "unexpected success: {stderr}");
    assert!(output.stdout.is_empty());
    assert!(stderr.contains(expected), "{stderr}");
}

pub async fn submits_authority_signed_transfer_and_rejects_replay(env: &TestEnv) {
    let authority = Keypair::new();
    let signer = programmatic_signer(&authority.pubkey());
    fund(env, &[signer]).await;
    let test = SubmitTest::new(env, &signer).await;
    let message = build_authorization_message(
        &test.execution_message(&[signer]),
        &test.nonce_account,
        &signer,
        &[authority.pubkey()],
    );
    let authority_entry = signature_entry(&authority, &message);

    assert_submitted(
        &submit(env, &message, &["--signer", &authority_entry], ""),
        None,
    );
    test.assert_received(env, 1).await;

    // The nonce has advanced, so the same signatures cannot be submitted again.
    let replay = submit(env, &message, &["--signer", &authority_entry], "");
    assert_failure(
        &replay,
        &format!(
            "authorization message uses nonce value {}, but nonce account {} currently has",
            test.nonce, test.nonce_account
        ),
    );
    test.assert_received(env, 1).await;
}

pub async fn submits_with_forwarded_ordinary_signer(env: &TestEnv) {
    let authority = Keypair::new();
    let signer = programmatic_signer(&authority.pubkey());
    let ordinary = Keypair::new();
    fund(env, &[signer, ordinary.pubkey()]).await;
    let test = SubmitTest::new(env, &signer).await;
    let message = build_authorization_message(
        &test.execution_message(&[signer, ordinary.pubkey()]),
        &test.nonce_account,
        &signer,
        &[authority.pubkey()],
    );
    let ordinary_file = keypair_file(&ordinary);

    assert_submitted(
        &submit(
            env,
            &message,
            &[
                "--signer",
                &signature_entry(&authority, &message),
                "--relay-signer",
                ordinary_file.path().to_str().unwrap(),
            ],
            "y",
        ),
        Some(Summary {
            authorities: &[authority.pubkey()],
            forwarded_signers: &[ordinary.pubkey()],
            confirmed_by: &[ordinary.pubkey()],
        }),
    );
    test.assert_received(env, 2).await;
}

pub async fn submits_with_plain_key_nonce_authority(env: &TestEnv) {
    let authority = Keypair::new();
    let signer = programmatic_signer(&authority.pubkey());
    let nonce_authority = Keypair::new();
    fund(env, &[signer]).await;
    let test = SubmitTest::new(env, &nonce_authority.pubkey()).await;
    let message = build_authorization_message(
        &test.execution_message(&[signer]),
        &test.nonce_account,
        &nonce_authority.pubkey(),
        &[authority.pubkey()],
    );
    let nonce_authority_file = keypair_file(&nonce_authority);

    assert_submitted(
        &submit(
            env,
            &message,
            &[
                "--signer",
                &signature_entry(&authority, &message),
                "--relay-signer",
                nonce_authority_file.path().to_str().unwrap(),
            ],
            "y",
        ),
        Some(Summary {
            authorities: &[authority.pubkey()],
            forwarded_signers: &[nonce_authority.pubkey()],
            confirmed_by: &[nonce_authority.pubkey()],
        }),
    );
    test.assert_received(env, 1).await;
}

pub async fn submits_with_fee_payer_as_forwarded_signer(env: &TestEnv) {
    let authority = Keypair::new();
    let signer = programmatic_signer(&authority.pubkey());
    fund(env, &[signer]).await;
    let test = SubmitTest::new(env, &signer).await;
    // The configured keypair pays the relay fee and also sends one of the execution message
    // transfers.
    let message = build_authorization_message(
        &test.execution_message(&[signer, env.payer.pubkey()]),
        &test.nonce_account,
        &signer,
        &[authority.pubkey()],
    );

    assert_submitted(
        &submit(
            env,
            &message,
            &["--signer", &signature_entry(&authority, &message)],
            "y",
        ),
        Some(Summary {
            authorities: &[authority.pubkey()],
            forwarded_signers: &[env.payer.pubkey()],
            confirmed_by: &[env.payer.pubkey()],
        }),
    );
    test.assert_received(env, 2).await;
}

pub async fn submits_authority_signatures_in_any_order(env: &TestEnv) {
    let mut authorities = [Keypair::new(), Keypair::new()];
    // Supply signatures in reverse message order, so passing them through unsorted would fail.
    authorities.sort_by_key(|authority| std::cmp::Reverse(authority.pubkey()));
    let signers = authorities
        .each_ref()
        .map(|authority| programmatic_signer(&authority.pubkey()));
    fund(env, &signers).await;
    let test = SubmitTest::new(env, &signers[0]).await;
    let message = build_authorization_message(
        &test.execution_message(&signers),
        &test.nonce_account,
        &signers[0],
        &authorities.each_ref().map(Signer::pubkey),
    );

    assert_submitted(
        &submit(
            env,
            &message,
            &[
                "--signer",
                &signature_entry(&authorities[0], &message),
                "--signer",
                &signature_entry(&authorities[1], &message),
            ],
            "",
        ),
        None,
    );
    test.assert_received(env, 2).await;
}

pub async fn submits_with_forwarded_authority(env: &TestEnv) {
    let authority = Keypair::new();
    let signer = programmatic_signer(&authority.pubkey());
    fund(env, &[signer, authority.pubkey()]).await;
    let test = SubmitTest::new(env, &signer).await;
    // The authority promotes its PDA and also sends one of the execution message transfers
    // directly.
    let message = build_authorization_message(
        &test.execution_message(&[signer, authority.pubkey()]),
        &test.nonce_account,
        &signer,
        &[authority.pubkey()],
    );
    let authority_file = keypair_file(&authority);

    assert_submitted(
        &submit(
            env,
            &message,
            &[
                "--signer",
                &signature_entry(&authority, &message),
                "--relay-signer",
                authority_file.path().to_str().unwrap(),
            ],
            "y",
        ),
        Some(Summary {
            authorities: &[authority.pubkey()],
            forwarded_signers: &[authority.pubkey()],
            confirmed_by: &[authority.pubkey()],
        }),
    );
    test.assert_received(env, 2).await;
}

pub async fn submits_with_authority_as_execution_message_non_signer(env: &TestEnv) {
    let authority = Keypair::new();
    let signer = programmatic_signer(&authority.pubkey());
    fund(env, &[signer]).await;
    let test = SubmitTest::new(env, &signer).await;
    // The authority's own address only receives a transfer, so it is not forwarded.
    let execution_message = v1::Message::try_compile(
        &signer,
        &[
            transfer(&signer, &test.recipient, TRANSFER_AMOUNT),
            transfer(&signer, &authority.pubkey(), TRANSFER_AMOUNT),
        ],
        test.nonce,
    )
    .unwrap();
    let message = build_authorization_message(
        &execution_message,
        &test.nonce_account,
        &signer,
        &[authority.pubkey()],
    );

    assert_submitted(
        &submit(
            env,
            &message,
            &["--signer", &signature_entry(&authority, &message)],
            "",
        ),
        None,
    );
    test.assert_received(env, 1).await;
    assert_eq!(
        env.rpc.get_balance(&authority.pubkey()).await.unwrap(),
        TRANSFER_AMOUNT
    );
}

pub async fn rejects_nonce_authority_mismatch(env: &TestEnv) {
    let authority = Keypair::new();
    let signer = programmatic_signer(&authority.pubkey());
    let other_authority = Keypair::new();
    fund(env, &[signer]).await;
    let test = SubmitTest::new(env, &signer).await;
    // The message names a different nonce authority than the live nonce account.
    let message = build_authorization_message(
        &test.execution_message(&[signer]),
        &test.nonce_account,
        &other_authority.pubkey(),
        &[authority.pubkey()],
    );
    let other_authority_file = keypair_file(&other_authority);

    assert_failure(
        &submit(
            env,
            &message,
            &[
                "--signer",
                &signature_entry(&authority, &message),
                "--relay-signer",
                other_authority_file.path().to_str().unwrap(),
            ],
            "",
        ),
        &format!(
            "authorization message uses nonce authority {}, but nonce account {} has authority \
             {signer}",
            other_authority.pubkey(),
            test.nonce_account
        ),
    );
    test.assert_received(env, 0).await;
}

pub async fn cancels_when_forwarded_signer_declines(env: &TestEnv) {
    let authority = Keypair::new();
    let signer = programmatic_signer(&authority.pubkey());
    let ordinary = Keypair::new();
    fund(env, &[signer, ordinary.pubkey()]).await;
    let test = SubmitTest::new(env, &signer).await;
    let message = build_authorization_message(
        &test.execution_message(&[signer, ordinary.pubkey()]),
        &test.nonce_account,
        &signer,
        &[authority.pubkey()],
    );
    let ordinary_file = keypair_file(&ordinary);

    let output = submit(
        env,
        &message,
        &[
            "--signer",
            &signature_entry(&authority, &message),
            "--relay-signer",
            ordinary_file.path().to_str().unwrap(),
        ],
        "n\n",
    );
    assert_failure(&output, "signing cancelled");
    assert_summary(
        String::from_utf8_lossy(&output.stderr).trim_end_matches("Error: signing cancelled\n"),
        &Summary {
            authorities: &[authority.pubkey()],
            forwarded_signers: &[ordinary.pubkey()],
            confirmed_by: &[ordinary.pubkey()],
        },
    );
    test.assert_received(env, 0).await;
}

pub async fn submits_quietly_without_confirmation(env: &TestEnv) {
    let authority = Keypair::new();
    let signer = programmatic_signer(&authority.pubkey());
    let ordinary = Keypair::new();
    fund(env, &[signer, ordinary.pubkey()]).await;
    let test = SubmitTest::new(env, &signer).await;
    let message = build_authorization_message(
        &test.execution_message(&[signer, ordinary.pubkey()]),
        &test.nonce_account,
        &signer,
        &[authority.pubkey()],
    );
    let ordinary_file = keypair_file(&ordinary);

    let output = submit(
        env,
        &message,
        &[
            "--signer",
            &signature_entry(&authority, &message),
            "--relay-signer",
            ordinary_file.path().to_str().unwrap(),
            "--quiet",
            "--yes",
        ],
        "",
    );
    assert_submitted(&output, None);
    test.assert_received(env, 2).await;
}

/// Sign `execution_message` offline against `nonce_hash` with `transaction sign`, returning its
/// single entry.
fn sign(
    env: &TestEnv,
    test: &SubmitTest,
    execution_message: &v1::Message,
    nonce_authority: &Address,
    nonce_hash: &str,
    authority: &Keypair,
) -> serde_json::Value {
    let execution_message = BASE64_STANDARD.encode(execution_message.serialize());
    let nonce_account = test.nonce_account.to_string();
    let nonce_authority = nonce_authority.to_string();
    let authority_address = authority.pubkey().to_string();
    let authority_file = keypair_file(authority);
    let output = run_psigner(&[
        "-C",
        &env.config_file_path,
        "--output",
        "json-compact",
        "transaction",
        "sign",
        "--execution-message",
        &execution_message,
        "--nonce-account",
        &nonce_account,
        "--nonce-authority",
        &nonce_authority,
        "--nonce-hash",
        nonce_hash,
        "--authority",
        &authority_address,
        "--signer",
        authority_file.path().to_str().unwrap(),
        "--quiet",
        "--yes",
    ]);
    let mut entries: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(entries.len(), 1);
    entries.remove(0)
}

/// Submit an authorization message whose only signer is the given address, with a precomputed
/// signature.
fn submit_signed(
    env: &TestEnv,
    address: &str,
    signature: &str,
    authorization_message: &str,
) -> Output {
    run_psigner_with_input(
        &[
            "-C",
            &env.config_file_path,
            "transaction",
            "submit",
            "--authorization-message",
            authorization_message,
            "--signer",
            &format!("{address}={signature}"),
        ],
        "",
    )
}

pub async fn submits_chain_signed_offline_with_next_nonce(env: &TestEnv) {
    let authority = Keypair::new();
    let signer = programmatic_signer(&authority.pubkey());
    fund(env, &[signer]).await;
    let test = SubmitTest::new(env, &signer).await;
    let execution_message = test.execution_message(&[signer]);

    // Both steps are signed before either is submitted, the second against the first's successor.
    let first = sign(
        env,
        &test,
        &execution_message,
        &signer,
        &test.nonce.to_string(),
        &authority,
    );
    let first_next = first["next_nonce"].as_str().unwrap();
    let second = sign(
        env,
        &test,
        &execution_message,
        &signer,
        first_next,
        &authority,
    );
    let second_next = second["next_nonce"].as_str().unwrap();

    // The second step cannot execute until the first advances the nonce to its successor.
    assert_failure(
        &submit_signed(
            env,
            second["address"].as_str().unwrap(),
            second["signature"].as_str().unwrap(),
            second["authorization_message"].as_str().unwrap(),
        ),
        &format!(
            "authorization message uses nonce value {first_next}, but nonce account {} currently \
             has",
            test.nonce_account
        ),
    );

    assert_submitted(
        &submit_signed(
            env,
            first["address"].as_str().unwrap(),
            first["signature"].as_str().unwrap(),
            first["authorization_message"].as_str().unwrap(),
        ),
        None,
    );
    assert_eq!(test.current_nonce(env).await.to_string(), first_next);
    test.assert_received(env, 1).await;

    assert_submitted(
        &submit_signed(
            env,
            second["address"].as_str().unwrap(),
            second["signature"].as_str().unwrap(),
            second["authorization_message"].as_str().unwrap(),
        ),
        None,
    );
    assert_eq!(test.current_nonce(env).await.to_string(), second_next);
    test.assert_received(env, 2).await;
}

pub async fn submits_with_durable_nonce(env: &TestEnv) {
    let authority = Keypair::new();
    let signer = programmatic_signer(&authority.pubkey());
    let ordinary = Keypair::new();
    fund(env, &[signer, ordinary.pubkey()]).await;
    let test = SubmitTest::new(env, &signer).await;
    // The forwarded signer also authorizes the durable nonce. A separate durable nonce authority
    // would push this relay transaction over the transaction size limit.
    // TODO: Test a separate durable nonce authority once the relay transaction is v1
    let durable_nonce = create_durable_nonce(env, &ordinary.pubkey()).await;
    let value = durable_nonce_value(env, &durable_nonce).await;
    let message = build_authorization_message(
        &test.execution_message(&[signer, ordinary.pubkey()]),
        &test.nonce_account,
        &signer,
        &[authority.pubkey()],
    );
    let ordinary_file = keypair_file(&ordinary);
    let ordinary_path = ordinary_file.path().to_str().unwrap();

    assert_submitted(
        &submit(
            env,
            &message,
            &[
                "--signer",
                &signature_entry(&authority, &message),
                "--relay-signer",
                ordinary_path,
                "--durable-nonce",
                &durable_nonce.to_string(),
                "--durable-nonce-authority",
                ordinary_path,
                "--blockhash",
                &value.to_string(),
            ],
            "y",
        ),
        Some(Summary {
            authorities: &[authority.pubkey()],
            forwarded_signers: &[ordinary.pubkey()],
            confirmed_by: &[ordinary.pubkey()],
        }),
    );
    test.assert_received(env, 2).await;
    // The relay transaction advanced its durable nonce.
    assert_ne!(durable_nonce_value(env, &durable_nonce).await, value);
}

pub async fn submits_with_blockhash(env: &TestEnv) {
    let authority = Keypair::new();
    let signer = programmatic_signer(&authority.pubkey());
    fund(env, &[signer]).await;
    let test = SubmitTest::new(env, &signer).await;
    let blockhash = env.rpc.get_latest_blockhash().await.unwrap();
    let message = build_authorization_message(
        &test.execution_message(&[signer]),
        &test.nonce_account,
        &signer,
        &[authority.pubkey()],
    );
    let authority_entry = signature_entry(&authority, &message);

    // An unknown blockhash is used as given rather than replaced with the latest.
    assert_failure(
        &submit(
            env,
            &message,
            &[
                "--signer",
                &authority_entry,
                "--blockhash",
                &Hash::new_unique().to_string(),
            ],
            "",
        ),
        "Blockhash not found",
    );
    test.assert_received(env, 0).await;

    assert_submitted(
        &submit(
            env,
            &message,
            &[
                "--signer",
                &authority_entry,
                "--blockhash",
                &blockhash.to_string(),
            ],
            "",
        ),
        None,
    );
    test.assert_received(env, 1).await;
}

pub async fn rejects_stale_durable_nonce_value(env: &TestEnv) {
    let authority = Keypair::new();
    let signer = programmatic_signer(&authority.pubkey());
    fund(env, &[signer]).await;
    let test = SubmitTest::new(env, &signer).await;
    // The durable nonce authority defaults to the fee payer.
    let durable_nonce = create_durable_nonce(env, &env.payer.pubkey()).await;
    let value = durable_nonce_value(env, &durable_nonce).await;
    let stale = Hash::new_unique();
    let message = build_authorization_message(
        &test.execution_message(&[signer]),
        &test.nonce_account,
        &signer,
        &[authority.pubkey()],
    );

    assert_failure(
        &submit(
            env,
            &message,
            &[
                "--signer",
                &signature_entry(&authority, &message),
                "--durable-nonce",
                &durable_nonce.to_string(),
                "--blockhash",
                &stale.to_string(),
            ],
            "",
        ),
        &format!(
            "relay transaction uses durable nonce value {stale}, but durable nonce account \
             {durable_nonce} currently has {value}"
        ),
    );
    test.assert_received(env, 0).await;
}

pub async fn rejects_durable_nonce_authority_mismatch(env: &TestEnv) {
    let authority = Keypair::new();
    let signer = programmatic_signer(&authority.pubkey());
    let durable_nonce_authority = Keypair::new();
    fund(env, &[signer]).await;
    let test = SubmitTest::new(env, &signer).await;
    let durable_nonce = create_durable_nonce(env, &durable_nonce_authority.pubkey()).await;
    let message = build_authorization_message(
        &test.execution_message(&[signer]),
        &test.nonce_account,
        &signer,
        &[authority.pubkey()],
    );

    // Without --durable-nonce-authority, the fee payer is assumed to be the authority.
    assert_failure(
        &submit(
            env,
            &message,
            &[
                "--signer",
                &signature_entry(&authority, &message),
                "--durable-nonce",
                &durable_nonce.to_string(),
            ],
            "",
        ),
        &format!(
            "relay transaction uses durable nonce authority {}, but durable nonce account \
             {durable_nonce} has authority {}",
            env.payer.pubkey(),
            durable_nonce_authority.pubkey()
        ),
    );
    test.assert_received(env, 0).await;
}
