use {
    crate::common::{
        execute::{build_authorization_message, encode, programmatic_signer, signature_entry},
        helpers::{TestEnv, run_psigner, run_psigner_with_input},
        lighthouse,
    },
    base64::{Engine, prelude::BASE64_STANDARD},
    solana_address::Address,
    solana_cli_output::CliSignOnlyData,
    solana_commitment_config::CommitmentConfig,
    solana_hash::Hash,
    solana_keypair::{Keypair, write_keypair_file},
    solana_message::{VersionedMessage, v1},
    solana_nonce::{state::State, versions::Versions},
    solana_rpc_client_types::config::{RpcSimulateTransactionConfig, RpcTransactionConfig},
    solana_signer::Signer,
    solana_system_interface::instruction::{create_nonce_account, transfer},
    solana_transaction::{InstructionError, Transaction, TransactionError},
    solana_transaction_status::UiTransactionEncoding,
    spl_ed25519_signer_client::{
        instruction::submit as submit_instruction, message::authorization_message,
    },
    spl_message_executor_client::instruction::execute,
    spl_message_executor_interface::{
        error::Error as ExecutorError, instruction::derive_transition_commitment,
        pda::TransitionSigner,
    },
    spl_nonce_client::instruction::advance,
    spl_nonce_interface::state::Nonce,
    spl_programmatic_signer_cli::NonceCreateOutput,
    std::{
        collections::{BTreeMap, BTreeSet},
        process::Output,
        time::Duration,
    },
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
        v1::Message::try_compile_with_config(
            &senders[0],
            &transfers,
            self.nonce,
            v1::TransactionConfig::empty(),
        )
        .unwrap()
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

fn read_message(encoded: &str) -> VersionedMessage {
    wincode::deserialize_exact(&BASE64_STANDARD.decode(encoded).unwrap()).unwrap()
}

fn keypair_file(keypair: &Keypair) -> NamedTempFile {
    let file = NamedTempFile::new().unwrap();
    write_keypair_file(keypair, &file).unwrap();
    file
}

pub(crate) fn submit(
    env: &TestEnv,
    message: &VersionedMessage,
    extra: &[&str],
    input: &str,
) -> Output {
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

/// The signing summary shown when the authorization message has forwarded signers.
struct Summary<'a> {
    authorities: &'a [Address],
    forwarded_signers: &'a [Address],
    /// Local signers asked to confirm. Empty when no local signer signs the authorization message,
    /// so there is no prompt.
    confirmed_by: &'a [Address],
}

/// The signing summary shows when the authorization message has forwarded signers, and local
/// signers on it confirm.
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

/// A landed relay transaction from the signature `transaction submit` printed.
pub(crate) struct LandedRelayTransaction {
    pub(crate) message: v1::Message,
    /// Compute units the transaction consumed.
    pub(crate) units: u64,
    /// Fee charged to the fee payer, in lamports.
    pub(crate) fee: u64,
}

async fn landed_relay_transaction(env: &TestEnv, output: &Output) -> LandedRelayTransaction {
    let signature = String::from_utf8(output.stdout.clone())
        .unwrap()
        .trim()
        .parse::<solana_signature::Signature>()
        .unwrap();
    landed_transaction(env, &signature).await
}

/// Fetch the landed v1 transaction with `signature`.
pub(crate) async fn landed_transaction(
    env: &TestEnv,
    signature: &solana_signature::Signature,
) -> LandedRelayTransaction {
    // The CLI confirms at processed commitment, and transaction history starts at confirmed. A
    // confirmed signature status is not enough, since transaction history is written separately
    // and can lag behind it, so poll for the transaction itself.
    let config = RpcTransactionConfig {
        encoding: Some(UiTransactionEncoding::Base64),
        commitment: Some(CommitmentConfig::confirmed()),
        max_supported_transaction_version: Some(1),
        ..RpcTransactionConfig::default()
    };
    let mut attempts = 0..300;
    let transaction = loop {
        match env.rpc.get_transaction_with_config(signature, config).await {
            Ok(transaction) => break transaction,
            Err(_) if attempts.next().is_some() => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(error) => panic!("{error}"),
        }
    };
    let meta = transaction.transaction.meta.unwrap();
    let units: u64 = Option::from(meta.compute_units_consumed).unwrap();
    let VersionedMessage::V1(message) = transaction
        .transaction
        .transaction
        .decode()
        .unwrap()
        .message
    else {
        panic!("expected a v1 relay transaction");
    };
    LandedRelayTransaction {
        message,
        units,
        fee: meta.fee,
    }
}

/// A relay transaction sent without separate relay signatures requests its simulated compute units
/// and loaded accounts data size, rather than the maximum.
async fn assert_simulated_limits(env: &TestEnv, output: &Output) {
    let LandedRelayTransaction { message, units, .. } = landed_relay_transaction(env, output).await;
    let limit = u64::from(message.config.compute_unit_limit.unwrap());
    assert!(units <= limit && limit < 1_400_000, "{units} of {limit}");
    let size = message.config.loaded_accounts_data_size_limit.unwrap();
    assert!(size < 64 * 1024 * 1024, "{size}");
}

/// The fee for a landed relay transaction: the base fee for each signature plus its priority fee.
pub(crate) fn assert_fee(landed: &LandedRelayTransaction, priority_fee: u64) {
    assert_eq!(landed.message.config.priority_fee, Some(priority_fee));
    let base_fee = u64::from(landed.message.header.num_required_signatures)
        .checked_mul(5_000)
        .unwrap();
    assert_eq!(landed.fee, base_fee.checked_add(priority_fee).unwrap());
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
    if summary.confirmed_by.is_empty() {
        assert!(
            stderr.ends_with("Submits this Execute call immediately.\n"),
            "{stderr}"
        );
        return;
    }
    assert!(
        stderr.contains("Submits this Execute call immediately."),
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

    let output = submit(env, &message, &["--signer", &authority_entry], "");
    assert_submitted(&output, None);
    test.assert_received(env, 1).await;
    assert_simulated_limits(env, &output).await;

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

/// A failed Execute does not advance the nonce, so a failing authorization stays valid until the
/// nonce is used. An execution message expires by asserting a last valid slot: once the slot
/// passes, Execute fails, and no submission can succeed. The nonce stays usable by a new
/// authorization.
pub async fn rejects_expired_execution_message(env: &TestEnv) {
    let authority = Keypair::new();
    let signer = programmatic_signer(&authority.pubkey());
    fund(env, &[signer]).await;
    let test = SubmitTest::new(env, &signer).await;
    let authorize = |last_valid_slot| {
        let execution_message = v1::Message::try_compile_with_config(
            &signer,
            &[
                lighthouse::assert_slot_at_most(last_valid_slot),
                transfer(&signer, &test.recipient, TRANSFER_AMOUNT),
            ],
            test.nonce,
            v1::TransactionConfig::empty(),
        )
        .unwrap();
        let message = build_authorization_message(
            &execution_message,
            &test.nonce_account,
            &signer,
            &[authority.pubkey()],
        );
        let authority_entry = signature_entry(&authority, &message);
        (message, authority_entry)
    };

    // A slot that has already passed, so the execution message has expired.
    let last_valid_slot = env.rpc.get_slot().await.unwrap().checked_sub(1).unwrap();
    let (expired, expired_entry) = authorize(last_valid_slot);
    assert_failure(
        &submit(env, &expired, &["--signer", &expired_entry], ""),
        lighthouse::ASSERTION_FAILED,
    );
    test.assert_received(env, 0).await;
    assert_eq!(test.current_nonce(env).await, test.nonce);

    let (message, authority_entry) = authorize(u64::MAX);
    assert_submitted(
        &submit(env, &message, &["--signer", &authority_entry], ""),
        None,
    );
    test.assert_received(env, 1).await;
    assert_ne!(test.current_nonce(env).await, test.nonce);
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

/// A required relay signer approves each submission, first by signing the relay transaction, then
/// by signing the authorization message. A dry run does not need it.
pub async fn submits_with_required_relay_signer(env: &TestEnv) {
    let authority = Keypair::new();
    let signer = programmatic_signer(&authority.pubkey());
    let required_relay_signer = Keypair::new();
    let required_relay_signer_address = required_relay_signer.pubkey().to_string();
    fund(env, &[signer]).await;
    let test = SubmitTest::new(env, &signer).await;
    let execution_message = test.execution_message(&[signer]);
    let authority_file = keypair_file(&authority);
    let sign_with_required_relay_signer = |nonce_hash: &str| {
        let value = run_sign(
            env,
            &test,
            &execution_message,
            &signer,
            nonce_hash,
            &authority.pubkey(),
            &[
                "--required-relay-signer",
                &required_relay_signer_address,
                "--signer",
                authority_file.path().to_str().unwrap(),
                "--yes",
            ],
        );
        assert_eq!(
            value["required_relay_signers"],
            serde_json::json!([required_relay_signer_address])
        );
        let message = read_message(value["authorization_message"].as_str().unwrap());
        let authority_entry = format!(
            "{}={}",
            value["signatures"][0]["address"].as_str().unwrap(),
            value["signatures"][0]["signature"].as_str().unwrap()
        );
        (value, message, authority_entry)
    };

    let (first, message, authority_entry) =
        sign_with_required_relay_signer(&test.nonce.to_string());
    assert_failure(
        &submit(env, &message, &["--signer", &authority_entry], ""),
        &format!(
            "{required_relay_signer_address} is a required relay signer and must sign the relay \
             transaction or the authorization message"
        ),
    );
    // A dry run does not need the required relay signer.
    let output = dry_run(env, &message, &["--signer", &authority_entry]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    test.assert_received(env, 0).await;
    let required_relay_signer_file = keypair_file(&required_relay_signer);
    let output = submit(
        env,
        &message,
        &[
            "--signer",
            &authority_entry,
            "--relay-signer",
            required_relay_signer_file.path().to_str().unwrap(),
        ],
        "y",
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(
        stderr.contains(&format!(
            "Required relay signers (sign at submission):\n  {required_relay_signer_address}\n"
        )),
        "{stderr}"
    );
    assert!(
        stderr.ends_with(&format!(
            "Sign this message for {required_relay_signer_address}? [y/N] "
        )),
        "{stderr}"
    );
    test.assert_received(env, 1).await;

    let (_, message, authority_entry) =
        sign_with_required_relay_signer(first["next_nonce"].as_str().unwrap());
    assert_submitted(
        &submit(
            env,
            &message,
            &[
                "--signer",
                &authority_entry,
                "--signer",
                &signature_entry(&required_relay_signer, &message),
            ],
            "",
        ),
        None,
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
    let execution_message = v1::Message::try_compile_with_config(
        &signer,
        &[
            transfer(&signer, &test.recipient, TRANSFER_AMOUNT),
            transfer(&signer, &authority.pubkey(), TRANSFER_AMOUNT),
        ],
        test.nonce,
        v1::TransactionConfig::empty(),
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

/// A failed submission leaves the nonce unchanged, so the error says how to invalidate the
/// authorization message.
pub async fn suggests_nonce_advance_after_failed_submission(env: &TestEnv) {
    let authority = Keypair::new();
    // The derived signer is unfunded, so its transfer fails.
    let signer = programmatic_signer(&authority.pubkey());
    let test = SubmitTest::new(env, &signer).await;
    let message = build_authorization_message(
        &test.execution_message(&[signer]),
        &test.nonce_account,
        &signer,
        &[authority.pubkey()],
    );

    let output = submit(
        env,
        &message,
        &["--signer", &signature_entry(&authority, &message)],
        "",
    );
    assert_failure(&output, "Error: relay transaction ");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.ends_with(&format!(
            "\n\nIf the relay transaction did not land, the authorization message can still be \
             submitted until nonce account {nonce_account} advances. To invalidate it, run `nonce \
             advance {nonce_account}` with its nonce authority.\n",
            nonce_account = test.nonce_account,
        )),
        "{stderr}"
    );
    assert_eq!(test.current_nonce(env).await, test.nonce);
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
/// output.
fn sign(
    env: &TestEnv,
    test: &SubmitTest,
    execution_message: &v1::Message,
    nonce_authority: &Address,
    nonce_hash: &str,
    authority: &Keypair,
) -> serde_json::Value {
    let authority_file = keypair_file(authority);
    let value = run_sign(
        env,
        test,
        execution_message,
        nonce_authority,
        nonce_hash,
        &authority.pubkey(),
        &["--signer", authority_file.path().to_str().unwrap(), "--yes"],
    );
    assert_eq!(value["signatures"].as_array().unwrap().len(), 1);
    value
}

/// Run `transaction sign` for a single authority with `extra` arguments, returning its output.
fn run_sign(
    env: &TestEnv,
    test: &SubmitTest,
    execution_message: &v1::Message,
    nonce_authority: &Address,
    nonce_hash: &str,
    authority: &Address,
    extra: &[&str],
) -> serde_json::Value {
    let execution_message = BASE64_STANDARD.encode(execution_message.serialize());
    let nonce_account = test.nonce_account.to_string();
    let nonce_authority = nonce_authority.to_string();
    let authority_address = authority.to_string();
    let mut args = vec![
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
        "--quiet",
    ];
    args.extend_from_slice(extra);
    serde_json::from_slice(&run_psigner(&args).stdout).unwrap()
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
            second["signatures"][0]["address"].as_str().unwrap(),
            second["signatures"][0]["signature"].as_str().unwrap(),
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
            first["signatures"][0]["address"].as_str().unwrap(),
            first["signatures"][0]["signature"].as_str().unwrap(),
            first["authorization_message"].as_str().unwrap(),
        ),
        None,
    );
    assert_eq!(test.current_nonce(env).await.to_string(), first_next);
    test.assert_received(env, 1).await;

    assert_submitted(
        &submit_signed(
            env,
            second["signatures"][0]["address"].as_str().unwrap(),
            second["signatures"][0]["signature"].as_str().unwrap(),
            second["authorization_message"].as_str().unwrap(),
        ),
        None,
    );
    assert_eq!(test.current_nonce(env).await.to_string(), second_next);
    test.assert_received(env, 2).await;
}

/// Build a real Submit transaction without the CLI's additional signer validation.
async fn signed_submit_transaction(
    env: &TestEnv,
    nonce: &SubmitTest,
    authority: &Keypair,
    message: &v1::Message,
) -> Transaction {
    let signer = programmatic_signer(&authority.pubkey());
    let execute = execute(&nonce.nonce_account, &signer, message);
    let authorization = authorization_message(&execute, &[authority.pubkey()]).unwrap();
    let signature = authority.sign_message(&authorization.serialize());
    Transaction::new_signed_with_payer(
        &[submit_instruction(
            vec![Some(signature)],
            VersionedMessage::V1(authorization),
        )],
        Some(&env.payer.pubkey()),
        &[&env.payer],
        env.rpc.get_latest_blockhash().await.unwrap(),
    )
}

pub async fn rejects_nonce_chain_skips_through_submit(env: &TestEnv) {
    let authority = Keypair::new();
    let signer = programmatic_signer(&authority.pubkey());
    fund(env, &[signer]).await;
    let chain = SubmitTest::new(env, &signer).await;
    // Use a separate nonce to execute attempts to skip the chain's predecessor.
    let attack_nonce = SubmitTest::new(env, &signer).await;
    let predecessor = chain.execution_message(&[signer]);
    let commitment = derive_transition_commitment(&VersionedMessage::V1(predecessor));
    let expected_successor = Nonce {
        nonce: chain.nonce,
        ..Nonce::default()
    }
    .derive_next_nonce(
        &spl_nonce_interface::ID,
        &chain.nonce_account,
        &TransitionSigner::ADDRESS,
        &commitment,
    );
    let mut successor = chain.execution_message(&[signer]);
    successor.lifetime_specifier = expected_successor;
    let presigned_successor = signed_submit_transaction(env, &chain, &authority, &successor).await;

    // The promoted user PDA can advance the other account with itself as transition signer.
    // That succeeds, but produces a different nonce than the next message was signed for.
    let attack = advance(
        &signer,
        &signer,
        &chain.nonce_account,
        chain.nonce,
        commitment,
    );
    let message = v1::Message::try_compile_with_config(
        &signer,
        &[attack],
        attack_nonce.nonce,
        v1::TransactionConfig::empty(),
    )
    .unwrap();
    let transaction = signed_submit_transaction(env, &attack_nonce, &authority, &message).await;
    env.rpc
        .send_and_confirm_transaction(&transaction)
        .await
        .unwrap();
    assert_ne!(chain.current_nonce(env).await, expected_successor);

    let simulation = env
        .rpc
        .simulate_transaction_with_config(
            &presigned_successor,
            RpcSimulateTransactionConfig {
                sig_verify: true,
                commitment: Some(env.rpc.commitment()),
                ..RpcSimulateTransactionConfig::default()
            },
        )
        .await
        .unwrap()
        .value;
    let nonce_mismatch = ExecutorError::NonceMismatch as u32;
    let error: TransactionError = simulation
        .err
        .expect("presigned successor was unlocked")
        .into();
    assert_eq!(
        error,
        TransactionError::InstructionError(0, InstructionError::Custom(nonce_mismatch)),
    );
    assert!(simulation.logs.unwrap().contains(&format!(
        "Program {} failed: custom program error: {nonce_mismatch:#x}",
        spl_message_executor_interface::ID,
    )));
}

pub async fn submits_with_durable_nonce(env: &TestEnv) {
    let authority = Keypair::new();
    let signer = programmatic_signer(&authority.pubkey());
    let ordinary = Keypair::new();
    let durable_nonce_authority = Keypair::new();
    fund(env, &[signer, ordinary.pubkey()]).await;
    let test = SubmitTest::new(env, &signer).await;
    let durable_nonce = create_durable_nonce(env, &durable_nonce_authority.pubkey()).await;
    let value = durable_nonce_value(env, &durable_nonce).await;
    let message = build_authorization_message(
        &test.execution_message(&[signer, ordinary.pubkey()]),
        &test.nonce_account,
        &signer,
        &[authority.pubkey()],
    );
    let ordinary_file = keypair_file(&ordinary);
    let ordinary_path = ordinary_file.path().to_str().unwrap();
    let durable_nonce_authority_file = keypair_file(&durable_nonce_authority);

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
                durable_nonce_authority_file.path().to_str().unwrap(),
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

/// The fee payer and forwarded signer each sign in a separate --sign-only run, and a final run
/// with no local signers submits their signatures.
pub async fn submits_with_offline_relay_signatures(env: &TestEnv) {
    let authority = Keypair::new();
    let signer = programmatic_signer(&authority.pubkey());
    let ordinary = Keypair::new();
    let fee_payer = Keypair::new();
    fund(env, &[signer, ordinary.pubkey(), fee_payer.pubkey()]).await;
    let test = SubmitTest::new(env, &signer).await;
    // The durable nonce authority defaults to the fee payer.
    let durable_nonce = create_durable_nonce(env, &fee_payer.pubkey()).await;
    let value = durable_nonce_value(env, &durable_nonce).await;
    let message = build_authorization_message(
        &test.execution_message(&[signer, ordinary.pubkey()]),
        &test.nonce_account,
        &signer,
        &[authority.pubkey()],
    );
    let authority_entry = signature_entry(&authority, &message);
    let durable_nonce = durable_nonce.to_string();
    let value = value.to_string();
    let fee_payer_address = fee_payer.pubkey().to_string();
    let fee_payer_file = keypair_file(&fee_payer);
    let ordinary_file = keypair_file(&ordinary);
    let sign_only = |extra: &[&str]| {
        let mut args = vec![
            "--output",
            "json",
            "--signer",
            &authority_entry,
            "--durable-nonce",
            &durable_nonce,
            "--blockhash",
            &value,
            "--sign-only",
            "--with-compute-unit-limit",
            "300000",
            "--with-priority-fee",
            "450",
        ];
        args.extend_from_slice(extra);
        let output = submit(env, &message, &args, "");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let [entry] = serde_json::from_slice::<CliSignOnlyData>(&output.stdout)
            .unwrap()
            .signers
            .try_into()
            .unwrap();
        entry
    };
    let fee_payer_entry = sign_only(&["--fee-payer", fee_payer_file.path().to_str().unwrap()]);
    let ordinary_entry = sign_only(&[
        "--fee-payer",
        &fee_payer_address,
        "--relay-signer",
        ordinary_file.path().to_str().unwrap(),
        "--yes",
    ]);

    // The forwarded signer still shows the signing summary, but no local signer remains to confirm.
    let output = submit(
        env,
        &message,
        &[
            "--signer",
            &authority_entry,
            "--fee-payer",
            &fee_payer_address,
            "--durable-nonce",
            &durable_nonce,
            "--blockhash",
            &value,
            "--relay-signature",
            &fee_payer_entry,
            "--relay-signature",
            &ordinary_entry,
            "--with-compute-unit-limit",
            "300000",
            "--with-priority-fee",
            "450",
        ],
        "",
    );
    assert_submitted(
        &output,
        Some(Summary {
            authorities: &[authority.pubkey()],
            forwarded_signers: &[ordinary.pubkey()],
            confirmed_by: &[],
        }),
    );
    test.assert_received(env, 2).await;
    // Every run used the same fixed limits, so the relay signatures match, and the landed relay
    // transaction keeps them rather than simulating.
    let landed = landed_relay_transaction(env, &output).await;
    assert_eq!(landed.message.config.compute_unit_limit, Some(300_000));
    assert_eq!(
        landed.message.config.loaded_accounts_data_size_limit,
        Some(64 * 1024 * 1024)
    );
    assert_fee(&landed, 450);
    assert_ne!(
        durable_nonce_value(env, &durable_nonce.parse().unwrap())
            .await
            .to_string(),
        value
    );
}

/// The fee payer, forwarded signer and a separate durable nonce authority each sign in a separate
/// --sign-only run, and a final run with no local signers submits their signatures.
pub async fn submits_with_offline_durable_nonce_authority(env: &TestEnv) {
    let authority = Keypair::new();
    let signer = programmatic_signer(&authority.pubkey());
    let ordinary = Keypair::new();
    let fee_payer = Keypair::new();
    let durable_nonce_authority = Keypair::new();
    fund(env, &[signer, ordinary.pubkey(), fee_payer.pubkey()]).await;
    let test = SubmitTest::new(env, &signer).await;
    let durable_nonce = create_durable_nonce(env, &durable_nonce_authority.pubkey()).await;
    let value = durable_nonce_value(env, &durable_nonce).await;
    let message = build_authorization_message(
        &test.execution_message(&[signer, ordinary.pubkey()]),
        &test.nonce_account,
        &signer,
        &[authority.pubkey()],
    );
    let authority_entry = signature_entry(&authority, &message);
    let durable_nonce = durable_nonce.to_string();
    let value = value.to_string();
    let fee_payer_address = fee_payer.pubkey().to_string();
    let durable_nonce_authority_address = durable_nonce_authority.pubkey().to_string();
    let fee_payer_file = keypair_file(&fee_payer);
    let ordinary_file = keypair_file(&ordinary);
    let durable_nonce_authority_file = keypair_file(&durable_nonce_authority);
    let sign_only = |extra: &[&str]| {
        let mut args = vec![
            "--output",
            "json",
            "--signer",
            &authority_entry,
            "--durable-nonce",
            &durable_nonce,
            "--blockhash",
            &value,
            "--sign-only",
        ];
        args.extend_from_slice(extra);
        let output = submit(env, &message, &args, "");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let [entry] = serde_json::from_slice::<CliSignOnlyData>(&output.stdout)
            .unwrap()
            .signers
            .try_into()
            .unwrap();
        entry
    };
    let fee_payer_entry = sign_only(&[
        "--fee-payer",
        fee_payer_file.path().to_str().unwrap(),
        "--durable-nonce-authority",
        &durable_nonce_authority_address,
    ]);
    let ordinary_entry = sign_only(&[
        "--fee-payer",
        &fee_payer_address,
        "--durable-nonce-authority",
        &durable_nonce_authority_address,
        "--relay-signer",
        ordinary_file.path().to_str().unwrap(),
        "--yes",
    ]);
    let durable_nonce_authority_entry = sign_only(&[
        "--fee-payer",
        &fee_payer_address,
        "--durable-nonce-authority",
        durable_nonce_authority_file.path().to_str().unwrap(),
    ]);

    assert_submitted(
        &submit(
            env,
            &message,
            &[
                "--signer",
                &authority_entry,
                "--fee-payer",
                &fee_payer_address,
                "--durable-nonce",
                &durable_nonce,
                "--durable-nonce-authority",
                &durable_nonce_authority_address,
                "--blockhash",
                &value,
                "--relay-signature",
                &fee_payer_entry,
                "--relay-signature",
                &ordinary_entry,
                "--relay-signature",
                &durable_nonce_authority_entry,
            ],
            "",
        ),
        Some(Summary {
            authorities: &[authority.pubkey()],
            forwarded_signers: &[ordinary.pubkey()],
            confirmed_by: &[],
        }),
    );
    test.assert_received(env, 2).await;
    assert_ne!(
        durable_nonce_value(env, &durable_nonce.parse().unwrap())
            .await
            .to_string(),
        value
    );
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

pub async fn submits_unsigned_message_with_external_signature(env: &TestEnv) {
    let authority = Keypair::new();
    let signer = programmatic_signer(&authority.pubkey());
    fund(env, &[signer]).await;
    let test = SubmitTest::new(env, &signer).await;
    let execution_message = test.execution_message(&[signer]);
    let unsigned = run_sign(
        env,
        &test,
        &execution_message,
        &signer,
        &test.nonce.to_string(),
        &authority.pubkey(),
        &[],
    );
    assert_eq!(unsigned["signatures"], serde_json::json!([]));
    let authorization_message = unsigned["authorization_message"].as_str().unwrap();

    // The external signer, e.g. an HSM, signs the decoded message bytes as-is.
    let signature = authority.sign_message(&BASE64_STANDARD.decode(authorization_message).unwrap());
    assert_submitted(
        &submit_signed(
            env,
            &authority.pubkey().to_string(),
            &signature.to_string(),
            authorization_message,
        ),
        None,
    );
    assert_eq!(
        test.current_nonce(env).await.to_string(),
        unsigned["next_nonce"].as_str().unwrap()
    );
    test.assert_received(env, 1).await;
}

/// Run `transaction submit --dry-run` with JSON output.
fn dry_run(env: &TestEnv, message: &VersionedMessage, extra: &[&str]) -> Output {
    let mut args = vec!["--output", "json-compact", "--dry-run"];
    args.extend_from_slice(extra);
    submit(env, message, &args, "")
}

/// Each SOL balance change from a dry run, keyed by address.
fn sol_balance_changes(value: &serde_json::Value) -> BTreeMap<String, serde_json::Value> {
    value["solBalanceChanges"]
        .as_array()
        .unwrap()
        .iter()
        .map(|change| {
            (
                change["address"].as_str().unwrap().to_owned(),
                change.clone(),
            )
        })
        .collect()
}

/// A dry run needs no relay signers: the forwarded signer is omitted and the fee payer is given as
/// an address. Nothing is signed or submitted.
pub async fn dry_runs_without_relay_signers(env: &TestEnv) {
    let authority = Keypair::new();
    let signer = programmatic_signer(&authority.pubkey());
    let ordinary = Keypair::new();
    let fee_payer = Keypair::new();
    fund(env, &[signer, ordinary.pubkey(), fee_payer.pubkey()]).await;
    let test = SubmitTest::new(env, &signer).await;
    let message = build_authorization_message(
        &test.execution_message(&[signer, ordinary.pubkey()]),
        &test.nonce_account,
        &signer,
        &[authority.pubkey()],
    );

    let output = dry_run(
        env,
        &message,
        &[
            "--signer",
            &signature_entry(&authority, &message),
            "--fee-payer",
            &fee_payer.pubkey().to_string(),
        ],
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    // Nothing is signed, so there is no signing summary.
    assert!(stderr.is_empty(), "{stderr}");
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let fee = value["fee"].as_i64().unwrap();
    assert!(fee > 0);
    assert!(value["unitsConsumed"].as_u64().unwrap() > 0);
    let transfer = i64::try_from(TRANSFER_AMOUNT).unwrap();
    let sent = transfer.checked_neg().unwrap();
    let changes = sol_balance_changes(&value);
    let expected = [
        (signer, sent, Some(authority.pubkey())),
        (ordinary.pubkey(), sent, None),
        (test.recipient, transfer.checked_mul(2).unwrap(), None),
        // The relay transaction pays its own fee.
        (fee_payer.pubkey(), fee.checked_neg().unwrap(), None),
    ]
    .into_iter()
    .map(|(address, lamports, authority)| {
        let mut change = serde_json::json!({
            "address": address.to_string(),
            "lamports": lamports,
        });
        if let Some(authority) = authority {
            change["signingPubkey"] = authority.to_string().into();
        }
        (address.to_string(), change)
    })
    .collect::<BTreeMap<_, _>>();
    assert_eq!(changes, expected);
    assert_eq!(value["tokenBalanceChanges"], serde_json::json!([]));

    // --verbose adds the full simulation result on stderr.
    let output = dry_run(
        env,
        &message,
        &[
            "--signer",
            &signature_entry(&authority, &message),
            "--fee-payer",
            &fee_payer.pubkey().to_string(),
            "--verbose",
        ],
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    let verbose: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(verbose["unitsConsumed"], value["unitsConsumed"]);
    let result = stderr
        .strip_prefix("Simulation result:\n")
        .unwrap_or_else(|| panic!("{stderr}"));
    let result: serde_json::Value = serde_json::from_str(result).unwrap();
    assert!(result["err"].is_null());
    assert!(!result["innerInstructions"].as_array().unwrap().is_empty());
    // The relay transaction's writable accounts include the executed transfer's.
    let accounts = result["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["address"].as_str().unwrap().to_owned())
        .collect::<BTreeSet<_>>();
    for address in [
        fee_payer.pubkey(),
        signer,
        ordinary.pubkey(),
        test.recipient,
    ] {
        assert!(accounts.contains(&address.to_string()), "{accounts:?}");
    }

    test.assert_received(env, 0).await;
    assert_eq!(test.current_nonce(env).await, test.nonce);
}

/// A dry run with a durable nonce keeps its value as the blockhash, and checks the durable nonce
/// authority given as an address.
pub async fn dry_runs_with_durable_nonce(env: &TestEnv) {
    let authority = Keypair::new();
    let signer = programmatic_signer(&authority.pubkey());
    let durable_nonce_authority = Keypair::new();
    fund(env, &[signer]).await;
    let test = SubmitTest::new(env, &signer).await;
    let durable_nonce = create_durable_nonce(env, &durable_nonce_authority.pubkey()).await;
    let value = durable_nonce_value(env, &durable_nonce).await;
    let message = build_authorization_message(
        &test.execution_message(&[signer]),
        &test.nonce_account,
        &signer,
        &[authority.pubkey()],
    );
    let authority_entry = signature_entry(&authority, &message);
    let durable_nonce = durable_nonce.to_string();
    let durable_nonce_authority = durable_nonce_authority.pubkey().to_string();
    let args = |blockhash: &Hash| {
        dry_run(
            env,
            &message,
            &[
                "--signer",
                &authority_entry,
                "--durable-nonce",
                &durable_nonce,
                "--durable-nonce-authority",
                &durable_nonce_authority,
                "--blockhash",
                &blockhash.to_string(),
            ],
        )
    };

    let output = args(&value);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(output["fee"].as_u64().unwrap() > 0);
    test.assert_received(env, 0).await;
    assert_eq!(
        durable_nonce_value(env, &durable_nonce.parse().unwrap()).await,
        value
    );

    // The durable nonce value is checked before simulating.
    let stale = Hash::new_unique();
    assert_failure(
        &args(&stale),
        &format!("relay transaction uses durable nonce value {stale}"),
    );
}

pub async fn dry_run_reports_failed_simulation(env: &TestEnv) {
    let authority = Keypair::new();
    // The derived signer is unfunded, so its transfer fails.
    let signer = programmatic_signer(&authority.pubkey());
    let test = SubmitTest::new(env, &signer).await;
    let message = build_authorization_message(
        &test.execution_message(&[signer]),
        &test.nonce_account,
        &signer,
        &[authority.pubkey()],
    );

    let output = dry_run(
        env,
        &message,
        &["--signer", &signature_entry(&authority, &message)],
    );
    assert_failure(&output, "simulation failed");
    assert_failure(&output, "Logs:\nProgram ");
}

/// A dry run still needs the authority signatures, since Submit checks them.
pub async fn dry_run_requires_authority_signatures(env: &TestEnv) {
    let authority = Keypair::new();
    let signer = programmatic_signer(&authority.pubkey());
    let test = SubmitTest::new(env, &signer).await;
    let message = build_authorization_message(
        &test.execution_message(&[signer]),
        &test.nonce_account,
        &signer,
        &[authority.pubkey()],
    );

    assert_failure(
        &dry_run(env, &message, &[]),
        &format!("missing signature for authority {}", authority.pubkey()),
    );
}

/// An online run with --with-priority-fee sizes the limits from a simulation and pays the fee as
/// given.
pub async fn submits_with_priority_fee(env: &TestEnv) {
    submit_with_compute_budget_flags(
        env,
        BudgetFlags {
            priority_fee: Some(600),
            ..BudgetFlags::default()
        },
    )
    .await;
}

/// A fixed compute unit limit replaces the simulated one, and the loaded accounts data size is
/// still simulated.
pub async fn submits_with_compute_unit_limit(env: &TestEnv) {
    submit_with_compute_budget_flags(
        env,
        BudgetFlags {
            unit_limit: Some(300_000),
            ..BudgetFlags::default()
        },
    )
    .await;
}

/// A fixed loaded accounts data size limit replaces the simulated one, and the compute units are
/// still simulated.
pub async fn submits_with_loaded_accounts_data_size_limit(env: &TestEnv) {
    submit_with_compute_budget_flags(
        env,
        BudgetFlags {
            loaded_accounts_data_size_limit: Some(1_000_000),
            ..BudgetFlags::default()
        },
    )
    .await;
}

/// With every option, the fixed limits and the fee are all kept.
pub async fn submits_with_all_compute_budget_flags(env: &TestEnv) {
    submit_with_compute_budget_flags(
        env,
        BudgetFlags {
            unit_limit: Some(300_000),
            loaded_accounts_data_size_limit: Some(1_000_000),
            priority_fee: Some(450),
        },
    )
    .await;
}

/// The compute budget options for a `transaction submit` run.
#[derive(Default)]
struct BudgetFlags {
    unit_limit: Option<u32>,
    loaded_accounts_data_size_limit: Option<u32>,
    priority_fee: Option<u64>,
}

impl BudgetFlags {
    fn args(&self) -> Vec<String> {
        let mut args = vec![];
        if let Some(limit) = self.unit_limit {
            args.extend(["--with-compute-unit-limit".to_string(), limit.to_string()]);
        }
        if let Some(limit) = self.loaded_accounts_data_size_limit {
            args.extend([
                "--with-loaded-accounts-data-size-limit".to_string(),
                limit.to_string(),
            ]);
        }
        if let Some(fee) = self.priority_fee {
            args.extend(["--with-priority-fee".to_string(), fee.to_string()]);
        }
        args
    }
}

/// Submit online with `flags`, and check the landed relay transaction keeps the fixed limits,
/// sizes the rest from a simulation, and pays the priority fee as given. Each case is a separate
/// test so they run in parallel, since each waits for transaction history.
async fn submit_with_compute_budget_flags(env: &TestEnv, flags: BudgetFlags) {
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
    let flag_args = flags.args();
    let mut args = vec!["--signer", authority_entry.as_str()];
    args.extend(flag_args.iter().map(String::as_str));

    let output = submit(env, &message, &args, "");
    assert_submitted(&output, None);
    test.assert_received(env, 1).await;
    let landed = landed_relay_transaction(env, &output).await;
    let config = &landed.message.config;
    let unit_limit = config.compute_unit_limit.unwrap();
    match flags.unit_limit {
        Some(limit) => assert_eq!(unit_limit, limit),
        None => assert!(
            landed.units <= u64::from(unit_limit) && unit_limit < 1_400_000,
            "{} of {unit_limit}",
            landed.units
        ),
    }
    let size = config.loaded_accounts_data_size_limit.unwrap();
    match flags.loaded_accounts_data_size_limit {
        Some(limit) => assert_eq!(size, limit),
        None => assert!(size < 64 * 1024 * 1024, "{size}"),
    }
    match flags.priority_fee {
        Some(fee) => assert_fee(&landed, fee),
        None => assert_eq!(config.priority_fee, None),
    }
}

/// Fixed limits below what the relay transaction uses are kept rather than replaced by the
/// simulated ones, so the submission fails and the nonce does not advance.
pub async fn rejects_limits_below_usage(env: &TestEnv) {
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
    // Each failure leaves the nonce unchanged, so the same authorization message is reused.
    for (flag, limit, expected) in [
        ("--with-compute-unit-limit", "1000", "exceeded CUs meter"),
        (
            "--with-loaded-accounts-data-size-limit",
            "10000",
            "exceeded max loaded accounts data size cap",
        ),
    ] {
        let output = submit(
            env,
            &message,
            &["--signer", &authority_entry, flag, limit],
            "",
        );
        assert_failure(&output, expected);
        test.assert_received(env, 0).await;
        assert_eq!(test.current_nonce(env).await, test.nonce);
    }
}
