use {
    crate::common::{
        execute::{encode, execute_message, programmatic_signer, signature_entry},
        helpers::{TestEnv, run_psigner, run_psigner_with_input},
    },
    solana_address::Address,
    solana_hash::Hash,
    solana_keypair::{Keypair, write_keypair_file},
    solana_message::{VersionedMessage, legacy::Message},
    solana_signer::Signer,
    solana_system_interface::instruction::transfer,
    solana_transaction::Transaction,
    spl_programmatic_signer_cli::NonceCreateOutput,
    std::process::Output,
    tempfile::NamedTempFile,
};

const INITIAL_BALANCE: u64 = 10_000_000;
pub(crate) const TRANSFER_AMOUNT: u64 = 1_000_000;

/// A funded recipient and a nonce account whose value the inner message uses as its blockhash.
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

    /// An inner message transferring from each sender to the recipient.
    pub(crate) fn inner(&self, senders: &[Address]) -> Message {
        let transfers = senders
            .iter()
            .map(|sender| transfer(sender, &self.recipient, TRANSFER_AMOUNT))
            .collect::<Vec<_>>();
        Message::new_with_blockhash(&transfers, Some(&senders[0]), &self.nonce)
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
        "--execute-message",
        &encoded,
    ];
    args.extend_from_slice(extra);
    run_psigner_with_input(&args, input)
}

/// The signing summary shown to local signers on the execute message.
struct Summary<'a> {
    authorities: &'a [Address],
    forwarded_signers: &'a [Address],
    confirmed_by: &'a [Address],
}

/// Local signers on the execute message see the signing summary and confirm; a fee payer that
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
    assert!(stderr.starts_with("=== Authorization ==="), "{stderr}");
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
    let message = execute_message(
        &test.inner(&[signer]),
        &test.nonce_account,
        &signer,
        &[authority.pubkey()],
    );
    let authority_entry = signature_entry(&authority, &message);

    assert_submitted(
        &submit(env, &message, &["--authority", &authority_entry], ""),
        None,
    );
    test.assert_received(env, 1).await;

    // The nonce has advanced, so the same signatures cannot be submitted again.
    let replay = submit(env, &message, &["--authority", &authority_entry], "");
    assert_failure(
        &replay,
        &format!(
            "execute message uses nonce value {}, but nonce account {} currently has",
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
    let message = execute_message(
        &test.inner(&[signer, ordinary.pubkey()]),
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
                "--authority",
                &signature_entry(&authority, &message),
                "--signer",
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
    let message = execute_message(
        &test.inner(&[signer]),
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
                "--authority",
                &signature_entry(&authority, &message),
                "--signer",
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
    // The configured keypair pays the relay fee and also sends one of the inner transfers.
    let message = execute_message(
        &test.inner(&[signer, env.payer.pubkey()]),
        &test.nonce_account,
        &signer,
        &[authority.pubkey()],
    );

    assert_submitted(
        &submit(
            env,
            &message,
            &["--authority", &signature_entry(&authority, &message)],
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
    let message = execute_message(
        &test.inner(&signers),
        &test.nonce_account,
        &signers[0],
        &authorities.each_ref().map(Signer::pubkey),
    );

    assert_submitted(
        &submit(
            env,
            &message,
            &[
                "--authority",
                &signature_entry(&authorities[0], &message),
                "--authority",
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
    // The authority promotes its PDA and also sends one of the inner transfers directly.
    let message = execute_message(
        &test.inner(&[signer, authority.pubkey()]),
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
                "--authority",
                &signature_entry(&authority, &message),
                "--signer",
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

pub async fn submits_with_authority_as_inner_non_signer(env: &TestEnv) {
    let authority = Keypair::new();
    let signer = programmatic_signer(&authority.pubkey());
    fund(env, &[signer]).await;
    let test = SubmitTest::new(env, &signer).await;
    // The authority's own address only receives a transfer, so it is not forwarded.
    let inner = Message::new_with_blockhash(
        &[
            transfer(&signer, &test.recipient, TRANSFER_AMOUNT),
            transfer(&signer, &authority.pubkey(), TRANSFER_AMOUNT),
        ],
        Some(&signer),
        &test.nonce,
    );
    let message = execute_message(&inner, &test.nonce_account, &signer, &[authority.pubkey()]);

    assert_submitted(
        &submit(
            env,
            &message,
            &["--authority", &signature_entry(&authority, &message)],
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
    let message = execute_message(
        &test.inner(&[signer]),
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
                "--authority",
                &signature_entry(&authority, &message),
                "--signer",
                other_authority_file.path().to_str().unwrap(),
            ],
            "",
        ),
        &format!(
            "execute message uses nonce authority {}, but nonce account {} has authority {signer}",
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
    let message = execute_message(
        &test.inner(&[signer, ordinary.pubkey()]),
        &test.nonce_account,
        &signer,
        &[authority.pubkey()],
    );
    let ordinary_file = keypair_file(&ordinary);

    let output = submit(
        env,
        &message,
        &[
            "--authority",
            &signature_entry(&authority, &message),
            "--signer",
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
    let message = execute_message(
        &test.inner(&[signer, ordinary.pubkey()]),
        &test.nonce_account,
        &signer,
        &[authority.pubkey()],
    );
    let ordinary_file = keypair_file(&ordinary);

    let output = submit(
        env,
        &message,
        &[
            "--authority",
            &signature_entry(&authority, &message),
            "--signer",
            ordinary_file.path().to_str().unwrap(),
            "--quiet",
            "--yes",
        ],
        "",
    );
    assert_submitted(&output, None);
    test.assert_received(env, 2).await;
}
