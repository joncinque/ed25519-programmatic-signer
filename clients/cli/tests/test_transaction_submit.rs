use {
    crate::common::{
        execute::{encode, execute_message, programmatic_signer, signature_entry},
        helpers::run_psigner_with_input,
    },
    solana_address::Address,
    solana_cli_config::Config as SolanaConfig,
    solana_hash::Hash,
    solana_instruction::{AccountMeta, Instruction},
    solana_keypair::{Keypair, write_keypair_file},
    solana_message::{VersionedMessage, legacy, v1},
    solana_signer::Signer,
    solana_system_interface::instruction::transfer,
    spl_ed25519_signer_client::message::wrapped_message,
    spl_message_executor_client::instruction::execute,
    spl_message_executor_interface::instruction::Instruction as ExecutorInstruction,
    std::{path::PathBuf, process::Output},
    tempfile::TempDir,
    test_case::test_case,
};

pub mod common;

/// An execute message signed by one PDA authority, whose derived signer is the nonce
/// authority, and one ordinary inner signer forwarded from the relay transaction.
struct SubmitTestEnv {
    directory: TempDir,
    config_file_path: String,
    authority: Keypair,
    ordinary: Keypair,
    nonce_account: Address,
    message: VersionedMessage,
}

impl SubmitTestEnv {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let fee_payer = Keypair::new();
        let fee_payer_file = directory.path().join("fee-payer.json");
        write_keypair_file(&fee_payer, &fee_payer_file).unwrap();
        let config_file_path = directory
            .path()
            .join("config.yml")
            .to_str()
            .unwrap()
            .to_string();
        SolanaConfig {
            // Every offline check must run before the nonce account lookup
            json_rpc_url: "http://127.0.0.1:1".into(),
            keypair_path: fee_payer_file.to_str().unwrap().into(),
            ..SolanaConfig::default()
        }
        .save(&config_file_path)
        .unwrap();

        let authority = Keypair::new();
        let ordinary = Keypair::new();
        let nonce_account = Address::new_unique();
        let nonce_authority = programmatic_signer(&authority.pubkey());
        let recipient = Address::new_unique();
        let inner = v1::Message::try_compile(
            &nonce_authority,
            &[
                transfer(&nonce_authority, &recipient, 1),
                transfer(&ordinary.pubkey(), &recipient, 1),
            ],
            Hash::new_unique(),
        )
        .unwrap();
        let message = execute_message(
            &inner,
            &nonce_account,
            &nonce_authority,
            &[authority.pubkey()],
        );
        Self {
            directory,
            config_file_path,
            authority,
            ordinary,
            nonce_account,
            message,
        }
    }

    fn keypair_file(&self, keypair: &Keypair) -> String {
        let path: PathBuf = self
            .directory
            .path()
            .join(format!("{}.json", keypair.pubkey()));
        write_keypair_file(keypair, &path).unwrap();
        path.to_str().unwrap().to_string()
    }

    fn authority_entry(&self) -> String {
        signature_entry(&self.authority, &self.message)
    }

    fn submit(&self, execute_message: &str, extra: &[&str]) -> Output {
        let mut args = vec![
            "-C",
            &self.config_file_path,
            "transaction",
            "submit",
            "--execute-message",
            execute_message,
        ];
        args.extend_from_slice(extra);
        run_psigner_with_input(&args, "")
    }

    fn submit_message(&self, extra: &[&str]) -> Output {
        self.submit(&encode(&self.message), extra)
    }

    /// Valid input fails only when the command reaches the unreachable RPC endpoint.
    fn assert_passes_offline_checks(&self, output: &Output) {
        assert_failure(
            output,
            &format!("failed to fetch account {}", self.nonce_account),
        );
    }
}

fn assert_failure(output: &Output, expected: &str) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "unexpected success: {stderr}");
    assert!(output.stdout.is_empty());
    assert!(stderr.contains(expected), "{stderr}");
}

#[test]
fn accepts_authority_signatures_and_forwarded_signers() {
    let env = SubmitTestEnv::new();
    let output = env.submit_message(&[
        "--authority",
        &env.authority_entry(),
        "--signer",
        &env.keypair_file(&env.ordinary),
    ]);
    env.assert_passes_offline_checks(&output);
}

#[test]
fn accepts_fee_payer_as_forwarded_signer() {
    let env = SubmitTestEnv::new();
    let output = env.submit_message(&[
        "--authority",
        &env.authority_entry(),
        "--fee-payer",
        &env.keypair_file(&env.ordinary),
    ]);
    env.assert_passes_offline_checks(&output);
}

#[test_case("!", "invalid base64 execute message"; "invalid base64")]
#[test_case("", "invalid serialized execute message"; "empty message")]
#[test_case("AA==", "invalid serialized execute message"; "truncated message")]
fn rejects_invalid_message_encoding(encoded: &str, expected: &str) {
    let env = SubmitTestEnv::new();
    assert_failure(&env.submit(encoded, &[]), expected);
}

#[test]
fn rejects_non_executor_instruction() {
    let env = SubmitTestEnv::new();
    let message = wrapped_message(
        &transfer(&env.authority.pubkey(), &Address::new_unique(), 1),
        &[env.authority.pubkey()],
    );
    assert_failure(
        &env.submit(&encode(&message), &[]),
        "expected an Executor Execute instruction",
    );
}

#[test]
fn rejects_execute_without_nonce_accounts() {
    let env = SubmitTestEnv::new();
    let instruction = Instruction::new_with_wincode(
        spl_message_executor_interface::id(),
        &ExecutorInstruction::Execute(VersionedMessage::V1(v1::Message::default())),
        vec![AccountMeta::new(Address::new_unique(), false)],
    );
    let message = wrapped_message(&instruction, &[env.authority.pubkey()]);
    assert_failure(
        &env.submit(&encode(&message), &[]),
        "expected the nonce authority, nonce account, and SPL Nonce program in Execute accounts",
    );
}

#[test_case(
    VersionedMessage::Legacy(legacy::Message::default()),
    "the executor supports only v1 inner messages";
    "legacy"
)]
#[test_case(
    VersionedMessage::V1(v1::Message {
        config: v1::TransactionConfig::default().with_priority_fee(1),
        ..v1::Message::default()
    }),
    "inner message must not set transaction config fields";
    "transaction config"
)]
fn rejects_inner_message_the_executor_cannot_invoke(inner: VersionedMessage, expected: &str) {
    let env = SubmitTestEnv::new();
    let instruction = Instruction::new_with_wincode(
        spl_message_executor_interface::id(),
        &ExecutorInstruction::Execute(inner),
        vec![AccountMeta::new(Address::new_unique(), false)],
    );
    let message = wrapped_message(&instruction, &[env.authority.pubkey()]);
    assert_failure(&env.submit(&encode(&message), &[]), expected);
}

#[test_case("missing separator", "invalid authority: expected ADDRESS=SIGNATURE"; "missing separator")]
#[test_case("invalid=invalid", "invalid authority address"; "invalid address")]
#[test_case("11111111111111111111111111111111=invalid", "invalid authority signature"; "invalid signature")]
fn rejects_malformed_authority_args(entry: &str, expected: &str) {
    let env = SubmitTestEnv::new();
    assert_failure(&env.submit_message(&["--authority", entry]), expected);
}

#[test]
fn rejects_authority_arg_not_on_execute_message() {
    let env = SubmitTestEnv::new();
    let stranger = Keypair::new();
    assert_failure(
        &env.submit_message(&["--authority", &signature_entry(&stranger, &env.message)]),
        &format!(
            "{} is not a signer on the execute message",
            stranger.pubkey()
        ),
    );
}

#[test]
fn rejects_authority_arg_for_a_different_message() {
    let env = SubmitTestEnv::new();
    let other = SubmitTestEnv::new();
    let entry = format!(
        "{}={}",
        env.authority.pubkey(),
        env.authority.sign_message(&other.message.serialize())
    );
    assert_failure(
        &env.submit_message(&["--authority", &entry]),
        &format!("invalid signature for authority {}", env.authority.pubkey()),
    );
}

#[test]
fn rejects_authority_without_authority_arg() {
    let env = SubmitTestEnv::new();
    assert_failure(
        &env.submit_message(&["--signer", &env.keypair_file(&env.ordinary)]),
        &format!(
            "missing signature for authority {}, authorities sign with `transaction sign`",
            env.authority.pubkey()
        ),
    );
}

#[test_case(false; "unsigned")]
#[test_case(true; "already signed")]
fn rejects_signer_arg_for_non_forwarded_authority(with_signature: bool) {
    let env = SubmitTestEnv::new();
    let authority_entry = env.authority_entry();
    let authority_file = env.keypair_file(&env.authority);
    let ordinary_file = env.keypair_file(&env.ordinary);
    let mut args = vec!["--signer", &authority_file, "--signer", &ordinary_file];
    if with_signature {
        args.extend(["--authority", &authority_entry]);
    }
    assert_failure(
        &env.submit_message(&args),
        &format!(
            "{} is not a forwarded signer on the execute message, PDA authorities sign with \
             `transaction sign`",
            env.authority.pubkey()
        ),
    );
}

#[test]
fn rejects_authority_arg_for_non_authority() {
    let env = SubmitTestEnv::new();
    assert_failure(
        &env.submit_message(&[
            "--authority",
            &env.authority_entry(),
            "--authority",
            &signature_entry(&env.ordinary, &env.message),
            "--signer",
            &env.keypair_file(&env.ordinary),
        ]),
        &format!(
            "{} is not a PDA authority on the execute message; pass it with --signer",
            env.ordinary.pubkey()
        ),
    );
}

#[test]
fn rejects_forwarded_signer_without_signer_arg() {
    let env = SubmitTestEnv::new();
    assert_failure(
        &env.submit_message(&["--authority", &env.authority_entry()]),
        &format!(
            "{} is a forwarded signer and must sign the relay transaction; pass it with --signer",
            env.ordinary.pubkey()
        ),
    );
}

#[test]
fn rejects_signer_arg_not_on_execute_message() {
    let env = SubmitTestEnv::new();
    let stranger = Keypair::new();
    assert_failure(
        &env.submit_message(&[
            "--authority",
            &env.authority_entry(),
            "--signer",
            &env.keypair_file(&env.ordinary),
            "--signer",
            &env.keypair_file(&stranger),
        ]),
        &format!(
            "{} is not a forwarded signer on the execute message",
            stranger.pubkey()
        ),
    );
}

/// An authority that is also an inner signer needs its `transaction sign` signature for the
/// execute message and a local signer for the relay transaction.
#[test_case(true, true, None; "authority and signer")]
#[test_case(true, false, Some("{} is a forwarded signer and must sign the relay transaction"); "authority only")]
#[test_case(false, true, Some("missing signature for authority {}"); "signer only")]
fn forwarded_authority_needs_authority_and_signer_args(
    with_signature: bool,
    with_signer: bool,
    expected: Option<&str>,
) {
    let env = SubmitTestEnv::new();
    let authority = env.authority.pubkey();
    let signer = programmatic_signer(&authority);
    let recipient = Address::new_unique();
    let inner = v1::Message::try_compile(
        &signer,
        &[
            transfer(&signer, &recipient, 1),
            transfer(&authority, &recipient, 1),
        ],
        Hash::new_unique(),
    )
    .unwrap();
    let message = execute_message(&inner, &env.nonce_account, &signer, &[authority]);
    let authority_entry = signature_entry(&env.authority, &message);
    let authority_file = env.keypair_file(&env.authority);
    let mut args = vec![];
    if with_signature {
        args.extend(["--authority", authority_entry.as_str()]);
    }
    if with_signer {
        args.extend(["--signer", authority_file.as_str()]);
    }
    let output = env.submit(&encode(&message), &args);
    match expected {
        None => env.assert_passes_offline_checks(&output),
        Some(expected) => assert_failure(&output, &expected.replace("{}", &authority.to_string())),
    }
}

/// An authority whose own address the executor uses only as a non-signer is not forwarded.
#[test_case(false, None; "authority only")]
#[test_case(true, Some("{} is not a forwarded signer on the execute message, PDA authorities sign with `transaction sign`"); "with signer")]
fn authority_as_inner_non_signer_is_not_forwarded(with_signer: bool, expected: Option<&str>) {
    let env = SubmitTestEnv::new();
    let authority = env.authority.pubkey();
    let signer = programmatic_signer(&authority);
    let inner = v1::Message::try_compile(
        &signer,
        &[transfer(&signer, &authority, 1)],
        Hash::new_unique(),
    )
    .unwrap();
    let message = execute_message(&inner, &env.nonce_account, &signer, &[authority]);
    let authority_entry = signature_entry(&env.authority, &message);
    let authority_file = env.keypair_file(&env.authority);
    let mut args = vec!["--authority", authority_entry.as_str()];
    if with_signer {
        args.extend(["--signer", authority_file.as_str()]);
    }
    let output = env.submit(&encode(&message), &args);
    match expected {
        None => env.assert_passes_offline_checks(&output),
        Some(expected) => assert_failure(&output, &expected.replace("{}", &authority.to_string())),
    }
}

#[test]
fn rejects_message_signer_unused_by_execute() {
    let env = SubmitTestEnv::new();
    let authority = env.authority.pubkey();
    let signer = programmatic_signer(&authority);
    let unused = Address::new_unique();
    let inner = v1::Message::try_compile(
        &signer,
        &[transfer(&signer, &Address::new_unique(), 1)],
        Hash::new_unique(),
    )
    .unwrap();
    // `transaction sign` never adds a signer the Execute instruction does not use.
    let message = wrapped_message(
        &execute(&env.nonce_account, &signer, &inner),
        &[authority, unused],
    );
    assert_failure(
        &env.submit(
            &encode(&message),
            &["--authority", &signature_entry(&env.authority, &message)],
        ),
        &format!("{unused} is neither a PDA authority nor a signer the executor uses"),
    );
}
