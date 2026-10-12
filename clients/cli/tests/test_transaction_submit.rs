use {
    crate::common::{
        execute::{build_authorization_message, encode, programmatic_signer, signature_entry},
        helpers::run_psigner_with_input,
    },
    base64::{Engine, prelude::BASE64_STANDARD},
    solana_address::Address,
    solana_cli_config::Config as SolanaConfig,
    solana_cli_output::CliSignOnlyData,
    solana_hash::Hash,
    solana_instruction::{AccountMeta, Instruction},
    solana_keypair::{Keypair, write_keypair_file},
    solana_message::{VersionedMessage, legacy, v1},
    solana_signature::Signature,
    solana_signer::Signer,
    solana_system_interface::instruction::transfer,
    spl_ed25519_signer_client::message::authorization_message,
    spl_message_executor_client::instruction::execute,
    spl_message_executor_interface::instruction::Instruction as ExecutorInstruction,
    std::{collections::BTreeSet, path::PathBuf, process::Output},
    tempfile::TempDir,
    test_case::test_case,
};

pub mod common;

/// An authorization message signed by one PDA authority, whose derived signer is the nonce
/// authority, and one ordinary execution message signer forwarded from the relay transaction.
struct SubmitTestEnv {
    directory: TempDir,
    config_file_path: String,
    fee_payer: Keypair,
    authority: Keypair,
    ordinary: Keypair,
    nonce_account: Address,
    message: VersionedMessage,
    durable_nonce: Address,
    durable_nonce_value: Hash,
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
        let execution_message = v1::Message::try_compile(
            &nonce_authority,
            &[
                transfer(&nonce_authority, &recipient, 1),
                transfer(&ordinary.pubkey(), &recipient, 1),
            ],
            Hash::new_unique(),
        )
        .unwrap();
        let message = build_authorization_message(
            &execution_message,
            &nonce_account,
            &nonce_authority,
            &[authority.pubkey()],
        );
        Self {
            directory,
            config_file_path,
            fee_payer,
            authority,
            ordinary,
            nonce_account,
            message,
            durable_nonce: Address::new_unique(),
            durable_nonce_value: Hash::new_unique(),
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

    fn submit(&self, authorization_message: &str, extra: &[&str]) -> Output {
        let mut args = vec![
            "-C",
            &self.config_file_path,
            "transaction",
            "submit",
            "--authorization-message",
            authorization_message,
        ];
        args.extend_from_slice(extra);
        run_psigner_with_input(&args, "")
    }

    fn submit_message(&self, extra: &[&str]) -> Output {
        self.submit(&encode(&self.message), extra)
    }

    /// Run `--sign-only` with the authority signature and durable nonce, returning the JSON
    /// output. The RPC endpoint is unreachable, so this also checks no RPC calls are made.
    fn sign_only(&self, extra: &[&str]) -> CliSignOnlyData {
        let authority_entry = self.authority_entry();
        let durable_nonce = self.durable_nonce.to_string();
        let durable_nonce_value = self.durable_nonce_value.to_string();
        let mut args = vec![
            "--output",
            "json",
            "--signer",
            &authority_entry,
            "--durable-nonce",
            &durable_nonce,
            "--blockhash",
            &durable_nonce_value,
            "--sign-only",
            "--dump-transaction-message",
        ];
        args.extend_from_slice(extra);
        let output = self.submit_message(&args);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
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
        "--signer",
        &env.authority_entry(),
        "--relay-signer",
        &env.keypair_file(&env.ordinary),
    ]);
    env.assert_passes_offline_checks(&output);
}

#[test]
fn accepts_fee_payer_as_forwarded_signer() {
    let env = SubmitTestEnv::new();
    let output = env.submit_message(&[
        "--signer",
        &env.authority_entry(),
        "--fee-payer",
        &env.keypair_file(&env.ordinary),
    ]);
    env.assert_passes_offline_checks(&output);
}

#[test_case("!", "invalid base64 authorization message"; "invalid base64")]
#[test_case("", "invalid serialized authorization message"; "empty message")]
#[test_case("AA==", "invalid serialized authorization message"; "truncated message")]
fn rejects_invalid_message_encoding(encoded: &str, expected: &str) {
    let env = SubmitTestEnv::new();
    assert_failure(&env.submit(encoded, &[]), expected);
}

#[test_case(
    |message| VersionedMessage::Legacy(legacy::Message {
        header: message.header,
        account_keys: message.account_keys,
        recent_blockhash: message.lifetime_specifier,
        instructions: message.instructions,
    }),
    "the signer program supports only v1 authorization messages";
    "legacy"
)]
#[test_case(
    |message| VersionedMessage::V1(v1::Message {
        config: v1::TransactionConfig::default().with_priority_fee(1),
        ..message
    }),
    "authorization message must not set transaction config fields";
    "transaction config"
)]
fn rejects_authorization_message_the_signer_cannot_submit(
    convert: fn(v1::Message) -> VersionedMessage,
    expected: &str,
) {
    let env = SubmitTestEnv::new();
    let VersionedMessage::V1(message) = env.message.clone() else {
        panic!("expected a v1 authorization message");
    };
    assert_failure(&env.submit(&encode(&convert(message)), &[]), expected);
}

#[test]
fn rejects_non_executor_instruction() {
    let env = SubmitTestEnv::new();
    let message = authorization_message(
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
    let message = authorization_message(&instruction, &[env.authority.pubkey()]);
    assert_failure(
        &env.submit(&encode(&message), &[]),
        "expected the nonce authority, nonce account, and SPL Nonce program in Execute accounts",
    );
}

#[test_case(
    VersionedMessage::Legacy(legacy::Message::default()),
    "the executor supports only v1 execution messages";
    "legacy"
)]
#[test_case(
    VersionedMessage::V1(v1::Message {
        config: v1::TransactionConfig::default().with_priority_fee(1),
        ..v1::Message::default()
    }),
    "execution message must not set transaction config fields";
    "transaction config"
)]
fn rejects_execution_message_the_executor_cannot_invoke(
    execution_message: VersionedMessage,
    expected: &str,
) {
    let env = SubmitTestEnv::new();
    let instruction = Instruction::new_with_wincode(
        spl_message_executor_interface::id(),
        &ExecutorInstruction::Execute(execution_message),
        vec![AccountMeta::new(Address::new_unique(), false)],
    );
    let message = authorization_message(&instruction, &[env.authority.pubkey()]);
    assert_failure(&env.submit(&encode(&message), &[]), expected);
}

#[test_case("missing separator", "invalid authority: expected ADDRESS=SIGNATURE"; "missing separator")]
#[test_case("invalid=invalid", "invalid authority address"; "invalid address")]
#[test_case("11111111111111111111111111111111=invalid", "invalid authority signature"; "invalid signature")]
fn rejects_malformed_signer_args(entry: &str, expected: &str) {
    let env = SubmitTestEnv::new();
    assert_failure(&env.submit_message(&["--signer", entry]), expected);
}

#[test]
fn rejects_signer_arg_not_on_authorization_message() {
    let env = SubmitTestEnv::new();
    let stranger = Keypair::new();
    assert_failure(
        &env.submit_message(&["--signer", &signature_entry(&stranger, &env.message)]),
        &format!(
            "{} is not a signer on the authorization message",
            stranger.pubkey()
        ),
    );
}

#[test]
fn rejects_signer_arg_for_a_different_message() {
    let env = SubmitTestEnv::new();
    let other = SubmitTestEnv::new();
    let entry = format!(
        "{}={}",
        env.authority.pubkey(),
        env.authority.sign_message(&other.message.serialize())
    );
    assert_failure(
        &env.submit_message(&["--signer", &entry]),
        &format!("invalid signature for authority {}", env.authority.pubkey()),
    );
}

#[test]
fn rejects_authority_without_signer_arg() {
    let env = SubmitTestEnv::new();
    assert_failure(
        &env.submit_message(&["--relay-signer", &env.keypair_file(&env.ordinary)]),
        &format!(
            "missing signature for authority {}, authorities sign with `transaction sign`",
            env.authority.pubkey()
        ),
    );
}

#[test_case(false; "unsigned")]
#[test_case(true; "already signed")]
fn rejects_relay_signer_arg_for_non_forwarded_authority(with_signature: bool) {
    let env = SubmitTestEnv::new();
    let authority_entry = env.authority_entry();
    let authority_file = env.keypair_file(&env.authority);
    let ordinary_file = env.keypair_file(&env.ordinary);
    let mut args = vec![
        "--relay-signer",
        &authority_file,
        "--relay-signer",
        &ordinary_file,
    ];
    if with_signature {
        args.extend(["--signer", &authority_entry]);
    }
    assert_failure(
        &env.submit_message(&args),
        &format!(
            "{} is not a forwarded signer on the authorization message, PDA authorities sign with \
             `transaction sign`",
            env.authority.pubkey()
        ),
    );
}

#[test]
fn rejects_signer_arg_for_non_authority() {
    let env = SubmitTestEnv::new();
    assert_failure(
        &env.submit_message(&[
            "--signer",
            &env.authority_entry(),
            "--signer",
            &signature_entry(&env.ordinary, &env.message),
            "--relay-signer",
            &env.keypair_file(&env.ordinary),
        ]),
        &format!(
            "{} is not a PDA authority on the authorization message; pass it with --relay-signer",
            env.ordinary.pubkey()
        ),
    );
}

#[test]
fn rejects_forwarded_signer_without_relay_signer_arg() {
    let env = SubmitTestEnv::new();
    assert_failure(
        &env.submit_message(&["--signer", &env.authority_entry()]),
        &format!(
            "{} is a forwarded signer and must sign the relay transaction; pass it with \
             --relay-signer",
            env.ordinary.pubkey()
        ),
    );
}

#[test]
fn rejects_relay_signer_arg_not_on_authorization_message() {
    let env = SubmitTestEnv::new();
    let stranger = Keypair::new();
    assert_failure(
        &env.submit_message(&[
            "--signer",
            &env.authority_entry(),
            "--relay-signer",
            &env.keypair_file(&env.ordinary),
            "--relay-signer",
            &env.keypair_file(&stranger),
        ]),
        &format!(
            "{} is not a forwarded signer on the authorization message",
            stranger.pubkey()
        ),
    );
}

/// An authority that is also an execution message signer needs its `transaction sign` signature
/// for the authorization message and a local signer for the relay transaction.
#[test_case(true, true, None; "signer and relay signer")]
#[test_case(true, false, Some("{} is a forwarded signer and must sign the relay transaction"); "signer only")]
#[test_case(false, true, Some("missing signature for authority {}"); "relay signer only")]
fn forwarded_authority_needs_signer_and_relay_signer_args(
    with_signature: bool,
    with_relay_signer: bool,
    expected: Option<&str>,
) {
    let env = SubmitTestEnv::new();
    let authority = env.authority.pubkey();
    let signer = programmatic_signer(&authority);
    let recipient = Address::new_unique();
    let execution_message = v1::Message::try_compile(
        &signer,
        &[
            transfer(&signer, &recipient, 1),
            transfer(&authority, &recipient, 1),
        ],
        Hash::new_unique(),
    )
    .unwrap();
    let message = build_authorization_message(
        &execution_message,
        &env.nonce_account,
        &signer,
        &[authority],
    );
    let authority_entry = signature_entry(&env.authority, &message);
    let authority_file = env.keypair_file(&env.authority);
    let mut args = vec![];
    if with_signature {
        args.extend(["--signer", authority_entry.as_str()]);
    }
    if with_relay_signer {
        args.extend(["--relay-signer", authority_file.as_str()]);
    }
    let output = env.submit(&encode(&message), &args);
    match expected {
        None => env.assert_passes_offline_checks(&output),
        Some(expected) => assert_failure(&output, &expected.replace("{}", &authority.to_string())),
    }
}

/// An authority whose own address the executor uses only as a non-signer is not forwarded.
#[test_case(false, None; "signer only")]
#[test_case(true, Some("{} is not a forwarded signer on the authorization message, PDA authorities sign with `transaction sign`"); "with relay signer")]
fn authority_as_execution_message_non_signer_is_not_forwarded(
    with_relay_signer: bool,
    expected: Option<&str>,
) {
    let env = SubmitTestEnv::new();
    let authority = env.authority.pubkey();
    let signer = programmatic_signer(&authority);
    let execution_message = v1::Message::try_compile(
        &signer,
        &[transfer(&signer, &authority, 1)],
        Hash::new_unique(),
    )
    .unwrap();
    let message = build_authorization_message(
        &execution_message,
        &env.nonce_account,
        &signer,
        &[authority],
    );
    let authority_entry = signature_entry(&env.authority, &message);
    let authority_file = env.keypair_file(&env.authority);
    let mut args = vec!["--signer", authority_entry.as_str()];
    if with_relay_signer {
        args.extend(["--relay-signer", authority_file.as_str()]);
    }
    let output = env.submit(&encode(&message), &args);
    match expected {
        None => env.assert_passes_offline_checks(&output),
        Some(expected) => assert_failure(&output, &expected.replace("{}", &authority.to_string())),
    }
}

/// A forwarded signer whose derived signer the executor uses only as a non-signer is not a PDA
/// authority, matching `transaction sign`, which rejects it as an authority.
#[test]
fn forwarded_signer_with_non_signer_derived_signer_is_not_an_authority() {
    let env = SubmitTestEnv::new();
    let ordinary = env.ordinary.pubkey();
    let signer = programmatic_signer(&env.authority.pubkey());
    let execution_message = v1::Message::try_compile(
        &signer,
        &[
            transfer(&signer, &programmatic_signer(&ordinary), 1),
            transfer(&ordinary, &Address::new_unique(), 1),
        ],
        Hash::new_unique(),
    )
    .unwrap();
    let message = build_authorization_message(
        &execution_message,
        &env.nonce_account,
        &signer,
        &[env.authority.pubkey()],
    );
    let output = env.submit(
        &encode(&message),
        &[
            "--signer",
            &signature_entry(&env.authority, &message),
            "--relay-signer",
            &env.keypair_file(&env.ordinary),
        ],
    );
    env.assert_passes_offline_checks(&output);
}

#[test]
fn rejects_message_signer_unused_by_execute() {
    let env = SubmitTestEnv::new();
    let authority = env.authority.pubkey();
    let signer = programmatic_signer(&authority);
    let unused = Address::new_unique();
    let execution_message = v1::Message::try_compile(
        &signer,
        &[transfer(&signer, &Address::new_unique(), 1)],
        Hash::new_unique(),
    )
    .unwrap();
    // `transaction sign` never adds a signer the Execute instruction does not use.
    let message = authorization_message(
        &execute(&env.nonce_account, &signer, &execution_message),
        &[authority, unused],
    );
    assert_failure(
        &env.submit(
            &encode(&message),
            &["--signer", &signature_entry(&env.authority, &message)],
        ),
        &format!("{unused} is neither a PDA authority nor a signer the executor uses"),
    );
}

/// The relay signers each sign in a separate --sign-only run, naming the others by address. Every
/// run must sign the same message.
#[test]
fn sign_only_runs_sign_the_same_relay_message() {
    let env = SubmitTestEnv::new();
    let fee_payer = env.fee_payer.pubkey().to_string();
    let nonce_authority = Keypair::new();
    let nonce_authority_address = nonce_authority.pubkey().to_string();
    let nonce_authority_file = env.keypair_file(&nonce_authority);
    let ordinary_file = env.keypair_file(&env.ordinary);
    let runs = [
        (
            env.sign_only(&[
                "--fee-payer",
                &env.keypair_file(&env.fee_payer),
                "--durable-nonce-authority",
                &nonce_authority_address,
            ]),
            env.fee_payer.pubkey(),
        ),
        (
            env.sign_only(&[
                "--fee-payer",
                &fee_payer,
                "--durable-nonce-authority",
                &nonce_authority_file,
            ]),
            nonce_authority.pubkey(),
        ),
        (
            env.sign_only(&[
                "--fee-payer",
                &fee_payer,
                "--durable-nonce-authority",
                &nonce_authority_address,
                "--relay-signer",
                &ordinary_file,
                "--yes",
            ]),
            env.ordinary.pubkey(),
        ),
    ];

    let message = runs[0].0.message.clone().unwrap();
    let message_bytes = BASE64_STANDARD.decode(&message).unwrap();
    let relay_signers = BTreeSet::from([
        env.fee_payer.pubkey(),
        nonce_authority.pubkey(),
        env.ordinary.pubkey(),
    ]);
    for (run, signer) in &runs {
        assert_eq!(run.message.as_ref(), Some(&message));
        assert_eq!(run.blockhash, env.durable_nonce_value.to_string());
        let [entry] = run.signers.as_slice() else {
            panic!("expected one signature, got {:?}", run.signers);
        };
        let (address, signature) = entry.split_once('=').unwrap();
        assert_eq!(address, signer.to_string());
        assert!(
            signature
                .parse::<Signature>()
                .unwrap()
                .verify(signer.as_ref(), &message_bytes)
        );
        let absent = run
            .absent
            .iter()
            .map(|address| address.parse().unwrap())
            .collect::<BTreeSet<Address>>();
        let mut expected_absent = relay_signers.clone();
        expected_absent.remove(signer);
        assert_eq!(absent, expected_absent);
        assert!(run.bad_sig.is_empty());
    }
}

#[test]
fn sign_only_defaults_durable_nonce_authority_to_fee_payer() {
    let env = SubmitTestEnv::new();
    let run = env.sign_only(&["--fee-payer", &env.keypair_file(&env.fee_payer)]);
    assert_eq!(
        run.signers,
        [format!(
            "{}={}",
            env.fee_payer.pubkey(),
            env.fee_payer.sign_message(
                &BASE64_STANDARD
                    .decode(run.message.as_ref().unwrap())
                    .unwrap()
            )
        )]
    );
    assert_eq!(run.absent, [env.ordinary.pubkey().to_string()]);
}

/// Without a durable nonce, the relay transaction uses the given blockhash as its lifetime.
#[test]
fn sign_only_with_blockhash() {
    let env = SubmitTestEnv::new();
    let blockhash = Hash::new_unique();
    let output = env.submit_message(&[
        "--output",
        "json",
        "--signer",
        &env.authority_entry(),
        "--fee-payer",
        &env.keypair_file(&env.fee_payer),
        "--blockhash",
        &blockhash.to_string(),
        "--sign-only",
        "--dump-transaction-message",
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let run: CliSignOnlyData = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(run.blockhash, blockhash.to_string());
    let message_bytes = BASE64_STANDARD.decode(run.message.unwrap()).unwrap();
    assert_eq!(
        run.signers,
        [format!(
            "{}={}",
            env.fee_payer.pubkey(),
            env.fee_payer.sign_message(&message_bytes)
        )]
    );
    assert_eq!(run.absent, [env.ordinary.pubkey().to_string()]);
}

#[test]
fn sign_only_requires_authority_signatures() {
    let env = SubmitTestEnv::new();
    assert_failure(
        &env.submit_message(&[
            "--fee-payer",
            &env.keypair_file(&env.fee_payer),
            "--durable-nonce",
            &env.durable_nonce.to_string(),
            "--blockhash",
            &env.durable_nonce_value.to_string(),
            "--sign-only",
        ]),
        &format!(
            "missing signature for authority {}, authorities sign with `transaction sign`",
            env.authority.pubkey()
        ),
    );
}

#[test]
fn sign_only_defaults_fee_payer_to_configured_keypair() {
    let env = SubmitTestEnv::new();
    let run = env.sign_only(&[]);
    assert_eq!(
        run.signers,
        [format!(
            "{}={}",
            env.fee_payer.pubkey(),
            env.fee_payer.sign_message(
                &BASE64_STANDARD
                    .decode(run.message.as_ref().unwrap())
                    .unwrap()
            )
        )]
    );
    assert_eq!(run.absent, [env.ordinary.pubkey().to_string()]);
}

#[test]
fn accepts_durable_nonce_online() {
    let env = SubmitTestEnv::new();
    let nonce_authority = Keypair::new();
    let output = env.submit_message(&[
        "--signer",
        &env.authority_entry(),
        "--relay-signer",
        &env.keypair_file(&env.ordinary),
        "--durable-nonce",
        &env.durable_nonce.to_string(),
        "--durable-nonce-authority",
        &env.keypair_file(&nonce_authority),
    ]);
    env.assert_passes_offline_checks(&output);
}

#[test_case(&["--fee-payer", "{}"]; "fee payer")]
#[test_case(&["--durable-nonce", "{}", "--durable-nonce-authority", "{}"]; "durable nonce authority")]
fn rejects_address_signer_without_sign_only(args: &[&str]) {
    let env = SubmitTestEnv::new();
    let address = Address::new_unique().to_string();
    let mut args = args
        .iter()
        .map(|arg| arg.replace("{}", &address))
        .collect::<Vec<_>>();
    args.extend([
        "--signer".to_string(),
        env.authority_entry(),
        "--relay-signer".to_string(),
        env.keypair_file(&env.ordinary),
    ]);
    assert_failure(
        &env.submit_message(&args.iter().map(String::as_str).collect::<Vec<_>>()),
        &format!("missing signature for supplied pubkey: {address}"),
    );
}

#[test_case(&["--sign-only"], "--blockhash <HASH>"; "sign only without blockhash")]
#[test_case(&["--dump-transaction-message"], "--sign-only"; "dump without sign only")]
#[test_case(&["--durable-nonce-authority", "{}"], "--durable-nonce <ADDRESS>"; "durable nonce authority without durable nonce")]
fn rejects_missing_required_args(args: &[&str], expected: &str) {
    let env = SubmitTestEnv::new();
    let address = Address::new_unique().to_string();
    let args = args
        .iter()
        .map(|arg| arg.replace("{}", &address))
        .collect::<Vec<_>>();
    assert_failure(
        &env.submit_message(&args.iter().map(String::as_str).collect::<Vec<_>>()),
        expected,
    );
}

/// A fee payer given as an address still signs when the same key is a local relay signer.
#[test]
fn sign_only_fee_payer_address_signs_as_local_relay_signer() {
    let env = SubmitTestEnv::new();
    let run = env.sign_only(&[
        "--fee-payer",
        &env.ordinary.pubkey().to_string(),
        "--relay-signer",
        &env.keypair_file(&env.ordinary),
        "--yes",
    ]);
    let message_bytes = BASE64_STANDARD.decode(run.message.unwrap()).unwrap();
    assert_eq!(
        run.signers,
        [format!(
            "{}={}",
            env.ordinary.pubkey(),
            env.ordinary.sign_message(&message_bytes)
        )]
    );
    assert!(run.absent.is_empty());
}
