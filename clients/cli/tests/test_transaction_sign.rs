use {
    crate::common::helpers::{run_psigner, run_psigner_with_input},
    base64::{Engine, prelude::BASE64_STANDARD},
    solana_address::Address,
    solana_cli_config::Config as SolanaConfig,
    solana_hash::Hash,
    solana_instruction::AccountMeta,
    solana_keypair::{Keypair, write_keypair_file},
    solana_message::{VersionedMessage, legacy, v0, v1},
    solana_signature::Signature,
    solana_signer::Signer,
    solana_system_interface::instruction::transfer,
    spl_ed25519_signer_client::{ProgrammaticSigner, message::wrapped_message},
    spl_message_executor_client::instruction::execute,
    spl_message_executor_interface::instruction::Instruction as ExecutorInstruction,
    std::{fs, str::FromStr},
    tempfile::TempDir,
    test_case::test_case,
};

pub mod common;

struct SignTestEnv {
    directory: TempDir,
    config: String,
    authority: Keypair,
    authorities: Vec<String>,
    inner: v1::Message,
    encoded: String,
    nonce_account: String,
    nonce_hash: String,
    nonce_authority: String,
}

impl SignTestEnv {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let authority = Keypair::new_from_array([1; 32]);
        let keypair_file = directory.path().join("authority.json");
        write_keypair_file(&authority, &keypair_file).unwrap();
        let config = directory
            .path()
            .join("config.yml")
            .to_str()
            .unwrap()
            .to_owned();
        SolanaConfig {
            // Signing must succeed without a working RPC endpoint
            json_rpc_url: "http://127.0.0.1:1".into(),
            keypair_path: keypair_file.to_str().unwrap().into(),
            ..SolanaConfig::default()
        }
        .save(&config)
        .unwrap();
        let pda = ProgrammaticSigner::derive_address(
            &spl_ed25519_signer_client::id(),
            &authority.pubkey(),
        );
        let inner = v1::Message::try_compile(
            &pda,
            &[transfer(&pda, &Address::new_from_array([3; 32]), 1)],
            Hash::new_from_array([99; 32]),
        )
        .unwrap();
        Self {
            encoded: BASE64_STANDARD.encode(inner.serialize()),
            inner,
            directory,
            config,
            authorities: vec![authority.pubkey().to_string()],
            authority,
            nonce_account: Address::new_from_array([2; 32]).to_string(),
            nonce_hash: Hash::new_from_array([8; 32]).to_string(),
            nonce_authority: pda.to_string(),
        }
    }

    fn add_nonce_authority(&mut self, authority: Address) {
        self.authorities.push(authority.to_string());
        self.nonce_authority =
            ProgrammaticSigner::derive_address(&spl_ed25519_signer_client::id(), &authority)
                .to_string();
    }

    fn args<'a>(&'a self, extra: &[&'a str]) -> Vec<&'a str> {
        let mut args = vec![
            "-C",
            &self.config,
            "transaction",
            "sign",
            "--inner-message",
            &self.encoded,
            "--nonce-account",
            &self.nonce_account,
            "--nonce-hash",
            &self.nonce_hash,
            "--nonce-authority",
            &self.nonce_authority,
        ];
        for authority in &self.authorities {
            args.extend(["--authority", authority]);
        }
        args.extend_from_slice(extra);
        args
    }

    fn expected(&self, authorities: &[Address]) -> VersionedMessage {
        let mut inner = self.inner.clone();
        inner.lifetime_specifier = self.nonce_hash.parse().unwrap();
        let mut authorities = authorities.to_vec();
        authorities.sort_unstable();
        authorities.dedup();
        wrapped_message(
            &execute(
                &self.nonce_account.parse().unwrap(),
                &self.nonce_authority.parse().unwrap(),
                &inner,
            ),
            &authorities,
        )
    }

    fn reject(&self, expected: &str) {
        let output = run_psigner_with_input(&self.args(&["--quiet", "--yes"]), "");
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(!output.status.success(), "{stderr}");
        assert!(stderr.contains(expected), "{stderr}");
        assert!(output.stdout.is_empty());
        assert!(!stderr.contains("Sign this message for "));
    }
}

#[test]
fn approval_display_matches_golden() {
    let env = SignTestEnv::new();
    let output = run_psigner_with_input(&env.args(&[]), "y\n");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stderr).unwrap().trim_end(),
        include_str!("goldens/transaction-approval.txt").trim_end()
    );
}

#[test_case("json"; "json")]
#[test_case("json-compact"; "compact")]
fn signs_wrapped_message_offline(format: &str) {
    let env = SignTestEnv::new();
    let output = run_psigner(&env.args(&["--yes", "--output", format]));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let expected = env.expected(&[env.authority.pubkey()]);
    assert_eq!(
        value,
        serde_json::json!([{
            "address": env.authority.pubkey().to_string(),
            "signature": env.authority.sign_message(&expected.serialize()).to_string(),
            "forwarded_signers": [],
            "execute_message": BASE64_STANDARD.encode(expected.serialize()),
        }])
    );
    let bytes = BASE64_STANDARD
        .decode(value[0]["execute_message"].as_str().unwrap())
        .unwrap();
    let message: VersionedMessage = wincode::deserialize_exact(&bytes).unwrap();
    assert_eq!(message.recent_blockhash(), &Hash::default());
    let instruction = &message.instructions()[0];
    assert_eq!(
        message.static_account_keys()[usize::from(instruction.accounts[0])],
        env.nonce_authority.parse::<Address>().unwrap()
    );
    let ExecutorInstruction::Execute(VersionedMessage::V1(inner)) =
        ExecutorInstruction::try_from_bytes(&instruction.data).unwrap()
    else {
        panic!("expected a v1 inner message");
    };
    assert_eq!(
        inner.lifetime_specifier,
        env.nonce_hash.parse::<Hash>().unwrap()
    );
    assert_eq!(inner.instructions, env.inner.instructions);
    assert_eq!(inner.account_keys, env.inner.account_keys);
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains(&format!("Nonce authority: {}", env.nonce_authority)));
    assert!(stderr.contains("Nothing is submitted."));
}

#[test]
fn multiple_signers_sign_the_same_message_and_duplicates_are_ignored() {
    let mut env = SignTestEnv::new();
    let second = Keypair::new_from_array([4; 32]);
    env.add_nonce_authority(second.pubkey());
    let second_file = env.directory.path().join("second.json");
    write_keypair_file(&second, &second_file).unwrap();
    let first_file = env.directory.path().join("authority.json");
    let output = run_psigner(&env.args(&[
        "--yes",
        "--output",
        "json",
        "--signer",
        first_file.to_str().unwrap(),
        "--signer",
        second_file.to_str().unwrap(),
        "--signer",
        first_file.to_str().unwrap(),
    ]));
    let values: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(values.len(), 2);
    let expected = env.expected(&[env.authority.pubkey(), second.pubkey()]);
    for (value, key) in values.iter().zip([&env.authority, &second]) {
        assert_eq!(value["address"], key.pubkey().to_string());
        let signature = Signature::from_str(value["signature"].as_str().unwrap()).unwrap();
        assert!(signature.verify(key.pubkey().as_ref(), &expected.serialize()));
        assert_eq!(
            value["execute_message"],
            BASE64_STANDARD.encode(expected.serialize())
        );
    }
}

#[test]
fn explicit_signer_ignores_default_keypair_and_fee_payer() {
    let env = SignTestEnv::new();
    let mut config = SolanaConfig::load(&env.config).unwrap();
    config.keypair_path = env
        .directory
        .path()
        .join("missing.json")
        .to_str()
        .unwrap()
        .into();
    config.save(&env.config).unwrap();
    let invalid = env.directory.path().join("invalid.json");
    fs::write(&invalid, "not a keypair").unwrap();
    let signer = env.directory.path().join("authority.json");
    run_psigner(&env.args(&[
        "--yes",
        "--output",
        "json",
        "--signer",
        signer.to_str().unwrap(),
        "--fee-payer",
        invalid.to_str().unwrap(),
    ]));
}

#[test]
fn quiet_preserves_json() {
    let env = SignTestEnv::new();
    let normal = run_psigner(&env.args(&["--yes", "--output", "json"]));
    let quiet = run_psigner(&env.args(&["--yes", "--quiet", "--output", "json"]));
    assert_eq!(normal.stdout, quiet.stdout);
    assert!(quiet.stderr.is_empty());
}

#[test_case("y\n", true; "accept")]
#[test_case("  YES  \n", true; "trimmed yes")]
#[test_case("n\n", false; "decline")]
#[test_case("", false; "eof")]
fn confirmation_is_required_even_when_quiet(answer: &str, approved: bool) {
    let env = SignTestEnv::new();
    let output = run_psigner_with_input(&env.args(&["--quiet"]), answer);
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.starts_with(&format!(
            "Sign this message for {}? [y/N] ",
            env.authority.pubkey()
        )),
        "{stderr}"
    );
    assert_eq!(output.status.success(), approved);
    assert_eq!(output.stdout.is_empty(), !approved);
}

#[test_case("!", "invalid base64 inner message"; "invalid base64")]
#[test_case("", "invalid serialized inner message"; "empty")]
#[test_case("AA==", "invalid serialized inner message"; "truncated")]
fn rejects_invalid_encoding(encoded: &str, error: &str) {
    let mut env = SignTestEnv::new();
    env.encoded = encoded.into();
    env.reject(error);
}

#[test]
fn rejects_trailing_bytes_before_loading_signer() {
    let mut env = SignTestEnv::new();
    let mut bytes = env.inner.serialize();
    bytes.push(0);
    env.encoded = BASE64_STANDARD.encode(bytes);
    fs::remove_file(env.directory.path().join("authority.json")).unwrap();
    env.reject("invalid serialized inner message");
}

#[test_case(|inner| VersionedMessage::Legacy(legacy::Message {
    header: inner.header,
    account_keys: inner.account_keys.clone(),
    recent_blockhash: inner.lifetime_specifier,
    instructions: inner.instructions.clone(),
}); "legacy")]
#[test_case(|inner| VersionedMessage::V0(v0::Message {
    header: inner.header,
    account_keys: inner.account_keys.clone(),
    recent_blockhash: inner.lifetime_specifier,
    instructions: inner.instructions.clone(),
    address_table_lookups: vec![],
}); "v0")]
fn rejects_non_v1_inner_message(convert: fn(&v1::Message) -> VersionedMessage) {
    let mut env = SignTestEnv::new();
    env.encoded = BASE64_STANDARD.encode(convert(&env.inner).serialize());
    env.reject("supports only v1 inner messages");
}

#[test_case(|m| m.instructions[0].program_id_index = u8::MAX, "invalid inner message"; "bad index")]
#[test_case(|m| m.account_keys[1] = m.account_keys[0], "invalid inner message"; "duplicate keys")]
#[test_case(|m| { m.header.num_required_signatures = 127; }, "invalid inner message"; "bad header")]
#[test_case(
    |m| m.config = v1::TransactionConfig::default().with_compute_unit_limit(1),
    "inner message must not set transaction config fields";
    "transaction config"
)]
fn rejects_invalid_inner(mutate: fn(&mut v1::Message), error: &str) {
    let mut env = SignTestEnv::new();
    mutate(&mut env.inner);
    env.encoded = BASE64_STANDARD.encode(env.inner.serialize());
    env.reject(error);
}

#[test]
fn rejects_too_many_wrapped_accounts() {
    let mut env = SignTestEnv::new();
    // The inner message sits at the v1 account limit, and the wrapped message adds the nonce and
    // executor accounts on top.
    let pda = env.inner.account_keys[0];
    let mut instruction = transfer(&pda, &Address::new_from_array([3; 32]), 1);
    // The system program takes the last account key.
    while instruction.accounts.len() < usize::from(v1::MAX_ADDRESSES) - 1 {
        instruction
            .accounts
            .push(AccountMeta::new_readonly(Address::new_unique(), false));
    }
    env.inner = v1::Message::try_compile(&pda, &[instruction], Hash::default()).unwrap();
    assert_eq!(env.inner.account_keys.len(), usize::from(v1::MAX_ADDRESSES));
    env.encoded = BASE64_STANDARD.encode(env.inner.serialize());
    env.reject("too many addresses (max 64)");
}

#[test]
fn public_only_signer_cannot_emit_placeholder_signature() {
    let env = SignTestEnv::new();
    let output = run_psigner_with_input(
        &env.args(&["--yes", "--signer", &env.authority.pubkey().to_string()]),
        "",
    );
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("missing signature for supplied pubkey")
    );
}

#[test_case("account"; "nonce account")]
#[test_case("hash"; "nonce hash")]
#[test_case("authority"; "nonce authority outside inner message")]
fn signatures_bind_all_supplied_nonce_details(field: &str) {
    let mut env = SignTestEnv::new();
    let original = env.expected(&[env.authority.pubkey()]);
    match field {
        "account" => env.nonce_account = Address::new_from_array([5; 32]).to_string(),
        "hash" => env.nonce_hash = Hash::new_from_array([6; 32]).to_string(),
        "authority" => env.nonce_authority = env.authority.pubkey().to_string(),
        _ => unreachable!(),
    }
    let output = run_psigner(&env.args(&["--yes", "--output", "json"]));
    let values: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
    let signature = Signature::from_str(values[0]["signature"].as_str().unwrap()).unwrap();
    let expected = env.expected(&[env.authority.pubkey()]);
    assert!(signature.verify(env.authority.pubkey().as_ref(), &expected.serialize()));
    assert!(!signature.verify(env.authority.pubkey().as_ref(), &original.serialize()));
    assert_eq!(
        values[0]["execute_message"],
        BASE64_STANDARD.encode(expected.serialize())
    );
}

#[test]
fn independent_signers_produce_identical_messages() {
    let mut env = SignTestEnv::new();
    let bob = Keypair::new_from_array([4; 32]);
    let bob_file = env.directory.path().join("bob.json");
    write_keypair_file(&bob, &bob_file).unwrap();
    env.add_nonce_authority(bob.pubkey());
    let alice_output = run_psigner(&env.args(&["--yes", "--output", "json"]));
    let alice: Vec<serde_json::Value> = serde_json::from_slice(&alice_output.stdout).unwrap();

    // Bob uses a different order, repeats an authority, and has only his own key available.
    env.authorities.reverse();
    env.authorities.push(bob.pubkey().to_string());
    fs::remove_file(env.directory.path().join("authority.json")).unwrap();
    let bob_output = run_psigner(&env.args(&[
        "--yes",
        "--output",
        "json",
        "--signer",
        bob_file.to_str().unwrap(),
    ]));
    let bob_values: Vec<serde_json::Value> = serde_json::from_slice(&bob_output.stdout).unwrap();
    assert_eq!(alice.len(), 1);
    assert_eq!(bob_values.len(), 1);
    assert_eq!(
        alice[0]["execute_message"],
        bob_values[0]["execute_message"]
    );
    let bytes = BASE64_STANDARD
        .decode(alice[0]["execute_message"].as_str().unwrap())
        .unwrap();
    let message: VersionedMessage = wincode::deserialize_exact(&bytes).unwrap();
    assert_eq!(message.header().num_required_signatures, 2);
    for (entry, key) in [(&alice[0], &env.authority), (&bob_values[0], &bob)] {
        assert_eq!(entry["address"], key.pubkey().to_string());
        let signature = Signature::from_str(entry["signature"].as_str().unwrap()).unwrap();
        assert!(signature.verify(key.pubkey().as_ref(), &bytes));
    }
}

#[test]
fn rejects_signer_outside_explicit_authorities() {
    let mut env = SignTestEnv::new();
    env.authorities.clear();
    env.add_nonce_authority(Keypair::new_from_array([4; 32]).pubkey());
    env.reject("is not in the supplied --authority list");
}

#[test]
fn requires_explicit_authorities() {
    let mut env = SignTestEnv::new();
    env.authorities.clear();
    env.reject("--authority");
}

#[test]
fn rejects_too_many_authorities_before_loading_wallet() {
    let mut env = SignTestEnv::new();
    env.authorities = (0..=v1::MAX_SIGNATURES)
        .map(|_| Address::new_unique().to_string())
        .collect();
    fs::remove_file(env.directory.path().join("authority.json")).unwrap();
    env.reject("too many required signers");
}

#[test_case("y\n", true; "accept all")]
#[test_case("n\n", false; "decline all")]
#[test_case("", false; "eof declines all")]
fn multiple_signers_share_one_confirmation(answer: &str, approved: bool) {
    let mut env = SignTestEnv::new();
    let second = Keypair::new_from_array([4; 32]);
    env.add_nonce_authority(second.pubkey());
    let second_file = env.directory.path().join("second.json");
    write_keypair_file(&second, &second_file).unwrap();
    let first_file = env.directory.path().join("authority.json");
    let output = run_psigner_with_input(
        &env.args(&[
            "--quiet",
            "--output",
            "json",
            "--signer",
            first_file.to_str().unwrap(),
            "--signer",
            second_file.to_str().unwrap(),
        ]),
        answer,
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.starts_with(&format!(
            "Sign this message for {}, {}? [y/N] ",
            env.authority.pubkey(),
            second.pubkey()
        )),
        "{stderr}"
    );
    assert_eq!(
        stderr.matches("Sign this message for ").count(),
        1,
        "{stderr}"
    );
    assert_eq!(output.status.success(), approved, "{stderr}");
    if approved {
        let entries: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(entries.len(), 2);
        let expected = env.expected(&[env.authority.pubkey(), second.pubkey()]);
        for (entry, key) in entries.iter().zip([&env.authority, &second]) {
            assert_eq!(entry["address"], key.pubkey().to_string());
            let signature = Signature::from_str(entry["signature"].as_str().unwrap()).unwrap();
            assert!(signature.verify(key.pubkey().as_ref(), &expected.serialize()));
        }
    } else {
        assert!(output.stdout.is_empty());
        assert!(stderr.contains("signing cancelled"));
    }
}

#[test_case(false; "one signer")]
#[test_case(true; "multiple signers")]
fn default_display_shows_pairs_and_one_execute_message(multiple: bool) {
    let mut env = SignTestEnv::new();
    let second = Keypair::new_from_array([4; 32]);
    let second_file = env.directory.path().join("second.json");
    write_keypair_file(&second, &second_file).unwrap();
    let first_file = env.directory.path().join("authority.json");
    let mut extra = vec!["--yes", "--signer", first_file.to_str().unwrap()];
    if multiple {
        env.add_nonce_authority(second.pubkey());
    }
    let mut keys = vec![&env.authority];
    if multiple {
        extra.extend(["--signer", second_file.to_str().unwrap()]);
        keys.push(&second);
    }
    let message = env.expected(&keys.iter().map(|key| key.pubkey()).collect::<Vec<_>>());
    let encoded = BASE64_STANDARD.encode(message.serialize());
    let expected_pairs = keys
        .iter()
        .map(|key| {
            format!(
                "Address: {}\nSignature: {}\n\n",
                key.pubkey(),
                key.sign_message(&message.serialize())
            )
        })
        .collect::<String>();
    let output = run_psigner(&env.args(&extra));
    assert_eq!(
        String::from_utf8(output.stdout.clone()).unwrap(),
        format!("{expected_pairs}Execute message (base64):\n{encoded}\n")
    );
    extra.extend(["--quiet", "--output", "display"]);
    let quiet = run_psigner(&env.args(&extra));
    assert_eq!(quiet.stdout, output.stdout);
    assert!(quiet.stderr.is_empty());
}

#[test]
fn nonce_only_approval_includes_ordinary_inner_signers() {
    let mut env = SignTestEnv::new();
    let inner_signer = Keypair::new_from_array([7; 32]).pubkey();
    env.inner = v1::Message::try_compile(
        &inner_signer,
        &[transfer(&inner_signer, &Address::new_unique(), 1)],
        Hash::default(),
    )
    .unwrap();
    env.encoded = BASE64_STANDARD.encode(env.inner.serialize());
    let output = run_psigner(&env.args(&["--yes", "--output", "json"]));
    let values: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(values.len(), 1);
    let summary = String::from_utf8(output.stderr).unwrap();
    assert!(summary.contains(&format!(
        "Forwarded signers (sign at submission):\n  {inner_signer}"
    )));
    let expected = env.expected(&[env.authority.pubkey(), inner_signer]);
    assert_eq!(
        values[0]["forwarded_signers"],
        serde_json::json!([inner_signer.to_string()])
    );
    assert_eq!(
        values[0]["execute_message"],
        BASE64_STANDARD.encode(expected.serialize())
    );

    let display = run_psigner(&env.args(&["--yes", "--quiet"]));
    assert_eq!(
        String::from_utf8(display.stdout).unwrap(),
        format!(
            "Address: {}\nSignature: {}\n\nForwarded signers (sign at submission):\n  \
             {inner_signer}\n\nExecute message (base64):\n{}\n",
            env.authority.pubkey(),
            env.authority.sign_message(&expected.serialize()),
            BASE64_STANDARD.encode(expected.serialize())
        )
    );
}

#[test_case(false; "unused PDA")]
#[test_case(true; "non signer PDA")]
fn rejects_authority_without_signer_role(pda_is_account: bool) {
    let mut env = SignTestEnv::new();
    let pda: Address = env.nonce_authority.parse().unwrap();
    env.nonce_authority = Address::new_unique().to_string();
    let recipient = if pda_is_account {
        pda
    } else {
        Address::new_unique()
    };
    // The raw authority being an inner signer does not qualify its derived PDA.
    env.inner = v1::Message::try_compile(
        &env.authority.pubkey(),
        &[transfer(&env.authority.pubkey(), &recipient, 1)],
        Hash::default(),
    )
    .unwrap();
    env.encoded = BASE64_STANDARD.encode(env.inner.serialize());
    fs::remove_file(env.directory.path().join("authority.json")).unwrap();
    env.reject("is neither the nonce authority nor a signer on the inner message");
}

#[test]
fn rejects_unused_authority_even_when_only_valid_authority_signs_locally() {
    let mut env = SignTestEnv::new();
    env.authorities
        .push(Keypair::new_from_array([4; 32]).pubkey().to_string());
    env.reject("is neither the nonce authority nor a signer on the inner message");
}

#[test_case(false; "nonce authority outside inner message")]
#[test_case(true; "nonce authority also an inner signer")]
fn includes_ordinary_nonce_authority_once(also_inner_signer: bool) {
    let mut env = SignTestEnv::new();
    let nonce_authority = Keypair::new_from_array([7; 32]).pubkey();
    env.nonce_authority = nonce_authority.to_string();
    if also_inner_signer {
        let pda = env.inner.account_keys[0];
        env.inner = v1::Message::try_compile(
            &pda,
            &[
                transfer(&pda, &Address::new_unique(), 1),
                transfer(&nonce_authority, &Address::new_unique(), 1),
            ],
            Hash::default(),
        )
        .unwrap();
        env.encoded = BASE64_STANDARD.encode(env.inner.serialize());
    }
    let output = run_psigner(&env.args(&["--yes", "--output", "json"]));
    let values: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(values.len(), 1);
    let expected = env.expected(&[env.authority.pubkey(), nonce_authority]);
    assert_eq!(expected.header().num_required_signatures, 2);
    assert_eq!(
        values[0]["forwarded_signers"],
        serde_json::json!([nonce_authority.to_string()])
    );
    assert_eq!(
        values[0]["execute_message"],
        BASE64_STANDARD.encode(expected.serialize())
    );
    let signature = Signature::from_str(values[0]["signature"].as_str().unwrap()).unwrap();
    assert!(signature.verify(env.authority.pubkey().as_ref(), &expected.serialize()));
}

#[test_case(false; "authority is an inner signer")]
#[test_case(true; "authority is the nonce authority")]
fn authority_used_directly_is_also_forwarded(is_nonce_authority: bool) {
    let mut env = SignTestEnv::new();
    let authority = env.authority.pubkey();
    let pda = env.inner.account_keys[0];
    if is_nonce_authority {
        env.nonce_authority = authority.to_string();
    } else {
        env.inner = v1::Message::try_compile(
            &pda,
            &[
                transfer(&pda, &Address::new_unique(), 1),
                transfer(&authority, &Address::new_unique(), 1),
            ],
            Hash::default(),
        )
        .unwrap();
        env.encoded = BASE64_STANDARD.encode(env.inner.serialize());
    }
    let output = run_psigner(&env.args(&["--yes", "--output", "json"]));
    let values: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(values.len(), 1);
    let summary = String::from_utf8(output.stderr).unwrap();
    assert!(summary.contains(&format!("  {authority} (derived signer: {pda})")));
    assert!(summary.contains(&format!(
        "Forwarded signers (sign at submission):\n  {authority}"
    )));
    let expected = env.expected(&[authority]);
    assert_eq!(expected.header().num_required_signatures, 1);
    assert_eq!(values[0]["address"], authority.to_string());
    assert_eq!(
        values[0]["forwarded_signers"],
        serde_json::json!([authority.to_string()])
    );
    assert_eq!(
        values[0]["execute_message"],
        BASE64_STANDARD.encode(expected.serialize())
    );
}

#[test]
fn rejects_too_many_combined_signers_before_loading_wallet() {
    let mut env = SignTestEnv::new();
    // The authorities alone reach the v1 signer limit, and the forwarded nonce authority pushes
    // the wrapped message over it.
    while env.authorities.len() < usize::from(v1::MAX_SIGNATURES) {
        env.authorities.push(Address::new_unique().to_string());
    }
    env.nonce_authority = Address::new_unique().to_string();
    fs::remove_file(env.directory.path().join("authority.json")).unwrap();
    env.reject("too many required signers");
}
