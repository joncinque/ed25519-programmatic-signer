//! Helpers shared by the `migrate` command tests.

use {
    crate::common::{
        execute::programmatic_signer,
        helpers::{TestEnv, run_psigner, run_psigner_with_input},
    },
    base64::{Engine, prelude::BASE64_STANDARD},
    serde::{Deserialize, de::DeserializeOwned},
    solana_address::Address,
    solana_hash::Hash,
    solana_keypair::{Keypair, write_keypair_file},
    solana_message::{VersionedMessage, v1},
    solana_signer::Signer,
    spl_nonce_interface::state::Nonce,
    spl_programmatic_signer_cli::{Authorization, NonceCreateOutput, RequiredSigners},
    tempfile::NamedTempFile,
};

/// The authorization an authority gives for its programmatic signer.
pub fn authorization(authority: &Address) -> Authorization {
    Authorization {
        programmatic_signer: programmatic_signer(authority).to_string(),
        signer_pubkey: Some(authority.to_string()),
    }
}

pub fn decode_execution_message(execution_message: &str) -> v1::Message {
    let bytes = BASE64_STANDARD.decode(execution_message).unwrap();
    let VersionedMessage::V1(message) = wincode::deserialize_exact(&bytes).unwrap() else {
        panic!("expected a v1 execution message");
    };
    message
}

/// Forwarded signers are compared in any order.
pub fn assert_signers(
    signers: &RequiredSigners,
    authorizations: &[Authorization],
    forwarded_signers: &[Address],
) {
    assert_eq!(signers.authorizations, authorizations);
    let mut actual = signers.forwarded_signers.clone();
    actual.sort();
    let mut expected = forwarded_signers
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    expected.sort();
    assert_eq!(actual, expected);
}

#[derive(Deserialize)]
struct SignOutput {
    authorization_message: String,
    signatures: Vec<SignatureEntry>,
}

#[derive(Deserialize)]
struct SignatureEntry {
    address: String,
    signature: String,
}

/// An SPL nonce account whose authority is `authority`'s programmatic signer.
pub fn create_nonce(env: &TestEnv, authority: &Address) -> Address {
    let create = run_psigner(&[
        "-C",
        &env.config_file_path,
        "--output",
        "json-compact",
        "nonce",
        "create",
        "--cold-authority",
        &authority.to_string(),
    ]);
    let create: NonceCreateOutput = serde_json::from_slice(&create.stdout).unwrap();
    create.nonce_account.parse().unwrap()
}

async fn current_nonce(env: &TestEnv, nonce_account: &Address) -> Hash {
    let data = env.rpc.get_account_data(nonce_account).await.unwrap();
    Nonce::view(&data).unwrap().nonce
}

fn keypair_file(keypair: &Keypair) -> NamedTempFile {
    let file = NamedTempFile::new().unwrap();
    write_keypair_file(keypair, &file).unwrap();
    file
}

/// Run `migrate <kind> <account> [--new-authority-signing-pubkey <new_owner>] [extra]` and parse
/// its JSON output. Without `new_owner`, the migration defaults to the current authority.
pub fn migrate<T: DeserializeOwned>(
    env: &TestEnv,
    kind: &str,
    account: &Address,
    new_owner: Option<&Address>,
    extra: &[&str],
) -> T {
    let account = account.to_string();
    let new_owner = new_owner.map(ToString::to_string);
    let mut args = vec![
        "-C",
        &env.config_file_path,
        "--output",
        "json",
        "migrate",
        kind,
        &account,
    ];
    if let Some(new_owner) = &new_owner {
        args.extend(["--new-authority-signing-pubkey", new_owner]);
    }
    args.extend_from_slice(extra);
    serde_json::from_slice(&run_psigner(&args).stdout).unwrap()
}

/// Run a migration that must fail and return its stderr.
pub fn migrate_error(
    env: &TestEnv,
    kind: &str,
    account: &Address,
    new_owner: Option<&Address>,
    extra: &[&str],
) -> String {
    let account = account.to_string();
    let new_owner = new_owner.map(ToString::to_string);
    let mut args = vec!["-C", &env.config_file_path, "migrate", kind, &account];
    if let Some(new_owner) = &new_owner {
        args.extend(["--new-authority-signing-pubkey", new_owner]);
    }
    args.extend_from_slice(extra);
    let output = run_psigner_with_input(&args, "");
    assert!(!output.status.success());
    String::from_utf8(output.stderr).unwrap()
}

/// Sign an execution message with the new authority, whose programmatic signer is the nonce
/// authority, and any other authorities whose programmatic signers the migration needs. Then submit
/// it with the forwarded signers signing the relay transaction.
pub async fn execute_as_new_owner(
    env: &TestEnv,
    execution_message: &str,
    nonce_account: &Address,
    new_owner: &Keypair,
    other_authorities: &[&Keypair],
    relay_signers: &[&Keypair],
) {
    let nonce_account_arg = nonce_account.to_string();
    let nonce_authority = programmatic_signer(&new_owner.pubkey()).to_string();
    let nonce_hash = current_nonce(env, nonce_account).await.to_string();
    let authorities = std::iter::once(new_owner)
        .chain(other_authorities.iter().copied())
        .collect::<Vec<_>>();
    let authority_args = authorities
        .iter()
        .map(|authority| authority.pubkey().to_string())
        .collect::<Vec<_>>();
    let authority_files = authorities
        .iter()
        .map(|authority| keypair_file(authority))
        .collect::<Vec<_>>();
    let mut args = vec![
        "-C",
        &env.config_file_path,
        "--output",
        "json",
        "transaction",
        "sign",
        "--execution-message",
        execution_message,
        "--nonce-account",
        &nonce_account_arg,
        "--nonce-authority",
        &nonce_authority,
        "--nonce-hash",
        &nonce_hash,
        "--quiet",
        "--yes",
    ];
    for (authority, file) in authority_args.iter().zip(&authority_files) {
        args.extend([
            "--authority",
            authority,
            "--signer",
            file.path().to_str().unwrap(),
        ]);
    }
    let sign: SignOutput = serde_json::from_slice(&run_psigner(&args).stdout).unwrap();
    assert_eq!(sign.signatures.len(), authorities.len());
    let signatures = sign
        .signatures
        .iter()
        .map(|signature| format!("{}={}", signature.address, signature.signature))
        .collect::<Vec<_>>();

    let relay_signer_files = relay_signers
        .iter()
        .map(|signer| keypair_file(signer))
        .collect::<Vec<_>>();
    let mut args = vec![
        "-C",
        &env.config_file_path,
        "transaction",
        "submit",
        "--authorization-message",
        &sign.authorization_message,
        "--quiet",
        "--yes",
    ];
    for signature in &signatures {
        args.extend(["--signer", signature]);
    }
    for file in &relay_signer_files {
        args.extend(["--relay-signer", file.path().to_str().unwrap()]);
    }
    run_psigner(&args);
}
