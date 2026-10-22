use {
    crate::common::helpers::{TestEnv, run_psigner, run_psigner_with_input},
    base64::{Engine, prelude::BASE64_STANDARD},
    solana_keypair::{Keypair, write_keypair_file},
    solana_signer::Signer,
    spl_programmatic_signer_cli::{
        NonceAdvanceAuthorizationOutput, NonceAdvanceOutput, NonceCreateOutput, NonceShowOutput,
    },
    tempfile::NamedTempFile,
};

fn create_nonce(env: &TestEnv, authority_arg: &str, authority: &str) -> NonceCreateOutput {
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
    serde_json::from_slice(&create.stdout).unwrap()
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

fn advance_args<'a>(env: &'a TestEnv, nonce_account: &'a str, extra: &[&'a str]) -> Vec<&'a str> {
    let mut args = vec![
        "-C",
        &env.config_file_path,
        "--output",
        "json-compact",
        "nonce",
        "advance",
        nonce_account,
    ];
    args.extend(extra);
    args
}

/// Advance the nonce, optionally with an explicit nonce authority signer, and check the stored
/// nonce moved to the reported value.
fn advance_nonce(env: &TestEnv, create: &NonceCreateOutput, nonce_authority: Option<&str>) {
    let mut extra = vec![];
    if let Some(nonce_authority) = nonce_authority {
        extra.extend(["--nonce-authority", nonce_authority]);
    }
    let advance = run_psigner(&advance_args(env, &create.nonce_account, &extra));
    let advance: NonceAdvanceOutput = serde_json::from_slice(&advance.stdout).unwrap();
    assert_eq!(advance.nonce_account, create.nonce_account);
    assert_eq!(advance.previous_nonce, create.nonce);
    assert_ne!(advance.nonce, create.nonce);
    assert!(!advance.signature.is_empty());

    let show = show_nonce(env, &create.nonce_account);
    assert_eq!(show.nonce, advance.nonce);
    assert_eq!(show.authority, create.authority);
}

pub async fn advances_nonce_with_plain_key_authority(env: &TestEnv) {
    // The configured keypair is both the nonce authority and the fee payer.
    let create = create_nonce(env, "--nonce-authority", &env.payer_address);
    advance_nonce(env, &create, None);

    // A separate nonce authority signs alongside the fee payer.
    let authority = Keypair::new();
    let authority_file = NamedTempFile::new().unwrap();
    write_keypair_file(&authority, &authority_file).unwrap();
    let create = create_nonce(env, "--nonce-authority", &authority.pubkey().to_string());
    advance_nonce(env, &create, Some(authority_file.path().to_str().unwrap()));
}

pub async fn advances_nonce_with_cold_authority(env: &TestEnv) {
    // The configured keypair is both the cold authority and the fee payer.
    let create = create_nonce(env, "--cold-authority", &env.payer_address);
    advance_nonce(env, &create, None);

    // An unfunded cold authority signs only the authorization message.
    let cold_authority = Keypair::new();
    let cold_authority_file = NamedTempFile::new().unwrap();
    write_keypair_file(&cold_authority, &cold_authority_file).unwrap();
    let create = create_nonce(
        env,
        "--cold-authority",
        &cold_authority.pubkey().to_string(),
    );
    advance_nonce(
        env,
        &create,
        Some(cold_authority_file.path().to_str().unwrap()),
    );
}

pub async fn advances_nonce_with_external_cold_authority(env: &TestEnv) {
    let cold_authority = Keypair::new();
    let cold_authority_address = cold_authority.pubkey().to_string();
    let create = create_nonce(env, "--cold-authority", &cold_authority_address);
    let salt = Keypair::new().pubkey().to_string();
    let dump = || {
        let dump = run_psigner(&advance_args(
            env,
            &create.nonce_account,
            &[
                "--nonce-authority",
                &cold_authority_address,
                "--salt",
                &salt,
            ],
        ));
        serde_json::from_slice::<NonceAdvanceAuthorizationOutput>(&dump.stdout).unwrap()
    };
    let unsigned = dump();
    // A fixed salt builds the same authorization message, and so the same next nonce value.
    assert_eq!(unsigned, dump());
    assert_eq!(unsigned.nonce_account, create.nonce_account);
    assert_eq!(unsigned.current_nonce, create.nonce);
    assert_eq!(unsigned.signer, cold_authority_address);
    // Printing the message signs and submits nothing.
    assert_eq!(show_nonce(env, &create.nonce_account).nonce, create.nonce);

    // The external signer, e.g. an HSM, signs the decoded message bytes as-is, and the
    // signature goes through the usual submit flow.
    let authorization_message = &unsigned.authorization_message;
    let signature =
        cold_authority.sign_message(&BASE64_STANDARD.decode(authorization_message).unwrap());
    run_psigner(&[
        "-C",
        &env.config_file_path,
        "--output",
        "json-compact",
        "transaction",
        "submit",
        "--authorization-message",
        authorization_message,
        "--signer",
        &format!("{cold_authority_address}={signature}"),
    ]);
    assert_eq!(
        show_nonce(env, &create.nonce_account).nonce,
        unsigned.next_nonce
    );
}

pub async fn rejects_offline_plain_key_authority(env: &TestEnv) {
    let authority = Keypair::new().pubkey().to_string();
    let create = create_nonce(env, "--nonce-authority", &authority);
    let advance = run_psigner_with_input(
        &advance_args(
            env,
            &create.nonce_account,
            &["--nonce-authority", &authority],
        ),
        "",
    );
    assert!(!advance.status.success());
    let stderr = String::from_utf8_lossy(&advance.stderr);
    assert!(
        stderr.contains(&format!(
            "nonce authority {authority} signs the relay transaction directly, so it must be \
             passed as a signer"
        )),
        "{stderr}"
    );
}

pub async fn rejects_unrelated_nonce_authority(env: &TestEnv) {
    let authority = Keypair::new().pubkey().to_string();
    let create = create_nonce(env, "--nonce-authority", &authority);
    let advance = run_psigner_with_input(&advance_args(env, &create.nonce_account, &[]), "");
    assert!(!advance.status.success());
    let stderr = String::from_utf8_lossy(&advance.stderr);
    assert!(
        stderr.contains(&format!(
            "nonce account {} has authority {authority}, but the nonce authority given is {}",
            create.nonce_account, env.payer_address
        )),
        "{stderr}"
    );
}
