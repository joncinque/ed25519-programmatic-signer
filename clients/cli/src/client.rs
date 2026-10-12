use {
    crate::cli::ClientArgs,
    anyhow::{Context, Result, anyhow, bail, ensure},
    clap::ArgMatches,
    solana_account::Account,
    solana_account_decoder_client_types::UiAccountEncoding,
    solana_address::Address,
    solana_clap_v3_utils::{
        input_parsers::{parse_url_or_moniker, signer::SignerSource},
        keypair::{SignerFromPathConfig, signer_from_source_with_config},
    },
    solana_cli_config::{CONFIG_FILE, Config as SolanaCliConfig},
    solana_commitment_config::CommitmentConfig,
    solana_hash::Hash,
    solana_nonce::{
        state::{Data, State},
        versions::Versions,
    },
    solana_remote_wallet::remote_wallet::RemoteWalletManager,
    solana_rpc_client::nonblocking::rpc_client::RpcClient,
    solana_rpc_client_types::{
        config::{
            RpcSendTransactionConfig, RpcSimulateTransactionAccountsConfig,
            RpcSimulateTransactionConfig,
        },
        response::RpcSimulateTransactionResult,
    },
    solana_signer::Signer,
    solana_transaction::Transaction,
    spl_nonce_interface::state::Nonce,
    std::{cell::RefCell, io::ErrorKind, path::Path, rc::Rc, str::FromStr},
};

#[derive(Debug)]
pub(crate) struct NonceAccount {
    pub(crate) state: Nonce,
    pub(crate) lamports: u64,
}

pub(crate) struct Client {
    rpc: RpcClient,
    fee_payer: Option<SignerSource>,
    config_keypair_path: String,
    skip_preflight: bool,
    matches: ArgMatches,
    wallet_manager: RefCell<Option<Rc<RemoteWalletManager>>>,
}

impl Client {
    pub(crate) fn new(args: ClientArgs, matches: ArgMatches) -> Result<Self> {
        let config = load_cli_config(args.config.as_deref())?;
        let url = match args.url {
            Some(url) => url,
            None => parse_url_or_moniker(&config.json_rpc_url)
                .map_err(|error| anyhow!(error))
                .context("invalid RPC URL in Solana CLI configuration")?,
        };
        let commitment = match args.commitment {
            Some(commitment) => commitment,
            None if config.commitment.is_empty() => CommitmentConfig::confirmed(),
            None => CommitmentConfig::from_str(&config.commitment).with_context(|| {
                format!(
                    "invalid commitment {:?} in Solana CLI configuration",
                    config.commitment
                )
            })?,
        };

        Ok(Self {
            rpc: RpcClient::new_with_commitment(url, commitment),
            fee_payer: args.fee_payer,
            config_keypair_path: config.keypair_path,
            skip_preflight: args.skip_preflight,
            matches,
            wallet_manager: RefCell::new(None),
        })
    }

    pub(crate) fn fee_payer(&self) -> Result<Box<dyn Signer>> {
        self.load_signer(&self.fee_payer_source()?, "fee payer", false)
    }

    /// The `--fee-payer` source, or the configured keypair.
    pub(crate) fn fee_payer_source(&self) -> Result<SignerSource> {
        self.fee_payer
            .clone()
            .map_or_else(|| self.config_keypair_source(), Ok)
    }

    /// Load a signer. With `allow_null_signer`, an address source loads a [`NullSigner`] whose
    /// signature is collected separately.
    ///
    /// [`NullSigner`]: solana_signer::null_signer::NullSigner
    pub(crate) fn load_signer(
        &self,
        source: &SignerSource,
        name: &str,
        allow_null_signer: bool,
    ) -> Result<Box<dyn Signer>> {
        let mut wallet_manager = self.wallet_manager.borrow_mut();
        signer_from_source_with_config(
            &self.matches,
            source,
            name,
            &mut wallet_manager,
            &SignerFromPathConfig { allow_null_signer },
        )
        .map_err(|error| anyhow!(error.to_string()))
        .with_context(|| format!("failed to load {name}"))
    }

    /// The keypair from the Solana CLI configuration.
    pub(crate) fn config_keypair_source(&self) -> Result<SignerSource> {
        SignerSource::parse(&self.config_keypair_path)
            .map_err(|error| anyhow!(error.to_string()))
            .context("invalid configured keypair path")
    }

    pub(crate) async fn minimum_balance_for_rent_exemption(&self, data_len: usize) -> Result<u64> {
        self.rpc
            .get_minimum_balance_for_rent_exemption(data_len)
            .await
            .context("failed to query rent exemption")
    }

    pub(crate) async fn latest_blockhash(&self) -> Result<Hash> {
        self.rpc
            .get_latest_blockhash()
            .await
            .context("failed to get latest blockhash")
    }

    pub(crate) async fn nonce_account(&self, address: &Address) -> Result<NonceAccount> {
        let account = self
            .rpc
            .get_account_with_commitment(address, self.rpc.commitment())
            .await
            .with_context(|| format!("failed to fetch account {address}"))?
            .value
            .with_context(|| format!("nonce account {address} was not found"))?;
        decode_nonce_account(address, account)
    }

    /// Fetch a System Program nonce account, used as a relay transaction's durable nonce.
    pub(crate) async fn durable_nonce_account(&self, address: &Address) -> Result<Data> {
        let account = self
            .rpc
            .get_account_with_commitment(address, self.rpc.commitment())
            .await
            .with_context(|| format!("failed to fetch account {address}"))?
            .value
            .with_context(|| format!("durable nonce account {address} was not found"))?;
        decode_durable_nonce_account(address, &account)
    }

    /// Simulate without verifying signatures, against the latest blockhash. With
    /// `verbose_accounts`, also requests the inner instructions and the post-simulation state of
    /// those accounts.
    pub(crate) async fn simulate_transaction(
        &self,
        transaction: &Transaction,
        verbose_accounts: Option<&[Address]>,
    ) -> Result<RpcSimulateTransactionResult> {
        let accounts = verbose_accounts.map(|addresses| RpcSimulateTransactionAccountsConfig {
            encoding: Some(UiAccountEncoding::JsonParsed),
            addresses: addresses.iter().map(ToString::to_string).collect(),
        });
        self.rpc
            .simulate_transaction_with_config(
                transaction,
                RpcSimulateTransactionConfig {
                    sig_verify: false,
                    replace_recent_blockhash: true,
                    commitment: Some(self.rpc.commitment()),
                    accounts,
                    inner_instructions: verbose_accounts.is_some(),
                    ..RpcSimulateTransactionConfig::default()
                },
            )
            .await
            .map(|response| response.value)
            .context("failed to simulate transaction")
    }

    pub(crate) async fn send_and_confirm_transaction(
        &self,
        transaction: &Transaction,
    ) -> Result<String> {
        self.rpc
            .send_and_confirm_transaction_with_config(
                transaction,
                self.rpc.commitment(),
                RpcSendTransactionConfig {
                    skip_preflight: self.skip_preflight,
                    preflight_commitment: Some(self.rpc.commitment().commitment),
                    ..RpcSendTransactionConfig::default()
                },
            )
            .await
            .map(|signature| signature.to_string())
            .context("failed to send and confirm transaction")
    }
}

fn decode_nonce_account(address: &Address, account: Account) -> Result<NonceAccount> {
    if account.owner != spl_nonce_interface::id() {
        bail!(
            "account {address} is owned by {}, not the SPL Nonce program {}",
            account.owner,
            spl_nonce_interface::id()
        );
    }
    let state = Nonce::view(&account.data)
        .cloned()
        .with_context(|| format!("account {address} contains invalid SPL Nonce data"))?;
    Ok(NonceAccount {
        state,
        lamports: account.lamports,
    })
}

fn decode_durable_nonce_account(address: &Address, account: &Account) -> Result<Data> {
    ensure!(
        account.owner == solana_system_interface::program::id(),
        "account {address} is owned by {}, not the System Program",
        account.owner
    );
    let versions = wincode::deserialize::<Versions>(&account.data)
        .with_context(|| format!("account {address} is not a durable nonce account"))?;
    let State::Initialized(data) = versions.state() else {
        bail!("durable nonce account {address} is not initialized");
    };
    Ok(data.clone())
}

fn load_cli_config(config_path: Option<&Path>) -> Result<SolanaCliConfig> {
    if let Some(config_path) = config_path {
        let config_path = config_path
            .to_str()
            .ok_or_else(|| anyhow!("Solana CLI config path is not valid UTF-8"))?;
        return SolanaCliConfig::load(config_path)
            .with_context(|| format!("failed to load Solana CLI config {config_path}"));
    }

    let Some(config_path) = CONFIG_FILE.as_deref() else {
        return Ok(SolanaCliConfig::default());
    };

    match SolanaCliConfig::load(config_path) {
        Ok(config) => Ok(config),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(SolanaCliConfig::default()),
        Err(error) => {
            Err(error).with_context(|| format!("failed to load Solana CLI config {config_path}"))
        }
    }
}
