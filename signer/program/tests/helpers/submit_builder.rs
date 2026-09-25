use {
    crate::helpers::{common::init_mollusk, stub_executor},
    mollusk_svm::result::{Check, InstructionResult},
    solana_account::Account,
    solana_address::Address,
    solana_instruction::Instruction as SolanaInstruction,
    solana_keypair::Keypair,
    solana_message::{VersionedMessage, v1},
    solana_program_error::ProgramError,
    solana_signer::Signer as _,
    solana_system_interface::instruction::transfer,
    solana_transaction::versioned::VersionedTransaction,
    spl_ed25519_signer_client::{instruction::submit, message::wrapped_message},
    spl_ed25519_signer_interface::pda::ProgrammaticSigner,
};

pub const DEFAULT_TRANSFER_LAMPORTS: u64 = 1_000_000;

type IxMutation = Box<dyn FnOnce(&mut SolanaInstruction)>;
type MessageMutation = Box<dyn FnOnce(&mut v1::Message)>;
type TransactionTamper = Box<dyn FnOnce(&mut VersionedTransaction)>;

pub fn funded_account() -> Account {
    Account {
        lamports: 100_000_000,
        ..Account::default()
    }
}

struct SubmitContext {
    authorities: Vec<Address>,
    programmatic_signer: Address,
    recipient: Address,
}

/// Builds, signs, and submits a wrapped transaction through Mollusk.
///
/// A stub at the allowed executor address forwards to the system program.  A transfer from the
/// promoted `ProgrammaticSigner` consumes the promotion, so success proves the verify, promote, and
/// CPI chain. These fixtures carry no replay protection.
pub struct SubmitBuilder<'a> {
    authorities: Vec<Keypair>,
    recipient: Address,
    executor_instruction: Option<SolanaInstruction>,
    message_override: Option<VersionedMessage>,
    executor_instruction_mutations: Vec<IxMutation>,
    message_mutations: Vec<MessageMutation>,
    message_tampers: Vec<MessageMutation>,
    transaction_tampers: Vec<TransactionTamper>,
    submit_instruction_mutations: Vec<IxMutation>,
    account_overrides: Vec<(Address, Account)>,
    checks: Vec<Check<'a>>,
}

impl<'a> SubmitBuilder<'a> {
    pub fn default_transfer() -> Self {
        Self::default_transfer_with_authority(Keypair::new())
    }

    pub fn default_transfer_with_authority(authority: Keypair) -> Self {
        Self {
            authorities: vec![authority],
            recipient: Address::new_unique(),
            executor_instruction: None,
            message_override: None,
            executor_instruction_mutations: vec![],
            message_mutations: vec![],
            message_tampers: vec![],
            transaction_tampers: vec![],
            submit_instruction_mutations: vec![],
            account_overrides: vec![],
            checks: vec![],
        }
    }

    pub fn additional_authority(mut self, authority: Keypair) -> Self {
        self.authorities.push(authority);
        self
    }

    pub fn recipient(mut self, recipient: Address) -> Self {
        self.recipient = recipient;
        self
    }

    pub fn executor_instruction(mut self, ix: SolanaInstruction) -> Self {
        self.executor_instruction = Some(ix);
        self
    }

    pub fn message(mut self, message: VersionedMessage) -> Self {
        self.message_override = Some(message);
        self
    }

    /// Mutates the executor instruction before signing, so the authorities sign the change.
    pub fn mutate_executor_instruction(
        mut self,
        mutation: impl FnOnce(&mut SolanaInstruction) + 'static,
    ) -> Self {
        self.executor_instruction_mutations.push(Box::new(mutation));
        self
    }

    /// Mutates the wrapped message before signing, so the authorities sign the change.
    pub fn mutate_message(mut self, mutation: impl FnOnce(&mut v1::Message) + 'static) -> Self {
        self.message_mutations.push(Box::new(mutation));
        self
    }

    /// Tampers with the wrapped message after signing, so signatures no longer cover it.
    pub fn tamper_message(mut self, tamper: impl FnOnce(&mut v1::Message) + 'static) -> Self {
        self.message_tampers.push(Box::new(tamper));
        self
    }

    /// Tampers with the signed transaction after signing, so signatures no longer cover it.
    pub fn tamper_transaction(
        mut self,
        tamper: impl FnOnce(&mut VersionedTransaction) + 'static,
    ) -> Self {
        self.transaction_tampers.push(Box::new(tamper));
        self
    }

    /// Mutates the outer `Submit` instruction the relayer sends.
    pub fn mutate_submit_ix(
        mut self,
        mutation: impl FnOnce(&mut SolanaInstruction) + 'static,
    ) -> Self {
        self.submit_instruction_mutations.push(Box::new(mutation));
        self
    }

    pub fn account(mut self, address: Address, account: Account) -> Self {
        self.account_overrides.push((address, account));
        self
    }

    pub fn check(mut self, check: Check<'a>) -> Self {
        self.checks.push(check);
        self
    }

    pub fn check_err(self, error: impl Into<ProgramError>) -> Self {
        self.check(Check::err(error.into()))
    }

    pub fn execute(mut self) -> SubmitResult {
        let context = self.context();

        let message = match self.message_override.take() {
            Some(message) => message,
            None => {
                let inner_executor_instruction =
                    self.executor_instruction.take().unwrap_or_else(|| {
                        transfer(
                            &context.programmatic_signer,
                            &context.recipient,
                            DEFAULT_TRANSFER_LAMPORTS,
                        )
                    });
                let mut executor_instruction = stub_executor::wrap(inner_executor_instruction);
                for mutation in self.executor_instruction_mutations.drain(..) {
                    mutation(&mut executor_instruction);
                }

                let mut message = wrapped_message(&executor_instruction, &context.authorities);
                let VersionedMessage::V1(v1_message) = &mut message else {
                    panic!("expected v1 message");
                };
                for mutation in self.message_mutations.drain(..) {
                    mutation(v1_message);
                }
                message
            }
        };

        let signers = self.authorities.iter().collect::<Vec<_>>();
        let mut transaction = VersionedTransaction::try_new(message, &signers).unwrap();

        if !self.message_tampers.is_empty() {
            let VersionedMessage::V1(msg) = &mut transaction.message else {
                panic!("tamper_message requires a v1 wrapped message");
            };
            for tamper in self.message_tampers.drain(..) {
                tamper(msg);
            }
        }
        for tamper in self.transaction_tampers.drain(..) {
            tamper(&mut transaction);
        }

        let VersionedTransaction {
            signatures,
            message,
        } = transaction;
        let mut ix = submit(signatures, message);
        for mutation in self.submit_instruction_mutations.drain(..) {
            mutation(&mut ix);
        }

        let accounts = ix
            .accounts
            .iter()
            .map(|meta| self.default_account_for(meta.pubkey, &context))
            .collect::<Vec<_>>();
        if self.checks.is_empty() {
            self.checks.push(Check::success());
        }
        let raw = init_mollusk().process_and_validate_instruction(&ix, &accounts, &self.checks);

        SubmitResult {
            programmatic_signer: context.programmatic_signer,
            recipient: context.recipient,
            instruction: ix,
            raw,
        }
    }

    fn context(&self) -> SubmitContext {
        let authorities = self
            .authorities
            .iter()
            .map(|authority| authority.pubkey())
            .collect::<Vec<_>>();
        let programmatic_signer = ProgrammaticSigner::derive_address(
            &spl_ed25519_signer_interface::id(),
            &authorities[0],
        );
        SubmitContext {
            authorities,
            programmatic_signer,
            recipient: self.recipient,
        }
    }

    fn default_account_for(&self, key: Address, context: &SubmitContext) -> (Address, Account) {
        if let Some((_, account)) = self
            .account_overrides
            .iter()
            .rev()
            .find(|(address, _)| *address == key)
        {
            return (key, account.clone());
        }
        if key == solana_system_interface::program::id() {
            return mollusk_svm::program::keyed_account_for_system_program();
        }
        if key == spl_message_executor_interface::id() {
            return stub_executor::keyed_account();
        }
        // Only the first authority's programmatic signer is prefunded. Promotion tests that
        // create accounts at later programmatic signers need those to start empty.
        if key == context.programmatic_signer {
            return (key, funded_account());
        }
        (key, Account::default())
    }
}

pub struct SubmitResult {
    pub programmatic_signer: Address,
    pub recipient: Address,
    pub instruction: SolanaInstruction,
    raw: InstructionResult,
}

impl SubmitResult {
    pub fn account(&self, key: &Address) -> Option<&Account> {
        self.raw.get_account(key)
    }
}
