use {
    crate::helpers::common::{init_mollusk, initialize_nonce_account},
    alloc::collections::BTreeMap,
    mollusk_svm::{
        Mollusk,
        result::{Check, InstructionResult},
    },
    solana_account::Account,
    solana_address::Address,
    solana_hash::Hash,
    solana_instruction::Instruction,
    solana_message::v1,
    solana_program_error::ProgramError,
    spl_message_executor_client::instruction::execute,
    spl_nonce_interface::state::Nonce,
};

type MessageMutation = Box<dyn FnOnce(&mut v1::Message)>;
type InstructionMutation = Box<dyn FnOnce(&mut Instruction)>;

pub const DEFAULT_AUTHORITY: Address = Address::new_from_array([3; 32]);

pub struct ExecuteBuilder<'a> {
    mollusk: Mollusk,
    nonce_account: Option<(Address, Account)>,
    authority: Address,
    payer: Option<Address>,
    inner_instructions: Vec<Instruction>,
    recent_blockhash: Option<Hash>,
    message: Option<v1::Message>,
    message_mutations: Vec<MessageMutation>,
    execute_instruction_mutations: Vec<InstructionMutation>,
    account_overrides: Vec<(Address, Account)>,
    checks: Vec<Check<'a>>,
}

impl Default for ExecuteBuilder<'_> {
    fn default() -> Self {
        Self::new(init_mollusk())
    }
}

impl<'a> ExecuteBuilder<'a> {
    pub fn new(mollusk: Mollusk) -> Self {
        Self {
            mollusk,
            nonce_account: None,
            authority: DEFAULT_AUTHORITY,
            payer: None,
            inner_instructions: vec![],
            recent_blockhash: None,
            message: None,
            message_mutations: vec![],
            execute_instruction_mutations: vec![],
            account_overrides: vec![],
            checks: vec![],
        }
    }

    pub fn nonce_account(mut self, nonce_address: Address, nonce_account: Account) -> Self {
        self.nonce_account = Some((nonce_address, nonce_account));
        self
    }

    pub fn authority(mut self, authority: Address) -> Self {
        self.authority = authority;
        self
    }

    pub fn payer(mut self, payer: Address) -> Self {
        self.payer = Some(payer);
        self
    }

    pub fn inner_instruction(mut self, instruction: Instruction) -> Self {
        self.inner_instructions.push(instruction);
        self
    }

    pub fn recent_blockhash(mut self, recent_blockhash: Hash) -> Self {
        self.recent_blockhash = Some(recent_blockhash);
        self
    }

    pub fn message(mut self, message: v1::Message) -> Self {
        self.message = Some(message);
        self
    }

    pub fn mutate_message(mut self, mutation: impl FnOnce(&mut v1::Message) + 'static) -> Self {
        self.message_mutations.push(Box::new(mutation));
        self
    }

    pub fn mutate_execute_ix(mut self, mutation: impl FnOnce(&mut Instruction) + 'static) -> Self {
        self.execute_instruction_mutations.push(Box::new(mutation));
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

    pub fn execute(self) -> ExecuteResult {
        let Self {
            mollusk,
            nonce_account: nonce_account_override,
            authority,
            payer,
            inner_instructions,
            recent_blockhash: recent_blockhash_override,
            message: message_override,
            message_mutations,
            execute_instruction_mutations,
            account_overrides,
            mut checks,
        } = self;

        let (nonce_address, initial_nonce_account) = nonce_account_override
            .unwrap_or_else(|| initialize_nonce_account(&mollusk, &authority));

        let recent_blockhash = recent_blockhash_override.unwrap_or_else(|| {
            wincode::deserialize_exact::<Nonce>(&initial_nonce_account.data)
                .map(|nonce| nonce.nonce)
                .unwrap_or_default()
        });

        let mut message = message_override.unwrap_or_else(|| {
            v1::Message::try_compile(
                payer.as_ref().unwrap_or(&authority),
                &inner_instructions,
                recent_blockhash,
            )
            .unwrap()
        });

        for mutation in message_mutations {
            mutation(&mut message);
        }

        let mut instruction = execute(&nonce_address, &authority, &message);

        for mutation in execute_instruction_mutations {
            mutation(&mut instruction);
        }

        let mut accounts_by_address = BTreeMap::from([
            (
                authority,
                Account {
                    lamports: 100_000_000,
                    ..Account::default()
                },
            ),
            mollusk_svm::program::keyed_account_for_system_program(),
            (
                spl_nonce_interface::id(),
                mollusk_svm::program::create_program_account_loader_v3(&spl_nonce_interface::id()),
            ),
        ]);
        accounts_by_address.extend(account_overrides);
        accounts_by_address.insert(nonce_address, initial_nonce_account.clone());

        let accounts = instruction
            .accounts
            .iter()
            .map(|meta| {
                (
                    meta.pubkey,
                    accounts_by_address
                        .get(&meta.pubkey)
                        .cloned()
                        .unwrap_or_default(),
                )
            })
            .collect::<Vec<_>>();

        if checks.is_empty() {
            checks.push(Check::success());
        }

        let raw = mollusk.process_and_validate_instruction(&instruction, &accounts, &checks);

        let resulting_nonce_account = raw
            .get_account(&nonce_address)
            .unwrap_or(&initial_nonce_account)
            .clone();

        ExecuteResult {
            nonce_address,
            nonce_account: resulting_nonce_account,
            message,
            raw,
        }
    }
}

pub struct ExecuteResult {
    pub nonce_address: Address,
    pub nonce_account: Account,
    pub message: v1::Message,
    raw: InstructionResult,
}

impl ExecuteResult {
    pub fn account(&self, address: &Address) -> Option<&Account> {
        self.raw.get_account(address)
    }
}
