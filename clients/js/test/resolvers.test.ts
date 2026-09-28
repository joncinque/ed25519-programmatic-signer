import { LOADER_V3_PROGRAM_ADDRESS } from '@solana-program/loader-v3';
import {
    AccountRole,
    createNoopSigner,
    getAddressDecoder,
    getBlockhashDecoder,
    getCompiledTransactionMessageEncoder,
    SOLANA_ERROR__CODECS__EXPECTED_DECODER_TO_CONSUME_ENTIRE_BYTE_ARRAY,
    SolanaError,
    type CompiledTransactionMessage,
    type CompiledTransactionMessageWithLifetime,
    TransactionVersion,
} from '@solana/kit';
import { describe, expect, it } from 'vitest';

import { getExecuteInstruction, getSubmitInstruction, NONCE_PROGRAM_ADDRESS } from '../src';

const UNSUPPORTED_MESSAGE_VERSIONS = [
    ['legacy', 'legacy'],
    [0, 'v0'],
] as const;

type TestMessage = CompiledTransactionMessage & CompiledTransactionMessageWithLifetime;

const addressDecoder = getAddressDecoder();
const blockhashDecoder = getBlockhashDecoder();
const messageEncoder = getCompiledTransactionMessageEncoder();

const getTestAddress = (byte: number) => addressDecoder.decode(new Uint8Array(32).fill(byte));

const NONCE_ACCOUNT = getTestAddress(1);
const NONCE_AUTHORITY = createNoopSigner(getTestAddress(2));
const LIFETIME_TOKEN = blockhashDecoder.decode(new Uint8Array(32).fill(10));
const TEST_ACCOUNTS = {
    feePayer: getTestAddress(11),
    secondSigner: getTestAddress(12),
    writable: getTestAddress(13),
    invokedProgram: getTestAddress(14),
    readonly: getTestAddress(15),
} as const;
const STATIC_ACCOUNTS = [
    TEST_ACCOUNTS.feePayer,
    TEST_ACCOUNTS.secondSigner,
    TEST_ACCOUNTS.writable,
    TEST_ACCOUNTS.invokedProgram,
    TEST_ACCOUNTS.readonly,
];

const getTestMessage = (
    version: TransactionVersion,
    config: Readonly<{
        includeLoader?: boolean;
        numReadonlySignerAccounts?: number;
        programAccountIndexes?: readonly number[];
    }> = {},
): TestMessage => {
    const staticAccounts = [
        ...STATIC_ACCOUNTS.slice(0, 4),
        config.includeLoader ? LOADER_V3_PROGRAM_ADDRESS : STATIC_ACCOUNTS[4],
    ];
    const header = {
        numReadonlyNonSignerAccounts: 1,
        numReadonlySignerAccounts: config.numReadonlySignerAccounts ?? 1,
        numSignerAccounts: 2,
    };
    const programAccountIndexes = config.programAccountIndexes ?? [3];
    const instructions = programAccountIndexes.map(programAddressIndex => ({
        accountIndices: [0, 2, 4],
        data: new Uint8Array([7]),
        programAddressIndex,
    }));

    if (version === 'legacy') {
        return {
            header,
            instructions,
            lifetimeToken: LIFETIME_TOKEN,
            staticAccounts,
            version: 'legacy',
        };
    }

    if (version === 0) {
        return {
            addressTableLookups: [],
            header,
            instructions,
            lifetimeToken: LIFETIME_TOKEN,
            staticAccounts,
            version: 0,
        };
    }

    return {
        configMask: 0,
        configValues: [],
        header,
        instructionHeaders: programAccountIndexes.map(programAccountIndex => ({
            numInstructionAccounts: 3,
            numInstructionDataBytes: 1,
            programAccountIndex,
        })),
        instructionPayloads: programAccountIndexes.map(() => ({
            instructionAccountIndices: [0, 2, 4],
            instructionData: new Uint8Array([7]),
        })),
        lifetimeToken: LIFETIME_TOKEN,
        numInstructions: programAccountIndexes.length,
        numStaticAccounts: staticAccounts.length,
        staticAccounts,
        version: 1,
    };
};

const encodeMessage = (message: TestMessage) => messageEncoder.encode(message);

const getExecuteAccounts = (message: TestMessage) =>
    getExecuteInstruction({
        message: encodeMessage(message),
        nonceAccount: NONCE_ACCOUNT,
        nonceAuthority: NONCE_AUTHORITY,
    }).accounts;

const getRemainingExecuteAccounts = (message: TestMessage) => getExecuteAccounts(message).slice(3);

const getSubmitAccounts = (message: TestMessage) =>
    getSubmitInstruction({
        message: encodeMessage(message),
        signatures: Array.from({ length: message.header.numSignerAccounts }, () => new Uint8Array(64)),
    }).accounts;

const expectedExecuteAccounts = [
    { address: TEST_ACCOUNTS.feePayer, role: AccountRole.WRITABLE_SIGNER },
    { address: TEST_ACCOUNTS.secondSigner, role: AccountRole.READONLY_SIGNER },
    { address: TEST_ACCOUNTS.writable, role: AccountRole.WRITABLE },
    { address: TEST_ACCOUNTS.invokedProgram, role: AccountRole.READONLY },
    { address: TEST_ACCOUNTS.readonly, role: AccountRole.READONLY },
];

const expectedSubmitAccounts = [
    { address: TEST_ACCOUNTS.feePayer, role: AccountRole.WRITABLE },
    { address: TEST_ACCOUNTS.secondSigner, role: AccountRole.READONLY },
    { address: TEST_ACCOUNTS.writable, role: AccountRole.WRITABLE },
    { address: TEST_ACCOUNTS.invokedProgram, role: AccountRole.READONLY },
    { address: TEST_ACCOUNTS.readonly, role: AccountRole.READONLY },
];

describe('remaining account resolvers', () => {
    it('resolves account order and permissions for a v1 execution message', () => {
        expect(getExecuteAccounts(getTestMessage(1))).toEqual([
            { address: NONCE_AUTHORITY.address, role: AccountRole.READONLY_SIGNER, signer: NONCE_AUTHORITY },
            { address: NONCE_ACCOUNT, role: AccountRole.WRITABLE },
            { address: NONCE_PROGRAM_ADDRESS, role: AccountRole.READONLY },
            ...expectedExecuteAccounts,
        ]);
    });

    it('removes signer privileges from a v1 authorization message', () => {
        expect(getSubmitAccounts(getTestMessage(1))).toEqual(expectedSubmitAccounts);
    });

    it.each(UNSUPPORTED_MESSAGE_VERSIONS)('rejects a %s execution message', (version, label) => {
        expect(() => getExecuteAccounts(getTestMessage(version))).toThrow(
            `The message executor only supports v1 execution messages, got a ${label} message`,
        );
    });

    it.each(UNSUPPORTED_MESSAGE_VERSIONS)('rejects a %s authorization message', (version, label) => {
        expect(() => getSubmitAccounts(getTestMessage(version))).toThrow(
            `The signer program only supports v1 authorization messages, got a ${label} message`,
        );
    });

    it('keeps an invoked program writable when loader v3 is present', () => {
        const message = getTestMessage(1, { includeLoader: true });
        const executeAccounts = getRemainingExecuteAccounts(message);
        const submitAccounts = getSubmitAccounts(message);
        const expectedProgramAccounts = [
            { address: TEST_ACCOUNTS.invokedProgram, role: AccountRole.WRITABLE },
            { address: LOADER_V3_PROGRAM_ADDRESS, role: AccountRole.READONLY },
        ];

        expect(executeAccounts.slice(3)).toEqual(expectedProgramAccounts);
        expect(submitAccounts.slice(3)).toEqual(expectedProgramAccounts);
    });

    it('demotes every program account used by multiple instructions', () => {
        const remainingAccounts = getRemainingExecuteAccounts(getTestMessage(1, { programAccountIndexes: [2, 3] }));

        expect(remainingAccounts.slice(2, 4)).toEqual([
            { address: TEST_ACCOUNTS.writable, role: AccountRole.READONLY },
            { address: TEST_ACCOUNTS.invokedProgram, role: AccountRole.READONLY },
        ]);
    });

    it('preserves signer status when demoting a program account', () => {
        const message = getTestMessage(1, {
            numReadonlySignerAccounts: 0,
            programAccountIndexes: [1],
        });
        const executeAccounts = getRemainingExecuteAccounts(message);
        const submitAccounts = getSubmitAccounts(message);

        expect(executeAccounts[1]).toEqual({
            address: TEST_ACCOUNTS.secondSigner,
            role: AccountRole.READONLY_SIGNER,
        });
        expect(submitAccounts[1]).toEqual({
            address: TEST_ACCOUNTS.secondSigner,
            role: AccountRole.READONLY,
        });
    });

    it('rejects trailing bytes after an execution message', () => {
        const message = encodeMessage(getTestMessage(1));

        expect(() =>
            getExecuteInstruction({
                message: new Uint8Array([...message, 255]),
                nonceAccount: NONCE_ACCOUNT,
                nonceAuthority: NONCE_AUTHORITY,
            }),
        ).toThrow(
            new SolanaError(SOLANA_ERROR__CODECS__EXPECTED_DECODER_TO_CONSUME_ENTIRE_BYTE_ARRAY, {
                expectedLength: message.length,
                numExcessBytes: 1,
            }),
        );
    });

    it('rejects trailing bytes after an authorization message', () => {
        const message = encodeMessage(getTestMessage(1));

        expect(() =>
            getSubmitInstruction({
                message: new Uint8Array([...message, 255]),
                signatures: [new Uint8Array(64)],
            }),
        ).toThrow(
            new SolanaError(SOLANA_ERROR__CODECS__EXPECTED_DECODER_TO_CONSUME_ENTIRE_BYTE_ARRAY, {
                expectedLength: message.length,
                numExcessBytes: 1,
            }),
        );
    });
});
