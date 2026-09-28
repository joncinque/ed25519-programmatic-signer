import { LOADER_V3_PROGRAM_ADDRESS } from '@solana-program/loader-v3';
import {
    createDecoderThatConsumesEntireByteArray,
    downgradeRoleToNonSigner,
    downgradeRoleToReadonly,
    getAccountMetasFromCompiledTransactionMessage,
    getCompiledTransactionMessageDecoder,
    type AccountMeta,
    type CompiledTransactionMessage,
    type ReadonlyUint8Array,
} from '@solana/kit';

type MessageAccountsResolverScope = Readonly<{
    args: Readonly<{ message: ReadonlyUint8Array }>;
}>;

type V1CompiledTransactionMessage = Extract<CompiledTransactionMessage, { version: 1 }>;

const compiledMessageDecoder = createDecoderThatConsumesEntireByteArray(getCompiledTransactionMessageDecoder());

/**
 * Resolves the remaining `Execute` accounts from the wrapped message's static account list.
 * Accounts keep the order and permissions they would have in a normal Solana transaction.
 * Throws for a message that is not v1, which the executor rejects.
 *
 * Mirrors `executor/client/src/instruction.rs`.
 */
export const resolveMessageAccounts = (scope: MessageAccountsResolverScope): AccountMeta[] => {
    const message = decodeV1Message(scope.args.message, 'The message executor only supports v1 inner messages');
    return getStaticAccountMetas(message);
};

/**
 * Resolves the remaining `Submit` accounts from the wrapped message's static account list.
 * Account order and writable privileges match the wrapped message, while signer privileges are
 * removed because the wrapped signers are not signers of the outer transaction.
 * Throws for a message that is not v1, which the signer program rejects.
 *
 * Mirrors `signer/client/src/instruction.rs`.
 */
export const resolveSubmitMessageAccounts = (scope: MessageAccountsResolverScope): AccountMeta[] => {
    const message = decodeV1Message(scope.args.message, 'The signer program only supports v1 wrapped messages');
    return getStaticAccountMetas(message).map(account => ({
        ...account,
        // Wrapped signatures authorize the wrapped message, not the outer transaction that submits it.
        role: downgradeRoleToNonSigner(account.role),
    }));
};

// Decodes a message that the programs accept, which must be v1.
const decodeV1Message = (bytes: ReadonlyUint8Array, errorMessage: string): V1CompiledTransactionMessage => {
    const message = compiledMessageDecoder.decode(bytes);
    if (message.version !== 1) {
        const version = message.version === 'legacy' ? 'legacy' : `v${message.version}`;
        throw new Error(`${errorMessage}, got a ${version} message`);
    }
    return message;
};

// Builds account metas out of a message's static account list.
const getStaticAccountMetas = (message: V1CompiledTransactionMessage): AccountMeta[] => {
    const programAccountIndexes = getProgramAccountIndexes(message);

    // Program accounts are normally readonly, but must remain writable when the upgradeable loader may upgrade one.
    const hasUpgradeableLoader = message.staticAccounts.includes(LOADER_V3_PROGRAM_ADDRESS);

    return getAccountMetasFromCompiledTransactionMessage(message).map((account, index) => {
        const isDemotedProgram = programAccountIndexes.has(index) && !hasUpgradeableLoader;
        return {
            ...account,
            role: isDemotedProgram ? downgradeRoleToReadonly(account.role) : account.role,
        };
    });
};

const getProgramAccountIndexes = (message: V1CompiledTransactionMessage): Set<number> => {
    return new Set(message.instructionHeaders.map(instruction => instruction.programAccountIndex));
};
