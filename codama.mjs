import {
    argumentValueNode,
    assertIsNode,
    instructionAccountDisplayNode,
    instructionRemainingAccountsNode,
    resolverValueNode,
} from 'codama';

const executeRemainingAccounts = instructionRemainingAccountsNode(
    resolverValueNode('resolveMessageAccounts', {
        dependsOn: [argumentValueNode('message')],
        docs: "Preserves each execution message account's signer and writable role.",
    }),
    {
        display: instructionAccountDisplayNode({ label: 'Execution message accounts' }),
        docs: "One account for each key in the execution message's static account-key list, in the same order.",
        isOptional: false,
        isSigner: 'either',
    },
);

const submitRemainingAccounts = instructionRemainingAccountsNode(
    resolverValueNode('resolveSubmitMessageAccounts', {
        dependsOn: [argumentValueNode('message')],
        docs: "Preserves each authorization message account's writable role without marking it as a relay transaction signer.",
    }),
    {
        display: instructionAccountDisplayNode({
            label: 'Authorization message accounts',
        }),
        docs: "One account for each key in the authorization message's static account-key list, in the same order.",
        isOptional: false,
        isSigner: false,
    },
);

const addRemainingAccounts = remainingAccounts => node => {
    assertIsNode(node, 'instructionNode');
    return { ...node, remainingAccounts: [remainingAccounts] };
};

export default {
    idl: 'target/codama-idl/signer-interface.json',
    additionalIdls: [
        'target/codama-idl/executor-interface.json',
        'target/codama-idl/nonce-interface.json',
    ],
    before: [
        {
            from: 'codama#bottomUpTransformerVisitor',
            args: [
                [
                    {
                        select: '[programNode]messageExecutor.[instructionNode]execute',
                        transform: addRemainingAccounts(executeRemainingAccounts),
                    },
                    {
                        select: '[programNode]ed25519Signer.[instructionNode]submit',
                        transform: addRemainingAccounts(submitRemainingAccounts),
                    },
                ],
            ],
        },
    ],
    scripts: {
        idl: { from: '@codama/renderers-core#writeIdlVisitor', args: ['idl.json'] },
        js: {
            from: '@codama/renderers-js',
            args: [
                'clients/js',
                {
                    kitImportStrategy: 'rootOnly',
                    syncPackageJson: true,
                    prettierOptions: {
                        arrowParens: 'avoid',
                        printWidth: 120,
                        singleQuote: true,
                        tabWidth: 4,
                        trailingComma: 'all',
                    },
                },
            ],
        },
    },
};
