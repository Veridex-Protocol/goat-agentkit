# `@veridex/goat-agentkit`

Security and evidence controls for GOAT Network AgentKit: exact transaction normalization, atomic economic policy, authenticated x402 challenges, RPC-backed settlement verification, KMS session signing, and ERC-8004 evidence.

## Production invariants

- A value-bearing operation must carry one immutable `NormalizedAction`. Caller-provided USD values, token labels, calldata semantics, or browser signatures are never authorization inputs.
- Production policy reservations, spend accounting, replay nonces, and session revocation require transactional shared providers.
- x402 success requires a complete merchant-signed, payer-bound V2 challenge, an exact EIP-712 payer authorization, and an RPC-verified mined transaction matching payer, chain, recipient/token contract, raw amount, calldata or native value, ERC-20 transfer log, and confirmation depth.
- Direct wallet-wrapper success evidence requires an independent `transactionVerifier` in production.
- EvidenceRegistry v3 separates evidence signers from gas-paying anchorers and binds the exact immutable storage URI in its EIP-712 authorization.
- Exportable session/relayer keys, unverified TEE claims, stale prices, unsigned metadata, and silent state resets fail closed in production.

## Install

```bash
npm install @veridex/goat-agentkit ethers
```

## Normalize once, then enforce and execute the same action

```ts
import {
  TransactionDecoder,
  VeridexPolicyGate,
  assertExecutionMatchesNormalizedAction,
} from "@veridex/goat-agentkit";

const action = TransactionDecoder.decodeAndNormalize({
  chainId: 48816,
  from: payerAddress,
  to: merchantAddress,
  asset: "USDC",
  rawValue: "20000000",
});

const evaluation = await policyGate.evaluate(action);
if (evaluation.verdict !== "pass") throw new Error(evaluation.reasons.join(", "));

const request = TransactionDecoder.buildExecutionRequest(action);
assertExecutionMatchesNormalizedAction(action, request);
```

Register ERC-20 contracts and fresh trusted prices before decoding. The demo uses pinned on-chain oracle feeds and stores exact USD-micros values.

## Real x402 payer interception

```ts
import {
  EvmRpcSettlementVerifier,
  PostgresX402NonceStore,
  wrapX402PaymentActions,
} from "@veridex/goat-agentkit";

const secured = wrapX402PaymentActions(
  paymentActions,
  policyGate,
  kmsSessionSigner,
  agentId,
  persistEvidence,
  {
    allowedMerchants: new Set([merchantSigner.toLowerCase()]),
    allowedMerchantOrigins: new Set(["https://merchant.example"]),
    nonceStore: new PostgresX402NonceStore(databaseUrl, agentId),
    settlementVerifier: new EvmRpcSettlementVerifier(rpcProvider, 2),
    sessionExpiresAt,
    sessionRevocationProvider,
    sessionAuthorizationVerifier,
    approvalVerifier,
    settlementNotifier,
  },
);
```

The wrapped spending action must broadcast the transaction derived from `_normalizedAction`. It must never recompute an amount from USD or return a synthetic hash.

## Evidence verification

Use `EvidenceBuilder.verifyBundle()` for cryptographic integrity only. For production authorization use `EvidenceBuilder.verifyBundleWithMandate(bundle, provider, registryAddress)`, which requires an immutable v3 registry record binding the recovered signer, agent, bundle hash, and storage URI.

## Deployment

Deploy [`contracts/EvidenceRegistry.sol`](./contracts/EvidenceRegistry.sol), transfer ownership to reviewed governance with the two-step handoff, configure distinct evidence-signer and anchorer roles, and pin the runtime bytecode hash, owner, chain, and v3 domain at service startup.

See `examples/goat-demo` for the end-to-end GOAT `ActionProvider`/`ExecutionRuntime`, all five documented AI framework adapters, KMS-backed session rotation, dual approval, real merchant settlement, immutable evidence storage, and hardened deployment topology.

## Verification

```bash
npm ci --workspaces=false
npm run lint
npm test
npm run build
```

MIT © Veridex Protocol
