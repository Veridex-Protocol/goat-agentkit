# `@veridex/goat-agentkit`

> **Verifiable Economic Policy Enforcement & ERC-8004 Validation Artifacts for GOAT Network AgentKit**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Network: GOAT Testnet3](https://img.shields.io/badge/Network-GOAT_Testnet3-cyan.svg)](https://explorer.testnet3.goat.network)
[![Standard: ERC-8004](https://img.shields.io/badge/Standard-ERC--8004-purple.svg)](https://eips.ethereum.org)

`@veridex/goat-agentkit` provides an in-path Economic Policy Enforcement Engine and ERC-8004 Evidence Verification layer for autonomous AI agents operating on GOAT Network.

---

## 🌟 Key Features

1. **🛡️ Pre-Signature Economic Policy Gate (< 1ms)**:
   - Enforces per-transaction limits, daily spending caps, velocity ceilings, allowed asset lists, and real-time counterparty denylists **before private keys touch transaction bytes** (`0% key touch` on policy rejection).

2. **📜 Signed ERC-8004 Evidence Bundles**:
   - Automatically emits cryptographically signed evidence bundles carrying the agent's `agentId`, policy decision, trace hash, Session Key signature, and optional TEE attestation quotes.

3. **🔗 On-Chain Proof Anchoring**:
   - Anchors evidence trace hashes directly to `EvidenceRegistry.sol` on GOAT Network Testnet3 (`0x40D9B16094808Fa48e73598E31AB964Cf15b475f`).

4. **⚡ Zero-Dependency Cryptographic Verifier**:
   - Proof verification requires zero Veridex SDK dependencies — verify any evidence bundle using native `ecrecover` in standard `ethers.js` or `viem`.

---

## 📦 Installation

```bash
npm install @veridex/goat-agentkit ethers
# or
bun add @veridex/goat-agentkit ethers
```

---

## 🚀 Quickstart

### 1. Initialize Policy Rules & Wrap GOAT AgentKit Wallet

```typescript
import { wrapWalletAdapter, VeridexPolicyGate } from "@veridex/goat-agentkit";

// Define Economic Mandate Rules
const policyRules = {
  spendingLimits: {
    maxPerTxUSD: 50,      // Max $50 USD per transaction
    maxDailyUSD: 500,     // Max $500 USD total daily velocity
  },
  velocityLimit: {
    maxTxPerHour: 60,     // Max 60 transactions/hour
  },
  sanctionedRecipients: [
    "0xBlockedAddress123...",
  ],
  allowedAssets: ["BTC", "USDC", "GOAT", "USDT"],
};

// Wrap your GOAT AgentKit Wallet Adapter
const veridexWallet = wrapWalletAdapter(goatWalletAdapter, {
  agentId: "erc8004:48816:1042",
  policyRules,
  teeAttestationEnabled: true,
  onBundleEmitted: (bundle) => {
    console.log("Signed Evidence Bundle Hash:", bundle.traceHash);
    console.log("On-Chain Explorer Link:", bundle.onChainExplorerUrl);
  },
});
```

---

## 🔐 Zero-Dependency Evidence Verification

Anyone can verify an ERC-8004 evidence bundle off-chain with 3 lines of standard `ethers.js`:

```typescript
import { ethers } from "ethers";

// 1. Re-hash trace payload
const traceHash = bundle.traceHash;

// 2. Recover Session Key signer address
const recoveredAddress = ethers.verifyMessage(
  ethers.getBytes(traceHash),
  bundle.signature
);

console.log("Verified Session Key Signer:", recoveredAddress);
```

---

## 🔗 On-Chain Contracts (GOAT Network Testnet3)

| Contract | Address | Explorer Link |
| :--- | :--- | :--- |
| **`EvidenceRegistry.sol`** | `0x40D9B16094808Fa48e73598E31AB964Cf15b475f` | [GOAT Testnet3 Explorer](https://explorer.testnet3.goat.network/address/0x40D9B16094808Fa48e73598E31AB964Cf15b475f) |

---

## 📄 License

MIT © [Veridex Protocol](https://github.com/Veridex-Protocol)
