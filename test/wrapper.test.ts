import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  wrapWalletAdapter,
  createGoatAgentSession,
  rotateSessionKey,
  VeridexPolicyGate,
  EvidenceBuilder,
  LocalSessionSigner,
  TransactionDecoder,
  registerAsset,
} from "../src/index.js";
import * as fs from "fs";
import { ethers } from "ethers";

describe("@veridex/goat-agentkit", () => {
  const policyRules = {
    spendingLimits: {
      maxPerTxUSD: 50,
      maxDailyUSD: 500,
    },
    velocityLimit: {
      maxTxPerHour: 10,
    },
    sanctionedRecipients: ["0x9999999999999999999999999999999999999999"],
    allowedAssets: ["USDC", "GOAT"],
  };

  const mockUnderlyingWallet = {
    getChainId: () => 30,
    sendTransaction: vi.fn().mockResolvedValue({ hash: "0x5d8e2c1a9f4b7306e2a5c1d9b3f80547a6e9c2b1d3f4a80c5e7b1d9a3f60528e" }),
    signTransaction: vi.fn().mockResolvedValue("0xrawsignature"),
  };

  beforeEach(() => {
    try {
      if (fs.existsSync("veridex-policy-state.json")) {
        fs.unlinkSync("veridex-policy-state.json");
      }
    } catch {}
    vi.clearAllMocks();
  });

  it("should create a new session and handle dynamic session key rotation seamlessly", async () => {
    const session1 = await createGoatAgentSession({
      agentId: "erc8004:30:1042",
      durationSeconds: 3600,
      policyRules,
    });

    expect(session1.sessionAddress).toBeDefined();
    expect(session1.expiresAt).toBeGreaterThan(Date.now());

    let emittedBundle: any = null;
    const wrappedWallet = wrapWalletAdapter(mockUnderlyingWallet, {
      agentId: session1.agentId,
      policyRules: session1.policyRules,
      sessionSigner: session1.sessionSigner,
      onBundleEmitted: (bundle) => {
        emittedBundle = bundle;
      },
    });

    const token = "0x3333333333333333333333333333333333333333";
    registerAsset(30, {
      symbol: "USDC", decimals: 6, native: false, tokenAddress: token,
      priceUSD: 1, priceUSDMicros: 1_000_000n,
      priceUpdatedAt: Math.floor(Date.now() / 1000), priceSource: "test:fixed", maxPriceAgeSeconds: 300,
    });
    const normalizedAction = TransactionDecoder.decodeAndNormalize({
      chainId: 30,
      from: "0x2222222222222222222222222222222222222222",
      to: "0x1111111111111111111111111111111111111111",
      humanAmount: "2.5",
      asset: "USDC",
    });
    const firstExecution = TransactionDecoder.buildExecutionRequest(normalizedAction);

    await wrappedWallet.sendTransaction({
      ...firstExecution,
      _normalizedAction: normalizedAction,
    });

    expect(EvidenceBuilder.verifyBundle(emittedBundle).recoveredAddress).toBe(session1.sessionAddress);

    // Rotate to Session Key #2 upon expiry
    const session2 = await createGoatAgentSession({
      agentId: "erc8004:30:1042",
      durationSeconds: 3600,
      policyRules,
    });

    rotateSessionKey(wrappedWallet, session2);

    const secondAction = TransactionDecoder.decodeAndNormalize({
      chainId: 30,
      from: normalizedAction.from,
      to: "0x4444444444444444444444444444444444444444",
      humanAmount: "2.5",
      asset: "USDC",
    });
    await wrappedWallet.sendTransaction({
      ...TransactionDecoder.buildExecutionRequest(secondAction),
      _normalizedAction: secondAction,
    });


    // Evidence Bundle now signed by Session Key #2!
    expect(EvidenceBuilder.verifyBundle(emittedBundle).recoveredAddress).toBe(session2.sessionAddress);
    expect(session2.sessionAddress).not.toBe(session1.sessionAddress);
  });
});
