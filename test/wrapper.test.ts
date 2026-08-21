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
  WalletBroadcastUncertainError,
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

  it("retains a durable reservation when a broadcast hash cannot be independently verified", async () => {
    const uncertainHandler = vi.fn().mockResolvedValue(undefined);
    let policyState: any;
    const stateProvider = {
      loadState: () => policyState,
      saveState: (next: any) => { policyState = structuredClone(next); },
    };
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
    const wrapped = wrapWalletAdapter(mockUnderlyingWallet, {
      agentId: "erc8004:30:1042",
      policyRules,
      policyStateProvider: stateProvider,
      transactionVerifier: async () => { throw new Error("independent RPC unavailable"); },
      onTransactionUncertain: uncertainHandler,
    });
    const request = {
      ...TransactionDecoder.buildExecutionRequest(normalizedAction),
      _normalizedAction: normalizedAction,
    };

    await expect(wrapped.sendTransaction(request)).rejects.toBeInstanceOf(WalletBroadcastUncertainError);
    expect(uncertainHandler).toHaveBeenCalledWith(expect.objectContaining({
      txHash: "0x5d8e2c1a9f4b7306e2a5c1d9b3f80547a6e9c2b1d3f4a80c5e7b1d9a3f60528e",
      action: normalizedAction,
    }));
    await expect(wrapped.sendTransaction(request)).rejects.toThrow("DUPLICATE_ACTION");
  });

  it("retains the reservation when a wallet may have broadcast before throwing without a hash", async () => {
    const uncertainHandler = vi.fn().mockResolvedValue(undefined);
    const chainId = 31;
    const underlyingWallet = {
      getChainId: vi.fn().mockResolvedValue(chainId),
      sendTransaction: vi.fn().mockRejectedValue(new Error("RPC connection closed after submission")),
    };
    let policyState: any;
    const policyStateProvider = {
      loadState: () => policyState,
      saveState: (next: any) => { policyState = structuredClone(next); },
    };
    registerAsset(chainId, {
      symbol: "USDC", decimals: 6, native: false,
      tokenAddress: "0x7777777777777777777777777777777777777777",
      priceUSD: 1, priceUSDMicros: 1_000_000n,
      priceUpdatedAt: Math.floor(Date.now() / 1000), priceSource: "test:fixed", maxPriceAgeSeconds: 300,
    });
    const wrapped = wrapWalletAdapter(underlyingWallet, {
      agentId: "erc8004:31:1042",
      policyRules,
      sessionSigner: new LocalSessionSigner("0x" + "9".repeat(64)),
      policyStateProvider,
      onTransactionUncertain: uncertainHandler,
    });
    const action = TransactionDecoder.decodeAndNormalize({
      from: "0x8888888888888888888888888888888888888888",
      to: "0x6666666666666666666666666666666666666666",
      humanAmount: "1",
      asset: "USDC",
      chainId,
      operationId: "0x" + "e".repeat(64),
    });
    const request = { ...TransactionDecoder.buildExecutionRequest(action), _normalizedAction: action };

    await expect(wrapped.sendTransaction(request)).rejects.toBeInstanceOf(WalletBroadcastUncertainError);
    expect(uncertainHandler).toHaveBeenCalledWith(expect.objectContaining({
      txHash: undefined,
      action,
    }));
    await expect(wrapped.sendTransaction(request)).rejects.toThrow("DUPLICATE_ACTION");
  });
});
