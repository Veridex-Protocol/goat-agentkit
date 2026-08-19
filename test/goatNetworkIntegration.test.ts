import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  GOAT_ERC8004_ADDRESSES,
  buildERC8004RegistrationJSON,
  parseX402Challenge,
  VeridexGoatX402Payer,
  EvidenceBuilder,
  GoatERC8004Client,
  VeridexPolicyGate,
  InMemoryX402NonceStore,
} from "../src/index.js";
import { ethers } from "ethers";
import * as fs from "fs";

describe("GOAT Network ERC-8004 & x402 Integration Spec", () => {
  beforeEach(() => {
    try {
      if (fs.existsSync("veridex-policy-state.json")) {
        fs.unlinkSync("veridex-policy-state.json");
      }
    } catch {}
    vi.clearAllMocks();
  });

  it("should provide canonical GOAT Network ERC-8004 contract addresses", () => {
    expect(GOAT_ERC8004_ADDRESSES.mainnet.identityRegistry).toBe("0x8004A169FB4a3325136EB29fA0ceB6D2e539a432");
    expect(GOAT_ERC8004_ADDRESSES.mainnet.reputationRegistry).toBe("0x8004BAa17C55a88189AE136b182e5fdA19dE9b63");
    // validationRegistry is now read from env (GOAT_MAINNET_VALIDATION_REGISTRY) — no hardcoded address
    expect(typeof GOAT_ERC8004_ADDRESSES.mainnet.validationRegistry).toBe("string");
    expect(GOAT_ERC8004_ADDRESSES.mainnet.agentRegistryId).toBe("eip155:2345:0x8004A169FB4a3325136EB29fA0ceB6D2e539a432");

    expect(GOAT_ERC8004_ADDRESSES.testnet3.identityRegistry).toBe("0x556089008Fc0a60cD09390Eca93477ca254A5522");
    expect(GOAT_ERC8004_ADDRESSES.testnet3.reputationRegistry).toBe("0xd9140951d8aE6E5F625a02F5908535e16e3af964");
    // validationRegistry is now read from env (GOAT_TESTNET_VALIDATION_REGISTRY) — no hardcoded address
    expect(typeof GOAT_ERC8004_ADDRESSES.testnet3.validationRegistry).toBe("string");
    expect(GOAT_ERC8004_ADDRESSES.testnet3.agentRegistryId).toBe("eip155:48816:0x556089008Fc0a60cD09390Eca93477ca254A5522");
  });

  it("should support Time-Locks and Circuit Breaker logic in VeridexPolicyGate", async () => {
    const policyRules = {
      spendingLimits: { maxPerTxUSD: 10, maxDailyUSD: 100 },
      timeLock: { cooldownMs: 500 },
      circuitBreaker: { tripOnHighRiskScore: 90 },
    };

    const gate = new VeridexPolicyGate(policyRules);

    // Initial evaluation should pass and set lastTxTimestamp
    const res1 = await gate.evaluate({
      recipient: "0x1111111111111111111111111111111111111111",
      amount: 1,
      amountUSD: 1,
      asset: "USDC",
      chain: 30,
    });
    expect(res1.verdict).toBe("pass");
    await gate.commit(1, res1.evaluatedAt);

    // Second evaluation immediately following should fail due to time-lock cooldown
    const res2 = await gate.evaluate({
      recipient: "0x1111111111111111111111111111111111111111",
      amount: 1,
      amountUSD: 1,
      asset: "USDC",
      chain: 30,
    });
    expect(res2.verdict).toBe("deny");
    expect(res2.reasons[0]).toContain("Cooldown");

    // Violating a rule that trips high risk should activate circuit breaker
    await gate.resetCircuitBreaker();
    const highRiskRes = await gate.evaluate({
      recipient: "0x1111111111111111111111111111111111111111",
      amount: 250, // exceeds max limit, causing high risk
      amountUSD: 250,
      asset: "USDC",
      chain: 30,
    });
    expect(highRiskRes.verdict).toBe("deny");
    await gate.commit(250, highRiskRes.evaluatedAt);

    // Subsequent normal transaction should now be blocked by tripped circuit breaker
    const resBlocked = await gate.evaluate({
      recipient: "0x1111111111111111111111111111111111111111",
      amount: 1,
      amountUSD: 1,
      asset: "USDC",
      chain: 30,
    });

    expect(resBlocked.verdict).toBe("deny");
    expect(resBlocked.reasons[0]).toContain("Circuit breaker is active");
  });

  it("should support mock-integration for GoatERC8004Client", async () => {
    const mockSigner = {
      provider: {},
      getAddress: async () => "0x1111111111111111111111111111111111111111",
    };

    const mockContractInstance = {
      register: vi.fn().mockResolvedValue({ wait: async () => ({ hash: "0xregHash" }) }),
      giveFeedback: vi.fn().mockResolvedValue({ wait: async () => ({ hash: "0xfeedHash" }) }),
      validationRequest: vi.fn().mockResolvedValue({ wait: async () => ({ hash: "0xreqHash" }) }),
      validationResponse: vi.fn().mockResolvedValue({ wait: async () => ({ hash: "0xrespHash" }) }),
    };

    const client = new GoatERC8004Client(mockSigner as any, "testnet3");
    (client as any).identityContract = mockContractInstance;
    (client as any).reputationContract = mockContractInstance;
    (client as any).validationContract = mockContractInstance;

    const reg = await client.registerAgent("ipfs://QmSomeURI");
    expect(reg.txHash).toBe("0xregHash");

    const feed = await client.submitFeedback({
      agentId: 1,
      value: 95,
      tag1: "starred",
    });
    expect(feed).toBe("0xfeedHash");

    const req = await client.submitValidationRequest({
      validatorAddress: "0x2222222222222222222222222222222222222222",
      agentId: 1,
      requestURI: "ipfs://QmRequest",
      requestHash: "0x0000000000000000000000000000000000000000000000000000000000000001",
    });
    expect(req).toBe("0xreqHash");

    const resp = await client.submitValidationResponse({
      requestHash: "0x0000000000000000000000000000000000000000000000000000000000000001",
      response: 100,
      responseURI: "ipfs://QmResponse",
      responseHash: "0x0000000000000000000000000000000000000000000000000000000000000002",
      tag: "hard-finality",
    });
    expect(resp).toBe("0xrespHash");

    vi.restoreAllMocks();
  });

  it("should build a valid ERC-8004 Agent Registration JSON document", () => {
    const registrationJson = buildERC8004RegistrationJSON({
      name: "GoatAgent",
      description: "Autonomous service agent on GOAT Network",
      agentId: 1,
      network: "mainnet",
      x402Endpoint: "https://agent.example/api/x402/orders",
      a2aEndpoint: "https://agent.example/.well-known/agent-card.json",
      mcpEndpoint: "https://mcp.agent.example/",
    });

    expect(registrationJson.type).toBe("https://eips.ethereum.org/EIPS/eip-8004#registration-v1");
    expect(registrationJson.x402Support).toBe(true);
    expect(registrationJson.registrations[0].agentRegistry).toBe("eip155:2345:0x8004A169FB4a3325136EB29fA0ceB6D2e539a432");
    expect(registrationJson.services.length).toBe(3);
  });

  it("should parse x402 payment challenges from merchant HTTP responses", () => {
    const mockHeaders = {};
    const mockResponseBody = {
      status: 402,
      accepts: "USDC",
      priceUSDC: "2500000",
      amountUSD: 2.5,
      payTo: "0x9a7c3f5b2e8d14a6c0f9e7b2d5a8f1c3b4d6e0a2",
      chain: 30,
      scheme: "authorization",
    };

    const challenge = parseX402Challenge(mockHeaders, mockResponseBody);
    expect(challenge.status).toBe(402);
    expect(challenge.payTo).toBe("0x9a7c3f5b2e8d14a6c0f9e7b2d5a8f1c3b4d6e0a2");
    expect(challenge.amountUSD).toBe(2.5);
  });

  it("should evaluate x402 payment in-path with policy gate and emit Evidence Bundle", async () => {
    const payer = new VeridexGoatX402Payer({
      agentId: "erc8004:30:1042",
      policyRules: {
        spendingLimits: { maxPerTxUSD: 50, maxDailyUSD: 500 },
        allowedAssets: ["USDC"],
      },
    });

    const mockWallet = {
      sendTransaction: async () => ({
        hash: "0x5d8e2c1a9f4b7306e2a5c1d9b3f80547a6e9c2b1d3f4a80c5e7b1d9a3f60528e",
        receipt: { status: 1, chain: 30 },
      }),
    };

    const merchant = ethers.Wallet.createRandom();
    const challenge: any = {
      status: 402,
      accepts: "USDC",
      amount: "2500000",
      amountUSD: 2.5,
      payTo: "0x9a7c3f5b2e8d14a6c0f9e7b2d5a8f1c3b4d6e0a2",
      chain: 30,
      scheme: "authorization" as const,
      nonce: "integration-nonce-1",
      validBefore: Math.floor(Date.now() / 1000) + 300,
      merchantPublicKey: merchant.address,
    };
    challenge.signature = await merchant.signMessage(JSON.stringify({
      accepts: challenge.accepts, amount: challenge.amount, amountUSD: challenge.amountUSD,
      payTo: challenge.payTo, chain: challenge.chain, scheme: challenge.scheme,
      nonce: challenge.nonce, validAfter: challenge.validAfter, validBefore: challenge.validBefore,
    }));
    const normalizedAction: any = Object.freeze({
      actionId: ethers.id("integration-bound-action"), chainId: 30,
      from: "0x1111111111111111111111111111111111111111", to: challenge.payTo,
      value: 2500000n, assetType: "erc20", symbol: "USDC",
      tokenAddress: "0x2222222222222222222222222222222222222222", calldataSelector: "0xa9059cbb",
      decimals: 6, priceUSD: 1, usdValue: 2.5,
    });

    const res = await payer.executeX402Payment(challenge, normalizedAction, mockWallet, {
      nonceStore: new InMemoryX402NonceStore(),
      allowedMerchants: new Set([merchant.address.toLowerCase()]),
    });
    expect(res.txHash).toBe("0x5d8e2c1a9f4b7306e2a5c1d9b3f80547a6e9c2b1d3f4a80c5e7b1d9a3f60528e");
    expect(res.evidenceBundle.verdict.verdict).toBe("pass");

    const verification = EvidenceBuilder.verifyBundle(res.evidenceBundle);
    expect(verification.valid).toBe(true);
  });
});
