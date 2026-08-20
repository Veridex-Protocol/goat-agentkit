import { describe, expect, it } from "vitest";
import { ethers } from "ethers";
import {
  EvmRpcSettlementVerifier,
  canonicalX402Challenge,
  type NormalizedAction,
  type X402Challenge,
} from "../src/index.js";

const payer = "0x1111111111111111111111111111111111111111";
const recipient = "0x2222222222222222222222222222222222222222";
const token = "0x3333333333333333333333333333333333333333";
const txHash = `0x${"a".repeat(64)}`;
const blockHash = `0x${"b".repeat(64)}`;
const transfer = new ethers.Interface([
  "function transfer(address to, uint256 value)",
  "event Transfer(address indexed from, address indexed to, uint256 value)",
]);

function action(assetType: "native" | "erc20"): NormalizedAction {
  return Object.freeze({
    actionId: ethers.id(`settlement-${assetType}`),
    chainId: 48816,
    from: payer,
    to: recipient,
    value: 2_500_000n,
    assetType,
    symbol: assetType === "native" ? "BTC" : "USDC",
    tokenAddress: assetType === "native" ? null : token,
    calldataSelector: assetType === "native" ? "0x00000000" : "0xa9059cbb",
    decimals: 6,
    priceUSD: 1,
    usdValue: 2.5,
    priceUSDMicros: 1_000_000n,
    usdMicros: 2_500_000n,
    priceUpdatedAt: Math.floor(Date.now() / 1000),
    priceSource: "test",
  });
}

function challenge(bound: NormalizedAction): X402Challenge {
  return {
    version: "2",
    status: 402,
    accepts: bound.symbol,
    amount: bound.value.toString(),
    amountUSD: bound.usdValue,
    payTo: bound.to,
    chain: bound.chainId,
    scheme: "exact",
    nonce: ethers.id("settlement-test-nonce"),
    validBefore: Math.floor(Date.now() / 1000) + 300,
    orderId: "ord_settlement_test",
    resource: "dataset:premium",
    merchantOrigin: "https://merchant.example.com",
    tokenAddress: bound.tokenAddress,
  };
}

function providerFor(bound: NormalizedAction, overrides: Record<string, unknown> = {}): any {
  const data = bound.assetType === "erc20"
    ? transfer.encodeFunctionData("transfer", [bound.to, bound.value])
    : "0x";
  const logs = bound.assetType === "erc20"
    ? [transfer.encodeEventLog(transfer.getEvent("Transfer")!, [bound.from, bound.to, bound.value])]
    : [];
  return {
    getNetwork: async () => ({ chainId: 48816n }),
    getBlockNumber: async () => 101,
    getTransactionReceipt: async () => ({
      hash: txHash,
      status: 1,
      from: bound.from,
      to: bound.assetType === "erc20" ? token : bound.to,
      blockNumber: 100,
      blockHash,
      logs: logs.map((log) => ({ address: token, topics: log.topics, data: log.data })),
      ...overrides.receipt as object,
    }),
    getTransaction: async () => ({
      hash: txHash,
      to: bound.assetType === "erc20" ? token : bound.to,
      value: bound.assetType === "erc20" ? 0n : bound.value,
      data,
      ...overrides.transaction as object,
    }),
    ...overrides.provider as object,
  };
}

describe("RPC-backed x402 settlement verification", () => {
  it("accepts an exact ERC-20 transfer transaction and Transfer event", async () => {
    const bound = action("erc20");
    const proof = await new EvmRpcSettlementVerifier(providerFor(bound), 2)
      .verify({ txHash, action: bound, challenge: challenge(bound) });
    expect(proof.status).toBe(1);
    expect(proof.amount).toBe("2500000");
    expect(proof.orderId).toBe("ord_settlement_test");
  });

  it("rejects calldata that differs from the policy-approved transfer", async () => {
    const bound = action("erc20");
    const wrongData = transfer.encodeFunctionData("transfer", [payer, bound.value]);
    await expect(new EvmRpcSettlementVerifier(providerFor(bound, {
      transaction: { data: wrongData },
    })).verify({ txHash, action: bound, challenge: challenge(bound) }))
      .rejects.toThrow("calldata");
  });

  it("rejects a receipt whose payer differs from the normalized action", async () => {
    const bound = action("native");
    await expect(new EvmRpcSettlementVerifier(providerFor(bound, {
      receipt: { from: recipient },
    })).verify({ txHash, action: bound, challenge: challenge(bound) }))
      .rejects.toThrow("payer");
  });

  it("merchant signatures bind the complete V2 order identity", async () => {
    const merchant = ethers.Wallet.createRandom();
    const bound = action("native");
    const signed = challenge(bound);
    signed.merchantPublicKey = merchant.address;
    signed.signature = await merchant.signMessage(canonicalX402Challenge(signed));
    const original = canonicalX402Challenge(signed);
    expect(canonicalX402Challenge({ ...signed, resource: "dataset:other" })).not.toBe(original);
    expect(canonicalX402Challenge({ ...signed, orderId: "ord_other_order" })).not.toBe(original);
  });
});
