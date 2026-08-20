import { ethers, type Provider } from "ethers";
import type { NormalizedAction } from "../types/action.js";
import type { X402Challenge } from "./goatX402.js";

export interface VerifiedX402Settlement {
  txHash: string;
  status: 1;
  chain: number;
  blockNumber: number;
  blockHash: string;
  confirmations: number;
  payer: string;
  recipient: string;
  tokenAddress: string | null;
  amount: string;
  orderId: string;
  resource: string;
  verifiedAt: number;
}

export interface X402SettlementVerifier {
  verify(params: {
    txHash: string;
    action: NormalizedAction;
    challenge: X402Challenge;
  }): Promise<VerifiedX402Settlement>;
}

const ERC20_TRANSFER = new ethers.Interface([
  "function transfer(address to, uint256 value)",
  "event Transfer(address indexed from, address indexed to, uint256 value)",
]);

/**
 * Independently reconciles a mined transaction against the immutable action.
 * Adapter-returned status objects are never trusted as settlement proof.
 */
export class EvmRpcSettlementVerifier implements X402SettlementVerifier {
  constructor(
    private readonly provider: Provider,
    private readonly minConfirmations = 1,
  ) {
    if (!Number.isSafeInteger(minConfirmations) || minConfirmations < 1 || minConfirmations > 1_000) {
      throw new Error("minConfirmations must be an integer from 1 to 1000");
    }
  }

  public async verify(params: {
    txHash: string;
    action: NormalizedAction;
    challenge: X402Challenge;
  }): Promise<VerifiedX402Settlement> {
    const { txHash, action, challenge } = params;
    if (!/^0x[a-fA-F0-9]{64}$/.test(txHash)) throw new Error("Settlement transaction hash is malformed");

    const [network, receipt, transaction, latestBlock] = await Promise.all([
      this.provider.getNetwork(),
      this.provider.getTransactionReceipt(txHash),
      this.provider.getTransaction(txHash),
      this.provider.getBlockNumber(),
    ]);
    if (Number(network.chainId) !== action.chainId) throw new Error("Settlement provider is connected to the wrong chain");
    if (!receipt || !transaction) throw new Error("Settlement transaction is not available from the configured RPC provider");
    if (receipt.status !== 1) throw new Error("Settlement transaction reverted");
    if (receipt.hash.toLowerCase() !== txHash.toLowerCase() || transaction.hash.toLowerCase() !== txHash.toLowerCase()) {
      throw new Error("Settlement RPC returned inconsistent transaction identity");
    }
    const confirmations = Math.max(0, latestBlock - receipt.blockNumber + 1);
    if (confirmations < this.minConfirmations) {
      throw new Error(`Settlement has ${confirmations} confirmations; ${this.minConfirmations} required`);
    }
    if (ethers.getAddress(receipt.from) !== ethers.getAddress(action.from)) {
      throw new Error("Settlement payer does not match the normalized action");
    }
    if (ethers.getAddress(transaction.from) !== ethers.getAddress(receipt.from)) {
      throw new Error("Settlement transaction sender does not match the receipt payer");
    }

    const expected = TransactionShape.from(action);
    if (!transaction.to || ethers.getAddress(transaction.to) !== ethers.getAddress(expected.to)) {
      throw new Error("Settlement destination does not match the normalized action");
    }
    if (transaction.value !== expected.value) throw new Error("Settlement native value does not match the normalized action");
    const actualData = transaction.data && transaction.data !== "0x" ? transaction.data.toLowerCase() : "0x";
    if (actualData !== expected.data.toLowerCase()) throw new Error("Settlement calldata does not match the normalized action");

    if (action.assetType === "erc20") {
      const token = ethers.getAddress(action.tokenAddress!);
      const transferTopic = ERC20_TRANSFER.getEvent("Transfer")!.topicHash;
      const matchingTransfer = receipt.logs.some((log) => {
        if (ethers.getAddress(log.address) !== token || log.topics[0] !== transferTopic) return false;
        try {
          const parsed = ERC20_TRANSFER.parseLog({ topics: [...log.topics], data: log.data });
          return !!parsed &&
            ethers.getAddress(parsed.args[0]) === ethers.getAddress(action.from) &&
            ethers.getAddress(parsed.args[1]) === ethers.getAddress(action.to) &&
            BigInt(parsed.args[2]) === action.value;
        } catch {
          return false;
        }
      });
      if (!matchingTransfer) throw new Error("Settlement receipt has no exact ERC-20 Transfer event");
    }

    return {
      txHash: receipt.hash,
      status: 1,
      chain: action.chainId,
      blockNumber: receipt.blockNumber,
      blockHash: receipt.blockHash,
      confirmations,
      payer: ethers.getAddress(receipt.from),
      recipient: action.to,
      tokenAddress: action.tokenAddress,
      amount: action.value.toString(),
      orderId: challenge.orderId,
      resource: challenge.resource,
      verifiedAt: Date.now(),
    };
  }
}

class TransactionShape {
  public static from(action: NormalizedAction): { to: string; value: bigint; data: string } {
    if (action.assetType === "native") return { to: action.to, value: action.value, data: "0x" };
    if (!action.tokenAddress) throw new Error("ERC-20 settlement action has no token address");
    return {
      to: action.tokenAddress,
      value: 0n,
      data: ERC20_TRANSFER.encodeFunctionData("transfer", [action.to, action.value]),
    };
  }
}
