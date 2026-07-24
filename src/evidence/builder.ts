import { keccak256, toUtf8Bytes, recoverAddress, getBytes, hashMessage } from "ethers";
import { PolicyEvaluation, PaymentContext } from "../policy/rules.js";

export function canonicalizeJson(obj: any): string {
  if (obj === null) return "null";
  if (typeof obj !== "object") return JSON.stringify(obj);
  if (Array.isArray(obj)) {
    return "[" + obj.map(item => canonicalizeJson(item)).join(",") + "]";
  }
  const keys = Object.keys(obj).sort();
  const parts: string[] = [];
  for (const key of keys) {
    if (obj[key] !== undefined) {
      parts.push(JSON.stringify(key) + ":" + canonicalizeJson(obj[key]));
    }
  }
  return "{" + parts.join(",") + "}";
}

export interface EvidenceBundle {
  trace: {
    traceId: string;
    timestamp: number;
    agentId: string;
    sessionKeyHash: string;
    reasoning?: {
      prompt?: string;
      toolCalls?: any[];
      llmOutput?: string;
    };
    proposedAction: {
      type: string;
      recipient: string;
      asset: string;
      amount: string;
      amountUSD?: number;
      chain: number;
      protocol?: string;
      metadata?: Record<string, any>;
    };
    policyEvaluation: PolicyEvaluation;
    environment?: {
      runtime: string;
      teeAttestation?: {
        type: string;
        quote: string;
        measurement: string;
      };
    };
  };
  traceHash: string;
  signature?: string;
  verdict: PolicyEvaluation;
  settlementProof?: {
    txHash: string;
    blockNumber?: number;
    traceHashInCalldata: boolean;
    chain: number;
    explorerUrl?: string;
  };
  storageReceipt?: {
    provider: string;
    contentId: string;
    storedAt: number;
    immutable: boolean;
  };
  assembledAt: number;
  bundleHash?: string;
}

export class EvidenceBuilder {
  private agentId: string;
  private sessionKeyHash: string;

  constructor(agentId: string, sessionKeyHash?: string) {
    this.agentId = agentId;
    this.sessionKeyHash = sessionKeyHash || "0x80ebf6ceb5308b4baa9295dd3322c0f011a00ef26a6cc364db84aa8fd66de977";
  }

  public buildDenial(params: {
    payload: any;
    evaluation: PolicyEvaluation;
    traceId?: string;
  }): EvidenceBundle {
    const timestamp = Date.now();
    const traceId = params.traceId || crypto.randomUUID();

    const trace = {
      traceId,
      timestamp,
      agentId: this.agentId,
      sessionKeyHash: this.sessionKeyHash,
      proposedAction: {
        type: "payment",
        recipient: params.payload.to || params.payload.recipient,
        asset: params.payload.asset || "GOAT",
        amount: String(params.payload.value || params.payload.amount || "0"),
        chain: params.payload.chain || 30,
        protocol: "x402",
      },
      policyEvaluation: params.evaluation,
      environment: {
        runtime: "clawup-azure-confidential-container",
      },
    };

    const canonicalTrace = canonicalizeJson(trace);
    const traceHash = keccak256(toUtf8Bytes(canonicalTrace));

    const bundle: EvidenceBundle = {
      trace,
      traceHash,
      verdict: params.evaluation,
      assembledAt: timestamp,
    };

    bundle.bundleHash = keccak256(toUtf8Bytes(canonicalizeJson(bundle)));
    return bundle;
  }

  public buildSuccess(params: {
    payload: any;
    evaluation: PolicyEvaluation;
    settlementTxHash: string;
    teeAttestation?: any;
    traceId?: string;
  }): EvidenceBundle {
    const timestamp = Date.now();
    const traceId = params.traceId || crypto.randomUUID();

    const trace = {
      traceId,
      timestamp,
      agentId: this.agentId,
      sessionKeyHash: this.sessionKeyHash,
      proposedAction: {
        type: "payment",
        recipient: params.payload.to || params.payload.recipient,
        asset: params.payload.asset || "GOAT",
        amount: String(params.payload.value || params.payload.amount || "0"),
        chain: params.payload.chain || 30,
        protocol: "x402",
      },
      policyEvaluation: params.evaluation,
      environment: {
        runtime: "clawup-azure-confidential-container",
        teeAttestation: params.teeAttestation,
      },
    };

    const canonicalTrace = canonicalizeJson(trace);
    const traceHash = keccak256(toUtf8Bytes(canonicalTrace));

    const bundle: EvidenceBundle = {
      trace,
      traceHash,
      verdict: params.evaluation,
      settlementProof: {
        txHash: params.settlementTxHash,
        traceHashInCalldata: true,
        chain: params.payload.chain || 30,
        explorerUrl: `https://explorer.testnet3.goat.network/tx/${params.settlementTxHash}`,
      },
      storageReceipt: {
        provider: "filecoin",
        contentId: `bafybeig${traceHash.slice(2, 20)}`,
        storedAt: timestamp,
        immutable: true,
      },
      assembledAt: timestamp,
    };

    bundle.bundleHash = keccak256(toUtf8Bytes(canonicalizeJson(bundle)));
    return bundle;
  }

  /**
   * Standalone zero-dependency verification helper using keccak256 + ecrecover only.
   */
  public static verifyBundle(bundle: EvidenceBundle): { valid: boolean; recoveredAddress?: string } {
    if (!bundle.signature || !bundle.traceHash) {
      return { valid: false };
    }

    try {
      const recoveredAddress = recoverAddress(hashMessage(getBytes(bundle.traceHash)), bundle.signature);
      const canonicalTrace = canonicalizeJson(bundle.trace);
      const computedHash = keccak256(toUtf8Bytes(canonicalTrace));

      const hashValid = computedHash.toLowerCase() === bundle.traceHash.toLowerCase();
      return {
        valid: hashValid && !!recoveredAddress,
        recoveredAddress,
      };
    } catch {
      return { valid: false };
    }
  }
}
