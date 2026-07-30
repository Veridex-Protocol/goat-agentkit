import { keccak256, toUtf8Bytes, recoverAddress, getBytes, hashMessage, ethers } from "ethers";
import { PolicyEvaluation, PaymentContext } from "../policy/rules.js";

export function canonicalizeJson(obj: any): string {
  if (obj === null) return "null";
  if (typeof obj === "bigint") return JSON.stringify(obj.toString());
  if (typeof obj !== "object") return JSON.stringify(obj);
  if (Array.isArray(obj)) {
    return "[" + obj.map((item) => canonicalizeJson(item)).join(",") + "]";
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
  } | null;
  assembledAt: number;
  bundleHash?: string;
}

export class EvidenceBuilder {
  private agentId: string;
  private sessionKeyHash: string;

  constructor(agentId: string, sessionKeyHash: string) {
    if (!sessionKeyHash || typeof sessionKeyHash !== "string" || sessionKeyHash.trim().length === 0) {
      throw new Error("[EvidenceBuilder] sessionKeyHash parameter is required and cannot be empty.");
    }
    this.agentId = agentId;
    this.sessionKeyHash = sessionKeyHash;
  }

  public buildDenial(params: {
    payload: any;
    evaluation: PolicyEvaluation;
    traceId?: string;
    runtime?: string;
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
        chain: params.payload.chain || 48816,
        protocol: "x402",
      },
      policyEvaluation: params.evaluation,
      environment: {
        runtime: params.runtime || (process.env.CLOUD_MODE === "true" ? "tee-attest-environment" : "node-runtime"),
      },
    };

    const canonicalTrace = canonicalizeJson(trace);
    const traceHash = keccak256(toUtf8Bytes(canonicalTrace));

    const finalBundle: EvidenceBundle = {
      trace,
      traceHash,
      verdict: params.evaluation,
      assembledAt: timestamp,
    };

    const copy = { ...finalBundle };
    const bundleHash = keccak256(toUtf8Bytes(canonicalizeJson(copy)));
    finalBundle.bundleHash = bundleHash;

    return finalBundle;
  }

  public buildSuccess(params: {
    payload: any;
    evaluation: PolicyEvaluation;
    settlementTxHash: string;
    teeAttestation?: any;
    traceId?: string;
    runtime?: string;
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
        chain: params.payload.chain || 48816,
        protocol: "x402",
      },
      policyEvaluation: params.evaluation,
      environment: {
        runtime: params.runtime || (params.teeAttestation ? "azure-sev-snp-tee" : "node-runtime"),
        teeAttestation: params.teeAttestation,
      },
    };

    const canonicalTrace = canonicalizeJson(trace);
    const traceHash = keccak256(toUtf8Bytes(canonicalTrace));

    const finalBundle: EvidenceBundle = {
      trace,
      traceHash,
      verdict: params.evaluation,
      settlementProof: {
        txHash: params.settlementTxHash,
        traceHashInCalldata: false,
        chain: params.payload.chain || 48816,
        explorerUrl: `https://explorer.testnet3.goat.network/tx/${params.settlementTxHash}`,
      },
      storageReceipt: null,
      assembledAt: timestamp,
    };

    const copy = { ...finalBundle };
    const bundleHash = keccak256(toUtf8Bytes(canonicalizeJson(copy)));
    finalBundle.bundleHash = bundleHash;

    return finalBundle;
  }

  /**
   * Verification helper checking trace hash consistency and cryptographic signature recovery.
   */
  public static verifyBundle(bundle: EvidenceBundle): { valid: boolean; recoveredAddress?: string; reason?: string } {
    if (!bundle || !bundle.signature || !bundle.traceHash) {
      return { valid: false, reason: "Missing signature or traceHash" };
    }

    try {
      const recoveredAddress = recoverAddress(hashMessage(getBytes(bundle.traceHash)), bundle.signature);
      const canonicalTrace = canonicalizeJson(bundle.trace);
      const computedHash = keccak256(toUtf8Bytes(canonicalTrace));

      const hashValid = computedHash.toLowerCase() === bundle.traceHash.toLowerCase();
      if (!hashValid) {
        return { valid: false, recoveredAddress, reason: "Trace hash mismatch" };
      }

      if (bundle.trace?.sessionKeyHash) {
        const expectedHash = ethers.id(recoveredAddress).toLowerCase();
        const rawAddr = recoveredAddress.toLowerCase();
        const givenHash = bundle.trace.sessionKeyHash.toLowerCase();
        if (givenHash !== expectedHash && givenHash !== rawAddr) {
          return { valid: false, recoveredAddress, reason: "Signer address does not match trace sessionKeyHash" };
        }
      }

      return {
        valid: true,
        recoveredAddress,
      };
    } catch (e: any) {
      return { valid: false, reason: e.message || "Verification exception" };
    }
  }
}
