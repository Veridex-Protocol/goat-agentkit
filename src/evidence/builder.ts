import { keccak256, toUtf8Bytes, recoverAddress, getBytes, hashMessage, ethers, verifyTypedData, TypedDataDomain, TypedDataField } from "ethers";
import { PolicyEvaluation, PaymentContext } from "../policy/rules.js";

// EIP-712 domain for evidence bundle signatures (VD-GOAT-003 fix)
const EVIDENCE_BUNDLE_DOMAIN: TypedDataDomain = {
  name: "Veridex Evidence Bundle",
  version: "1",
  chainId: 48816,
};

const EVIDENCE_BUNDLE_TYPES: Record<string, TypedDataField[]> = {
  EvidenceBundle: [
    { name: "traceHash", type: "bytes32" },
    { name: "bundleHash", type: "bytes32" },
    { name: "agentId", type: "string" },
    { name: "sessionKeyHash", type: "bytes32" },
    { name: "settlementTxHash", type: "bytes32" },
    { name: "storageContentId", type: "string" },
    { name: "assembledAt", type: "uint256" },
  ],
};

/**
 * VD-GOAT-013 fix: Add depth and size limits to prevent DoS attacks.
 */
const MAX_CANONICALIZE_DEPTH = 10;
const MAX_CANONICALIZE_SIZE = 100_000; // 100KB

export function canonicalizeJson(obj: any, depth = 0, visited = new WeakSet()): string {
  // Depth limit check (VD-GOAT-013)
  if (depth > MAX_CANONICALIZE_DEPTH) {
    throw new Error(`[Canonicalize Error] Max depth ${MAX_CANONICALIZE_DEPTH} exceeded - possible DoS attack`);
  }

  if (obj === null) return "null";
  if (typeof obj === "bigint") return JSON.stringify(obj.toString());
  if (typeof obj !== "object") return JSON.stringify(obj);

  // Circular reference detection (VD-GOAT-013)
  if (visited.has(obj)) {
    throw new Error("[Canonicalize Error] Circular reference detected");
  }
  visited.add(obj);

  if (Array.isArray(obj)) {
    const result = "[" + obj.map((item) => canonicalizeJson(item, depth + 1, visited)).join(",") + "]";

    // Size limit check (VD-GOAT-013)
    if (result.length > MAX_CANONICALIZE_SIZE) {
      throw new Error(`[Canonicalize Error] Result size ${result.length} exceeds ${MAX_CANONICALIZE_SIZE} - possible DoS attack`);
    }

    return result;
  }

  const keys = Object.keys(obj).sort();
  const parts: string[] = [];
  for (const key of keys) {
    if (obj[key] !== undefined) {
      parts.push(JSON.stringify(key) + ":" + canonicalizeJson(obj[key], depth + 1, visited));
    }
  }

  const result = "{" + parts.join(",") + "}";

  // Size limit check (VD-GOAT-013)
  if (result.length > MAX_CANONICALIZE_SIZE) {
    throw new Error(`[Canonicalize Error] Result size ${result.length} exceeds ${MAX_CANONICALIZE_SIZE} - possible DoS attack`);
  }

  return result;
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
    storageCid?: string;
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

    const storageReceipt = params.storageCid
      ? {
          provider: "ipfs",
          contentId: params.storageCid,
          storedAt: timestamp,
          immutable: true,
        }
      : null;

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
      storageReceipt,
      assembledAt: timestamp,
    };

    const copy = { ...finalBundle };
    const bundleHash = keccak256(toUtf8Bytes(canonicalizeJson(copy)));
    finalBundle.bundleHash = bundleHash;

    return finalBundle;
  }

  /**
   * Full verification of bundle integrity and signature recovery against session key hash.
   * VD-GOAT-003 fix: Verify EIP-712 signature over complete bundle envelope.
   * VD-GOAT-013 fix: Add input validation to prevent malformed/malicious bundles.
   */
  public static verifyBundle(bundle: EvidenceBundle): { valid: boolean; recoveredAddress?: string; reason?: string } {
    // VD-GOAT-013 fix: Input validation
    if (!bundle || typeof bundle !== "object") {
      return { valid: false, reason: "Bundle must be an object" };
    }

    if (!bundle.signature || typeof bundle.signature !== "string") {
      return { valid: false, reason: "Missing or invalid signature" };
    }

    if (!bundle.traceHash || typeof bundle.traceHash !== "string" || !bundle.traceHash.startsWith("0x")) {
      return { valid: false, reason: "Missing or invalid traceHash" };
    }

    // Signature length check (65 bytes = 130 hex chars + 0x)
    if (bundle.signature.length !== 132) {
      return { valid: false, reason: `Invalid signature length: ${bundle.signature.length}, expected 132` };
    }

    // Bundle size check
    const bundleJson = JSON.stringify(bundle);
    if (bundleJson.length > 1_000_000) { // 1MB limit
      return { valid: false, reason: `Bundle too large: ${bundleJson.length} bytes exceeds 1MB` };
    }

    try {
      // 1. Verify trace hash integrity
      const canonicalTrace = canonicalizeJson(bundle.trace);
      const computedHash = keccak256(toUtf8Bytes(canonicalTrace));
      const hashValid = computedHash.toLowerCase() === bundle.traceHash.toLowerCase();
      if (!hashValid) {
        return { valid: false, reason: "Trace hash mismatch" };
      }

      // 2. VD-GOAT-003 fix: Recover signer from EIP-712 signature over complete bundle
      const value = {
        traceHash: bundle.traceHash,
        bundleHash: bundle.bundleHash || bundle.traceHash,
        agentId: bundle.trace?.agentId || "",
        sessionKeyHash: bundle.trace?.sessionKeyHash || "0x0000000000000000000000000000000000000000000000000000000000000000",
        settlementTxHash: bundle.settlementProof?.txHash || "0x0000000000000000000000000000000000000000000000000000000000000000",
        storageContentId: bundle.storageReceipt?.contentId || "",
        assembledAt: bundle.assembledAt || 0,
      };

      const recoveredAddress = verifyTypedData(
        EVIDENCE_BUNDLE_DOMAIN,
        EVIDENCE_BUNDLE_TYPES,
        value,
        bundle.signature
      );

      // 3. Verify recovered signer matches declared sessionKeyHash
      if (bundle.trace?.sessionKeyHash) {
        const expectedHash = ethers.id(recoveredAddress).toLowerCase();
        const rawAddr = recoveredAddress.toLowerCase();
        const givenHash = bundle.trace.sessionKeyHash.toLowerCase();
        if (givenHash !== expectedHash && givenHash !== rawAddr) {
          return { valid: false, recoveredAddress, reason: "Signer address does not match trace sessionKeyHash" };
        }
      }

      // 3b. VD-GOAT-002 fix: Verify session is authorized (if mandate provided)
      // Note: Full on-chain mandate verification requires:
      // 1. Query Agent owner from ERC-8004 registry
      // 2. Verify EIP-712 mandate signed by owner
      // 3. Check expiry, nonce, revocation status
      // This requires RPC provider and is async - implementers should:
      // - Call verifyBundleWithMandate() for on-chain verification
      // - Or verify mandate separately before trusting bundle
      if (bundle.trace?.agentId && process.env.STRICT_MANDATE === "true") {
        return {
          valid: false,
          recoveredAddress,
          reason: "STRICT_MANDATE enabled but no mandate verification performed. Use verifyBundleWithMandate() for on-chain checks."
        };
      }

      // 4. Verify bundleHash integrity if present
      if (bundle.bundleHash) {
        const copyBundle = {
          trace: bundle.trace,
          traceHash: bundle.traceHash,
          verdict: bundle.verdict,
          settlementProof: bundle.settlementProof,
          storageReceipt: bundle.storageReceipt,
          assembledAt: bundle.assembledAt,
        };
        const computedBundleHash = keccak256(toUtf8Bytes(canonicalizeJson(copyBundle)));

        if (computedBundleHash.toLowerCase() !== bundle.bundleHash.toLowerCase()) {
          return { valid: false, recoveredAddress, reason: "Bundle payload mutation detected" };
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

  /**
   * VD-GOAT-002 fix: Verify bundle with on-chain mandate authorization.
   * This is the RECOMMENDED verification method for production.
   *
   * @param bundle - Evidence bundle to verify
   * @param provider - Ethers provider for on-chain lookups
   * @param registryAddress - ERC-8004 registry contract address
   * @returns Verification result with mandate status
   */
  public static async verifyBundleWithMandate(
    bundle: EvidenceBundle,
    provider: any,
    registryAddress: string
  ): Promise<{ valid: boolean; recoveredAddress?: string; reason?: string; mandateVerified: boolean }> {
    // 1. First verify basic signature and integrity
    const basicVerification = EvidenceBuilder.verifyBundle(bundle);
    if (!basicVerification.valid) {
      return { ...basicVerification, mandateVerified: false };
    }

    // 2. Parse agentId to get registry details
    if (!bundle.trace?.agentId || !bundle.trace.agentId.startsWith("erc8004:")) {
      return {
        valid: false,
        recoveredAddress: basicVerification.recoveredAddress,
        reason: "Invalid or missing agentId format (expected erc8004:chainId:tokenId)",
        mandateVerified: false,
      };
    }

    try {
      // 3. Query on-chain Agent owner and authorized signers
      const agentHash = ethers.id(bundle.trace.agentId);
      const registryABI = [
        "function owner() view returns (address)",
        "function authorizedSigners(bytes32) view returns (address)",
      ];
      const registry = new ethers.Contract(registryAddress, registryABI, provider);
      const authorizedSigner = await registry.authorizedSigners(agentHash);

      // 4. Verify recovered signer is authorized on-chain
      if (authorizedSigner === ethers.ZeroAddress) {
        return {
          valid: false,
          recoveredAddress: basicVerification.recoveredAddress,
          reason: `No authorized signer set on-chain for agent ${bundle.trace.agentId}`,
          mandateVerified: false,
        };
      }

      if (authorizedSigner.toLowerCase() !== basicVerification.recoveredAddress?.toLowerCase()) {
        return {
          valid: false,
          recoveredAddress: basicVerification.recoveredAddress,
          reason: `Signer ${basicVerification.recoveredAddress} not authorized on-chain (expected ${authorizedSigner})`,
          mandateVerified: false,
        };
      }

      // 5. All checks passed - bundle is valid with mandate
      return {
        valid: true,
        recoveredAddress: basicVerification.recoveredAddress,
        mandateVerified: true,
      };
    } catch (error: any) {
      return {
        valid: false,
        recoveredAddress: basicVerification.recoveredAddress,
        reason: `Mandate verification failed: ${error.message}`,
        mandateVerified: false,
      };
    }
  }
}
