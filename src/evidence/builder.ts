import { keccak256, toUtf8Bytes, recoverAddress, getBytes, hashMessage, ethers, verifyTypedData, TypedDataDomain, TypedDataField } from "ethers";
import { PolicyEvaluation, PaymentContext } from "../policy/rules.js";

export interface ERC8004AgentIdentity {
  chainId: number;
  tokenId: bigint;
}

/** Strict parser used by both evidence signing and on-chain verification. */
export function parseERC8004AgentId(agentId: unknown): ERC8004AgentIdentity {
  if (typeof agentId !== "string") {
    throw new Error("Invalid or missing agentId format (expected erc8004:chainId:tokenId)");
  }
  const match = /^erc8004:([1-9][0-9]*):(0|[1-9][0-9]*)$/.exec(agentId);
  if (!match) {
    throw new Error("Invalid or missing agentId format (expected erc8004:chainId:tokenId)");
  }
  const chainId = Number(match[1]);
  if (!Number.isSafeInteger(chainId) || chainId <= 0) {
    throw new Error("ERC-8004 agentId chainId must be a positive safe integer");
  }
  return { chainId, tokenId: BigInt(match[2]) };
}

/** EIP-712 domain is derived from the canonical ERC-8004 agent namespace. */
export function evidenceBundleDomain(agentId: unknown): TypedDataDomain {
  const { chainId } = parseERC8004AgentId(agentId);
  return {
    name: "Veridex Evidence Bundle",
    version: "1",
    chainId,
  };
}

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

    // Remove from visited after processing (allows shared references, only blocks true cycles)
    visited.delete(obj);

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

  // Remove from visited after processing (allows shared references, only blocks true cycles)
  visited.delete(obj);

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
  /** Immutable content URI bound by the EvidenceRegistry v3 authorization. */
  storageUrl?: string;
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
    const teeVerified = params.teeAttestation?.verified === true;
    if (process.env.NODE_ENV === "production" && params.teeAttestation && !teeVerified) {
      throw new Error("Refusing to label or emit production evidence with an unverified TEE attestation");
    }
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
        runtime: params.runtime || (teeVerified ? "verified-tee" : params.teeAttestation ? "unverified-attestation" : "node-runtime"),
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
    if (process.env.NODE_ENV === "production" || process.env.STRICT_MANDATE === "true") {
      return {
        valid: false,
        reason: "Production trust decisions require verifyBundleWithMandate(); verifyBundle() is integrity-only.",
      };
    }
    return EvidenceBuilder.verifyBundleIntegrity(bundle);
  }

  /** Cryptographic integrity primitive used internally by mandate-aware trust verification. */
  private static verifyBundleIntegrity(bundle: EvidenceBundle): { valid: boolean; recoveredAddress?: string; reason?: string } {
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
        evidenceBundleDomain(bundle.trace?.agentId),
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
    registryAddress: string,
    identity: {
      /** Official ERC-8004 Identity Registry for the agent namespace. */
      identityRegistryAddress: string;
      /** Optional additional pin for deployments that require a named owner. */
      expectedAgentOwner?: string;
    } | undefined = undefined,
  ): Promise<{ valid: boolean; recoveredAddress?: string; reason?: string; mandateVerified: boolean }> {
    // 1. First verify basic signature and integrity
    const basicVerification = EvidenceBuilder.verifyBundleIntegrity(bundle);
    if (!basicVerification.valid) {
      return { ...basicVerification, mandateVerified: false };
    }

    // 2. Parse agentId to get registry details
    let agentIdentity: ERC8004AgentIdentity;
    try {
      agentIdentity = parseERC8004AgentId(bundle.trace?.agentId);
    } catch (error: any) {
      return {
        valid: false,
        recoveredAddress: basicVerification.recoveredAddress,
        reason: error.message,
        mandateVerified: false,
      };
    }

    try {
      if (!identity?.identityRegistryAddress || !ethers.isAddress(identity.identityRegistryAddress)) {
        return {
          valid: false,
          recoveredAddress: basicVerification.recoveredAddress,
          reason: "A pinned ERC-8004 identityRegistryAddress is required for mandate verification",
          mandateVerified: false,
        };
      }
      if (!ethers.isAddress(registryAddress)) {
        return {
          valid: false,
          recoveredAddress: basicVerification.recoveredAddress,
          reason: "A valid evidence registry address is required for mandate verification",
          mandateVerified: false,
        };
      }
      const network = await provider.getNetwork();
      const connectedChainId = Number(network.chainId);
      if (connectedChainId !== agentIdentity.chainId) {
        return {
          valid: false,
          recoveredAddress: basicVerification.recoveredAddress,
          reason: `ERC-8004 chain mismatch: agentId declares ${agentIdentity.chainId}, provider is connected to ${connectedChainId}`,
          mandateVerified: false,
        };
      }

      // Query the immutable record created while the signer was authorized.
      // Looking only at the current allowlist would invalidate historical
      // evidence after a legitimate key rotation.
      const registryABI = [
        "function owner() view returns (address)",
        "function getEvidenceRecord(bytes32) view returns (tuple(string agentId, bytes32 bundleHash, address sessionSigner, uint256 timestamp, address anchorer, string storageUri, bool exists))",
      ];
      const registry = new ethers.Contract(registryAddress, registryABI, provider);
      const identityRegistry = new ethers.Contract(
        identity.identityRegistryAddress,
        ["function ownerOf(uint256 tokenId) view returns (address)"],
        provider,
      );
      const [agentOwner, evidenceRegistryOwner] = await Promise.all([
        identityRegistry.ownerOf(agentIdentity.tokenId),
        registry.owner(),
      ]);
      if (ethers.getAddress(agentOwner) !== ethers.getAddress(evidenceRegistryOwner)) {
        return {
          valid: false,
          recoveredAddress: basicVerification.recoveredAddress,
          reason: "Evidence registry governance is not controlled by the current ERC-8004 identity token owner",
          mandateVerified: false,
        };
      }
      if (identity.expectedAgentOwner &&
          ethers.getAddress(agentOwner) !== ethers.getAddress(identity.expectedAgentOwner)) {
        return {
          valid: false,
          recoveredAddress: basicVerification.recoveredAddress,
          reason: "ERC-8004 identity token owner does not match the pinned agent owner",
          mandateVerified: false,
        };
      }
      const recoveredSigner = basicVerification.recoveredAddress;
      if (!recoveredSigner) {
        return {
          valid: false,
          reason: "Evidence bundle has no recoverable session signer",
          mandateVerified: false,
        };
      }
      const bundleHash = bundle.bundleHash || bundle.traceHash;
      const record = await registry.getEvidenceRecord(bundleHash);
      if (!record?.exists || String(record.bundleHash).toLowerCase() !== bundleHash.toLowerCase()) {
        return {
          valid: false,
          recoveredAddress: recoveredSigner,
          reason: `Bundle ${bundleHash} has no immutable registry record`,
          mandateVerified: false,
        };
      }
      if (record.agentId !== bundle.trace.agentId ||
          ethers.getAddress(record.sessionSigner) !== ethers.getAddress(recoveredSigner)) {
        return {
          valid: false,
          recoveredAddress: recoveredSigner,
          reason: "Registry record does not bind this agent and recovered evidence signer",
          mandateVerified: false,
        };
      }
      if (!bundle.storageUrl || record.storageUri !== bundle.storageUrl) {
        return {
          valid: false,
          recoveredAddress: recoveredSigner,
          reason: "Registry record does not bind this evidence storage URI",
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
