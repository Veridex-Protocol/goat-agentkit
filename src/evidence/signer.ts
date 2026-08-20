import { Wallet, id, TypedDataDomain, TypedDataField, type Signer } from "ethers";
import { EvidenceBundle } from "./builder.js";

export interface SessionSigner {
  getAddress(): Promise<string>;
  signBundle(bundle: EvidenceBundle): Promise<EvidenceBundle>;
  signEvidenceAuthorization(params: EvidenceAuthorization): Promise<string>;
}

/** Adapts an HSM/KMS-backed ethers Signer without exporting key material. */
export class EthersSessionSigner implements SessionSigner {
  constructor(private readonly signer: Signer) {}

  public async getAddress(): Promise<string> {
    return this.signer.getAddress();
  }

  public async signBundle(bundle: EvidenceBundle): Promise<EvidenceBundle> {
    const value = evidenceBundleValue(bundle);
    bundle.signature = await this.signer.signTypedData(EVIDENCE_BUNDLE_DOMAIN, EVIDENCE_BUNDLE_TYPES, value);
    return bundle;
  }

  public async signEvidenceAuthorization(params: EvidenceAuthorization): Promise<string> {
    const expectedAddress = await this.getAddress();
    validateEvidenceAuthorization(params, expectedAddress);
    return this.signer.signTypedData(
      {
        name: "Veridex Evidence Registry",
        version: "2",
        chainId: params.chainId,
        verifyingContract: params.verifyingContract,
      },
      EVIDENCE_AUTHORIZATION_TYPES,
      evidenceAuthorizationValue(params),
    );
  }
}

/** EIP-712 delegation consumed by EvidenceRegistry v2 when a relayer anchors a bundle. */
export interface EvidenceAuthorization {
  agentId: string;
  bundleHash: string;
  sessionSigner: string;
  deadline: number;
  chainId: number;
  verifyingContract: string;
}

export const EVIDENCE_AUTHORIZATION_TYPES: Record<string, TypedDataField[]> = {
  EvidenceAuthorization: [
    { name: "agentHash", type: "bytes32" },
    { name: "bundleHash", type: "bytes32" },
    { name: "sessionSigner", type: "address" },
    { name: "deadline", type: "uint256" },
  ],
};

// EIP-712 domain for evidence bundle signatures (VD-GOAT-003 fix)
const EVIDENCE_BUNDLE_DOMAIN: TypedDataDomain = {
  name: "Veridex Evidence Bundle",
  version: "1",
  chainId: 48816, // GOAT Network Testnet3
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

export class LocalSessionSigner implements SessionSigner {
  private wallet: any;

  constructor(privateKey?: string) {
    // VD-GOAT-015 fix: Remove unsafe random wallet fallback
    if (!privateKey || typeof privateKey !== "string" || privateKey.trim().length === 0) {
      if (process.env.NODE_ENV === "production") {
        throw new Error(
          "[LocalSessionSigner] PRODUCTION ERROR: No private key provided. " +
          "Random wallet generation is disabled in production. " +
          "Provide a secure private key via environment variable or config."
        );
      }
      // Only allow random wallets in development/test
      console.warn(
        "[LocalSessionSigner] WARNING: Using random ephemeral wallet for development. " +
        "This will fail in production. Set a proper private key."
      );
      this.wallet = Wallet.createRandom();
      return;
    }

    try {
      const formattedKey = privateKey.trim().startsWith("0x") ? privateKey.trim() : `0x${privateKey.trim()}`;
      this.wallet = new Wallet(formattedKey);
    } catch (err: any) {
      throw new Error(`[LocalSessionSigner] Invalid private key provided: ${err.message}`);
    }
  }

  public async getAddress(): Promise<string> {
    return this.wallet.address;
  }

  public async signBundle(bundle: EvidenceBundle): Promise<EvidenceBundle> {
    // VD-GOAT-003 fix: Sign complete bundle envelope using EIP-712, not just traceHash
    const value = evidenceBundleValue(bundle);

    const signature = await this.wallet.signTypedData(
      EVIDENCE_BUNDLE_DOMAIN,
      EVIDENCE_BUNDLE_TYPES,
      value
    );

    bundle.signature = signature;
    return bundle;
  }

  public async signEvidenceAuthorization(params: EvidenceAuthorization): Promise<string> {
    const expectedAddress = await this.getAddress();
    validateEvidenceAuthorization(params, expectedAddress);
    return this.wallet.signTypedData(
      {
        name: "Veridex Evidence Registry",
        version: "2",
        chainId: params.chainId,
        verifyingContract: params.verifyingContract,
      },
      EVIDENCE_AUTHORIZATION_TYPES,
      evidenceAuthorizationValue(params),
    );
  }
}

function evidenceBundleValue(bundle: EvidenceBundle) {
  return {
    traceHash: bundle.traceHash,
    bundleHash: bundle.bundleHash || bundle.traceHash,
    agentId: bundle.trace?.agentId || "",
    sessionKeyHash: bundle.trace?.sessionKeyHash || "0x0000000000000000000000000000000000000000000000000000000000000000",
    settlementTxHash: bundle.settlementProof?.txHash || "0x0000000000000000000000000000000000000000000000000000000000000000",
    storageContentId: bundle.storageReceipt?.contentId || "",
    assembledAt: bundle.assembledAt || Date.now(),
  };
}

function validateEvidenceAuthorization(params: EvidenceAuthorization, expectedAddress: string): void {
  if (expectedAddress.toLowerCase() !== params.sessionSigner.toLowerCase()) {
    throw new Error("Evidence authorization must be signed by the declared session signer");
  }
  if (!/^0x[0-9a-fA-F]{64}$/.test(params.bundleHash)) {
    throw new Error("Evidence authorization bundleHash must be a bytes32 value");
  }
  if (!Number.isSafeInteger(params.deadline) || params.deadline <= Math.floor(Date.now() / 1000)) {
    throw new Error("Evidence authorization deadline must be a future Unix timestamp");
  }
}

function evidenceAuthorizationValue(params: EvidenceAuthorization) {
  return {
    agentHash: id(params.agentId),
    bundleHash: params.bundleHash,
    sessionSigner: params.sessionSigner,
    deadline: params.deadline,
  };
}
