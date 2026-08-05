import { Wallet, getBytes, TypedDataDomain, TypedDataField } from "ethers";
import { EvidenceBundle } from "./builder.js";

export interface SessionSigner {
  getAddress(): Promise<string>;
  signBundle(bundle: EvidenceBundle): Promise<EvidenceBundle>;
}

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
    const value = {
      traceHash: bundle.traceHash,
      bundleHash: bundle.bundleHash || bundle.traceHash, // fallback for backward compat
      agentId: bundle.trace?.agentId || "",
      sessionKeyHash: bundle.trace?.sessionKeyHash || "0x0000000000000000000000000000000000000000000000000000000000000000",
      settlementTxHash: bundle.settlementProof?.txHash || "0x0000000000000000000000000000000000000000000000000000000000000000",
      storageContentId: bundle.storageReceipt?.contentId || "",
      assembledAt: bundle.assembledAt || Date.now(),
    };

    const signature = await this.wallet.signTypedData(
      EVIDENCE_BUNDLE_DOMAIN,
      EVIDENCE_BUNDLE_TYPES,
      value
    );

    bundle.signature = signature;
    return bundle;
  }
}
