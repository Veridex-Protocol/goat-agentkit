import { Wallet, getBytes } from "ethers";
import { EvidenceBundle } from "./builder.js";

export interface SessionSigner {
  getAddress(): Promise<string>;
  signBundle(bundle: EvidenceBundle): Promise<EvidenceBundle>;
}

export class LocalSessionSigner implements SessionSigner {
  private wallet: any;

  constructor(privateKey?: string) {
    if (privateKey && typeof privateKey === "string" && privateKey.trim().length > 0) {
      try {
        const formattedKey = privateKey.trim().startsWith("0x") ? privateKey.trim() : `0x${privateKey.trim()}`;
        this.wallet = new Wallet(formattedKey);
      } catch (err) {
        console.warn("[LocalSessionSigner] Invalid private key provided, creating ephemeral session key fallback.");
        this.wallet = Wallet.createRandom();
      }
    } else {
      this.wallet = Wallet.createRandom();
    }
  }

  public async getAddress(): Promise<string> {
    return this.wallet.address;
  }

  public async signBundle(bundle: EvidenceBundle): Promise<EvidenceBundle> {
    const signature = await this.wallet.signMessage(getBytes(bundle.traceHash));
    bundle.signature = signature;
    return bundle;
  }
}
