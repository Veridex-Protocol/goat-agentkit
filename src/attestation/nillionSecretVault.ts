import { keccak256, toUtf8Bytes } from "ethers";
import { AttestationProvider, TEEAttestationReport, TEEProviderType } from "./types.js";

/**
 * Production Live Nillion Secret Vault & Nada MPC Attestation Driver
 *
 * Documentation Reference:
 * https://docs.nillion.com/secret-vault
 */
export class NillionSecretVaultAttestationProvider implements AttestationProvider {
  private vaultEndpoint: string;

  constructor(vaultEndpoint = "http://localhost:3000/api/nillion/attest") {
    this.vaultEndpoint = vaultEndpoint;
  }

  public getType(): TEEProviderType {
    return "nillion-secret-vault";
  }

  public async getAttestationReport(traceHash: string): Promise<TEEAttestationReport> {
    const boundHash = keccak256(toUtf8Bytes(traceHash));
    const timestamp = Date.now();

    try {
      const response = await fetch(this.vaultEndpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ traceHash: boundHash }),
      });

      if (response.ok) {
        const json: any = await response.json();
        if (process.env.NODE_ENV === "production") {
          throw new Error("[Nillion TEE Driver] MPC proof verification is not implemented; refusing production evidence.");
        }
        return {
          provider: "nillion-secret-vault",
          quote: json.mpcProof || json.quote || "NILLION_SECRET_VAULT_PROOF",
          measurement: json.clusterMeasurement || "0x9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e",
          boundHash,
          timestamp,
          verificationStatus: "unverified: vault proof and measurement were not verified",
          verified: false,
        };
      }
    } catch {
      // Nillion vault unavailable
    }

    if (process.env.NODE_ENV === "production") {
      throw new Error("[Nillion TEE Driver] vault proof unavailable or unverified in production.");
    }
    return {
      provider: "software",
      quote: "LIVE_NILLION_VAULT_UNAVAILABLE_LOCAL_ENV",
      measurement: "0x9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e",
      boundHash,
      timestamp,
      verificationStatus: "unverified: vault unavailable (software fallback)",
      verified: false,
    };
  }
}
