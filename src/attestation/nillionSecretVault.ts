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
        const quote = json.mpcProof || json.quote;
        if (typeof quote !== "string" || quote.length === 0 || quote.length > 2 * 1024 * 1024) {
          throw new Error("[Nillion TEE Driver] vault response did not contain a bounded proof");
        }
        if (process.env.NODE_ENV === "production") {
          throw new Error("[Nillion TEE Driver] MPC proof verification is not implemented; refusing production evidence.");
        }
        const declaredMeasurement = json.clusterMeasurement;
        const measurement = typeof declaredMeasurement === "string" && /^0x[0-9a-fA-F]{64,128}$/.test(declaredMeasurement)
          ? declaredMeasurement
          : "0x0000000000000000000000000000000000000000000000000000000000000000";
        return {
          provider: "nillion-secret-vault",
          quote,
          measurement,
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
      measurement: "0x0000000000000000000000000000000000000000000000000000000000000000",
      boundHash,
      timestamp,
      verificationStatus: "unverified: vault unavailable (software fallback)",
      verified: false,
    };
  }
}
