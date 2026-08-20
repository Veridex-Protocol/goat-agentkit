import { keccak256, toUtf8Bytes } from "ethers";
import { AttestationProvider, TEEAttestationReport, TEEProviderType } from "./types.js";

/**
 * Production Live Phala Network dstack TEE Attestation Driver (Intel SGX / TDX)
 *
 * Documentation Reference:
 * https://docs.phala.network/developers/dstack-sdk
 * Local dstack sidecar endpoint: http://127.0.0.1:8090/attestation/quote
 */
export class PhalaDstackAttestationProvider implements AttestationProvider {
  private dstackEndpoint: string;

  constructor(dstackEndpoint = "http://127.0.0.1:8090/attestation/quote") {
    this.dstackEndpoint = dstackEndpoint;
  }

  public getType(): TEEProviderType {
    return "phala-dstack";
  }

  /**
   * Queries live Phala dstack sidecar service to generate Intel SGX / TDX hardware quote.
   */
  public async getAttestationReport(traceHash: string): Promise<TEEAttestationReport> {
    const boundHash = keccak256(toUtf8Bytes(traceHash));
    const timestamp = Date.now();

    try {
      const response = await fetch(this.dstackEndpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ customData: boundHash }),
      });

      if (response.ok) {
        const json: any = await response.json();
        const quote = json.quote || json.attestation || json.token;
        if (typeof quote !== "string" || quote.length === 0 || quote.length > 2 * 1024 * 1024) {
          throw new Error("[Phala TEE Driver] dstack response did not contain a bounded quote");
        }
        if (process.env.NODE_ENV === "production") {
          throw new Error("[Phala TEE Driver] Quote verification is not implemented; refusing production evidence.");
        }
        const declaredMeasurement = json.mrEnclave || json.measurement;
        const measurement = typeof declaredMeasurement === "string" && /^0x[0-9a-fA-F]{64,128}$/.test(declaredMeasurement)
          ? declaredMeasurement
          : "0x0000000000000000000000000000000000000000000000000000000000000000";
        return {
          provider: "phala-dstack",
          quote,
          measurement,
          boundHash,
          timestamp,
          verificationStatus: "unverified: dstack quote signature and measurement were not verified",
          verified: false,
        };
      }
    } catch {
      // dstack unavailable
    }

    if (process.env.NODE_ENV === "production") {
      throw new Error("[Phala TEE Driver] dstack quote unavailable or unverified in production.");
    }
    return {
      provider: "software",
      quote: "LIVE_PHALA_DSTACK_UNAVAILABLE_LOCAL_ENV",
      measurement: "0x0000000000000000000000000000000000000000000000000000000000000000",
      boundHash,
      timestamp,
      verificationStatus: "unverified: dstack unavailable (software fallback)",
      verified: false,
    };
  }
}
