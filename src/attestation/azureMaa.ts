import { keccak256, toUtf8Bytes } from "ethers";
import fs from "fs";
import { execSync } from "child_process";
import { createVerify, X509Certificate } from "crypto";
import { AttestationProvider, TEEAttestationReport, TEEProviderType } from "./types.js";

function decodeBase64Url(str: string): string {
  let base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4 !== 0) {
    base64 += "=";
  }
  return Buffer.from(base64, "base64").toString("utf-8");
}

/**
 * Production Live Azure Confidential Containers Attestation Driver
 */
export class AzureMaaAttestationProvider implements AttestationProvider {
  private imdsEndpoint: string;
  private devSevGuestPath: string;

  constructor(
    imdsEndpoint = "http://169.254.169.254/metadata/attestation/user-data?api-version=2021-01-01",
    devSevGuestPath = "/dev/sev-guest"
  ) {
    this.imdsEndpoint = imdsEndpoint;
    this.devSevGuestPath = devSevGuestPath;
  }

  public getType(): TEEProviderType {
    return "azure-maa/sev-snp";
  }

  /**
   * Generates a live hardware attestation report embedding traceHash as user_data.
   */
  public async getAttestationReport(traceHash: string): Promise<TEEAttestationReport> {
    const boundHash = keccak256(toUtf8Bytes(traceHash));
    const timestamp = Date.now();

    // Strategy 1: Live Azure IMDS Guest Attestation Endpoint
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 2000);

      const response = await fetch(this.imdsEndpoint, {
        method: "POST",
        headers: {
          Metadata: "true",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ userData: boundHash }),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (response.ok) {
        const json: any = await response.json();
        const jwtToken = json.quote || json.attestationToken || json.token;

        if (jwtToken) {
          const parsed = this.parseMaaJwt(jwtToken, boundHash);

          // VD-GOAT-007 fix: Check JWT verification status
          if (!parsed.verified && this.requiresVerifiedAttestation()) {
            throw new Error(`[Azure MAA] JWT verification failed: ${parsed.error}`);
          }

          return {
            provider: parsed.verified ? "azure-maa/sev-snp" : "azure-maa/sev-snp-unverified",
            quote: jwtToken,
            measurement: parsed.measurement || "0x2b8d4056a1f3e7c9b0d2854f6a9e1c3b7d05f28a4c6e1b9d3f705a2c8f3a1c7e9",
            boundHash,
            issuerCertChain: parsed.certChain,
            timestamp,
            verificationStatus: parsed.verified ? "verified" : `unverified: ${parsed.error}`,
            verified: parsed.verified,
          };
        }
      }
    } catch {
      // IMDS unavailable
    }

    // Strategy 2: Direct Linux Device Driver (/dev/sev-guest)
    try {
      if (fs.existsSync(this.devSevGuestPath)) {
        const output = execSync(`/usr/bin/azguestattest --user-data ${boundHash} --api-version 2021-01-01`, { stdio: "pipe" });
        const res = JSON.parse(output.toString("utf-8"));
        const hexQuote = res.quote || res.attestationToken || res.token || res.raw_quote;
        const measurement = res.measurement || "0x2b8d4056a1f3e7c9b0d2854f6a9e1c3b7d05f28a4c6e1b9d3f705a2c8f3a1c7e9";

        if (this.requiresVerifiedAttestation()) {
          throw new Error("[Azure MAA] Direct device quote has no configured remote verification path");
        }
        return {
          provider: "azure-maa/sev-snp",
          quote: hexQuote,
          measurement,
          boundHash,
          timestamp,
          verificationStatus: "unverified: local quote was not verified against Azure MAA trust roots",
          verified: false,
        };
      }
    } catch {
      // Hardware device unavailable
    }

    if (this.requiresVerifiedAttestation()) {
      throw new Error("[Azure TEE Driver] Production Environment Error: Hardware attestation failed or SEV-SNP device is unavailable.");
    }

    // Fallback if hardware TEE device is not present (software attestation mode)
    return {
      provider: "software",
      quote: "SOFTWARE_ATTESTATION_ONLY",
      measurement: "0x0000000000000000000000000000000000000000000000000000000000000000",
      boundHash,
      timestamp,
      verificationStatus: "unverified: software fallback",
      verified: false,
    };
  }

  private requiresVerifiedAttestation(): boolean {
    // A production runtime must never emit hardware-labelled evidence from a
    // merely parseable quote. Development can opt into the same posture.
    return process.env.NODE_ENV === "production" || process.env.STRICT_TEE === "true";
  }

  /**
   * Parses and verifies Microsoft Azure Attestation JWT token.
   * VD-GOAT-007 fix: Added signature, issuer, audience, expiry verification.
   */
  private parseMaaJwt(jwt: string, expectedBoundHash?: string): { measurement?: string; certChain?: string[]; verified: boolean; error?: string } {
    try {
      const parts = jwt.split(".");
      if (parts.length !== 3) {
        return { verified: false, error: "Invalid JWT format" };
      }

      const header = JSON.parse(decodeBase64Url(parts[0]));
      const payload = JSON.parse(decodeBase64Url(parts[1]));
      const signature = parts[2];
      const strict = this.requiresVerifiedAttestation();

      if (header.alg !== "RS256") {
        return { verified: false, error: `Unexpected JWT algorithm ${header.alg || "(missing)"}` };
      }

      // 1. Verify issuer (must be an Azure MAA endpoint with strict URL validation)
      if (!payload.iss) {
        return { verified: false, error: "Missing issuer (iss) claim" };
      }
      try {
        const issuerUrl = new URL(payload.iss);
        const trustedIssuers = process.env.AZURE_MAA_TRUSTED_ISSUERS;
        if (strict && !trustedIssuers) {
          return { verified: false, error: "AZURE_MAA_TRUSTED_ISSUERS is required when verified attestation is required" };
        }
        const allowlist = new Set((trustedIssuers || "").split(",").map((value) => value.trim()).filter(Boolean));
        if (issuerUrl.protocol !== "https:" || issuerUrl.origin !== payload.iss ||
            (allowlist.size > 0 && !allowlist.has(payload.iss))) {
          return { verified: false, error: `Untrusted or non-canonical issuer: ${payload.iss}` };
        }
      } catch {
        return { verified: false, error: `Invalid issuer URL: ${payload.iss}` };
      }

      // 2. Verify expiry
      const now = Math.floor(Date.now() / 1000);
      if (!Number.isSafeInteger(payload.exp)) {
        return { verified: false, error: "Missing or invalid expiry (exp) claim" };
      }
      if (payload.exp < now) {
        return { verified: false, error: `Token expired at ${payload.exp}, now ${now}` };
      }

      // 3. Verify not-before
      if (!Number.isSafeInteger(payload.nbf) || payload.nbf > now + 30) {
        return { verified: false, error: `Token not yet valid, nbf: ${payload.nbf}, now ${now}` };
      }
      if (!Number.isSafeInteger(payload.iat) || payload.iat > now + 30 || now - payload.iat > 300) {
        return { verified: false, error: "Missing, future, or stale issued-at (iat) claim" };
      }
      if (payload.exp - payload.iat > 600) {
        return { verified: false, error: "Attestation token lifetime exceeds 10 minutes" };
      }

      // 4. Extract measurement
      const measurement =
        payload["x-ms-sevsnpvm-launchmeasurement"] ||
        payload["x-ms-isolation-tee"]?.["launch-measurement"];

      // 4b. Verify audience (if configured)
      const expectedAudience = process.env.AZURE_MAA_AUDIENCE;
      if (strict && !expectedAudience) {
        return { verified: false, error: "AZURE_MAA_AUDIENCE is required when verified attestation is required" };
      }
      const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
      if (expectedAudience && !audiences.includes(expectedAudience)) {
        return { verified: false, error: `Audience mismatch: got ${payload.aud}, expected ${expectedAudience}` };
      }

      // 5. VD-GOAT-007 complete fix: Verify RS256 signature with x5c certificate chain
      let signatureVerified = false;
      let signatureError: string | undefined;

      if (header.x5c && header.x5c.length > 0) {
        try {
          const certificates = header.x5c.map((encoded: string) =>
            new X509Certificate(Buffer.from(encoded, "base64"))
          );
          const leaf = certificates[0];
          const tokenTime = Date.now();
          for (const certificate of certificates) {
            const validFrom = new Date(certificate.validFrom).getTime();
            const validTo = new Date(certificate.validTo).getTime();
            if (!Number.isFinite(validFrom) || !Number.isFinite(validTo) || tokenTime < validFrom || tokenTime > validTo) {
              throw new Error("x5c certificate is outside its validity interval");
            }
          }
          if (leaf.ca) throw new Error("x5c leaf certificate must not be a CA");

          // Construct signed data (JWT header + payload)
          const signedData = `${parts[0]}.${parts[1]}`;

          // Decode signature from base64url
          const signatureBytes = Buffer.from(signature.replace(/-/g, "+").replace(/_/g, "/"), "base64");

          // Verify RS256 signature against the leaf certificate
          const verifier = createVerify("RSA-SHA256");
          verifier.update(signedData);
          signatureVerified = verifier.verify(leaf.toString(), signatureBytes);

          if (!signatureVerified) {
            signatureError = "RS256 signature verification failed against x5c[0]";
          }

          // VRD-2026-006 fix: Validate certificate chain is rooted in Microsoft
          if (signatureVerified && certificates.length < 2) {
            signatureVerified = false;
            signatureError = "Certificate chain too short: x5c must include intermediate and root certificates from Microsoft";
          }

          if (signatureVerified && certificates.length >= 2) {
            for (let i = 0; i < certificates.length - 1; i++) {
              if (!certificates[i + 1].ca) {
                signatureVerified = false;
                signatureError = `x5c issuer certificate ${i + 1} is not a CA`;
                break;
              }
              if (!certificates[i].verify(certificates[i + 1].publicKey)) {
                signatureVerified = false;
                signatureError = `x5c certificate chain validation failed at certificate ${i}`;
                break;
              }
            }
            const root = certificates[certificates.length - 1];
            if (signatureVerified && !root.verify(root.publicKey)) {
              signatureVerified = false;
              signatureError = "x5c root certificate is not self-signed";
            }
            const configuredRoots = process.env.AZURE_MAA_TRUSTED_ROOT_FINGERPRINTS;
            if (signatureVerified && strict && !configuredRoots) {
              signatureVerified = false;
              signatureError = "AZURE_MAA_TRUSTED_ROOT_FINGERPRINTS is required when verified attestation is required";
            }
            if (signatureVerified && configuredRoots) {
              const trusted = new Set(configuredRoots.split(",").map((value) => value.replace(/:/g, "").trim().toUpperCase()));
              const rootFingerprint = certificates[certificates.length - 1].fingerprint256.replace(/:/g, "").toUpperCase();
              if (!trusted.has(rootFingerprint)) {
                signatureVerified = false;
                signatureError = "x5c chain terminates in a root not present in AZURE_MAA_TRUSTED_ROOT_FINGERPRINTS";
              }
            }
          }
        } catch (error: any) {
          signatureVerified = false;
          signatureError = `RS256 verification error: ${error.message}`;
        }
      } else {
        signatureError = "No x5c certificate chain in JWT header";
      }

      // 6. VRD-2026-006 fix: Bind runtime data / report data to the expected
      // boundHash. A hardware-backed token must carry the exact value we asked the
      // TEE to attest; otherwise the attestation is not bound to this trace.
      if (signatureVerified && expectedBoundHash) {
        const reportData: string | undefined =
          payload["x-ms-sevsnpvm-reportdata"] ||
          payload["x-ms-runtime"]?.["report-data"] ||
          payload["x-ms-runtime"]?.["user-data"] ||
          payload["nonce"] ||
          payload["runtime_data"]?.["user-data"];
        const norm = (s: string) => {
          const raw = String(s);
          if (/^(0x)?[a-fA-F0-9]+$/.test(raw)) return raw.toLowerCase().replace(/^0x/, "");
          try { return Buffer.from(raw, "base64url").toString("hex").toLowerCase(); } catch { return raw.toLowerCase(); }
        };
        const want = norm(expectedBoundHash);
        if (!reportData) {
          signatureVerified = false;
          signatureError = "No runtime/report data claim to bind against expected boundHash";
        } else if (norm(String(reportData)) !== want) {
          signatureVerified = false;
          signatureError = `Runtime data does not match expected boundHash`;
        }
      }

      // 7. VRD-2026-006 fix: Enforce an approved measurement allowlist if configured.
      const allowed = process.env.AZURE_MAA_ALLOWED_MEASUREMENTS;
      if (strict && !allowed) {
        signatureVerified = false;
        signatureError = "AZURE_MAA_ALLOWED_MEASUREMENTS is required when verified attestation is required";
      }
      if (signatureVerified && allowed) {
        const allowedSet = new Set(allowed.split(",").map((m) => m.trim().toLowerCase().replace(/^0x/, "")));
        const m = measurement ? String(measurement).toLowerCase().replace(/^0x/, "") : "";
        if (!m || !allowedSet.has(m)) {
          signatureVerified = false;
          signatureError = `Measurement ${m || "(missing)"} not in approved allowlist`;
        }
      }

      return {
        measurement: measurement ? `0x${String(measurement).replace(/^0x/, "")}` : undefined,
        certChain: header.x5c || undefined,
        verified: signatureVerified,
        error: signatureVerified ? undefined : signatureError,
      };
    } catch (error: any) {
      return { verified: false, error: `JWT parse error: ${error.message}` };
    }
  }
}

export class AzureMaaAttestation {
  public static async getQuote(traceHash: string): Promise<any> {
    const provider = new AzureMaaAttestationProvider();
    const report = await provider.getAttestationReport(traceHash);
    return {
      type: report.provider,
      quote: report.quote,
      measurement: report.measurement,
      boundHash: report.boundHash,
      verified: report.verified === true,
    };
  }
}
