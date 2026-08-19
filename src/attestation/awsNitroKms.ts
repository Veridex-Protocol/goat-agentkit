import { keccak256, toUtf8Bytes } from "ethers";
import fs from "fs";
import { execSync } from "child_process";
import { AttestationProvider, TEEAttestationReport, TEEProviderType } from "./types.js";

/**
 * Production Live AWS Nitro Enclaves & AWS KMS Attestation Driver
 *
 * Documentation Reference:
 * https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-ref-nsm.html
 * KMS Condition Key: kms:RecipientAttestation:PCR0
 *
 * Intercepts live NSM (Nitro Security Module) attestation reports via:
 * 1. Linux kernel device driver (/dev/nsm)
 * 2. VSOCK socket proxy inside AWS EC2 Nitro micro-VMs
 */
export class AwsNitroKmsAttestationProvider implements AttestationProvider {
  private nsmDevicePath: string;

  constructor(nsmDevicePath = "/dev/nsm") {
    this.nsmDevicePath = nsmDevicePath;
  }

  public getType(): TEEProviderType {
    return "aws-nitro-enclave";
  }

  /**
   * Queries NSM hardware driver to generate a live Nitro Attestation Document (CBOR),
   * embedding traceHash as userData.
   */
  public async getAttestationReport(traceHash: string): Promise<TEEAttestationReport> {
    const boundHash = keccak256(toUtf8Bytes(traceHash));
    const timestamp = Date.now();

    // Strategy 1: Query live /dev/nsm device driver inside AWS Nitro Enclave via nsm-cli/ioctl
    try {
      if (fs.existsSync(this.nsmDevicePath)) {
        // AWS Nitro NSM requires specific ioctl calls.
        // We invoke the nsm-cli system tool to fetch the CBOR attestation document securely.
        const output = execSync(`/usr/bin/nsm-cli --user-data ${boundHash} --raw`, { stdio: "pipe" });
        const hexQuote = output.toString("hex");

        // VRD-2026-006 fix: Do not fabricate a PCR0. The measurement must be parsed
        // from the CBOR attestation document and verified against a KMS PCR0
        // condition/allowlist by the caller. We surface the raw quote and mark the
        // measurement as not-yet-extracted rather than returning a plausible fake.
        if (process.env.NODE_ENV === "production") {
          throw new Error("[AWS Nitro TEE Driver] A raw NSM document is not verified. Configure a CBOR/KMS verification provider before enabling production evidence.");
        }
        return {
          provider: "aws-nitro-enclave",
          quote: hexQuote,
          measurement: "0x0000000000000000000000000000000000000000000000000000000000000000",
          boundHash,
          timestamp,
          verificationStatus: "unverified: PCR0 requires CBOR parsing + KMS attestation policy check",
          verified: false,
        };
      }
    } catch (e) {
      // NSM device or tool execution failed
    }

    if (process.env.NODE_ENV === "production") {
      throw new Error("[AWS Nitro TEE Driver] Production Environment Error: NSM hardware device or enclave CLI is unavailable.");
    }

    // VRD-2026-006 fix: When no NSM hardware is present we return an explicitly
    // UNVERIFIED software report with a zeroed measurement. We never reuse the
    // hardware provider label or a plausible-looking PCR0 for placeholder evidence.
    return {
      provider: "software",
      quote: "LIVE_AWS_NITRO_NSM_UNAVAILABLE_LOCAL_ENV",
      measurement: "0x0000000000000000000000000000000000000000000000000000000000000000",
      boundHash,
      timestamp,
      verificationStatus: "unverified: NSM hardware unavailable (software fallback)",
      verified: false,
    };
  }
}
