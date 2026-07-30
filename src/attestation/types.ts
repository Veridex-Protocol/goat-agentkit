/**
 * Common Confidential Compute & Attestation Provider Interfaces
 */

export type TEEProviderType =
  | "azure-maa/sev-snp"
  | "azure-maa/tdx"
  | "aws-nitro-enclave"
  | "phala-dstack"
  | "nillion-secret-vault"
  | "mock-simulator"
  | "software";

export interface TEEAttestationReport {
  provider: TEEProviderType;
  quote: string; // Base64 or Hex encoded attestation quote / doc
  measurement: string; // PCR0 / SEV-SNP launch measurement
  boundHash: string; // keccak256 hash of policy verdict & trace
  issuerCertChain?: string[];
  timestamp: number;
}

export interface AttestationProvider {
  getType(): TEEProviderType;
  /**
   * Generates a hardware-bound remote attestation report embedding traceHash as user_data / nonce.
   */
  getAttestationReport(traceHash: string): Promise<TEEAttestationReport>;
}
