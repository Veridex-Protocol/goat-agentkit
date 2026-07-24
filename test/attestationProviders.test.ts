import { describe, it, expect } from "vitest";
import {
  getAttestationProvider,
  AzureMaaAttestationProvider,
  AwsNitroKmsAttestationProvider,
  PhalaDstackAttestationProvider,
  NillionSecretVaultAttestationProvider,
} from "../src/index.js";

describe("Confidential Compute & TEE Attestation Drivers (Live Specification)", () => {
  const sampleTraceHash = "0xd59a34f028d1150b26f0384aeb20f0ffc254814ac0f96c5055ea54b0795b59dd";

  it("should execute Azure MAA SEV-SNP attestation driver and parse MAA JWT payload", async () => {
    const provider = new AzureMaaAttestationProvider();
    expect(provider.getType()).toBe("azure-maa/sev-snp");

    const report = await provider.getAttestationReport(sampleTraceHash);
    expect(report.provider).toBe("azure-maa/sev-snp");
    expect(report.boundHash).toBeDefined();
    expect(report.quote).toBeDefined();
  });

  it("should execute AWS Nitro Enclaves NSM attestation driver and extract PCR0 measurement", async () => {
    const provider = new AwsNitroKmsAttestationProvider();
    expect(provider.getType()).toBe("aws-nitro-enclave");

    const report = await provider.getAttestationReport(sampleTraceHash);
    expect(report.provider).toBe("aws-nitro-enclave");
    expect(report.measurement).toBeDefined();
    expect(report.boundHash).toBeDefined();
  });

  it("should execute Phala Network dstack TEE attestation driver", async () => {
    const provider = new PhalaDstackAttestationProvider();
    expect(provider.getType()).toBe("phala-dstack");

    const report = await provider.getAttestationReport(sampleTraceHash);
    expect(report.provider).toBe("phala-dstack");
    expect(report.quote).toBeDefined();
  });

  it("should execute Nillion Secret Vault MPC attestation driver", async () => {
    const provider = new NillionSecretVaultAttestationProvider();
    expect(provider.getType()).toBe("nillion-secret-vault");

    const report = await provider.getAttestationReport(sampleTraceHash);
    expect(report.provider).toBe("nillion-secret-vault");
    expect(report.quote).toBeDefined();
  });

  it("should resolve unified attestation drivers via factory", () => {
    expect(getAttestationProvider("azure-maa/sev-snp").getType()).toBe("azure-maa/sev-snp");
    expect(getAttestationProvider("aws-nitro-enclave").getType()).toBe("aws-nitro-enclave");
    expect(getAttestationProvider("phala-dstack").getType()).toBe("phala-dstack");
    expect(getAttestationProvider("nillion-secret-vault").getType()).toBe("nillion-secret-vault");
  });
});
