import { AttestationProvider, TEEProviderType } from "./types.js";
import { AzureMaaAttestationProvider } from "./azureMaa.js";
import { AwsNitroKmsAttestationProvider } from "./awsNitroKms.js";
import { PhalaDstackAttestationProvider } from "./phalaDstack.js";
import { NillionSecretVaultAttestationProvider } from "./nillionSecretVault.js";

export interface AttestationFactoryOptions {
  provider: TEEProviderType;
  endpoint?: string;
  measurement?: string;
}

export function getAttestationProvider(options: AttestationFactoryOptions | TEEProviderType): AttestationProvider {
  const providerType = typeof options === "string" ? options : options.provider;

  switch (providerType) {
    case "azure-maa/sev-snp":
    case "azure-maa/tdx":
      return new AzureMaaAttestationProvider(typeof options === "object" ? options.endpoint : undefined);

    case "aws-nitro-enclave":
      return new AwsNitroKmsAttestationProvider(typeof options === "object" ? options.measurement : undefined);

    case "phala-dstack":
      return new PhalaDstackAttestationProvider(typeof options === "object" ? options.endpoint : undefined);

    case "nillion-secret-vault":
      return new NillionSecretVaultAttestationProvider(typeof options === "object" ? options.endpoint : undefined);

    default:
      return new AzureMaaAttestationProvider();
  }
}
