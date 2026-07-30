import { GOAT_ERC8004_ADDRESSES } from "../erc8004/goatContracts.js";

export function validateBootConfiguration(env: Record<string, string | undefined> = process.env): void {
  const registryAddr = env.EVIDENCE_REGISTRY_ADDRESS || GOAT_ERC8004_ADDRESSES.testnet3.evidenceRegistry;

  if (!registryAddr || registryAddr === "0x0000000000000000000000000000000000000000") {
    console.error("[Boot Validation Error] Invalid EVIDENCE_REGISTRY_ADDRESS: Contract address cannot be zero.");
    process.exit(1);
  }

  const sessionKey = env.SESSION_KEY;
  if (sessionKey && !/^(0x)?[0-9a-fA-F]{64}$/.test(sessionKey.trim())) {
    console.error("[Boot Validation Error] Invalid SESSION_KEY: Must be a valid 64-character hex private key.");
    process.exit(1);
  }

  console.log(`[Boot Validation] Configuration verified. Registry: ${registryAddr}`);
}
