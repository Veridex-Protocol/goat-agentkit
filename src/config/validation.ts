import { GOAT_ERC8004_ADDRESSES } from "../erc8004/goatContracts.js";

/**
 * VD-GOAT-015 fix: Validate configuration to reject unsafe defaults at startup.
 *
 * In production, this prevents:
 * - Zero address registry contracts
 * - Missing session keys (random wallet fallback)
 * - Placeholder token prices
 * - Invalid environment configs
 */
export function validateBootConfiguration(env: Record<string, string | undefined> = process.env): void {
  const isProduction = env.NODE_ENV === "production";
  const errors: string[] = [];

  // 1. Validate Evidence Registry address
  const registryAddr = env.EVIDENCE_REGISTRY_ADDRESS || GOAT_ERC8004_ADDRESSES.testnet3.evidenceRegistry;
  if (!registryAddr || registryAddr === "0x0000000000000000000000000000000000000000") {
    errors.push("EVIDENCE_REGISTRY_ADDRESS cannot be zero or empty");
  }

  // 2. In production, session key is REQUIRED (no random wallet fallback)
  const sessionKey = env.SESSION_KEY;
  if (isProduction && !sessionKey) {
    errors.push("SESSION_KEY is required in production (random wallet generation disabled)");
  }

  if (sessionKey && !/^(0x)?[0-9a-fA-F]{64}$/.test(sessionKey.trim())) {
    errors.push("SESSION_KEY must be a valid 64-character hex private key");
  }

  // 3. Validate relayer wallet (if provided)
  const relayerKey = env.RELAYER_PRIVATE_KEY;
  if (relayerKey && !/^(0x)?[0-9a-fA-F]{64}$/.test(relayerKey.trim())) {
    errors.push("RELAYER_PRIVATE_KEY must be a valid 64-character hex private key");
  }

  // 4. Browser-facing deployments use OIDC. Internal dashboard-to-agent calls
  // are body-bound HMAC requests with one-time nonces, never static bearers.
  if (isProduction && (!env.INTERNAL_AGENT_HMAC_SECRET || env.INTERNAL_AGENT_HMAC_SECRET.trim().length < 32)) {
    errors.push("INTERNAL_AGENT_HMAC_SECRET is required in production and must be >= 32 characters");
  }

  // 5. Validate PRIVATE_KEY/RELAYER key in production
  const privateKey = env.PRIVATE_KEY || env.RELAYER_PRIVATE_KEY;
  if (isProduction && !privateKey) {
    errors.push("PRIVATE_KEY or RELAYER_PRIVATE_KEY is required in production");
  }
  if (privateKey && !/^(0x)?[0-9a-fA-F]{64}$/.test(privateKey.trim())) {
    errors.push("PRIVATE_KEY or RELAYER_PRIVATE_KEY must be a valid 64-character hex private key");
  }

  // 6. Durable policy state must be signed with a stable vault-provided secret.
  if (isProduction && (!env.STATE_SIGNING_SECRET || env.STATE_SIGNING_SECRET.trim().length < 32)) {
    errors.push("STATE_SIGNING_SECRET is required in production and must be >= 32 characters");
  }

  // 7. A signed file is safe only for an explicitly verified one-replica
  // deployment. A production service must use shared transactional state so
  // spend caps and x402 nonce consumption are atomic across replicas.
  const policyDatabaseUrl = env.POLICY_STATE_DATABASE_URL;
  if (isProduction && !policyDatabaseUrl) {
    errors.push("POLICY_STATE_DATABASE_URL is required in production for transactional policy and x402 nonce state");
  }
  if (policyDatabaseUrl && !/^postgres(?:ql)?:\/\//i.test(policyDatabaseUrl)) {
    errors.push("POLICY_STATE_DATABASE_URL must be a PostgreSQL connection URL");
  }

  // 8. Check for placeholder/test values in production
  if (isProduction) {
    if (registryAddr?.toLowerCase().includes("test") || registryAddr?.toLowerCase().includes("placeholder")) {
      errors.push("Production detected but registry address contains 'test' or 'placeholder'");
    }

    // Mainnet evidence registry must be set
    if (env.GOAT_NETWORK === "mainnet" && !GOAT_ERC8004_ADDRESSES.mainnet.evidenceRegistry) {
      errors.push("Mainnet evidence registry not configured");
    }
  }

  // 5. Fail fast if any errors
  if (errors.length > 0) {
    console.error("[Boot Validation FAILED]");
    errors.forEach((err) => console.error(`  ❌ ${err}`));
    if (isProduction) {
      process.exit(1);
    } else {
      console.warn("  ⚠️  Continuing in development mode despite errors");
    }
  } else {
    console.log(`[Boot Validation] ✅ Configuration verified. Registry: ${registryAddr}`);
  }
}
