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
  const addressPattern = /^0x[a-fA-F0-9]{40}$/;
  const bytes32Pattern = /^(?:0x)?[a-fA-F0-9]{64}$/;
  const isPlaceholder = (value: string | undefined) => !value || /REPLACE_WITH|CHANGE_ME|PLACEHOLDER/i.test(value);

  if (isProduction && !/^erc8004:[1-9][0-9]*:(0|[1-9][0-9]*)$/.test(env.AGENT_ID || "")) {
    errors.push("AGENT_ID must explicitly identify a canonical erc8004:chainId:tokenId in production");
  }

  // 1. Validate Evidence Registry address
  const registryAddr = env.EVIDENCE_REGISTRY_ADDRESS || (isProduction ? undefined : GOAT_ERC8004_ADDRESSES.testnet3.evidenceRegistry);
  if (!registryAddr || registryAddr === "0x0000000000000000000000000000000000000000") {
    errors.push("EVIDENCE_REGISTRY_ADDRESS must explicitly identify the reviewed registry");
  }
  if (isProduction && !addressPattern.test(registryAddr || "")) {
    errors.push("EVIDENCE_REGISTRY_ADDRESS must be an EVM address");
  }
  if (isProduction && (!addressPattern.test(env.IDENTITY_REGISTRY_ADDRESS || "") ||
      !bytes32Pattern.test(env.IDENTITY_REGISTRY_CODE_HASH || ""))) {
    errors.push("IDENTITY_REGISTRY_ADDRESS and IDENTITY_REGISTRY_CODE_HASH must pin the official ERC-8004 identity registry");
  }

  // 2. In production, session key is REQUIRED (no random wallet fallback)
  const sessionKey = env.SESSION_KEY;
  const sessionKmsKey = env.SESSION_AWS_KMS_KEY_ID;
  if (isProduction && !sessionKmsKey) {
    errors.push("SESSION_AWS_KMS_KEY_ID is required in production; exportable session keys are development-only");
  }
  if (isProduction && sessionKey) errors.push("SESSION_KEY must not be present in production");

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
  if (isProduction && (!env.INTERNAL_IDENTITY_HMAC_SECRET || env.INTERNAL_IDENTITY_HMAC_SECRET.trim().length < 32)) {
    errors.push("INTERNAL_IDENTITY_HMAC_SECRET is required in production and must be >= 32 characters");
  }
  if (isProduction && (!env.SESSION_PROPOSAL_ENCRYPTION_KEY || env.SESSION_PROPOSAL_ENCRYPTION_KEY.trim().length < 32)) {
    errors.push("SESSION_PROPOSAL_ENCRYPTION_KEY is required in production and must be >= 32 characters");
  }

  // 5. Validate PRIVATE_KEY/RELAYER key in production
  const privateKey = env.PRIVATE_KEY || env.RELAYER_PRIVATE_KEY;
  const relayerKmsKey = env.AWS_KMS_KEY_ID || env.KMS_KEY_ID;
  if (isProduction && !relayerKmsKey) {
    errors.push("AWS_KMS_KEY_ID is required in production; exportable relayer keys are development-only");
  }
  if (isProduction && privateKey) errors.push("PRIVATE_KEY and RELAYER_PRIVATE_KEY must not be present in production");
  if (isProduction && sessionKmsKey && relayerKmsKey && sessionKmsKey === relayerKmsKey) {
    errors.push("Relayer and evidence session roles must use distinct KMS keys");
  }
  if (isProduction && (!env.NEXT_SESSION_AWS_KMS_KEY_ID || env.NEXT_SESSION_AWS_KMS_KEY_ID === sessionKmsKey || env.NEXT_SESSION_AWS_KMS_KEY_ID === relayerKmsKey)) {
    errors.push("NEXT_SESSION_AWS_KMS_KEY_ID must stage a distinct production KMS key");
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

    if (!addressPattern.test(env.USDC_TOKEN_ADDRESS || "") || !addressPattern.test(env.USDC_USD_ORACLE_ADDRESS || "")) {
      errors.push("USDC_TOKEN_ADDRESS and USDC_USD_ORACLE_ADDRESS are required for the production x402 showcase");
    }
    const rpcEndpoints = (env.GOAT_NETWORK_RPC_URLS || env.GOAT_NETWORK_RPC || "")
      .split(",").map((value) => value.trim()).filter(Boolean);
    try {
      if (rpcEndpoints.length === 0 || rpcEndpoints.some((value) => new URL(value).protocol !== "https:")) {
        errors.push("At least one explicitly configured HTTPS GOAT RPC endpoint is required in production");
      }
    } catch {
      errors.push("GOAT RPC endpoint configuration contains an invalid URL");
    }
    const confirmations = Number(env.X402_MIN_CONFIRMATIONS || "0");
    if (!Number.isSafeInteger(confirmations) || confirmations < 1 || confirmations > 64) {
      errors.push("X402_MIN_CONFIRMATIONS must be an integer between 1 and 64");
    }
    const priceMaxAge = Number(env.PRICE_MAX_AGE_SECONDS || "0");
    if (!Number.isSafeInteger(priceMaxAge) || priceMaxAge < 1 || priceMaxAge > 86_400) {
      errors.push("PRICE_MAX_AGE_SECONDS must be an integer between 1 and 86400");
    }
    if (!env.X402_ALLOWED_MERCHANTS || !env.X402_ALLOWED_MERCHANT_ORIGINS) {
      errors.push("X402_ALLOWED_MERCHANTS and X402_ALLOWED_MERCHANT_ORIGINS are required in production");
    } else {
      const merchants = env.X402_ALLOWED_MERCHANTS.split(",").map((value) => value.trim()).filter(Boolean);
      if (merchants.length === 0 || merchants.some((value) => !addressPattern.test(value))) {
        errors.push("X402_ALLOWED_MERCHANTS must contain only EVM addresses");
      }
      try {
        const origins = env.X402_ALLOWED_MERCHANT_ORIGINS.split(",").map((value) => value.trim()).filter(Boolean);
        if (origins.length === 0 || origins.some((value) => {
          const parsed = new URL(value);
          return parsed.protocol !== "https:" || parsed.origin !== value;
        })) errors.push("X402_ALLOWED_MERCHANT_ORIGINS must contain canonical HTTPS origins");
      } catch {
        errors.push("X402_ALLOWED_MERCHANT_ORIGINS contains an invalid URL");
      }
    }
    if (env.EVIDENCE_ANCHORING_ENABLED !== "true" || env.STRICT_REGISTRY !== "true") {
      errors.push("Production evidence requires EVIDENCE_ANCHORING_ENABLED=true and STRICT_REGISTRY=true");
    }
    if (!bytes32Pattern.test(env.EVIDENCE_REGISTRY_CODE_HASH || "") ||
        !addressPattern.test(env.EVIDENCE_REGISTRY_OWNER || "") || !env.EVIDENCE_CONTENT_BASE_URL ||
        !env.EVIDENCE_CONTENT_WRITE_URL || !env.EVIDENCE_CONTENT_WRITE_TOKEN) {
      errors.push("Pinned registry code hash/owner and immutable evidence read/write storage are required in production");
    } else {
      try {
        if (new URL(env.EVIDENCE_CONTENT_BASE_URL).protocol !== "https:") {
          errors.push("EVIDENCE_CONTENT_BASE_URL must use HTTPS in production");
        }
        if (new URL(env.EVIDENCE_CONTENT_WRITE_URL!).protocol !== "https:") {
          errors.push("EVIDENCE_CONTENT_WRITE_URL must use HTTPS in production");
        }
      } catch {
        errors.push("Evidence content read/write URL is invalid");
      }
    }
    if (env.AGENTKIT_IDEMPOTENCY_MODE !== "redis" || !env.AGENTKIT_REDIS_URL) {
      errors.push("AGENTKIT_IDEMPOTENCY_MODE=redis and AGENTKIT_REDIS_URL are required in production");
    }
    if (!/^[a-fA-F0-9]{64}$/.test(env.GOAT_ACTION_MANIFEST_SHA256 || "")) {
      errors.push("GOAT_ACTION_MANIFEST_SHA256 is required to pin AgentKit tool metadata");
    }
    if (env.CLOUD_MODE === "true" && (!env.AZURE_MAA_TRUSTED_ISSUERS || !env.AZURE_MAA_AUDIENCE ||
        !env.AZURE_MAA_TRUSTED_ROOT_FINGERPRINTS || !env.AZURE_MAA_ALLOWED_MEASUREMENTS ||
        !env.AZURE_MAA_ALLOWED_TCB_STATUSES || !env.AZURE_MAA_ALLOWED_PRODUCTS ||
        !/^\d+$/.test(env.AZURE_MAA_MIN_GUEST_SVN || ""))) {
      errors.push("Verified Azure MAA mode requires pinned issuers, audience, roots, measurements, products, TCB statuses, and minimum guest SVN");
    }
    for (const [name, value] of Object.entries({
      INTERNAL_AGENT_HMAC_SECRET: env.INTERNAL_AGENT_HMAC_SECRET,
      INTERNAL_IDENTITY_HMAC_SECRET: env.INTERNAL_IDENTITY_HMAC_SECRET,
      STATE_SIGNING_SECRET: env.STATE_SIGNING_SECRET,
      SESSION_PROPOSAL_ENCRYPTION_KEY: env.SESSION_PROPOSAL_ENCRYPTION_KEY,
      EVIDENCE_CONTENT_WRITE_TOKEN: env.EVIDENCE_CONTENT_WRITE_TOKEN,
    })) {
      if (isPlaceholder(value) || value!.trim().length < 32) {
        errors.push(`${name} must be a vault-injected non-placeholder value of at least 32 characters`);
      }
    }
  }

  // 5. Fail fast if any errors
  if (errors.length > 0) {
    console.error("[Boot Validation FAILED]");
    errors.forEach((err) => console.error(`  ❌ ${err}`));
    if (isProduction) {
      throw new Error(`Boot configuration rejected: ${errors.join("; ")}`);
    } else {
      console.warn("  ⚠️  Continuing in development mode despite errors");
    }
  } else {
    console.log(`[Boot Validation] ✅ Configuration verified. Registry: ${registryAddr}`);
  }
}
