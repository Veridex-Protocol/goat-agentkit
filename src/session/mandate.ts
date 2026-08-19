import { verifyTypedData, getAddress, TypedDataDomain, TypedDataField } from "ethers";

/**
 * VRD-2026-003 fix: Server-side verification of the owner's EIP-712 SessionMandate.
 *
 * The dashboard collects a mandate signature but the agent previously ignored it
 * when rotating keys. This verifier lets the agent PROVE that an authorized owner
 * actually delegated authority (identity + scope + expiry) before a new session
 * key is activated.
 */
export const SESSION_MANDATE_DOMAIN: TypedDataDomain = {
  name: "Veridex GOAT Agent Fabric",
  version: "1.0.0",
  chainId: 48816,
};

export const SESSION_MANDATE_TYPES: Record<string, TypedDataField[]> = {
  SessionMandate: [
    { name: "owner", type: "address" },
    { name: "sessionSigner", type: "address" },
    { name: "expiresAt", type: "uint256" },
    { name: "maxPerTxUSD", type: "uint256" },
    { name: "agentId", type: "string" },
    // A proposal nonce binds the authorization to one server-generated session
    // key and makes a captured mandate unusable for a later rotation.
    { name: "nonce", type: "bytes32" },
  ],
};

export interface SessionMandate {
  owner: string;
  sessionSigner: string;
  expiresAt: number;
  maxPerTxUSD: number;
  agentId: string;
  nonce: string;
}

export interface MandateVerificationResult {
  valid: boolean;
  reason?: string;
  recoveredOwner?: string;
}

/**
 * Verify a SessionMandate signature.
 *
 * @param mandate       - The mandate fields the owner signed.
 * @param signature     - EIP-712 signature over the mandate.
 * @param options.authorizedOwners - Allowlist of owner addresses permitted to delegate.
 *                                    If omitted, any address that produces a valid
 *                                    signature is accepted (dev only).
 * @param options.agentId - Expected agentId the mandate must target.
 * @param options.maxPerTxCapUSD - Upper bound the mandate's maxPerTxUSD must respect.
 */
export function verifySessionMandate(
  mandate: SessionMandate,
  signature: string,
  options: {
    authorizedOwners?: string[];
    agentId?: string;
    maxPerTxCapUSD?: number;
    nowSeconds?: number;
  } = {}
): MandateVerificationResult {
  if (!signature || typeof signature !== "string" || signature.length !== 132) {
    return { valid: false, reason: "Missing or malformed mandate signature" };
  }

  let recoveredOwner: string;
  try {
    recoveredOwner = verifyTypedData(SESSION_MANDATE_DOMAIN, SESSION_MANDATE_TYPES, mandate, signature);
  } catch (e: any) {
    return { valid: false, reason: `Signature recovery failed: ${e.message}` };
  }

  // 1. Recovered signer must equal the claimed owner.
  try {
    if (getAddress(recoveredOwner) !== getAddress(mandate.owner)) {
      return { valid: false, recoveredOwner, reason: `Signer ${recoveredOwner} does not match declared owner ${mandate.owner}` };
    }
  } catch {
    return { valid: false, recoveredOwner, reason: "Invalid owner address" };
  }

  // 2. Owner must be on the allowlist (when one is configured).
  if (options.authorizedOwners && options.authorizedOwners.length > 0) {
    const allow = new Set(options.authorizedOwners.map((a) => a.toLowerCase()));
    if (!allow.has(recoveredOwner.toLowerCase())) {
      return { valid: false, recoveredOwner, reason: `Owner ${recoveredOwner} is not an authorized delegator` };
    }
  }

  // 3. Mandate must target the expected agent.
  if (options.agentId && mandate.agentId !== options.agentId) {
    return { valid: false, recoveredOwner, reason: `Mandate agentId ${mandate.agentId} != expected ${options.agentId}` };
  }

  // 4. Expiry must be in the future.
  const now = options.nowSeconds ?? Math.floor(Date.now() / 1000);
  if (!mandate.expiresAt || mandate.expiresAt <= now) {
    return { valid: false, recoveredOwner, reason: `Mandate expired (expiresAt ${mandate.expiresAt} <= now ${now})` };
  }

  // 5. Scope: per-tx limit must respect the server cap.
  if (options.maxPerTxCapUSD !== undefined && mandate.maxPerTxUSD > options.maxPerTxCapUSD) {
    return { valid: false, recoveredOwner, reason: `Mandate maxPerTxUSD ${mandate.maxPerTxUSD} exceeds cap ${options.maxPerTxCapUSD}` };
  }

  // 6. A mandate must carry a canonical 32-byte proposal nonce. The server
  // compares it to a single-use proposal before it creates the active session.
  if (!/^0x[0-9a-fA-F]{64}$/.test(mandate.nonce || "")) {
    return { valid: false, recoveredOwner, reason: "Mandate nonce must be a bytes32 value" };
  }

  return { valid: true, recoveredOwner };
}
