import { ethers } from "ethers";
import { VeridexPolicyGate, type PolicyStateProvider } from "../policy/gate.js";
import { PolicyRuleConfig } from "../policy/rules.js";
import { EvidenceBuilder, EvidenceBundle } from "../evidence/builder.js";
import { LocalSessionSigner, SessionSigner } from "../evidence/signer.js";
import { HumanApprovalRequiredError, SessionExpiredError } from "../wrapper.js";
import { x402RateLimiter } from "../utils/rateLimiter.js";
import type { NormalizedAction } from "../types/action.js";
import { assertNormalizedActionIntegrity, TransactionDecoder } from "../policy/decoder.js";
import { Pool, type PoolConfig } from "pg";
import type { SessionRevocationProvider } from "../session/revocation.js";
import type { VerifiedX402Settlement, X402SettlementVerifier } from "./settlement.js";

/**
 * An adapter throws this only after a transaction hash has been returned by
 * the network but durable verification/outbox work failed. The policy gate
 * keeps the reservation for durable reconciliation instead of pretending the
 * funds were never sent.
 */
export class X402BroadcastUncertainError extends Error {
  public readonly txHash: string;

  constructor(txHash: string, message: string, options?: { cause?: unknown }) {
    super(`${message} (broadcast transaction ${txHash})`, options);
    this.name = "X402BroadcastUncertainError";
    this.txHash = txHash;
  }
}

export interface X402Challenge {
  version: "2";
  status: number;
  message?: string;
  accepts: string; // e.g. "USDC" or "GOAT"
  amount: string; // e.g. "2500000" (raw units or string)
  amountUSD?: number;
  /** Exact account authorized to satisfy this invoice. */
  payer: string;
  payTo: string;
  chain: number;
  scheme: "exact" | "authorization" | "eip3009";
  nonce?: string;
  validAfter?: number;
  validBefore?: number;
  signature?: string; // VD-GOAT-008: Merchant signature over challenge
  merchantPublicKey?: string; // VD-GOAT-008: Merchant's signing key
  /** Merchant-generated, globally unique order identity. */
  orderId: string;
  /** Canonical resource or invoice URI purchased by this settlement. */
  resource: string;
  /** HTTPS origin independently allowlisted by the payer. */
  merchantOrigin: string;
  /** Exact ERC-20 contract, or null for native currency. */
  tokenAddress: string | null;
}

export interface X402ExecutionSecurity {
  allowedMerchants?: Set<string>;
  allowedMerchantOrigins?: Set<string>;
  usedNonces?: Set<string>;
  nonceStore?: X402NonceStore;
  settlementVerifier?: X402SettlementVerifier;
  sessionExpiresAt?: number;
  sessionRevocationProvider?: SessionRevocationProvider;
  /**
   * Binds the evidence signer to the configured agent identity. Production
   * callers normally implement this with the pinned ERC-8004 EvidenceRegistry.
   */
  sessionAuthorizationVerifier?: (params: {
    sessionAddress: string;
    agentId: string;
  }) => boolean | Promise<boolean>;
  /**
   * Called only after the transaction has been independently verified and the
   * policy reservation has been committed. A failed merchant callback can
   * therefore never make already-spent funds disappear from policy state.
   */
  settlementNotifier?: (params: {
    settlement: VerifiedX402Settlement;
    action: NormalizedAction;
    challenge: X402Challenge;
    result: unknown;
  }) => Promise<{ confirmed: boolean; receipt?: unknown; error?: string }>;
  /** Durable decision lookup for escalated exact invoice executions. */
  approvalVerifier?: (params: {
    approvalId: string;
    action: NormalizedAction;
    challenge: X402Challenge;
    context?: unknown;
  }) => Promise<boolean>;
  /**
   * Submit the payer's exact off-chain authorization for schemes that require
   * it. The callback normally signs the output of
   * `buildX402PaymentAuthorization()` with a KMS/HSM-backed payer and submits
   * it to the allowlisted merchant. Direct `exact` transfers do not use it.
   */
  paymentAuthorizer?: (params: {
    action: NormalizedAction;
    challenge: X402Challenge;
    context?: unknown;
  }) => Promise<{ authorized: true; proof?: unknown }>;
}

export function canonicalX402Challenge(challenge: X402Challenge): string {
  return JSON.stringify({
    version: challenge.version,
    orderId: challenge.orderId,
    resource: challenge.resource,
    merchantOrigin: challenge.merchantOrigin,
    accepts: challenge.accepts,
    tokenAddress: challenge.tokenAddress,
    amount: challenge.amount,
    amountUSD: challenge.amountUSD,
    payer: challenge.payer,
    payTo: challenge.payTo,
    chain: challenge.chain,
    scheme: challenge.scheme,
    nonce: challenge.nonce,
    validAfter: challenge.validAfter,
    validBefore: challenge.validBefore,
  });
}

/**
 * Stable, framework-independent EIP-712 authorization submitted by the payer
 * before settlement. This is an off-chain merchant authorization; the actual
 * asset movement remains an independently signed and verified chain
 * transaction.
 */
export const X402_PAYMENT_AUTHORIZATION_DOMAIN = {
  name: "Veridex GOAT x402 Merchant",
  version: "1",
} as const;

export const X402_PAYMENT_AUTHORIZATION_TYPES = {
  PaymentAuthorization: [
    { name: "payer", type: "address" },
    { name: "payTo", type: "address" },
    { name: "tokenAddress", type: "address" },
    { name: "amount", type: "uint256" },
    { name: "orderId", type: "string" },
    { name: "resource", type: "string" },
    { name: "nonce", type: "bytes32" },
    { name: "validAfter", type: "uint256" },
    { name: "validBefore", type: "uint256" },
  ],
} as const;

export function buildX402PaymentAuthorization(challenge: X402Challenge): {
  domain: ethers.TypedDataDomain;
  types: typeof X402_PAYMENT_AUTHORIZATION_TYPES;
  value: Record<string, string | number>;
} {
  if (!challenge.nonce || challenge.validBefore === undefined) {
    throw new Error("x402 authorization requires nonce and validBefore");
  }
  return {
    domain: {
      ...X402_PAYMENT_AUTHORIZATION_DOMAIN,
      chainId: challenge.chain,
      verifyingContract: ethers.getAddress(challenge.payTo),
    },
    types: X402_PAYMENT_AUTHORIZATION_TYPES,
    value: {
      payer: ethers.getAddress(challenge.payer),
      payTo: ethers.getAddress(challenge.payTo),
      tokenAddress: challenge.tokenAddress ? ethers.getAddress(challenge.tokenAddress) : ethers.ZeroAddress,
      amount: challenge.amount,
      orderId: challenge.orderId,
      resource: challenge.resource,
      nonce: challenge.nonce,
      validAfter: challenge.validAfter ?? 0,
      validBefore: challenge.validBefore,
    },
  };
}

export interface EIP3009Authorization {
  from: string;
  to: string;
  value: string;
  validAfter: number;
  validBefore: number;
  nonce: string;
  v?: number;
  r?: string;
  s?: string;
}

export interface ActionDefinition {
  name: string;
  description: string;
  schema?: any;
  /**
   * VRD-2026-005 fix: Explicit typed capability replaces name-string heuristics.
   * "read" actions bypass spending policy; "spend" actions are always gated.
   * When omitted the action is treated as spending (fail closed).
   */
  capability?: "read" | "spend";
  execute: (input: any, context?: any) => Promise<any>;
}

/**
 * A nonce store must be shared by every process serving a payer identity. A
 * Set is useful only for tests and single-process development; production
 * callers must provide a transactional implementation.
 */
export interface X402NonceStore {
  consume(nonce: string, validBefore: number): boolean | Promise<boolean>;
}

export class InMemoryX402NonceStore implements X402NonceStore {
  private readonly used = new Set<string>();

  consume(nonce: string): boolean {
    if (this.used.has(nonce)) return false;
    this.used.add(nonce);
    return true;
  }
}

/**
 * Shared, replay-safe nonce store. PostgreSQL's primary key provides the
 * compare-and-set primitive; expired entries are removed opportunistically.
 */
export class PostgresX402NonceStore implements X402NonceStore {
  private readonly pool: Pool;
  private readonly namespace: string;
  private schemaReady?: Promise<void>;

  constructor(connection: string | PoolConfig, namespace: string) {
    if (!namespace || namespace.length > 200) throw new Error("x402 nonce namespace must be 1-200 characters");
    this.pool = new Pool(typeof connection === "string" ? { connectionString: connection } : connection);
    this.namespace = namespace;
  }

  private async ensureSchema(): Promise<void> {
    if (!this.schemaReady) {
      this.schemaReady = this.pool.query(`
        CREATE TABLE IF NOT EXISTS veridex_x402_nonces (
          namespace TEXT NOT NULL,
          nonce TEXT NOT NULL,
          valid_before TIMESTAMPTZ NOT NULL,
          consumed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          PRIMARY KEY (namespace, nonce)
        )
      `).then(() => undefined).catch((error) => {
        this.schemaReady = undefined;
        throw error;
      });
    }
    await this.schemaReady;
  }

  public async consume(nonce: string, validBefore: number): Promise<boolean> {
    if (!nonce || nonce.length > 256 || !Number.isSafeInteger(validBefore)) return false;
    await this.ensureSchema();
    // Keep retention bounded without relying on an external maintenance job.
    await this.pool.query("DELETE FROM veridex_x402_nonces WHERE valid_before < NOW() - INTERVAL '1 day'");
    const result = await this.pool.query(
      `INSERT INTO veridex_x402_nonces (namespace, nonce, valid_before)
       VALUES ($1, $2, to_timestamp($3)) ON CONFLICT DO NOTHING`,
      [this.namespace, nonce, validBefore],
    );
    return result.rowCount === 1;
  }

  public async close(): Promise<void> {
    await this.pool.end();
  }
}

/**
 * Parses HTTP 402 responses into standardized GOAT x402 Payment Challenges.
 * VD-GOAT-008 fix: Extracts signature and merchant public key for verification.
 * VD-GOAT-013 fix: Add rate limiting and input validation.
 */
export function parseX402Challenge(responseHeaders: Record<string, string>, responseBody?: any, clientId?: string): X402Challenge {
  // VD-GOAT-013 fix: Rate limit x402 challenge parsing
  const rateLimitKey = clientId || "default";
  if (!x402RateLimiter.check(rateLimitKey)) {
    throw new Error(
      `[x402 Rate Limit] Too many challenge requests from ${rateLimitKey}. ` +
      `Remaining: ${x402RateLimiter.remaining(rateLimitKey)}`
    );
  }
  const headerValue = responseHeaders["x-402-payment-required"] || responseHeaders["X-402-Payment-Required"];
  if (headerValue) {
    // VD-GOAT-013 fix: Validate header size before decoding
    if (headerValue.length > 10_000) {
      throw new Error(`[x402 Validation] Challenge header too large: ${headerValue.length} bytes exceeds 10KB`);
    }

    try {
      const decoded = JSON.parse(Buffer.from(headerValue, "base64").toString("utf-8"));

      // VD-GOAT-013 fix: Validate decoded structure
      if (typeof decoded !== "object" || decoded === null) {
        throw new Error("[x402 Validation] Challenge must be an object");
      }
      const amountUSD = decoded.amountUSD;
      if (amountUSD === undefined) {
        throw new Error("[Veridex x402 Challenge] Cannot determine payment USD value: amountUSD is missing from the challenge data.");
      }
      return {
        version: decoded.version,
        status: 402,
        accepts: decoded.accepts || "USDC",
        amount: String(decoded.amount || decoded.priceUSDC || "0"),
        amountUSD,
        payer: decoded.payer,
        payTo: decoded.payTo,
        chain: decoded.chain || 48816,
        scheme: decoded.scheme || "authorization",
      nonce: decoded.nonce,
      validAfter: decoded.validAfter,
      validBefore: decoded.validBefore,
        signature: decoded.signature, // VD-GOAT-008: Merchant signature
        merchantPublicKey: decoded.merchantPublicKey, // VD-GOAT-008: Merchant's key
        orderId: decoded.orderId,
        resource: decoded.resource,
        merchantOrigin: decoded.merchantOrigin,
        tokenAddress: decoded.tokenAddress ?? null,
      };
    } catch (e: any) {
      if (e.message && e.message.includes("Cannot determine payment USD value")) {
        throw e;
      }
      // Fallback to body parsing
    }
  }

  if (responseBody) {
    const amountUSD = responseBody.amountUSD;
    if (amountUSD === undefined) {
      throw new Error("[Veridex x402 Challenge] Cannot determine payment USD value: amountUSD is missing from the challenge body.");
    }
    return {
      version: responseBody.version,
      status: 402,
      accepts: responseBody.accepts || "USDC",
      amount: String(responseBody.priceUSDC || responseBody.amount || "0"),
      amountUSD,
      payer: responseBody.payer,
      payTo: responseBody.payTo,
      chain: responseBody.chain || 48816,
      scheme: responseBody.scheme || "authorization",
      nonce: responseBody.nonce,
      validAfter: responseBody.validAfter,
      validBefore: responseBody.validBefore,
      signature: responseBody.signature, // VD-GOAT-008: Merchant signature
      merchantPublicKey: responseBody.merchantPublicKey, // VD-GOAT-008: Merchant's key
      orderId: responseBody.orderId,
      resource: responseBody.resource,
      merchantOrigin: responseBody.merchantOrigin,
      tokenAddress: responseBody.tokenAddress ?? null,
    };
  }

  throw new Error("Invalid x402 challenge: Missing x-402-payment-required header or body");
}

/**
 * VD-GOAT-008 fix: Verify x402 challenge authenticity to prevent replay attacks.
 *
 * Verifies:
 * 1. Challenge signature from merchant
 * 2. Nonce freshness (no replay)
 * 3. validBefore timestamp
 * 4. Settlement receipt (if provided)
 *
 * @param challenge - Parsed x402 challenge
 * @param options - Verification options
 * @returns Verification result
 */
export async function verifyX402Challenge(
  challenge: X402Challenge,
  options: {
    usedNonces?: Set<string>;
    allowedMerchants?: Set<string>;
    nonceStore?: X402NonceStore;
    allowedMerchantOrigins?: Set<string>;
    consumeNonce?: boolean;
  }
): Promise<{ valid: boolean; reason?: string }> {
  const now = Math.floor(Date.now() / 1000);
  if (challenge.version !== "2") return { valid: false, reason: "Unsupported x402 challenge version" };
  if (challenge.status !== 402) return { valid: false, reason: "x402 challenge status must be 402" };
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/.test(challenge.orderId || "")) {
    return { valid: false, reason: "Missing or malformed merchant orderId" };
  }
  if (typeof challenge.resource !== "string" || challenge.resource.length < 1 || challenge.resource.length > 2048) {
    return { valid: false, reason: "Missing or malformed x402 resource" };
  }
  let merchantOrigin: string;
  try {
    const parsedOrigin = new URL(challenge.merchantOrigin);
    if (parsedOrigin.protocol !== "https:" && process.env.NODE_ENV === "production") {
      return { valid: false, reason: "Merchant origin must use HTTPS in production" };
    }
    merchantOrigin = parsedOrigin.origin;
    if (merchantOrigin !== challenge.merchantOrigin) return { valid: false, reason: "Merchant origin must be canonical" };
  } catch {
    return { valid: false, reason: "Merchant origin is invalid" };
  }
  if (!options.allowedMerchantOrigins || !options.allowedMerchantOrigins.has(merchantOrigin)) {
    return { valid: false, reason: `Untrusted merchant origin: ${merchantOrigin}` };
  }
  if (!challenge.nonce || typeof challenge.nonce !== "string") {
    return { valid: false, reason: "Missing replay-protection nonce" };
  }
  if (!/^0x[a-fA-F0-9]{64}$/.test(challenge.nonce)) {
    return { valid: false, reason: "Replay-protection nonce must be bytes32" };
  }
  if (!/^\d+$/.test(challenge.amount) || BigInt(challenge.amount) <= 0n) {
    return { valid: false, reason: "Challenge amount must be a positive base-unit integer" };
  }
  if (!/^[A-Za-z0-9]{2,16}$/.test(challenge.accepts || "")) {
    return { valid: false, reason: "Challenge asset symbol is invalid" };
  }
  if (!["exact", "authorization", "eip3009"].includes(challenge.scheme)) {
    return { valid: false, reason: "Challenge settlement scheme is unsupported" };
  }
  if (!Number.isFinite(challenge.amountUSD) || challenge.amountUSD! < 0) {
    return { valid: false, reason: "Challenge amountUSD is invalid" };
  }
  if (!Number.isSafeInteger(challenge.chain) || challenge.chain <= 0) {
    return { valid: false, reason: "Challenge chain is invalid" };
  }
  try {
    ethers.getAddress(challenge.payer);
    ethers.getAddress(challenge.payTo);
    if (challenge.tokenAddress) ethers.getAddress(challenge.tokenAddress);
  } catch {
    return { valid: false, reason: "Challenge payment address is invalid" };
  }
  if (!challenge.validBefore || !Number.isInteger(challenge.validBefore) || challenge.validBefore <= now) {
    return { valid: false, reason: "Challenge is missing a future validBefore timestamp" };
  }
  if (challenge.validBefore > now + 60 * 60) {
    return { valid: false, reason: "Challenge validity window exceeds one hour" };
  }
  if (challenge.validAfter !== undefined && (!Number.isInteger(challenge.validAfter) || challenge.validAfter > now)) {
    return { valid: false, reason: "Challenge is not yet valid" };
  }
  if (!challenge.signature || !challenge.merchantPublicKey) {
    return { valid: false, reason: "Missing merchant signature or merchant identity" };
  }
  if (!options.allowedMerchants || options.allowedMerchants.size === 0) {
    return { valid: false, reason: "No merchant allowlist configured" };
  }
  if (options.consumeNonce !== false && !options.nonceStore && !options.usedNonces) {
    return { valid: false, reason: "No nonce store configured" };
  }

  // 1. Verify nonce freshness (prevent replay)
  if (options.consumeNonce !== false && challenge.nonce && options.usedNonces) {
    if (options.usedNonces.has(challenge.nonce)) {
      return { valid: false, reason: `Nonce replay detected: ${challenge.nonce}` };
    }
  }

  // 2. Verify merchant signature against an independently configured identity.
  try {
      const message = canonicalX402Challenge(challenge);

      const messageHash = ethers.hashMessage(message);
      const recoveredAddress = ethers.recoverAddress(messageHash, challenge.signature);

      // Verify recovered address matches merchant public key
      if (recoveredAddress.toLowerCase() !== challenge.merchantPublicKey.toLowerCase()) {
        return {
          valid: false,
          reason: `Invalid signature: recovered ${recoveredAddress}, expected ${challenge.merchantPublicKey}`,
        };
      }

      // Check if merchant is in the configured allowlist.
      if (!options.allowedMerchants.has(recoveredAddress.toLowerCase())) {
        return {
          valid: false,
          reason: `Untrusted merchant: ${recoveredAddress} not in allowed list`,
        };
      }
  } catch (error: any) {
    return { valid: false, reason: `Signature verification failed: ${error.message}` };
  }

  // Mark nonce as consumed only after all signature and policy-independent
  // checks pass. A durable nonceStore is required for production callers.
  if (options.consumeNonce !== false && options.nonceStore && !await options.nonceStore.consume(challenge.nonce, challenge.validBefore)) {
    return { valid: false, reason: `Nonce replay detected: ${challenge.nonce}` };
  }
  if (options.consumeNonce !== false && challenge.nonce && options.usedNonces) {
    options.usedNonces.add(challenge.nonce);
  }

  return { valid: true };
}

/**
 * VRD-2026-005 fix: Determine whether an action spends funds. An explicit typed
 * `capability` is authoritative. When it is absent the action is treated as
 * SPENDING (fail closed) — the previous name-substring heuristic could silently
 * skip policy for any action whose name contained "get/read/status/query/cancel".
 */
function isSpendingAction(action: ActionDefinition): boolean {
  if (action.capability === "read") return false;
  if (action.capability === "spend") return true;
  // No declared capability: fail closed and treat as spending.
  return true;
}

/**
 * Intercepts x402 payment actions and evaluates economic policy before execution.
 * If policy denies or escalates, handles accordingly and emits signed Evidence Bundles.
 */
export function wrapX402PaymentActions(
  actions: ActionDefinition[] | Record<string, ActionDefinition>,
  policyGate: VeridexPolicyGate,
  sessionSigner?: SessionSigner,
  agentId: string = "erc8004:48816:1042",
  onBundleEmitted?: (bundle: EvidenceBundle) => void | Promise<void>,
  options?: X402ExecutionSecurity,
): ActionDefinition[] {
  const signer = sessionSigner || new LocalSessionSigner();
  const usedNonces = options?.usedNonces || new Set<string>();
  const allowedMerchants = options?.allowedMerchants;
  const allowedMerchantOrigins = options?.allowedMerchantOrigins;
  const nonceStore = options?.nonceStore;
  const settlementVerifier = options?.settlementVerifier;

  const actionList: ActionDefinition[] = Array.isArray(actions)
    ? actions
    : Object.values(actions);

  return actionList.map((action) => {
    return {
      ...action,
      execute: async (input: any, context?: any) => {
        // VRD-2026-005 fix: capability-based classification (fail closed).
        if (!isSpendingAction(action)) {
          return await action.execute(input, context);
        }

        const normalized = input?._normalizedAction as NormalizedAction | undefined;
        if (!normalized) {
          throw new Error(
            `[Veridex x402 Actions] Unbound spending action '${action.name}' rejected. Supply an immutable _normalizedAction; caller amountUSD is not trusted.`
          );
        }
        assertNormalizedActionIntegrity(normalized);
        const challenge = input?.x402Challenge as X402Challenge | undefined;
        if (!challenge) {
          throw new Error(`[Veridex x402 Actions] Authenticated x402 challenge is required for '${action.name}'.`);
        }
        const sessionAddr = await signer.getAddress();
        await assertX402SessionActive(sessionAddr, agentId, options);
        const verification = await verifyX402Challenge(challenge, {
          usedNonces, allowedMerchants, allowedMerchantOrigins, nonceStore, consumeNonce: false,
        });
        if (!verification.valid) {
          throw new Error(`[Veridex x402 Actions] Challenge verification failed: ${verification.reason}`);
        }

        const recipient = normalized.to;
        const amountUSD = normalized.usdValue;
        const amount = normalized.value.toString();
        const asset = normalized.symbol;
        const chain = normalized.chainId;
        if (
          ethers.getAddress(challenge.payer) !== ethers.getAddress(normalized.from) ||
          ethers.getAddress(challenge.payTo) !== ethers.getAddress(recipient) ||
          challenge.chain !== chain ||
          challenge.accepts.toUpperCase() !== asset.toUpperCase() ||
          challenge.amount !== amount ||
          (challenge.tokenAddress ? ethers.getAddress(challenge.tokenAddress) : null) !==
            (normalized.tokenAddress ? ethers.getAddress(normalized.tokenAddress) : null)
        ) {
          throw new Error("[Veridex x402 Actions] Challenge does not describe the exact normalized action.");
        }

        const sessionKeyHash = ethers.id(sessionAddr);
        const evidenceBuilder = new EvidenceBuilder(agentId, sessionKeyHash);

        // 1. Policy Gate Evaluation (<1ms)
        const evaluation = await policyGate.evaluate({
          recipient,
          amount,
          amountUSD,
          asset,
          chain,
          metadata: { actionName: action.name, input },
        });

        // 2a. Pre-Signature Enforcement Gate: Denial
        if (evaluation.verdict === "deny") {
          const denialBundle = evidenceBuilder.buildDenial({
            payload: { to: recipient, amount, asset, chain },
            evaluation,
          });
          const signedBundle = await signer.signBundle(denialBundle);
          if (onBundleEmitted) {
            await onBundleEmitted(signedBundle);
          }

          return {
            status: "POLICY_BLOCKED",
            blocked: true,
            reasons: evaluation.reasons,
            evidenceBundle: signedBundle,
            error: `[Veridex Policy Gate] Payment blocked: ${evaluation.reasons.join(", ")}`,
          };
        }

        const actionId = ethers.id(`${normalized.actionId}:${challenge.orderId}:${challenge.nonce}`);

        // 2b. Pre-Signature Enforcement Gate: Escalation. A durable approval
        // lookup may authorize this exact order/action pair; a boolean supplied
        // in the request body is never trusted.
        const approved = evaluation.verdict === "escalate" && options?.approvalVerifier
          ? await options.approvalVerifier({ approvalId: actionId, action: normalized, challenge, context })
          : false;
        if (evaluation.verdict === "escalate" && !approved) {
          const escalationBundle = evidenceBuilder.buildDenial({
            payload: { to: recipient, amount, asset, chain },
            evaluation,
          });
          const signedBundle = await signer.signBundle(escalationBundle);
          if (onBundleEmitted) {
            await onBundleEmitted(signedBundle);
          }

          return {
            status: "PENDING_APPROVAL",
            blocked: true,
            verdict: "escalate",
            approvalId: actionId,
            reasons: evaluation.reasons,
            evidenceBundle: signedBundle,
            error: `[Veridex Policy Gate] Payment requires human approval: ${evaluation.reasons.join(", ")}`,
          };
        }

        // VRD-2026-007 fix: Atomically reserve budget BEFORE the external action so
        // two concurrent x402 requests cannot both pass the same daily cap.
        // Consume the durable nonce immediately before reservation/execution.
        // Pending approvals therefore do not burn an invoice, while concurrent
        // approved attempts still have exactly one winner.
        const consumed = await verifyX402Challenge(challenge, {
          usedNonces, allowedMerchants, allowedMerchantOrigins, nonceStore, consumeNonce: true,
        });
        if (!consumed.valid) throw new Error(`[Veridex x402] Challenge consumption failed: ${consumed.reason}`);
        const reserved = await policyGate.reserve(actionId, amountUSD);
        if (!reserved) {
          const reservationBundle = await signer.signBundle(evidenceBuilder.buildDenial({
            payload: { to: recipient, amount, asset, chain },
            evaluation: {
              ...evaluation,
              verdict: "deny",
              reasons: [...evaluation.reasons, "Atomic budget reservation rejected the action"],
            },
          }));
          if (onBundleEmitted) await onBundleEmitted(reservationBundle);
          return {
            status: "POLICY_BLOCKED",
            blocked: true,
            reasons: ["Budget reservation failed: would exceed daily spending limit"],
            evidenceBundle: reservationBundle,
            error: "[Veridex x402] Budget reservation failed: would exceed daily spending limit",
          };
        }

        // 3. Delegate to original action execution.
        let result: any;
        let txHash: string | undefined;
        let settlement: VerifiedX402Settlement | undefined;
        let merchantConfirmation: { confirmed: boolean; receipt?: unknown; error?: string } = {
          confirmed: options?.settlementNotifier ? false : true,
        };
        let committed = false;
        let broadcastUncertain = false;
        try {
          if (challenge.scheme !== "exact") {
            if (!options?.paymentAuthorizer) {
              throw new Error(`[Veridex x402] Scheme '${challenge.scheme}' requires a payer authorization submitter`);
            }
            const authorization = await options.paymentAuthorizer({ action: normalized, challenge, context });
            if (authorization?.authorized !== true) {
              throw new Error("[Veridex x402] Merchant did not accept the payer authorization");
            }
          }
          result = await action.execute(input, context);
          txHash = typeof result?.txHash === "string" ? result.txHash : result?.settlementReceipt?.txHash;
          if (!txHash || !settlementVerifier) {
            throw new Error("[Veridex x402] An RPC-backed settlement verifier and transaction hash are required");
          }
          settlement = await settlementVerifier.verify({ txHash, action: normalized, challenge });

          // Convert the reservation into a committed spend now that the
          // transaction actually broadcast.
          await policyGate.commit(amountUSD, evaluation.evaluatedAt, actionId);
          committed = true;

          if (options?.settlementNotifier) {
            try {
              merchantConfirmation = await options.settlementNotifier({
                settlement,
                action: normalized,
                challenge,
                result,
              });
            } catch (error: any) {
              // The on-chain transfer is final and the spend is already
              // committed. Surface a retryable merchant-confirmation state;
              // never roll back policy accounting for an external callback.
              merchantConfirmation = {
                confirmed: false,
                error: error?.message || "Merchant settlement notification failed",
              };
            }
          }
        } catch (error) {
          if (error instanceof X402BroadcastUncertainError) {
            broadcastUncertain = true;
          }
          throw error;
        } finally {
          // If broadcast is uncertain, retain the reservation and trip the
          // breaker until reconciliation proves whether funds moved.
          if (!committed && !broadcastUncertain) {
            await policyGate.releaseReservation(actionId);
          }
        }

        // 4. Build & Sign Success Evidence Bundle
        const successBundle = evidenceBuilder.buildSuccess({
          payload: { to: recipient, amount, asset, chain },
          evaluation,
          settlementTxHash: txHash!,
        });

        const signedSuccessBundle = await signer.signBundle(successBundle);
        if (onBundleEmitted) {
          await onBundleEmitted(signedSuccessBundle);
        }

        return {
          status: merchantConfirmation.confirmed ? "SUCCESS" : "MERCHANT_CONFIRMATION_PENDING",
          result,
          txHash,
          settlementReceipt: settlement,
          merchantConfirmation,
          evidenceBundle: signedSuccessBundle,
        };
      },
    };
  });
}

/**
 * In-Path GOAT x402 Payment Interceptor class.
 */
export class VeridexGoatX402Payer {
  private policyGate: VeridexPolicyGate;
  private sessionSigner: SessionSigner;
  private agentId: string;
  private onBundleEmitted?: (bundle: EvidenceBundle) => void | Promise<void>;
  private security?: X402ExecutionSecurity;

  constructor(params: {
    agentId: string;
    policyRules: PolicyRuleConfig;
    sessionSigner?: SessionSigner;
    onBundleEmitted?: (bundle: EvidenceBundle) => void | Promise<void>;
    policyStateProvider?: PolicyStateProvider;
    security?: X402ExecutionSecurity;
  }) {
    this.agentId = params.agentId;
    this.policyGate = new VeridexPolicyGate(params.policyRules, params.policyStateProvider);
    this.sessionSigner = params.sessionSigner || new LocalSessionSigner();
    this.onBundleEmitted = params.onBundleEmitted;
    this.security = params.security;
  }

  public async executeX402Payment(
    challenge: X402Challenge,
    normalizedAction: NormalizedAction,
    walletAdapter: any,
    verificationOptions?: X402ExecutionSecurity,
  ): Promise<{
    authorization?: EIP3009Authorization;
    txHash?: string;
    evidenceBundle: EvidenceBundle;
  }> {
    assertNormalizedActionIntegrity(normalizedAction);
    const security = { ...this.security, ...verificationOptions };
    // VRD-2026-005 fix: Mandatory challenge verification before execution
    const verification = await verifyX402Challenge(challenge, {
      usedNonces: security.usedNonces,
      allowedMerchants: security.allowedMerchants,
      nonceStore: security.nonceStore,
      allowedMerchantOrigins: security.allowedMerchantOrigins,
      consumeNonce: false,
    });
    if (!verification.valid) {
      throw new Error(`[Veridex x402] Challenge verification failed: ${verification.reason}`);
    }

    if (
      ethers.getAddress(challenge.payer) !== ethers.getAddress(normalizedAction.from) ||
      ethers.getAddress(challenge.payTo) !== ethers.getAddress(normalizedAction.to) ||
      challenge.chain !== normalizedAction.chainId ||
      challenge.accepts.toUpperCase() !== normalizedAction.symbol.toUpperCase() ||
      challenge.amount !== normalizedAction.value.toString() ||
      (challenge.tokenAddress ? ethers.getAddress(challenge.tokenAddress) : null) !==
        (normalizedAction.tokenAddress ? ethers.getAddress(normalizedAction.tokenAddress) : null)
    ) {
      throw new Error("[Veridex x402] Challenge does not match the immutable normalized action.");
    }
    const amountUSD = normalizedAction.usdValue;

    const sessionAddr = await this.sessionSigner.getAddress();
    await assertX402SessionActive(sessionAddr, this.agentId, security);
    const sessionKeyHash = ethers.id(sessionAddr);
    const evidenceBuilder = new EvidenceBuilder(this.agentId, sessionKeyHash);

    const evaluation = await this.policyGate.evaluate(normalizedAction);

    if (evaluation.verdict === "deny") {
      const denialBundle = evidenceBuilder.buildDenial({
        payload: {
          to: challenge.payTo,
          amount: challenge.amount,
          asset: challenge.accepts,
          chain: challenge.chain,
        },
        evaluation,
      });

      const signedDenial = await this.sessionSigner.signBundle(denialBundle);
      if (this.onBundleEmitted) {
        await this.onBundleEmitted(signedDenial);
      }

      const error: any = new Error(`[Veridex x402 Policy Denial] Payment blocked: ${evaluation.reasons.join(", ")}`);
      error.evidenceBundle = signedDenial;
      error.denialBundle = signedDenial;
      throw error;
    }

    if (evaluation.verdict === "escalate") {
      const escalationBundle = evidenceBuilder.buildDenial({
        payload: {
          to: challenge.payTo,
          amount: challenge.amount,
          asset: challenge.accepts,
          chain: challenge.chain,
        },
        evaluation,
      });

      const signedBundle = await this.sessionSigner.signBundle(escalationBundle);
      if (this.onBundleEmitted) {
        await this.onBundleEmitted(signedBundle);
      }

      throw new HumanApprovalRequiredError(
        `[Veridex x402 Policy Escalation] Human approval required: ${evaluation.reasons.join(", ")}`,
        evaluation
      );
    }

    // VRD-2026-007 fix: reserve budget atomically, execute in try/finally, and
    // release on any non-committed exit.
    const actionId = ethers.id(`${normalizedAction.actionId}:${challenge.orderId}:${challenge.nonce}`);
    const consumed = await verifyX402Challenge(challenge, {
      usedNonces: security.usedNonces,
      allowedMerchants: security.allowedMerchants,
      nonceStore: security.nonceStore,
      allowedMerchantOrigins: security.allowedMerchantOrigins,
      consumeNonce: true,
    });
    if (!consumed.valid) throw new Error(`[Veridex x402] Challenge consumption failed: ${consumed.reason}`);
    const reserved = await this.policyGate.reserve(actionId, amountUSD);
    if (!reserved) {
      const reservationBundle = await this.sessionSigner.signBundle(evidenceBuilder.buildDenial({
        payload: {
          to: challenge.payTo,
          amount: challenge.amount,
          asset: challenge.accepts,
          chain: challenge.chain,
        },
        evaluation: {
          ...evaluation,
          verdict: "deny",
          reasons: [...evaluation.reasons, "Atomic budget reservation rejected the action"],
        },
      }));
      if (this.onBundleEmitted) await this.onBundleEmitted(reservationBundle);
      const error: any = new Error("[Veridex x402] Budget reservation failed: would exceed daily spending limit");
      error.evidenceBundle = reservationBundle;
      throw error;
    }

    let txHash: string | undefined;
    let settlement: VerifiedX402Settlement | undefined;
    let merchantConfirmation: { confirmed: boolean; receipt?: unknown; error?: string } = {
      confirmed: verificationOptions?.settlementNotifier || this.security?.settlementNotifier ? false : true,
    };
    let committed = false;
    let broadcastUncertain = false;
    try {
      if (challenge.scheme !== "exact") {
        if (!security.paymentAuthorizer) {
          throw new Error(`[Veridex x402] Scheme '${challenge.scheme}' requires a payer authorization submitter`);
        }
        const authorization = await security.paymentAuthorizer({ action: normalizedAction, challenge });
        if (authorization?.authorized !== true) {
          throw new Error("[Veridex x402] Merchant did not accept the payer authorization");
        }
      }
      if (walletAdapter && typeof walletAdapter.sendTransaction === "function") {
        const execution = TransactionDecoder.buildExecutionRequest(normalizedAction);
        const res = await walletAdapter.sendTransaction({ ...execution, _normalizedAction: normalizedAction });
        txHash = typeof res === "string" ? undefined : res?.hash;
      }

      if (!txHash) {
        throw new Error(
          "[Veridex x402] Wallet adapter did not return a transaction hash. " +
          "Cannot produce settlement evidence without a verified on-chain receipt."
        );
      }

      const settlementVerifier = verificationOptions?.settlementVerifier || this.security?.settlementVerifier;
      if (!settlementVerifier) throw new Error("[Veridex x402] RPC-backed settlement verifier is required");
      settlement = await settlementVerifier.verify({ txHash, action: normalizedAction, challenge });

      // Convert reservation to committed spend now that the tx broadcast.
      await this.policyGate.commit(amountUSD, evaluation.evaluatedAt, actionId);
      committed = true;

      const notifier = verificationOptions?.settlementNotifier || this.security?.settlementNotifier;
      if (notifier) {
        try {
          merchantConfirmation = await notifier({ settlement, action: normalizedAction, challenge, result: { txHash } });
        } catch (error: any) {
          merchantConfirmation = { confirmed: false, error: error?.message || "Merchant settlement notification failed" };
        }
      }
    } catch (error) {
      if (error instanceof X402BroadcastUncertainError) {
        broadcastUncertain = true;
      }
      throw error;
    } finally {
      if (!committed && !broadcastUncertain) {
        await this.policyGate.releaseReservation(actionId);
      }
    }

    const bundle = evidenceBuilder.buildSuccess({
      payload: {
        to: challenge.payTo,
        amount: challenge.amount,
        asset: challenge.accepts,
        chain: challenge.chain,
      },
      evaluation,
      settlementTxHash: txHash,
    });

    const signedBundle = await this.sessionSigner.signBundle(bundle);
    if (this.onBundleEmitted) {
      await this.onBundleEmitted(signedBundle);
    }

    return {
      txHash,
      evidenceBundle: signedBundle,
    };
  }
}

async function assertX402SessionActive(
  sessionAddress: string,
  agentId: string,
  security?: X402ExecutionSecurity,
): Promise<void> {
  if (!security?.sessionExpiresAt) {
    if (process.env.NODE_ENV === "production") throw new Error("[Veridex x402] Session expiry is required in production");
  } else if (Date.now() > security.sessionExpiresAt) {
    throw new SessionExpiredError(sessionAddress, security.sessionExpiresAt);
  }
  if (!security?.sessionRevocationProvider) {
    if (process.env.NODE_ENV === "production") throw new Error("[Veridex x402] Durable session revocation is required in production");
  } else if (await security.sessionRevocationProvider.isRevoked(sessionAddress, agentId)) {
    throw new Error(`[Veridex x402] Session key ${sessionAddress} is revoked`);
  }
  if (!security?.sessionAuthorizationVerifier) {
    if (process.env.NODE_ENV === "production") {
      throw new Error("[Veridex x402] Session-to-agent authorization verification is required in production");
    }
  } else if (!await security.sessionAuthorizationVerifier({ sessionAddress, agentId })) {
    throw new Error(`[Veridex x402] Session key ${sessionAddress} is not authorized for agent ${agentId}`);
  }
}
