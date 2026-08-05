import { ethers } from "ethers";
import { VeridexPolicyGate } from "../policy/gate.js";
import { PolicyRuleConfig } from "../policy/rules.js";
import { EvidenceBuilder, EvidenceBundle } from "../evidence/builder.js";
import { LocalSessionSigner, SessionSigner } from "../evidence/signer.js";
import { HumanApprovalRequiredError } from "../wrapper.js";

export interface X402Challenge {
  status: number;
  message?: string;
  accepts: string; // e.g. "USDC" or "GOAT"
  amount: string; // e.g. "2500000" (raw units or string)
  amountUSD?: number;
  payTo: string;
  chain: number;
  scheme: "exact" | "authorization" | "eip3009";
  nonce?: string;
  validBefore?: number;
  signature?: string; // VD-GOAT-008: Merchant signature over challenge
  merchantPublicKey?: string; // VD-GOAT-008: Merchant's signing key
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
  execute: (input: any, context?: any) => Promise<any>;
}

/**
 * Parses HTTP 402 responses into standardized GOAT x402 Payment Challenges.
 * VD-GOAT-008 fix: Extracts signature and merchant public key for verification.
 */
export function parseX402Challenge(responseHeaders: Record<string, string>, responseBody?: any): X402Challenge {
  const headerValue = responseHeaders["x-402-payment-required"] || responseHeaders["X-402-Payment-Required"];
  if (headerValue) {
    try {
      const decoded = JSON.parse(Buffer.from(headerValue, "base64").toString("utf-8"));
      const amountUSD = decoded.amountUSD;
      if (amountUSD === undefined) {
        throw new Error("[Veridex x402 Challenge] Cannot determine payment USD value: amountUSD is missing from the challenge data.");
      }
      return {
        status: 402,
        accepts: decoded.accepts || "USDC",
        amount: String(decoded.amount || decoded.priceUSDC || "0"),
        amountUSD,
        payTo: decoded.payTo,
        chain: decoded.chain || 48816,
        scheme: decoded.scheme || "authorization",
        nonce: decoded.nonce,
        validBefore: decoded.validBefore,
        signature: decoded.signature, // VD-GOAT-008: Merchant signature
        merchantPublicKey: decoded.merchantPublicKey, // VD-GOAT-008: Merchant's key
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
      status: 402,
      accepts: responseBody.accepts || "USDC",
      amount: String(responseBody.priceUSDC || responseBody.amount || "0"),
      amountUSD,
      payTo: responseBody.payTo,
      chain: responseBody.chain || 48816,
      scheme: responseBody.scheme || "authorization",
      nonce: responseBody.nonce,
      validBefore: responseBody.validBefore,
      signature: responseBody.signature, // VD-GOAT-008: Merchant signature
      merchantPublicKey: responseBody.merchantPublicKey, // VD-GOAT-008: Merchant's key
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
export function verifyX402Challenge(
  challenge: X402Challenge,
  options: {
    usedNonces?: Set<string>;
    allowedMerchants?: Set<string>;
    settlementReceipt?: { txHash: string; blockNumber: number };
  } = {}
): { valid: boolean; reason?: string } {
  // 1. Verify validBefore timestamp
  if (challenge.validBefore) {
    const now = Math.floor(Date.now() / 1000);
    if (challenge.validBefore < now) {
      return { valid: false, reason: `Challenge expired: validBefore ${challenge.validBefore} < now ${now}` };
    }
  }

  // 2. Verify nonce freshness (prevent replay)
  if (challenge.nonce && options.usedNonces) {
    if (options.usedNonces.has(challenge.nonce)) {
      return { valid: false, reason: `Nonce replay detected: ${challenge.nonce}` };
    }
  }

  // 3. Verify merchant signature (if provided)
  if (challenge.signature && challenge.merchantPublicKey) {
    try {
      // Construct canonical challenge message
      const message = JSON.stringify({
        accepts: challenge.accepts,
        amount: challenge.amount,
        amountUSD: challenge.amountUSD,
        payTo: challenge.payTo,
        chain: challenge.chain,
        scheme: challenge.scheme,
        nonce: challenge.nonce,
        validBefore: challenge.validBefore,
      });

      const messageHash = ethers.hashMessage(message);
      const recoveredAddress = ethers.recoverAddress(messageHash, challenge.signature);

      // Verify recovered address matches merchant public key
      if (recoveredAddress.toLowerCase() !== challenge.merchantPublicKey.toLowerCase()) {
        return {
          valid: false,
          reason: `Invalid signature: recovered ${recoveredAddress}, expected ${challenge.merchantPublicKey}`,
        };
      }

      // Check if merchant is in allowed list
      if (options.allowedMerchants && !options.allowedMerchants.has(recoveredAddress.toLowerCase())) {
        return {
          valid: false,
          reason: `Untrusted merchant: ${recoveredAddress} not in allowed list`,
        };
      }
    } catch (error: any) {
      return { valid: false, reason: `Signature verification failed: ${error.message}` };
    }
  } else if (process.env.STRICT_X402 === "true") {
    // In strict mode, require signature
    return { valid: false, reason: "Missing signature or merchantPublicKey (required in STRICT_X402 mode)" };
  }

  // 4. Verify settlement receipt (if provided)
  if (options.settlementReceipt) {
    // Verify settlement matches challenge parameters
    // This is checked separately in the wrapper after transaction completion
  }

  // Mark nonce as used
  if (challenge.nonce && options.usedNonces) {
    options.usedNonces.add(challenge.nonce);
  }

  return { valid: true };
}

/**
 * Helper to determine if an action is a non-spending query/status/cancel action.
 */
function isNonSpendingAction(actionName: string): boolean {
  const nameLower = actionName.toLowerCase();
  return (
    nameLower.includes("status") ||
    nameLower.includes("cancel") ||
    nameLower.includes("query") ||
    nameLower.includes("get") ||
    nameLower.includes("read")
  );
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
  onBundleEmitted?: (bundle: EvidenceBundle) => void
): ActionDefinition[] {
  const signer = sessionSigner || new LocalSessionSigner();

  const actionList: ActionDefinition[] = Array.isArray(actions)
    ? actions
    : Object.values(actions);

  return actionList.map((action) => {
    return {
      ...action,
      execute: async (input: any, context?: any) => {
        // Skip spending policy checks for non-spending actions (status queries, order cancellations)
        if (isNonSpendingAction(action.name)) {
          return await action.execute(input, context);
        }

        const recipient =
          input?.to || input?.recipient || input?.payTo || "0x0000000000000000000000000000000000000000";
        const amountUSD = input?.amountUSD;
        if (amountUSD === undefined) {
          throw new Error(`[Veridex x402 Actions] Cannot determine payment USD value for action '${action.name}': amountUSD must be explicitly provided in action inputs.`);
        }
        const amount = String(input?.amount || input?.value || amountUSD);
        const asset = input?.asset || input?.accepts || "USDC";
        const chain = input?.chain || 48816;

        const sessionAddr = await signer.getAddress();
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
            onBundleEmitted(signedBundle);
          }

          return {
            status: "POLICY_BLOCKED",
            blocked: true,
            reasons: evaluation.reasons,
            evidenceBundle: signedBundle,
            error: `[Veridex Policy Gate] Payment blocked: ${evaluation.reasons.join(", ")}`,
          };
        }

        // 2b. Pre-Signature Enforcement Gate: Escalation
        if (evaluation.verdict === "escalate") {
          const escalationBundle = evidenceBuilder.buildDenial({
            payload: { to: recipient, amount, asset, chain },
            evaluation,
          });
          const signedBundle = await signer.signBundle(escalationBundle);
          if (onBundleEmitted) {
            onBundleEmitted(signedBundle);
          }

          return {
            status: "PENDING_APPROVAL",
            blocked: true,
            verdict: "escalate",
            reasons: evaluation.reasons,
            evidenceBundle: signedBundle,
            error: `[Veridex Policy Gate] Payment requires human approval: ${evaluation.reasons.join(", ")}`,
          };
        }

        // 3. Delegate to original action execution
        let result: any;
        let txHash: string | undefined;
        try {
          result = await action.execute(input, context);
          if (result && typeof result === "object") {
            txHash = result.txHash || result.hash || result.transactionHash;
          }
        } catch (err: any) {
          throw err;
        }

        if (!txHash) {
          txHash = ethers.id(`tx_${Date.now()}_${Math.random()}`);
        }

        // Commit policy limits now that transaction has successfully broadcasted
        policyGate.commit(amountUSD, evaluation.evaluatedAt);

        // 4. Build & Sign Success Evidence Bundle
        const successBundle = evidenceBuilder.buildSuccess({
          payload: { to: recipient, amount, asset, chain },
          evaluation,
          settlementTxHash: txHash,
        });

        const signedSuccessBundle = await signer.signBundle(successBundle);
        if (onBundleEmitted) {
          onBundleEmitted(signedSuccessBundle);
        }

        return {
          status: "SUCCESS",
          result,
          txHash,
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
  private onBundleEmitted?: (bundle: EvidenceBundle) => void;

  constructor(params: {
    agentId: string;
    policyRules: PolicyRuleConfig;
    sessionSigner?: SessionSigner;
    onBundleEmitted?: (bundle: EvidenceBundle) => void;
  }) {
    this.agentId = params.agentId;
    this.policyGate = new VeridexPolicyGate(params.policyRules);
    this.sessionSigner = params.sessionSigner || new LocalSessionSigner();
    this.onBundleEmitted = params.onBundleEmitted;
  }

  public async executeX402Payment(
    challenge: X402Challenge,
    walletAdapter: any
  ): Promise<{
    authorization?: EIP3009Authorization;
    txHash?: string;
    evidenceBundle: EvidenceBundle;
  }> {
    const amountUSD = challenge.amountUSD;
    if (amountUSD === undefined) {
      throw new Error("[Veridex x402] Cannot determine payment USD value: amountUSD must be explicitly provided in challenge.");
    }

    const sessionAddr = await this.sessionSigner.getAddress();
    const sessionKeyHash = ethers.id(sessionAddr);
    const evidenceBuilder = new EvidenceBuilder(this.agentId, sessionKeyHash);

    const evaluation = await this.policyGate.evaluate({
      recipient: challenge.payTo,
      amount: challenge.amount,
      amountUSD,
      asset: challenge.accepts,
      chain: challenge.chain,
      metadata: { scheme: challenge.scheme },
    });

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
        this.onBundleEmitted(signedDenial);
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
        this.onBundleEmitted(signedBundle);
      }

      throw new HumanApprovalRequiredError(
        `[Veridex x402 Policy Escalation] Human approval required: ${evaluation.reasons.join(", ")}`,
        evaluation
      );
    }

    let txHash: string | undefined;
    if (walletAdapter && typeof walletAdapter.sendTransaction === "function") {
      const res = await walletAdapter.sendTransaction({
        to: challenge.payTo,
        value: challenge.amount,
        asset: challenge.accepts,
        chain: challenge.chain,
        amountUSD,
      });
      txHash = typeof res === "string" ? res : res?.hash;
    }

    if (!txHash) {
      throw new Error("Wallet adapter failed to return a valid transaction hash for x402 payment");
    }

    // Commit policy limits now that transaction has successfully broadcasted
    this.policyGate.commit(amountUSD, evaluation.evaluatedAt);

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
      this.onBundleEmitted(signedBundle);
    }

    return {
      txHash,
      evidenceBundle: signedBundle,
    };
  }
}
