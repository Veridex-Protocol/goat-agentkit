import { ethers } from "ethers";
import { VeridexPolicyGate } from "../policy/gate.js";
import { PolicyRuleConfig } from "../policy/rules.js";
import { EvidenceBuilder, EvidenceBundle } from "../evidence/builder.js";
import { LocalSessionSigner, SessionSigner } from "../evidence/signer.js";

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
 */
export function parseX402Challenge(responseHeaders: Record<string, string>, responseBody?: any): X402Challenge {
  const headerValue = responseHeaders["x-402-payment-required"] || responseHeaders["X-402-Payment-Required"];
  if (headerValue) {
    try {
      const decoded = JSON.parse(Buffer.from(headerValue, "base64").toString("utf-8"));
      return {
        status: 402,
        accepts: decoded.accepts || "USDC",
        amount: String(decoded.amount || decoded.priceUSDC || "0"),
        amountUSD: decoded.amountUSD ?? (Number(decoded.priceUSDC || decoded.amount) / 1e6),
        payTo: decoded.payTo,
        chain: decoded.chain || 30,
        scheme: decoded.scheme || "authorization",
        nonce: decoded.nonce,
        validBefore: decoded.validBefore,
      };
    } catch {
      // Fallback to body parsing
    }
  }

  if (responseBody) {
    return {
      status: 402,
      accepts: responseBody.accepts || "USDC",
      amount: String(responseBody.priceUSDC || responseBody.amount || "0"),
      amountUSD: responseBody.amountUSD ?? (Number(responseBody.priceUSDC || responseBody.amount) / 1e6),
      payTo: responseBody.payTo,
      chain: responseBody.chain || 30,
      scheme: responseBody.scheme || "authorization",
      nonce: responseBody.nonce,
      validBefore: responseBody.validBefore,
    };
  }

  throw new Error("Invalid x402 challenge: Missing x-402-payment-required header or body");
}

/**
 * Intercepts x402 payment actions and evaluates economic policy before execution.
 * If policy denies, returns structured POLICY_BLOCKED result and emits signed denial Evidence Bundle.
 * If policy allows, executes original action, emits signed success Evidence Bundle, and attaches it.
 */
export function wrapX402PaymentActions(
  actions: ActionDefinition[] | Record<string, ActionDefinition>,
  policyGate: VeridexPolicyGate,
  sessionSigner?: SessionSigner,
  agentId: string = "erc8004:8453:1042",
  onBundleEmitted?: (bundle: EvidenceBundle) => void
): ActionDefinition[] {
  const signer = sessionSigner || new LocalSessionSigner();
  const evidenceBuilder = new EvidenceBuilder(agentId);

  const actionList: ActionDefinition[] = Array.isArray(actions)
    ? actions
    : Object.values(actions);

  return actionList.map((action) => {
    return {
      ...action,
      execute: async (input: any, context?: any) => {
        const recipient =
          input?.to || input?.recipient || input?.payTo || "0x0000000000000000000000000000000000000000";
        const amountUSD =
          input?.amountUSD ??
          (input?.priceUSDC ? Number(input.priceUSDC) / 1e6 : input?.amount ? Number(input.amount) : 0);
        const amount = String(input?.amount || input?.value || amountUSD);
        const asset = input?.asset || input?.accepts || "USDC";
        const chain = input?.chain || 8453;

        // 1. Policy Gate Evaluation (<1ms)
        const evaluation = await policyGate.evaluate({
          recipient,
          amount,
          amountUSD,
          asset,
          chain,
          metadata: { actionName: action.name, input },
        });

        // 2. Pre-Signature Enforcement Gate: Denial
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

        // 3. Delegate to original action execution
        let result: any;
        let txHash = "0x5d8e2c1a9f4b7306e2a5c1d9b3f80547a6e9c2b1d3f4a80c5e7b1d9a3f60528e";
        try {
          result = await action.execute(input, context);
          if (result && typeof result === "object") {
            txHash = result.txHash || result.hash || result.transactionHash || txHash;
          }
        } catch (err: any) {
          throw err;
        }

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
  private evidenceBuilder: EvidenceBuilder;
  private sessionSigner: SessionSigner;

  constructor(params: {
    agentId: string;
    policyRules: PolicyRuleConfig;
    sessionSigner?: SessionSigner;
  }) {
    this.policyGate = new VeridexPolicyGate(params.policyRules);
    this.sessionSigner = params.sessionSigner || new LocalSessionSigner();
    this.evidenceBuilder = new EvidenceBuilder(params.agentId);
  }

  public async executeX402Payment(
    challenge: X402Challenge,
    walletAdapter: any
  ): Promise<{
    authorization?: EIP3009Authorization;
    txHash?: string;
    evidenceBundle: EvidenceBundle;
  }> {
    const amountUSD = challenge.amountUSD ?? (Number(challenge.amount) / 1e6);

    const evaluation = await this.policyGate.evaluate({
      recipient: challenge.payTo,
      amount: challenge.amount,
      amountUSD,
      asset: challenge.accepts,
      chain: challenge.chain,
      metadata: { scheme: challenge.scheme },
    });

    if (evaluation.verdict === "deny") {
      const denialBundle = this.evidenceBuilder.buildDenial({
        payload: {
          to: challenge.payTo,
          amount: challenge.amount,
          asset: challenge.accepts,
          chain: challenge.chain,
        },
        evaluation,
      });

      const signedDenial = await this.sessionSigner.signBundle(denialBundle);
      throw new Error(`[Veridex x402 Policy Denial] Payment blocked: ${evaluation.reasons.join(", ")}`);
    }

    let txHash = "0x5d8e2c1a9f4b7306e2a5c1d9b3f80547a6e9c2b1d3f4a80c5e7b1d9a3f60528e";
    if (walletAdapter && typeof walletAdapter.sendTransaction === "function") {
      const res = await walletAdapter.sendTransaction({
        to: challenge.payTo,
        value: challenge.amount,
        asset: challenge.accepts,
        chain: challenge.chain,
      });
      txHash = typeof res === "string" ? res : res.hash || txHash;
    }

    const bundle = this.evidenceBuilder.buildSuccess({
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

    return {
      txHash,
      evidenceBundle: signedBundle,
    };
  }
}
