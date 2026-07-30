import { ethers } from "ethers";
import { VeridexPolicyGate } from "./policy/gate.js";
import { PolicyRuleConfig } from "./policy/rules.js";
import { EvidenceBuilder } from "./evidence/builder.js";
import { LocalSessionSigner, SessionSigner } from "./evidence/signer.js";
import { AzureMaaAttestation } from "./attestation/azureMaa.js";

export interface VeridexGoatConfig {
  agentId: string; // e.g. "erc8004:48816:1042"
  policyRules: PolicyRuleConfig;
  sessionSigner?: SessionSigner;
  teeAttestationEnabled?: boolean;
  onBundleEmitted?: (bundle: any) => void;
  expiresAt?: number;
}

export interface SessionCreationOptions {
  agentId: string;
  durationSeconds?: number;
  policyRules: PolicyRuleConfig;
  privateKey?: string;
}

export interface ActiveSession {
  agentId: string;
  sessionSigner: SessionSigner;
  sessionAddress: string;
  expiresAt: number;
  policyRules: PolicyRuleConfig;
}

export class HumanApprovalRequiredError extends Error {
  public evaluation: any;
  public approvalId: string;

  constructor(message: string, evaluation: any) {
    super(message);
    this.name = "HumanApprovalRequiredError";
    this.evaluation = evaluation;
    this.approvalId = `appr_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`;
  }
}

export class SessionExpiredError extends Error {
  public sessionAddress: string;
  public expiresAt: number;

  constructor(sessionAddress: string, expiresAt: number) {
    super(`[Veridex Session Error] Session key ${sessionAddress} expired at ${new Date(expiresAt).toISOString()}`);
    this.name = "SessionExpiredError";
    this.sessionAddress = sessionAddress;
    this.expiresAt = expiresAt;
  }
}

/**
 * High-level helper encapsulating session key derivation for GOAT AgentKit developers.
 */
export async function createGoatAgentSession(options: SessionCreationOptions): Promise<ActiveSession> {
  const signer = new LocalSessionSigner(options.privateKey);
  const address = await signer.getAddress();
  const durationSeconds = options.durationSeconds || 86400; // Default 24 hours
  const expiresAt = Date.now() + durationSeconds * 1000;

  return {
    agentId: options.agentId,
    sessionSigner: signer,
    sessionAddress: address,
    expiresAt,
    policyRules: options.policyRules,
  };
}

/**
 * Dynamically updates the active session key on a wrapped wallet adapter without container restart.
 */
export function rotateSessionKey(wrappedAdapter: any, newSession: ActiveSession): void {
  if (wrappedAdapter && typeof wrappedAdapter.__rotateSession === "function") {
    wrappedAdapter.__rotateSession(newSession);
  }
}

const ERC20_INTERFACE = new ethers.Interface([
  "function transfer(address to, uint256 value)",
  "function transferFrom(address from, address to, uint256 value)",
  "function approve(address spender, uint256 value)"
]);

export function wrapWalletAdapter(
  underlyingAdapter: any,
  config: VeridexGoatConfig
): any {
  const policyGate = new VeridexPolicyGate(config.policyRules);
  let activeSessionSigner = config.sessionSigner || new LocalSessionSigner();
  let sessionExpiresAt: number | undefined = config.expiresAt;

  const interceptedMethods = [
    "sendTransaction",
    "signTransaction",
    "transfer",
    "writeContract",
    "signMessage",
    "sendRawTransaction",
    "estimateGas",
  ];

  const proxy = new Proxy(underlyingAdapter, {
    get(target, prop, receiver) {
      if (prop === "__rotateSession") {
        return (newSession: ActiveSession) => {
          activeSessionSigner = newSession.sessionSigner;
          sessionExpiresAt = newSession.expiresAt;
        };
      }

      if (typeof prop === "string" && interceptedMethods.includes(prop)) {
        return async (...args: any[]) => {
          if (sessionExpiresAt && Date.now() > sessionExpiresAt) {
            const addr = await activeSessionSigner.getAddress().catch(() => "unknown");
            throw new SessionExpiredError(addr, sessionExpiresAt);
          }

          const txPayload = args[0] || {};
          let recipient = txPayload.to || txPayload.recipient || "0x0000000000000000000000000000000000000000";
          let amount = txPayload.value || txPayload.amount || 0;
          let asset = txPayload.asset || "GOAT";
          const chain = typeof underlyingAdapter.getChainId === "function" ? await underlyingAdapter.getChainId() : 48816;

          if (txPayload.data && txPayload.data !== "0x") {
            try {
              const parsed = ERC20_INTERFACE.parseTransaction({ data: txPayload.data });
              if (parsed) {
                if (parsed.name === "transfer") {
                  recipient = parsed.args[0];
                  amount = parsed.args[1];
                } else if (parsed.name === "transferFrom") {
                  recipient = parsed.args[1];
                  amount = parsed.args[2];
                } else if (parsed.name === "approve") {
                  recipient = parsed.args[0];
                  amount = parsed.args[1];
                }
              }
            } catch (err) {
              // Ignore and fall back to original values
            }
          }

          const amountUSD = txPayload.amountUSD;
          if (amountUSD === undefined && (prop === "sendTransaction" || prop === "signTransaction" || prop === "transfer" || prop === "writeContract" || prop === "sendRawTransaction")) {
            throw new Error("[Veridex Wallet Adapter] Cannot determine transaction USD value: amountUSD must be explicitly provided in transaction payload.");
          }

          if (amountUSD !== undefined) {
            const sessionAddr = await activeSessionSigner.getAddress();
            const sessionKeyHash = ethers.id(sessionAddr);
            const evidenceBuilder = new EvidenceBuilder(config.agentId, sessionKeyHash);

            // 1. Policy Gate Evaluation (<1ms)
            const evaluation = await policyGate.evaluate({
              recipient,
              amount,
              amountUSD,
              asset,
              chain,
              metadata: { method: prop, txPayload },
            });

            // 2. Pre-Signature Enforcement Gate: Denial
            if (evaluation.verdict === "deny") {
              const denialBundle = evidenceBuilder.buildDenial({
                payload: { to: recipient, amount, asset, chain },
                evaluation,
              });
              const signedBundle = await activeSessionSigner.signBundle(denialBundle);
              if (config.onBundleEmitted) {
                config.onBundleEmitted(signedBundle);
              }
              throw new Error(`[Veridex Policy Denial] Payment blocked: ${evaluation.reasons.join(", ")}`);
            }

            // 2b. Pre-Signature Enforcement Gate: Escalation
            if (evaluation.verdict === "escalate") {
              const escalationBundle = evidenceBuilder.buildDenial({
                payload: { to: recipient, amount, asset, chain },
                evaluation,
              });
              const signedBundle = await activeSessionSigner.signBundle(escalationBundle);
              if (config.onBundleEmitted) {
                config.onBundleEmitted(signedBundle);
              }
              throw new HumanApprovalRequiredError(
                `[Veridex Policy Escalation] Human approval required: ${evaluation.reasons.join(", ")}`,
                evaluation
              );
            }

            // 3. TEE Attestation Quote Fetch (If enabled)
            let teeAttestation;
            if (config.teeAttestationEnabled && evaluation.traceHash) {
              teeAttestation = await AzureMaaAttestation.getQuote(evaluation.traceHash);
            }

            // 4. Delegate Execution to Underlying Wallet Adapter
            let result;
            if (typeof target[prop] === "function") {
              result = await target[prop](...args);
            } else {
              throw new Error(`Underlying wallet adapter function '${String(prop)}' is not invokable`);
            }

            const txHash = typeof result === "string" ? result : result?.hash;
            if (txHash) {
              // Commit policy limits now that transaction has successfully broadcasted
              policyGate.commit(amountUSD, evaluation.evaluatedAt);

              // 5. Build & Sign Complete Evidence Bundle
              const bundle = evidenceBuilder.buildSuccess({
                payload: { to: recipient, amount, asset, chain },
                evaluation,
                settlementTxHash: txHash,
                teeAttestation,
              });

              const signedBundle = await activeSessionSigner.signBundle(bundle);
              if (config.onBundleEmitted) {
                config.onBundleEmitted(signedBundle);
              }
            }

            return result;
          }

          if (typeof target[prop] === "function") {
            return await target[prop](...args);
          }
        };
      }
      return Reflect.get(target, prop, receiver);
    },
  });

  return proxy;
}

export const VeridexWalletAdapterWrapper = wrapWalletAdapter;
