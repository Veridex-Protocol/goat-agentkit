import { VeridexPolicyGate } from "./policy/gate.js";
import { PolicyRuleConfig } from "./policy/rules.js";
import { EvidenceBuilder } from "./evidence/builder.js";
import { LocalSessionSigner, SessionSigner } from "./evidence/signer.js";
import { AzureMaaAttestation } from "./attestation/azureMaa.js";

export interface VeridexGoatConfig {
  agentId: string; // e.g. "erc8004:30:1042"
  policyRules: PolicyRuleConfig;
  sessionSigner?: SessionSigner;
  teeAttestationEnabled?: boolean;
  onBundleEmitted?: (bundle: any) => void;
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

import { ethers } from "ethers";

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

  const proxy = new Proxy(underlyingAdapter, {
    get(target, prop, receiver) {
      if (prop === "__rotateSession") {
        return (newSession: ActiveSession) => {
          activeSessionSigner = newSession.sessionSigner;
        };
      }

      if (prop === "sendTransaction" || prop === "signTransaction") {
        return async (...args: any[]) => {
          const txPayload = args[0] || {};
          let recipient = txPayload.to || txPayload.recipient || "0x0000000000000000000000000000000000000000";
          let amount = txPayload.value || txPayload.amount || 0;
          let asset = txPayload.asset || "GOAT";
          const chain = typeof underlyingAdapter.getChainId === "function" ? await underlyingAdapter.getChainId() : 30;

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
          if (amountUSD === undefined) {
            throw new Error("[Veridex Wallet Adapter] Cannot determine transaction USD value: amountUSD must be explicitly provided in transaction payload.");
          }

          const sessionAddr = await activeSessionSigner.getAddress();
          const sessionKeyHash = ethers.id(sessionAddr);
          const evidenceBuilder = new EvidenceBuilder(config.agentId, sessionKeyHash);

          // 1. Hot-Path Deterministic Policy Check (< 1ms)
          const evaluation = await policyGate.evaluate({
            recipient,
            amount,
            amountUSD,
            asset,
            chain,
            metadata: txPayload,
          });

          // 2. Pre-Signature Enforcement Gate
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

          // 3. TEE Attestation Quote Fetch (If enabled)
          let teeAttestation;
          if (config.teeAttestationEnabled && evaluation.traceHash) {
            teeAttestation = await AzureMaaAttestation.getQuote(evaluation.traceHash);
          }

          // 4. Delegate Signature to Underlying Wallet Adapter
          let result;
          if (typeof target[prop] === "function") {
            result = await target[prop](...args);
          } else {
            throw new Error("Underlying wallet adapter function is not invokable");
          }

          const txHash = typeof result === "string" ? result : result?.hash;
          if (!txHash) {
            throw new Error("Wallet adapter failed to return a valid transaction hash");
          }

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

          return result;
        };
      }
      return Reflect.get(target, prop, receiver);
    },
  });

  return proxy;
}

export const VeridexWalletAdapterWrapper = wrapWalletAdapter;
