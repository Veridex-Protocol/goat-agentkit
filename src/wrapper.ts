import { ethers } from "ethers";
import { VeridexPolicyGate, type PolicyStateProvider } from "./policy/gate.js";
import { PolicyRuleConfig } from "./policy/rules.js";
import { EvidenceBuilder } from "./evidence/builder.js";
import { LocalSessionSigner, SessionSigner } from "./evidence/signer.js";
import { AzureMaaAttestation } from "./attestation/azureMaa.js";
import { getGlobalRevocationList, type SessionRevocationProvider } from "./session/revocation.js";
import { assertExecutionMatchesNormalizedAction } from "./policy/decoder.js";
import type { NormalizedAction } from "./types/action.js";

export interface VeridexGoatConfig {
  agentId: string; // e.g. "erc8004:48816:1042"
  policyRules: PolicyRuleConfig;
  sessionSigner?: SessionSigner;
  teeAttestationEnabled?: boolean;
  onBundleEmitted?: (bundle: any) => void | Promise<void>;
  expiresAt?: number;
  /** Required for multi-replica production enforcement; use PostgresPolicyStateProvider. */
  policyStateProvider?: PolicyStateProvider;
  /** Required for multi-replica session revocation; use PostgresSessionRevocationProvider. */
  sessionRevocationProvider?: SessionRevocationProvider;
  /** Independent RPC verification required before direct-wrapper success evidence. */
  transactionVerifier?: (params: {
    txHash: string;
    action: NormalizedAction;
    result: unknown;
  }) => Promise<{ txHash: string; status: 1; blockNumber?: number; blockHash?: string }>;
  /** Persist and reconcile any operation that may have broadcast but could not be verified. */
  onTransactionUncertain?: (params: {
    txHash?: string;
    action: NormalizedAction;
    error: unknown;
  }) => void | Promise<void>;
}

export interface SessionCreationOptions {
  agentId: string;
  durationSeconds?: number;
  policyRules: PolicyRuleConfig;
  privateKey?: string;
  /** Preferred production path: KMS/HSM-backed signer with no exportable key. */
  sessionSigner?: SessionSigner;
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
    this.approvalId = `appr_${ethers.hexlify(ethers.randomBytes(32)).slice(2)}`;
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

export class WalletBroadcastUncertainError extends Error {
  constructor(public readonly txHash: string | undefined, message: string, options?: { cause?: unknown }) {
    super(txHash ? `${message} (transaction ${txHash})` : message, options);
    this.name = "WalletBroadcastUncertainError";
  }
}

/**
 * High-level helper encapsulating session key derivation for GOAT AgentKit developers.
 */
export async function createGoatAgentSession(options: SessionCreationOptions): Promise<ActiveSession> {
  const signer = options.sessionSigner || new LocalSessionSigner(options.privateKey);
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
  const policyGate = new VeridexPolicyGate(config.policyRules, config.policyStateProvider);
  const sessionRevocations = config.sessionRevocationProvider || getGlobalRevocationList();
  let activeSessionSigner = config.sessionSigner || new LocalSessionSigner();
  let sessionExpiresAt: number | undefined = config.expiresAt;

  // VD-GOAT-006 fix: Intercept ALL signing methods to prevent policy bypass
  const interceptedMethods = [
    "sendTransaction",
    "signTransaction",
    "transfer",
    "writeContract",
    "signMessage",
    "signTypedData",        // EIP-712 typed data signing
    "_signTypedData",       // ethers v6 internal method
    "sendRawTransaction",
    "estimateGas",
    "sendUserOperation",    // ERC-4337 Account Abstraction
    "signUserOperation",    // ERC-4337 AA signing
    "permit",               // ERC-2612 Permit
    "permit2",              // Uniswap Permit2
  ];

  const proxy = new Proxy(underlyingAdapter, {
    get(target, prop, receiver) {
      if (prop === "__rotateSession") {
        return (newSession: ActiveSession) => {
          activeSessionSigner = newSession.sessionSigner;
          sessionExpiresAt = newSession.expiresAt;
        };
      }

      // VD-GOAT-012 fix: Session revocation API
      if (prop === "__revokeSession") {
        return async (address?: string, reason?: string) => {
          const targetAddr = address || (await activeSessionSigner.getAddress());
          await sessionRevocations.revoke(targetAddr, reason, config.agentId);
          return { revoked: targetAddr, at: Date.now() };
        };
      }

      if (prop === "__isSessionRevoked") {
        return async (address?: string) => {
          const targetAddr = address || (await activeSessionSigner.getAddress());
          return sessionRevocations.isRevoked(targetAddr, config.agentId);
        };
      }

      if (typeof prop === "string" && interceptedMethods.includes(prop)) {
        return async (...args: any[]) => {
          // VD-GOAT-012 fix: Check session expiry
          if (sessionExpiresAt && Date.now() > sessionExpiresAt) {
            const addr = await activeSessionSigner.getAddress().catch(() => "unknown");
            throw new SessionExpiredError(addr, sessionExpiresAt);
          }

          // VD-GOAT-012 fix: Check session revocation
          const sessionAddr = await activeSessionSigner.getAddress().catch(() => null);
          if (sessionAddr) {
            if (await sessionRevocations.isRevoked(sessionAddr, config.agentId)) {
              throw new Error(
                `[Veridex Session Error] Session key ${sessionAddr} has been revoked and cannot be used`
              );
            }
          }

          const txPayload = args[0] || {};

          // A raw amountUSD is only an assertion supplied by the caller; it is
          // never sufficient to authorize a value-bearing operation. The exact
          // transaction must be bound to the immutable normalized action.
          const boundAction: NormalizedAction | undefined =
            txPayload?._normalizedAction || args[3]?._normalizedAction;

          if (prop === "signMessage") {
            throw new Error(
              "[Veridex Wallet Adapter] signMessage is disabled: an arbitrary personal signature cannot be bound to a normalized economic action."
            );
          }

          // VD-GOAT-006 fix: Handle different signing method types
          let recipient = txPayload.to || txPayload.recipient || "0x0000000000000000000000000000000000000000";
          let amount = txPayload.value || txPayload.amount || 0;
          let asset = txPayload.asset || "GOAT";
          const chain = typeof underlyingAdapter.getChainId === "function" ? await underlyingAdapter.getChainId() : 48816;

          // Handle EIP-712 signTypedData - extract value from typed data
          if (prop === "signTypedData" || prop === "_signTypedData") {
            const domain = args[0];
            const types = args[1];
            const value = args[2];

            // Common EIP-712 patterns: Permit, Permit2, UserOperation
            if (types.Permit || types.Permit2) {
              recipient = value.spender || value.to;
              amount = value.value || value.amount || 0;
            } else if (types.UserOperation) {
              recipient = value.sender;
              amount = value.callGasLimit || 0;
            }
          }

          // Handle ERC-4337 UserOperation
          if (prop === "sendUserOperation" || prop === "signUserOperation") {
            recipient = txPayload.sender || txPayload.target;
            amount = txPayload.callGasLimit || 0;
          }

          // Handle Permit/Permit2
          if (prop === "permit" || prop === "permit2") {
            recipient = txPayload.spender;
            amount = txPayload.value || txPayload.amount;
          }

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

          // Value-bearing methods must have one immutable normalized action.
          const VALUE_BEARING_METHODS = [
            "sendTransaction",
            "signTransaction",
            "transfer",
            "writeContract",
            "sendRawTransaction",
            "signTypedData",
            "_signTypedData",
            "sendUserOperation",
            "signUserOperation",
            "permit",
            "permit2",
          ];

          if (VALUE_BEARING_METHODS.includes(prop as string)) {
            if (!boundAction) {
              throw new Error(
                "[Veridex Wallet Adapter] Unbound value-bearing operation rejected. Supply an immutable _normalizedAction; amountUSD alone is not trusted."
              );
            }

            // Direct message and typed-data signing can grant authority that is
            // not representable by this transfer-only action type. Disable them
            // until they have their own exact normalizers.
            if (["signMessage", "signTransaction", "signTypedData", "_signTypedData", "sendUserOperation", "signUserOperation", "permit", "permit2", "writeContract"].includes(prop as string)) {
              throw new Error(
                `[Veridex Wallet Adapter] ${String(prop)} is disabled until an exact normalized action type is implemented for it.`
              );
            }

            if (["sendTransaction", "transfer", "sendRawTransaction"].includes(prop as string)) {
              assertExecutionMatchesNormalizedAction(boundAction, txPayload);
            }

            if (chain !== boundAction.chainId) {
              throw new Error(
                `[Veridex Wallet Adapter] ACTION_BINDING_ERROR: adapter chain ${chain} does not match normalized chain ${boundAction.chainId}`
              );
            }

            recipient = boundAction.to;
            amount = boundAction.value;
            asset = boundAction.symbol;
          }

          const amountUSD = boundAction?.usdValue;

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
                await config.onBundleEmitted(signedBundle);
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
                await config.onBundleEmitted(signedBundle);
              }
              throw new HumanApprovalRequiredError(
                `[Veridex Policy Escalation] Human approval required: ${evaluation.reasons.join(", ")}`,
                evaluation
              );
            }

            // 2c. Reserve only an allowed action. Denied/escalated actions must
            // still emit their signed evidence bundle and never needlessly
            // mutate spend state. The action identifier is stable across retries.
            const actionId = boundAction!.actionId;
            const reservationSuccess = await policyGate.reserve(actionId, amountUSD);
            if (!reservationSuccess) {
              const reservationDenial = evidenceBuilder.buildDenial({
                payload: { to: recipient, amount, asset, chain },
                evaluation: {
                  ...evaluation,
                  verdict: "deny",
                  reasons: [...evaluation.reasons, "Atomic budget reservation rejected the action"],
                },
              });
              const signedBundle = await activeSessionSigner.signBundle(reservationDenial);
              if (config.onBundleEmitted) {
                await config.onBundleEmitted(signedBundle);
              }
              throw new Error(`[Veridex Policy Denial] Budget reservation failed: would exceed an active policy limit`);
            }

            let committed = false;
            let operationMayHaveBroadcast = false;
            let observedTxHash: string | undefined;
            try {
              // 3. TEE Attestation Quote Fetch (If enabled)
              let teeAttestation;
              if (config.teeAttestationEnabled && evaluation.traceHash) {
                teeAttestation = await AzureMaaAttestation.getQuote(evaluation.traceHash);
              }

              // 4. Delegate Execution to Underlying Wallet Adapter
              if (!config.transactionVerifier &&
                  (process.env.NODE_ENV === "production" || process.env.STRICT_SETTLEMENT_VERIFICATION === "true")) {
                throw new Error("[Veridex Wallet Adapter] An independent transactionVerifier is required before broadcasting");
              }
              if (!config.onTransactionUncertain && process.env.NODE_ENV === "production") {
                throw new Error("[Veridex Wallet Adapter] A durable onTransactionUncertain reconciler is required before broadcasting");
              }
              let result;
              if (typeof target[prop] === "function") {
                // A generic wallet method may broadcast and then throw while
                // waiting for an RPC response. Once control crosses this
                // boundary, absence of a returned hash is not proof that no
                // funds moved; retain the reservation for reconciliation.
                operationMayHaveBroadcast = true;
                result = await target[prop](...args);
              } else {
                throw new Error(`Underlying wallet adapter function '${String(prop)}' is not invokable`);
              }

              const txHash = typeof result === "string" ? result : result?.hash;
              if (!txHash || !/^0x[a-fA-F0-9]{64}$/.test(txHash)) {
                throw new Error("[Veridex Wallet Adapter] Underlying operation returned no transaction hash");
              }
              observedTxHash = txHash;
              if (config.transactionVerifier) {
                const verified = await config.transactionVerifier({ txHash, action: boundAction!, result });
                if (verified.status !== 1 || verified.txHash.toLowerCase() !== txHash.toLowerCase()) {
                  throw new Error("[Veridex Wallet Adapter] RPC verification did not confirm the exact transaction");
                }
              }

              // Commit only after the independent verifier confirms settlement.
              await policyGate.commit(amountUSD, evaluation.evaluatedAt, actionId);
              committed = true;

              // 5. Build & Sign Complete Evidence Bundle
              const bundle = evidenceBuilder.buildSuccess({
                payload: { to: recipient, amount, asset, chain },
                evaluation,
                settlementTxHash: txHash,
                teeAttestation,
              });

              const signedBundle = await activeSessionSigner.signBundle(bundle);
              if (config.onBundleEmitted) {
                await config.onBundleEmitted(signedBundle);
              }
              return result;
            } catch (error) {
              if (operationMayHaveBroadcast) {
                await config.onTransactionUncertain?.({ txHash: observedTxHash, action: boundAction!, error });
                throw new WalletBroadcastUncertainError(
                  observedTxHash,
                  "[Veridex Wallet Adapter] Transaction outcome is uncertain; the policy reservation was retained for reconciliation",
                  { cause: error },
                );
              }
              throw error;
            } finally {
              if (!committed && !operationMayHaveBroadcast) {
                await policyGate.releaseReservation(actionId);
              }
            }
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
