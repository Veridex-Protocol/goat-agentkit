import { PaymentContext, PolicyEvaluation, PolicyCheckResult, PolicyRuleConfig } from "./rules.js";
import { keccak256, toUtf8Bytes } from "ethers";
import { canonicalizeJson } from "../evidence/builder.js";
import { safeStringify } from "../utils/serialize.js";
import { NormalizedAction } from "../types/action.js";
import * as fs from "fs";
import * as path from "path";
import { SignedStateFile } from "../utils/atomicFile.js";

export interface PolicyState {
  txTimestamps: number[];
  dailySpendUSD: number;
  lastSpendResetDay: number;
  lastTxTimestamp: number;
  isCircuitBreakerTripped: boolean;
  // VRD-2026-007 fix: durable reservations + processed idempotency keys
  reservations: Record<string, number>;
  processedActionIds: string[];
}

export interface PolicyStateProvider {
  loadState(): PolicyState | Promise<PolicyState>;
  saveState(state: PolicyState): void | Promise<void>;
}

/**
 * A shared provider can execute a mutation while holding a database row lock.
 * This is deliberately a separate interface: a file is durable but cannot make
 * a daily-cap reservation atomic across replicas.
 */
export interface TransactionalPolicyStateProvider extends PolicyStateProvider {
  transact<T>(mutate: (state: PolicyState) => { state: PolicyState; result: T }): Promise<T>;
}

export function createDefaultPolicyState(): PolicyState {
  return {
    txTimestamps: [],
    dailySpendUSD: 0,
    lastSpendResetDay: Math.floor(Date.now() / 86400000),
    lastTxTimestamp: 0,
    isCircuitBreakerTripped: false,
    reservations: {},
    processedActionIds: [],
  };
}

export function sanitizePolicyState(value: Partial<PolicyState> | undefined): PolicyState {
  const fallback = createDefaultPolicyState();
  if (!value || typeof value !== "object") return fallback;
  const dailySpendUSD = value.dailySpendUSD;
  const lastSpendResetDay = value.lastSpendResetDay;
  const lastTxTimestamp = value.lastTxTimestamp;
  return {
    txTimestamps: Array.isArray(value.txTimestamps) ? value.txTimestamps.filter(Number.isFinite).slice(-10_000) : [],
    dailySpendUSD: Number.isFinite(dailySpendUSD) && (dailySpendUSD as number) >= 0 ? dailySpendUSD as number : 0,
    lastSpendResetDay: Number.isSafeInteger(lastSpendResetDay) ? lastSpendResetDay as number : fallback.lastSpendResetDay,
    lastTxTimestamp: Number.isFinite(lastTxTimestamp) && (lastTxTimestamp as number) >= 0 ? lastTxTimestamp as number : 0,
    isCircuitBreakerTripped: value.isCircuitBreakerTripped === true,
    reservations: value.reservations && typeof value.reservations === "object"
      ? Object.fromEntries(Object.entries(value.reservations).filter(([key, amount]) => key.length <= 256 && Number.isFinite(amount) && amount >= 0))
      : {},
    processedActionIds: Array.isArray(value.processedActionIds)
      ? value.processedActionIds.filter((id): id is string => typeof id === "string" && id.length > 0 && id.length <= 256).slice(-10_000)
      : [],
  };
}

/**
 * VD-GOAT-011 fix: File-based policy state with atomic writes and integrity protection.
 */
export class FilePolicyStateProvider implements PolicyStateProvider {
  private stateFile: SignedStateFile<PolicyState>;

  constructor(filePath: string = "veridex-policy-state.json", secret?: string) {
    if (
      process.env.NODE_ENV === "production" &&
      process.env.POLICY_STATE_SINGLE_WRITER !== "true"
    ) {
      throw new Error(
        "FilePolicyStateProvider is single-process only in production. Use a transactional shared PolicyStateProvider, or explicitly set POLICY_STATE_SINGLE_WRITER=true for a verified one-replica deployment."
      );
    }
    this.stateFile = new SignedStateFile(path.resolve(filePath), secret);
  }

  public loadState(): PolicyState {
    // VD-GOAT-011 fix: Use signed state file with HMAC verification
    try {
      const state = this.stateFile.read();
      if (state) {
        return state;
      }
    } catch (error: any) {
      // VRD-2026-007 fix: Fail closed on corrupt state in production
      if (process.env.NODE_ENV === "production" || process.env.STRICT_STATE_PERSISTENCE === "true") {
        throw new Error(
          `[Policy State] CRITICAL: State file is corrupt or tampered. ` +
          `Refusing to start with default state to prevent limit bypass: ${error.message}`
        );
      }
      console.error(`[Policy State] State verification failed: ${error.message}. Using default state (dev mode only).`);
    }

    // Default state only if file doesn't exist yet (first run)
    return createDefaultPolicyState();
  }

  public saveState(state: any): void {
    try {
      this.stateFile.write(state);
    } catch (error: any) {
      console.error(`[Policy State] CRITICAL: Failed to persist state: ${error.message}`);
      if (process.env.NODE_ENV === "production" || process.env.STRICT_STATE_PERSISTENCE === "true") {
        throw new Error(`[Policy State] State persistence failure - refusing to continue without durable state: ${error.message}`);
      }
    }
  }
}

export class VeridexPolicyGate {
  private config: PolicyRuleConfig;
  private stateProvider?: PolicyStateProvider;
  private txTimestamps: number[] = [];
  private dailySpendUSD: number = 0;
  private lastSpendResetDay: number = Math.floor(Date.now() / 86400000);
  private lastTxTimestamp: number = 0;
  private isCircuitBreakerTripped: boolean = false;
  // VRD-2026-007 fix: reservations and processed action IDs are hydrated from and
  // persisted to durable state so they survive restarts and are not merely
  // instance-local, and so idempotency keys reject replays across processes.
  private reservedActionIds: Map<string, number> = new Map();
  private processedActionIds: Set<string> = new Set();
  private readonly readyPromise: Promise<void>;
  private mutationQueue: Promise<void> = Promise.resolve();

  constructor(config: PolicyRuleConfig, stateProvider?: PolicyStateProvider) {
    this.config = config;
    this.stateProvider = stateProvider || new FilePolicyStateProvider();
    this.readyPromise = this.loadState();
  }

  /** Wait for an asynchronous/shared provider to hydrate the policy state. */
  public async ready(): Promise<void> {
    await this.readyPromise;
  }

  private hydrateState(stateInput: Partial<PolicyState> | undefined): void {
    const state = sanitizePolicyState(stateInput);
    this.txTimestamps = state.txTimestamps;
    this.dailySpendUSD = state.dailySpendUSD;
    this.lastSpendResetDay = state.lastSpendResetDay;
    this.lastTxTimestamp = state.lastTxTimestamp;
    this.isCircuitBreakerTripped = state.isCircuitBreakerTripped;
    this.reservedActionIds = new Map(Object.entries(state.reservations));
    this.processedActionIds = new Set(state.processedActionIds);
  }

  private snapshotState(): PolicyState {
    const processed = Array.from(this.processedActionIds).slice(-10_000);
    this.processedActionIds = new Set(processed);
    return {
      txTimestamps: this.txTimestamps.slice(-10_000),
      dailySpendUSD: this.dailySpendUSD,
      lastSpendResetDay: this.lastSpendResetDay,
      lastTxTimestamp: this.lastTxTimestamp,
      isCircuitBreakerTripped: this.isCircuitBreakerTripped,
      reservations: Object.fromEntries(this.reservedActionIds),
      processedActionIds: processed,
    };
  }

  private async loadState(): Promise<void> {
    if (this.stateProvider) {
      this.hydrateState(await this.stateProvider.loadState());
    }
  }

  private async saveState(): Promise<void> {
    if (this.stateProvider) {
      await this.stateProvider.saveState(this.snapshotState());
    }
  }

  /** Serialize mutations for file/in-memory providers and use DB row locks when available. */
  private async mutate<T>(operation: () => T): Promise<T> {
    await this.ready();
    const transactional = this.stateProvider as TransactionalPolicyStateProvider | undefined;
    if (transactional && typeof transactional.transact === "function") {
      return transactional.transact((state) => {
        this.hydrateState(state);
        const result = operation();
        return { state: this.snapshotState(), result };
      });
    }

    let release!: () => void;
    const previous = this.mutationQueue;
    this.mutationQueue = new Promise<void>((resolve) => { release = resolve; });
    await previous;
    try {
      const result = operation();
      await this.saveState();
      return result;
    } finally {
      release();
    }
  }

  public async tripCircuitBreaker(): Promise<void> {
    await this.mutate(() => { this.isCircuitBreakerTripped = true; });
  }

  public async resetCircuitBreaker(): Promise<void> {
    await this.mutate(() => { this.isCircuitBreakerTripped = false; });
  }

  /**
   * Atomic reservation lock to prevent concurrent daily spend race conditions (CAS).
   */
  public async reserve(actionId: string, amountUSD: number): Promise<boolean> {
    if (!actionId || actionId.length > 256 || !Number.isFinite(amountUSD) || amountUSD < 0) {
      throw new Error("INVALID_RESERVATION: actionId and amountUSD are invalid.");
    }
    return this.mutate(() => {
      const currentDay = Math.floor(Date.now() / 86400000);
      if (currentDay !== this.lastSpendResetDay) {
        this.dailySpendUSD = 0;
        this.lastSpendResetDay = currentDay;
      }
      if (this.processedActionIds.has(actionId) || this.reservedActionIds.has(actionId)) {
        throw new Error(`DUPLICATE_ACTION: Action ${actionId} has already been processed or is in flight.`);
      }
      if (this.config.spendingLimits && this.dailySpendUSD + amountUSD > this.config.spendingLimits.maxDailyUSD) {
        return false;
      }
      this.dailySpendUSD += amountUSD;
      this.reservedActionIds.set(actionId, amountUSD);
      return true;
    });
  }

  public async releaseReservation(actionId: string): Promise<void> {
    await this.mutate(() => {
      const reservedAmount = this.reservedActionIds.get(actionId);
      if (reservedAmount !== undefined) {
        this.dailySpendUSD = Math.max(0, this.dailySpendUSD - reservedAmount);
        this.reservedActionIds.delete(actionId);
      }
    });
  }

  public async evaluate(ctxInput: PaymentContext | NormalizedAction): Promise<PolicyEvaluation> {
    await this.ready();
    const evaluatedAt = Date.now();
    const checks: PolicyCheckResult[] = [];
    let riskScore = 0;

    const ctx = ctxInput as any;
    const currentDay = Math.floor(evaluatedAt / 86400000);
    if (currentDay !== this.lastSpendResetDay) {
      this.dailySpendUSD = 0;
      this.lastSpendResetDay = currentDay;
    }

    const amountUSD = ctx.usdValue !== undefined ? ctx.usdValue : ctx.amountUSD;
    if (amountUSD === undefined || isNaN(amountUSD) || amountUSD < 0) {
      throw new Error("INVALID_AMOUNT: Cannot evaluate policy on missing, invalid, or negative amountUSD.");
    }

    const recipient = ctx.to || ctx.recipient || "0x0000000000000000000000000000000000000000";

    // 0. Circuit Breaker Check
    if (this.isCircuitBreakerTripped) {
      checks.push({
        ruleId: "circuit-breaker",
        ruleName: "Circuit Breaker",
        passed: false,
        verdict: "deny",
        reason: "Circuit breaker is active. All transactions are blocked.",
        riskContribution: 100,
      });
    }

    // 0.5. Time-Lock Cooldown Check
    if (this.config.timeLock && this.lastTxTimestamp > 0) {
      const timeSinceLast = evaluatedAt - this.lastTxTimestamp;
      const cooldownMs = this.config.timeLock.cooldownMs;
      const passed = timeSinceLast >= cooldownMs;
      checks.push({
        ruleId: "time-lock",
        ruleName: "Time-Lock Cooldown",
        passed,
        verdict: passed ? "pass" : "deny",
        reason: passed
          ? `Cooldown of ${cooldownMs}ms satisfied (time since last tx: ${timeSinceLast}ms)`
          : `Cooldown of ${cooldownMs}ms violated (time since last tx: ${timeSinceLast}ms)`,
        riskContribution: passed ? 0 : 90,
      });
    }

    // 1. Asset Whitelist Check
    const assetStr = ctx.symbol || ctx.asset || "GOAT";
    if (this.config.allowedAssets && this.config.allowedAssets.length > 0) {
      const isAllowed = this.config.allowedAssets.includes(assetStr.toUpperCase());
      checks.push({
        ruleId: "asset-whitelist",
        ruleName: "Asset Whitelist",
        passed: isAllowed,
        verdict: isAllowed ? "pass" : "deny",
        reason: isAllowed ? `${assetStr} is an allowed asset` : `${assetStr} is not in allowed asset list`,
        riskContribution: isAllowed ? 0 : 100,
      });
    }

    // 2. Counterparty / Sanctions Check
    if (this.config.sanctionedRecipients && this.config.sanctionedRecipients.length > 0) {
      const recipientLower = recipient.toLowerCase();
      const isSanctioned = this.config.sanctionedRecipients.some((addr: string) => addr.toLowerCase() === recipientLower);
      checks.push({
        ruleId: "counterparty-sanctions",
        ruleName: "Counterparty / Sanctions",
        passed: !isSanctioned,
        verdict: isSanctioned ? "deny" : "pass",
        reason: isSanctioned ? `Recipient ${recipient} is on sanctions / block list` : `Recipient ${recipient} clear of sanctions`,
        riskContribution: isSanctioned ? 100 : 0,
      });
    }

    // 3. Spending Limits (Per-Tx & Daily)
    if (this.config.spendingLimits) {
      const { maxPerTxUSD, maxDailyUSD } = this.config.spendingLimits;
      const perTxPassed = amountUSD <= maxPerTxUSD;
      const dailyPassed = (this.dailySpendUSD + amountUSD) <= maxDailyUSD;
      const passed = perTxPassed && dailyPassed;

      let reason = `USD $${amountUSD.toFixed(2)} within per-tx $${maxPerTxUSD} and daily $${maxDailyUSD} (spent today $${this.dailySpendUSD.toFixed(2)})`;
      if (!perTxPassed) {
        reason = `Amount $${amountUSD.toFixed(2)} exceeds per-tx limit $${maxPerTxUSD}`;
      } else if (!dailyPassed) {
        reason = `Amount $${amountUSD.toFixed(2)} exceeds daily limit $${maxDailyUSD} (spent today $${this.dailySpendUSD.toFixed(2)})`;
      }

      checks.push({
        ruleId: "spending-limit",
        ruleName: "Spending Limit",
        passed,
        verdict: passed ? "pass" : "deny",
        reason,
        riskContribution: passed ? (amountUSD > maxPerTxUSD * 0.5 ? 15 : 5) : 80,
      });
    }

    // 4. Velocity Check
    if (this.config.velocityLimit) {
      const oneHourAgo = evaluatedAt - 3600 * 1000;
      this.txTimestamps = this.txTimestamps.filter(t => t > oneHourAgo);
      const passed = this.txTimestamps.length < this.config.velocityLimit.maxTxPerHour;

      checks.push({
        ruleId: "velocity",
        ruleName: "Velocity Limit",
        passed,
        verdict: passed ? "pass" : "deny",
        reason: `${this.txTimestamps.length} tx in last hour (ceiling ${this.config.velocityLimit.maxTxPerHour}/hr)`,
        riskContribution: passed ? Math.min(15, this.txTimestamps.length * 2) : 90,
      });
    }

    // 5. Human Approval Threshold Check
    if (this.config.humanApprovalThresholdUSD) {
      const exceedsThreshold = amountUSD > this.config.humanApprovalThresholdUSD;
      checks.push({
        ruleId: "human-approval",
        ruleName: "Human Approval Threshold",
        passed: !exceedsThreshold,
        verdict: exceedsThreshold ? "escalate" : "pass",
        reason: exceedsThreshold
          ? `Amount $${amountUSD.toFixed(2)} exceeds human approval threshold of $${this.config.humanApprovalThresholdUSD}`
          : `Amount $${amountUSD.toFixed(2)} below $${this.config.humanApprovalThresholdUSD} escalation threshold`,
        riskContribution: exceedsThreshold ? 50 : 0,
      });
    }

    // Determine final verdict
    let finalVerdict: "pass" | "deny" | "escalate" = "pass";
    const reasons: string[] = [];

    for (const check of checks) {
      riskScore += check.riskContribution;
      if (check.verdict === "deny") {
        finalVerdict = "deny";
        reasons.push(check.reason);
      } else if (check.verdict === "escalate" && finalVerdict !== "deny") {
        finalVerdict = "escalate";
        reasons.push(check.reason);
      }
    }

    if (this.config.circuitBreaker && this.config.circuitBreaker.tripOnHighRiskScore) {
      if (riskScore >= this.config.circuitBreaker.tripOnHighRiskScore) {
        await this.mutate(() => { this.isCircuitBreakerTripped = true; });
        finalVerdict = "deny";
        reasons.push(`Circuit breaker tripped due to high risk score: ${riskScore}`);
      }
    }

    if (finalVerdict === "pass") {
      reasons.push("All policy checks passed");
    }

    const canonicalInput = canonicalizeJson({ ctx, checks, evaluatedAt, finalVerdict });
    const traceHash = keccak256(toUtf8Bytes(canonicalInput));

    return {
      verdict: finalVerdict,
      riskScore: Math.min(100, riskScore),
      reasons,
      checks,
      mandateVersion: "1.2.0",
      evaluatedAt,
      traceHash,
    };
  }

  public async commit(amountUSD: number, evaluatedAt: number = Date.now(), actionId?: string): Promise<void> {
    if (!Number.isFinite(amountUSD) || amountUSD < 0) throw new Error("INVALID_COMMIT: amountUSD is invalid.");
    await this.mutate(() => {
      const currentDay = Math.floor(evaluatedAt / 86400000);
      if (currentDay !== this.lastSpendResetDay) {
        this.dailySpendUSD = 0;
        this.lastSpendResetDay = currentDay;
      }

      this.txTimestamps.push(evaluatedAt);
      if (actionId && this.reservedActionIds.has(actionId)) {
        this.reservedActionIds.delete(actionId);
        this.processedActionIds.add(actionId);
      } else {
        this.dailySpendUSD += amountUSD;
      }
      this.lastTxTimestamp = evaluatedAt;
    });
  }
}
