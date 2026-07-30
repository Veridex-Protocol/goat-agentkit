import { PaymentContext, PolicyEvaluation, PolicyCheckResult, PolicyRuleConfig } from "./rules.js";
import { keccak256, toUtf8Bytes } from "ethers";
import { canonicalizeJson } from "../evidence/builder.js";
import { safeStringify } from "../utils/serialize.js";
import { NormalizedAction } from "../types/action.js";
import * as fs from "fs";
import * as path from "path";

export interface PolicyStateProvider {
  loadState(): { txTimestamps: number[]; dailySpendUSD: number; lastSpendResetDay: number; lastTxTimestamp: number; isCircuitBreakerTripped: boolean };
  saveState(state: { txTimestamps: number[]; dailySpendUSD: number; lastSpendResetDay: number; lastTxTimestamp: number; isCircuitBreakerTripped: boolean }): void;
}

export class FilePolicyStateProvider implements PolicyStateProvider {
  private filePath: string;
  private saveTimeout: NodeJS.Timeout | null = null;

  constructor(filePath: string = "veridex-policy-state.json") {
    this.filePath = path.resolve(filePath);
  }

  public loadState() {
    try {
      if (fs.existsSync(this.filePath)) {
        const data = fs.readFileSync(this.filePath, "utf-8");
        return JSON.parse(data);
      }
    } catch (e) {
      // Fallback
    }
    return {
      txTimestamps: [],
      dailySpendUSD: 0,
      lastSpendResetDay: Math.floor(Date.now() / 86400000),
      lastTxTimestamp: 0,
      isCircuitBreakerTripped: false,
    };
  }

  public saveState(state: any): void {
    if (state.isCircuitBreakerTripped) {
      try {
        fs.writeFileSync(this.filePath, safeStringify(state, 2), "utf-8");
      } catch {}
      return;
    }

    if (this.saveTimeout) {
      clearTimeout(this.saveTimeout);
    }

    this.saveTimeout = setTimeout(() => {
      try {
        fs.promises.writeFile(this.filePath, safeStringify(state, 2), "utf-8").catch(() => {});
      } catch {}
    }, 50);
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
  private reservedActionIds: Map<string, number> = new Map();
  private processedActionIds: Set<string> = new Set();

  constructor(config: PolicyRuleConfig, stateProvider?: PolicyStateProvider) {
    this.config = config;
    this.stateProvider = stateProvider || new FilePolicyStateProvider();
    this.loadState();
  }

  private loadState(): void {
    if (this.stateProvider) {
      const state = this.stateProvider.loadState();
      this.txTimestamps = state.txTimestamps || [];
      this.dailySpendUSD = state.dailySpendUSD || 0;
      this.lastSpendResetDay = state.lastSpendResetDay ?? Math.floor(Date.now() / 86400000);
      this.lastTxTimestamp = state.lastTxTimestamp || 0;
      this.isCircuitBreakerTripped = state.isCircuitBreakerTripped || false;
    }
  }

  private saveState(): void {
    if (this.stateProvider) {
      this.stateProvider.saveState({
        txTimestamps: this.txTimestamps,
        dailySpendUSD: this.dailySpendUSD,
        lastSpendResetDay: this.lastSpendResetDay,
        lastTxTimestamp: this.lastTxTimestamp,
        isCircuitBreakerTripped: this.isCircuitBreakerTripped,
      });
    }
  }

  public tripCircuitBreaker(): void {
    this.isCircuitBreakerTripped = true;
    this.saveState();
  }

  public resetCircuitBreaker(): void {
    this.isCircuitBreakerTripped = false;
    this.saveState();
  }

  /**
   * Atomic reservation lock to prevent concurrent daily spend race conditions (CAS).
   */
  public reserve(actionId: string, amountUSD: number): boolean {
    if (this.processedActionIds.has(actionId)) {
      throw new Error(`DUPLICATE_ACTION: Action ${actionId} has already been processed.`);
    }

    if (this.config.spendingLimits) {
      const { maxDailyUSD } = this.config.spendingLimits;
      if (this.dailySpendUSD + amountUSD > maxDailyUSD) {
        return false;
      }
    }

    this.dailySpendUSD += amountUSD;
    this.reservedActionIds.set(actionId, amountUSD);
    this.saveState();
    return true;
  }

  public releaseReservation(actionId: string): void {
    const reservedAmount = this.reservedActionIds.get(actionId);
    if (reservedAmount !== undefined) {
      this.dailySpendUSD = Math.max(0, this.dailySpendUSD - reservedAmount);
      this.reservedActionIds.delete(actionId);
      this.saveState();
    }
  }

  public async evaluate(ctxInput: PaymentContext | NormalizedAction): Promise<PolicyEvaluation> {
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
    const assetStr = ctx.asset || "GOAT";
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
        this.isCircuitBreakerTripped = true;
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

  public commit(amountUSD: number, evaluatedAt: number = Date.now(), actionId?: string): void {
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
    this.saveState();
  }
}
