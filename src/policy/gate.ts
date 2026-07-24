import { PaymentContext, PolicyEvaluation, PolicyCheckResult, PolicyRuleConfig } from "./rules.js";
import { keccak256, toUtf8Bytes } from "ethers";

export class VeridexPolicyGate {
  private config: PolicyRuleConfig;
  private txTimestamps: number[] = [];
  private dailySpendUSD: number = 0;
  private lastSpendResetDay: number = new Date().getUTCDay();
  private lastTxTimestamp: number = 0;
  private isCircuitBreakerTripped: boolean = false;

  constructor(config: PolicyRuleConfig) {
    this.config = config;
  }

  public tripCircuitBreaker(): void {
    this.isCircuitBreakerTripped = true;
  }

  public resetCircuitBreaker(): void {
    this.isCircuitBreakerTripped = false;
  }

  public async evaluate(ctx: PaymentContext): Promise<PolicyEvaluation> {
    const evaluatedAt = Date.now();
    const checks: PolicyCheckResult[] = [];
    let riskScore = 0;

    // Reset daily spend if day changed
    const currentDay = new Date().getUTCDay();
    if (currentDay !== this.lastSpendResetDay) {
      this.dailySpendUSD = 0;
      this.lastSpendResetDay = currentDay;
    }

    const amountUSD = ctx.amountUSD ?? (typeof ctx.amount === "number" ? ctx.amount : Number(ctx.amount) / 1e6);

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
    if (this.config.allowedAssets && this.config.allowedAssets.length > 0) {
      const isAllowed = this.config.allowedAssets.includes(ctx.asset.toUpperCase());
      checks.push({
        ruleId: "asset-whitelist",
        ruleName: "Asset Whitelist",
        passed: isAllowed,
        verdict: isAllowed ? "pass" : "deny",
        reason: isAllowed ? `${ctx.asset} is an allowed asset` : `${ctx.asset} is not in allowed asset list`,
        riskContribution: isAllowed ? 0 : 100,
      });
    }

    // 2. Counterparty / Sanctions Check
    if (this.config.sanctionedRecipients && this.config.sanctionedRecipients.length > 0) {
      const recipientLower = ctx.recipient.toLowerCase();
      const isSanctioned = this.config.sanctionedRecipients.some(addr => addr.toLowerCase() === recipientLower);
      checks.push({
        ruleId: "counterparty-sanctions",
        ruleName: "Counterparty / Sanctions",
        passed: !isSanctioned,
        verdict: isSanctioned ? "deny" : "pass",
        reason: isSanctioned ? `Recipient ${ctx.recipient} is on sanctions / block list` : `Recipient ${ctx.recipient} clear of sanctions`,
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

    // Determine Circuit Breaker tripping post-evaluation
    if (this.config.circuitBreaker && this.config.circuitBreaker.tripOnHighRiskScore) {
      if (riskScore >= this.config.circuitBreaker.tripOnHighRiskScore) {
        this.isCircuitBreakerTripped = true;
        finalVerdict = "deny";
        reasons.push(`Circuit breaker tripped due to high risk score: ${riskScore}`);
      }
    }

    if (finalVerdict === "pass") {
      reasons.push("All policy checks passed");
      // Update running counters on pass
      this.txTimestamps.push(evaluatedAt);
      this.dailySpendUSD += amountUSD;
      this.lastTxTimestamp = evaluatedAt;
    }

    const canonicalInput = JSON.stringify({ ctx, checks, evaluatedAt, finalVerdict });
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
}
