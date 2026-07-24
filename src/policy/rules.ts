export interface PaymentContext {
  recipient: string;
  amount: bigint | string | number;
  amountUSD?: number;
  asset: string;
  chain: number;
  metadata?: Record<string, any>;
}

export interface PolicyCheckResult {
  ruleId: string;
  ruleName: string;
  passed: boolean;
  verdict: "pass" | "deny" | "escalate";
  reason: string;
  riskContribution: number;
}

export interface PolicyEvaluation {
  verdict: "pass" | "deny" | "escalate";
  riskScore: number;
  reasons: string[];
  checks: PolicyCheckResult[];
  mandateVersion: string;
  evaluatedAt: number;
  traceHash?: string;
}

export interface PolicyRuleConfig {
  spendingLimits?: {
    maxPerTxUSD: number;
    maxDailyUSD: number;
  };
  velocityLimit?: {
    maxTxPerHour: number;
  };
  sanctionedRecipients?: string[];
  allowedAssets?: string[];
  humanApprovalThresholdUSD?: number;
  timeLock?: {
    cooldownMs: number;
  };
  circuitBreaker?: {
    tripOnHighRiskScore?: number;
  };
}
