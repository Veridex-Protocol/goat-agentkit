import { z } from "zod";

/**
 * VRD-2026-001 fix: A NormalizedAction is the single immutable description of an
 * intended value transfer. Policy evaluation and on-chain execution MUST both
 * consume the exact same frozen object so that "what policy approved" and "what
 * was broadcast" can never diverge.
 *
 * - `assetType` distinguishes a native-currency transfer (value is wei) from an
 *   ERC-20 transfer (value is token base units moved via `transfer()` calldata).
 * - `value` is always raw base units of the asset being moved. It is never
 *   recomputed from `usdValue`.
 * - `usdValue` is a trusted valuation derived from `value` + `decimals` + a
 *   registry price at decode time. It is advisory for policy only.
 * - `actionId` is a deterministic content hash over the immutable fields (no
 *   timestamp), suitable as a durable idempotency key.
 */
export const NormalizedActionSchema = z.object({
  actionId: z.string(),
  chainId: z.number().int().positive(),
  from: z.string().regex(/^0x[a-fA-F0-9]{40}$/),
  to: z.string().regex(/^0x[a-fA-F0-9]{40}$/),
  value: z.bigint(),
  assetType: z.enum(["native", "erc20"]),
  symbol: z.string(),
  tokenAddress: z.string().regex(/^0x[a-fA-F0-9]{40}$/).nullable(),
  calldataSelector: z.string(),
  decimals: z.number().int().min(0).max(36),
  priceUSD: z.number().nonnegative(),
  usdValue: z.number().nonnegative(),
  rawCalldata: z.string().optional(),
});

export type NormalizedAction = z.infer<typeof NormalizedActionSchema>;
