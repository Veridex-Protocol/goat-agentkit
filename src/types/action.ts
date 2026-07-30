import { z } from "zod";

export const NormalizedActionSchema = z.object({
  actionId: z.string(),
  chainId: z.number().int().positive(),
  from: z.string().regex(/^0x[a-fA-F0-9]{40}$/),
  to: z.string().regex(/^0x[a-fA-F0-9]{40}$/),
  value: z.bigint(),
  tokenAddress: z.string().regex(/^0x[a-fA-F0-9]{40}$/).nullable(),
  calldataSelector: z.string(),
  decimals: z.number().int().min(0).max(36),
  usdValue: z.number().nonnegative(),
  rawCalldata: z.string().optional(),
});

export type NormalizedAction = z.infer<typeof NormalizedActionSchema>;
