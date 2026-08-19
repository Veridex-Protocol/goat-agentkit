import { ethers } from "ethers";
import { NormalizedAction } from "../types/action.js";

/**
 * VRD-2026-001 fix: Asset identity is resolved from a chain + symbol allowlist,
 * never from caller-selected labels alone. Each entry fixes the decimals, the
 * trusted USD price, and whether the asset is the chain-native currency or an
 * ERC-20 token (which must have a known contract address).
 *
 * ERC-20 token contract addresses are intentionally NOT hard-coded: they must be
 * supplied per deployment (e.g. via env) and registered with `registerAsset()`.
 * An asset that is not in this registry cannot be decoded — the decoder fails
 * closed rather than guessing semantics.
 */
export interface AssetDefinition {
  symbol: string;
  decimals: number;
  priceUSD: number;
  native: boolean;
  /** Required for ERC-20 assets, must be null for native assets. */
  tokenAddress: string | null;
}

type AssetRegistry = Map<number, Map<string, AssetDefinition>>;

const ASSET_REGISTRY: AssetRegistry = new Map();

function key(symbol: string): string {
  return symbol.trim().toUpperCase();
}

export function registerAsset(chainId: number, def: AssetDefinition): void {
  if (!def.native && !def.tokenAddress) {
    throw new Error(`[AssetRegistry] ERC-20 asset ${def.symbol} requires a tokenAddress`);
  }
  if (def.native && def.tokenAddress) {
    throw new Error(`[AssetRegistry] native asset ${def.symbol} must not have a tokenAddress`);
  }
  if (!ASSET_REGISTRY.has(chainId)) {
    ASSET_REGISTRY.set(chainId, new Map());
  }
  ASSET_REGISTRY.get(chainId)!.set(key(def.symbol), {
    ...def,
    symbol: key(def.symbol),
    tokenAddress: def.tokenAddress ? ethers.getAddress(def.tokenAddress) : null,
  });
}

export function getAssetDefinition(chainId: number, symbol: string): AssetDefinition | undefined {
  return ASSET_REGISTRY.get(chainId)?.get(key(symbol));
}

/**
 * Seed the default GOAT Testnet3 (chainId 48816) registry. The chain-native
 * currency is BTC. Stablecoins are declared but left without a contract address:
 * they must be configured per deployment before they can be transferred, so the
 * demo fails closed instead of silently sending native value for a token label.
 */
function seedDefaultRegistry(): void {
  const GOAT_TESTNET3 = 48816;
  if (ASSET_REGISTRY.has(GOAT_TESTNET3)) return;
  registerAsset(GOAT_TESTNET3, { symbol: "BTC", decimals: 18, priceUSD: 96500.0, native: true, tokenAddress: null });
  registerAsset(GOAT_TESTNET3, { symbol: "GOAT", decimals: 18, priceUSD: 0.85, native: true, tokenAddress: null });

  // ERC-20 stablecoins: register a contract address per deployment if configured.
  const usdc = process.env.USDC_TOKEN_ADDRESS;
  const usdt = process.env.USDT_TOKEN_ADDRESS;
  if (usdc) registerAsset(GOAT_TESTNET3, { symbol: "USDC", decimals: 6, priceUSD: 1.0, native: false, tokenAddress: usdc });
  if (usdt) registerAsset(GOAT_TESTNET3, { symbol: "USDT", decimals: 6, priceUSD: 1.0, native: false, tokenAddress: usdt });
}
seedDefaultRegistry();

const ERC20_INTERFACE = new ethers.Interface([
  "function transfer(address to, uint256 value)",
  "function transferFrom(address from, address to, uint256 value)",
  "function approve(address spender, uint256 value)",
  "function transferWithAuthorization(address from, address to, uint256 value, uint256 validAfter, uint256 validBefore, bytes32 nonce, uint8 v, bytes32 r, bytes32 s)",
]);

const ERC20_TRANSFER_SELECTOR = ERC20_INTERFACE.getFunction("transfer")!.selector;

/**
 * Verifies that a transaction request is the exact request represented by a
 * NormalizedAction. This is intentionally narrow: an action which cannot be
 * represented exactly must be rejected rather than approximated by policy.
 */
export function assertExecutionMatchesNormalizedAction(
  action: NormalizedAction,
  request: { to?: string; value?: bigint | string | number; data?: string }
): void {
  const expected = TransactionDecoder.buildExecutionRequest(action);
  if (!request.to || ethers.getAddress(request.to) !== ethers.getAddress(expected.to)) {
    throw new Error("ACTION_BINDING_ERROR: transaction recipient/contract does not match normalized action");
  }

  let suppliedValue: bigint;
  try {
    suppliedValue = BigInt(request.value ?? 0);
  } catch {
    throw new Error("ACTION_BINDING_ERROR: transaction value is not an integer base-unit amount");
  }
  if (suppliedValue !== expected.value) {
    throw new Error("ACTION_BINDING_ERROR: transaction value does not match normalized action");
  }

  const suppliedData = request.data && request.data !== "0x" ? request.data.toLowerCase() : "0x";
  const expectedData = expected.data && expected.data !== "0x" ? expected.data.toLowerCase() : "0x";
  if (suppliedData !== expectedData) {
    throw new Error("ACTION_BINDING_ERROR: transaction calldata does not match normalized action");
  }
}

export class TransactionDecoder {
  /**
   * Produce a single immutable NormalizedAction. Callers pass a HUMAN amount
   * (e.g. "2.5") and an asset symbol; the decoder converts to base units using
   * the REGISTRY decimals (not caller-supplied) and computes usdValue from the
   * REGISTRY price. The returned object is frozen so no downstream code can
   * mutate the bound action between policy and execution.
   */
  public static decodeAndNormalize(params: {
    from: string;
    to: string;
    /** Human-readable amount, e.g. "2.5". For raw-calldata paths, `data` is decoded instead. */
    humanAmount?: string | number;
    /** Raw base units. Only accepted at the low-level boundary; prefer humanAmount. */
    rawValue?: string | bigint;
    data?: string;
    asset?: string;
    chainId?: number;
  }): NormalizedAction {
    const chainId = params.chainId || 48816;
    const fromAddr = ethers.getAddress(params.from);
    let toAddr = ethers.getAddress(params.to);
    let symbol = key(params.asset || "GOAT");

    // Resolve asset identity from the allowlist. Fail closed on unknown asset.
    const asset = getAssetDefinition(chainId, symbol);
    if (!asset) {
      throw new Error(
        `INVALID_ASSET: '${symbol}' is not an allowlisted asset on chain ${chainId}. ` +
        `Register it with a trusted decimals/price (and contract address for ERC-20) before use.`
      );
    }

    // Initialise defensively so TypeScript (and the runtime) have a defined
    // value even if a future calldata branch is added without an amount.
    let rawValueBigInt = 0n;
    let calldataSelector = "0x00000000";
    let tokenAddress: string | null = asset.native ? null : asset.tokenAddress;

    if (params.data && params.data !== "0x" && params.data.length >= 10) {
      // Calldata path: decode the ERC-20 call and bind to the token contract (`to`).
      calldataSelector = params.data.slice(0, 10);
      const parsed = ERC20_INTERFACE.parseTransaction({ data: params.data });
      if (!parsed) {
        throw new Error(`INVALID_TRANSACTION: Unknown selector ${calldataSelector}`);
      }
      if (asset.native) {
        throw new Error(`INVALID_TRANSACTION: calldata supplied for native asset ${symbol}`);
      }
      // The contract receiving calldata is part of the asset identity. Never
      // allow a caller to label an arbitrary contract as a trusted asset.
      if (!asset.tokenAddress || ethers.getAddress(asset.tokenAddress) !== toAddr) {
        throw new Error(
          `INVALID_TRANSACTION: token contract ${toAddr} does not match allowlisted ${symbol} contract ${asset.tokenAddress}`
        );
      }
      tokenAddress = asset.tokenAddress;

      // A transfer can be represented exactly by NormalizedAction. Approvals,
      // transferFrom, and authorization calls have distinct authority semantics
      // and must use dedicated normalized action types before they are enabled.
      if (parsed.name !== "transfer") {
        throw new Error(
          `UNSUPPORTED_TRANSACTION: ${parsed.name} is not supported by the transfer normalizer; refusing to reinterpret calldata`
        );
      }
      if (parsed.name === "transfer") {
        toAddr = ethers.getAddress(parsed.args[0]);
        rawValueBigInt = BigInt(parsed.args[1]);
      }
    } else if (params.humanAmount !== undefined) {
      // Human amount path: convert with registry decimals.
      try {
        rawValueBigInt = ethers.parseUnits(String(params.humanAmount), asset.decimals);
      } catch (err: any) {
        throw new Error(`INVALID_AMOUNT: '${params.humanAmount}' is not a valid ${symbol} amount (${err.message})`);
      }
    } else if (params.rawValue !== undefined) {
      rawValueBigInt = BigInt(params.rawValue);
    } else {
      rawValueBigInt = 0n;
    }

    if (rawValueBigInt < 0n) {
      throw new Error("INVALID_AMOUNT: Transaction value is negative");
    }

    const formattedAmount = Number(ethers.formatUnits(rawValueBigInt, asset.decimals));
    if (isNaN(formattedAmount) || formattedAmount < 0) {
      throw new Error("INVALID_AMOUNT: Transaction value is negative or NaN");
    }

    const usdValue = formattedAmount * asset.priceUSD;

    // Deterministic content hash over the immutable identity (no timestamp), so
    // it doubles as a durable idempotency key.
    const actionId = ethers.id(
      [
        chainId,
        fromAddr.toLowerCase(),
        toAddr.toLowerCase(),
        asset.native ? "native" : (tokenAddress || "").toLowerCase(),
        rawValueBigInt.toString(),
        calldataSelector,
        symbol,
      ].join(":")
    );

    return Object.freeze({
      actionId,
      chainId,
      from: fromAddr,
      to: toAddr,
      value: rawValueBigInt,
      assetType: asset.native ? "native" : "erc20",
      symbol,
      tokenAddress,
      calldataSelector,
      decimals: asset.decimals,
      priceUSD: asset.priceUSD,
      usdValue,
      rawCalldata: params.data,
    }) as NormalizedAction;
  }

  /**
   * VRD-2026-001 fix: Build the exact transaction request that MUST be broadcast
   * for a normalized action. Execution adapters consume this object and never
   * recompute value. For native assets the recipient receives `value` wei; for
   * ERC-20 assets a `transfer(recipient, value)` call is sent to the token
   * contract with zero native value.
   */
  public static buildExecutionRequest(action: NormalizedAction): { to: string; value: bigint; data: string } {
    if (action.assetType === "native") {
      return { to: action.to, value: action.value, data: "0x" };
    }
    if (!action.tokenAddress) {
      throw new Error(`EXECUTION_ERROR: ERC-20 action for ${action.symbol} has no token contract configured`);
    }
    if (action.calldataSelector !== "0x00000000" && action.calldataSelector !== ERC20_TRANSFER_SELECTOR) {
      throw new Error(
        `EXECUTION_ERROR: normalized ERC-20 action selector ${action.calldataSelector} is not an exact transfer`
      );
    }
    const data = ERC20_INTERFACE.encodeFunctionData("transfer", [action.to, action.value]);
    return { to: action.tokenAddress, value: 0n, data };
  }
}
