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
  /** Exact policy valuation in millionths of one USD. */
  priceUSDMicros?: bigint;
  native: boolean;
  /** Required for ERC-20 assets, must be null for native assets. */
  tokenAddress: string | null;
  /** Unix seconds for the signed/operator-pinned price observation. */
  priceUpdatedAt?: number;
  priceSource?: string;
  maxPriceAgeSeconds?: number;
}

type AssetRegistry = Map<number, Map<string, AssetDefinition>>;

const ASSET_REGISTRY: AssetRegistry = new Map();

function key(symbol: string): string {
  return symbol.trim().toUpperCase();
}

export function registerAsset(chainId: number, def: AssetDefinition): void {
  if (!Number.isSafeInteger(chainId) || chainId <= 0 || !/^[A-Za-z0-9]{2,16}$/.test(def.symbol) ||
      !Number.isSafeInteger(def.decimals) || def.decimals < 0 || def.decimals > 36) {
    throw new Error("[AssetRegistry] chain, symbol, and decimals must be canonical");
  }
  if (!Number.isFinite(def.priceUSD) || def.priceUSD <= 0 || def.priceUSD > 1_000_000_000) {
    throw new Error(`[AssetRegistry] ${def.symbol} priceUSD must be finite and positive`);
  }
  const priceUpdatedAt = def.priceUpdatedAt ?? Math.floor(Date.now() / 1000);
  const priceSource = def.priceSource || (process.env.NODE_ENV === "production" ? "" : "development-static");
  const maxPriceAgeSeconds = def.maxPriceAgeSeconds ?? 300;
  if (!Number.isSafeInteger(priceUpdatedAt) || priceUpdatedAt <= 0 || !priceSource) {
    throw new Error(`[AssetRegistry] ${def.symbol} requires priceUpdatedAt and priceSource`);
  }
  if (!Number.isSafeInteger(maxPriceAgeSeconds) || maxPriceAgeSeconds < 1 || maxPriceAgeSeconds > 86_400) {
    throw new Error(`[AssetRegistry] ${def.symbol} maxPriceAgeSeconds must be 1-86400`);
  }
  const priceUSDMicros = def.priceUSDMicros ?? BigInt(Math.round(def.priceUSD * 1_000_000));
  if (priceUSDMicros <= 0n || priceUSDMicros > 1_000_000_000_000_000n) {
    throw new Error(`[AssetRegistry] ${def.symbol} exact USD-micros price is outside the supported range`);
  }
  if (!def.native && !def.tokenAddress) {
    throw new Error(`[AssetRegistry] ERC-20 asset ${def.symbol} requires a tokenAddress`);
  }
  if (def.native && def.tokenAddress) {
    throw new Error(`[AssetRegistry] native asset ${def.symbol} must not have a tokenAddress`);
  }
  if (!ASSET_REGISTRY.has(chainId)) {
    ASSET_REGISTRY.set(chainId, new Map());
  }
  const normalizedSymbol = key(def.symbol);
  const normalizedToken = def.tokenAddress ? ethers.getAddress(def.tokenAddress) : null;
  const existing = ASSET_REGISTRY.get(chainId)!.get(normalizedSymbol);
  if (existing && (existing.native !== def.native || existing.decimals !== def.decimals ||
      existing.tokenAddress !== normalizedToken)) {
    throw new Error(`[AssetRegistry] Refusing to change the on-chain identity of ${normalizedSymbol} on chain ${chainId}`);
  }
  ASSET_REGISTRY.get(chainId)!.set(normalizedSymbol, Object.freeze({
    ...def,
    priceUSD: Number(priceUSDMicros) / 1_000_000,
    priceUSDMicros,
    symbol: normalizedSymbol,
    tokenAddress: normalizedToken,
    priceUpdatedAt,
    priceSource,
    maxPriceAgeSeconds,
  }));
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
  const isProduction = process.env.NODE_ENV === "production";
  const price = (symbol: string, fallback: number) => {
    const raw = process.env[`${symbol}_PRICE_USD`];
    const timestamp = Number(process.env[`${symbol}_PRICE_UPDATED_AT`] || "0");
    const source = process.env[`${symbol}_PRICE_SOURCE`];
    if (isProduction && (!raw || !timestamp || !source)) return undefined;
    return {
      priceUSD: raw ? Number(raw) : fallback,
      priceUpdatedAt: timestamp || Math.floor(Date.now() / 1000),
      priceSource: source || "development-static",
      maxPriceAgeSeconds: Number(process.env.PRICE_MAX_AGE_SECONDS || "300"),
    };
  };
  const btc = price("BTC", 96500.0);
  if (btc) registerAsset(GOAT_TESTNET3, { symbol: "BTC", decimals: 18, native: true, tokenAddress: null, ...btc });

  // ERC-20 stablecoins: register a contract address per deployment if configured.
  const usdc = process.env.USDC_TOKEN_ADDRESS;
  const usdt = process.env.USDT_TOKEN_ADDRESS;
  const goat = process.env.GOAT_TOKEN_ADDRESS;
  const usdcPrice = price("USDC", 1);
  const usdtPrice = price("USDT", 1);
  const goatPrice = price("GOAT", 0.85);
  if (usdc && usdcPrice) registerAsset(GOAT_TESTNET3, { symbol: "USDC", decimals: 6, native: false, tokenAddress: usdc, ...usdcPrice });
  if (usdt && usdtPrice) registerAsset(GOAT_TESTNET3, { symbol: "USDT", decimals: 6, native: false, tokenAddress: usdt, ...usdtPrice });
  if (goat && goatPrice) registerAsset(GOAT_TESTNET3, { symbol: "GOAT", decimals: 18, native: false, tokenAddress: goat, ...goatPrice });
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
 * Re-derive every policy-relevant field from the trusted asset registry. A
 * TypeScript object is not a security boundary: callers can otherwise forge a
 * low `usdValue` while keeping transaction bytes that move a much larger value.
 */
export function assertNormalizedActionIntegrity(action: NormalizedAction): void {
  if (!action || typeof action !== "object" || !Object.isFrozen(action)) {
    throw new Error("ACTION_BINDING_ERROR: normalized action must be an immutable decoder result");
  }
  if (!Number.isSafeInteger(action.chainId) || action.chainId <= 0 || typeof action.value !== "bigint" || action.value < 0n) {
    throw new Error("ACTION_BINDING_ERROR: normalized chain or value is invalid");
  }
  const symbol = key(action.symbol);
  const operationPattern = /^(?:0x[a-fA-F0-9]{64}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12})$/;
  if ((process.env.NODE_ENV === "production" && !action.operationId) ||
      (action.operationId !== undefined && !operationPattern.test(action.operationId))) {
    throw new Error("ACTION_BINDING_ERROR: production actions require a random UUID or bytes32 operationId");
  }
  const asset = getAssetDefinition(action.chainId, symbol);
  if (!asset) throw new Error(`ACTION_BINDING_ERROR: ${symbol} is not registered on chain ${action.chainId}`);
  const from = ethers.getAddress(action.from);
  const recipient = ethers.getAddress(action.to);
  const expectedAssetType = asset.native ? "native" : "erc20";
  const expectedToken = asset.tokenAddress ? ethers.getAddress(asset.tokenAddress) : null;
  const suppliedToken = action.tokenAddress ? ethers.getAddress(action.tokenAddress) : null;
  if (action.assetType !== expectedAssetType || suppliedToken !== expectedToken || action.decimals !== asset.decimals) {
    throw new Error("ACTION_BINDING_ERROR: normalized asset identity does not match the trusted registry");
  }
  if (action.priceUSDMicros !== asset.priceUSDMicros || action.priceUpdatedAt !== asset.priceUpdatedAt ||
      action.priceSource !== asset.priceSource) {
    throw new Error("ACTION_BINDING_ERROR: normalized valuation is not the current trusted registry snapshot");
  }
  const now = Math.floor(Date.now() / 1000);
  if (action.priceUpdatedAt > now + 30 || now - action.priceUpdatedAt > asset.maxPriceAgeSeconds!) {
    throw new Error("ACTION_BINDING_ERROR: normalized valuation is stale or future-dated");
  }
  const expectedUsdMicros = (action.value * asset.priceUSDMicros!) / (10n ** BigInt(asset.decimals));
  if (expectedUsdMicros > BigInt(Number.MAX_SAFE_INTEGER) || action.usdMicros !== expectedUsdMicros ||
      action.usdValue !== Number(expectedUsdMicros) / 1_000_000 ||
      action.priceUSD !== Number(asset.priceUSDMicros!) / 1_000_000) {
    throw new Error("ACTION_BINDING_ERROR: normalized USD valuation was forged or corrupted");
  }
  const expectedSelector = asset.native ? "0x00000000" :
    (action.calldataSelector === "0x00000000" ? "0x00000000" : ERC20_TRANSFER_SELECTOR);
  if (action.calldataSelector !== expectedSelector) {
    throw new Error("ACTION_BINDING_ERROR: normalized selector is not an exact transfer");
  }
  if (action.rawCalldata && action.rawCalldata !== "0x") {
    if (asset.native || action.rawCalldata.toLowerCase() !==
        ERC20_INTERFACE.encodeFunctionData("transfer", [recipient, action.value]).toLowerCase()) {
      throw new Error("ACTION_BINDING_ERROR: normalized raw calldata is not the canonical transfer");
    }
  }
  const expectedActionId = ethers.id([
    action.chainId,
    from.toLowerCase(),
    recipient.toLowerCase(),
    asset.native ? "native" : expectedToken!.toLowerCase(),
    action.value.toString(),
    action.calldataSelector,
    symbol,
    action.operationId || "content-only-development",
  ].join(":"));
  if (action.actionId.toLowerCase() !== expectedActionId.toLowerCase()) {
    throw new Error("ACTION_BINDING_ERROR: normalized action identifier is invalid");
  }
}

/**
 * Verifies that a transaction request is the exact request represented by a
 * NormalizedAction. This is intentionally narrow: an action which cannot be
 * represented exactly must be rejected rather than approximated by policy.
 */
export function assertExecutionMatchesNormalizedAction(
  action: NormalizedAction,
  request: { to?: string; value?: bigint | string | number; data?: string }
): void {
  assertNormalizedActionIntegrity(action);
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
    /** Random UUID/bytes32 supplied by the durable request boundary. */
    operationId?: string;
  }): NormalizedAction {
    const chainId = params.chainId || 48816;
    const fromAddr = ethers.getAddress(params.from);
    let toAddr = ethers.getAddress(params.to);
    let symbol = key(params.asset || "GOAT");
    const operationPattern = /^(?:0x[a-fA-F0-9]{64}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12})$/;
    if ((process.env.NODE_ENV === "production" && !params.operationId) ||
        (params.operationId !== undefined && !operationPattern.test(params.operationId))) {
      throw new Error("INVALID_OPERATION_ID: production actions require a random UUID or bytes32 operationId");
    }

    // Resolve asset identity from the allowlist. Fail closed on unknown asset.
    const asset = getAssetDefinition(chainId, symbol);
    if (!asset) {
      throw new Error(
        `INVALID_ASSET: '${symbol}' is not an allowlisted asset on chain ${chainId}. ` +
        `Register it with a trusted decimals/price (and contract address for ERC-20) before use.`
      );
    }
    const nowSeconds = Math.floor(Date.now() / 1000);
    const priceUpdatedAt = asset.priceUpdatedAt!;
    if ((process.env.NODE_ENV === "production" || process.env.STRICT_PRICE_FRESHNESS === "true") &&
        (priceUpdatedAt > nowSeconds + 30 || nowSeconds - priceUpdatedAt > asset.maxPriceAgeSeconds!)) {
      throw new Error(`STALE_PRICE: ${symbol} price from ${asset.priceSource} is outside the freshness window`);
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

    const priceUSDMicros = asset.priceUSDMicros!;
    const usdMicros = (rawValueBigInt * priceUSDMicros) / (10n ** BigInt(asset.decimals));
    if (usdMicros > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new Error("INVALID_AMOUNT: USD valuation exceeds exact policy arithmetic range");
    }
    const usdValue = Number(usdMicros) / 1_000_000;

    // Bind the caller's durable random operation identity to the exact transfer
    // bytes. Retries reproduce this ID; two intentional identical transfers use
    // distinct operation IDs.
    const actionId = ethers.id(
      [
        chainId,
        fromAddr.toLowerCase(),
        toAddr.toLowerCase(),
        asset.native ? "native" : (tokenAddress || "").toLowerCase(),
        rawValueBigInt.toString(),
        calldataSelector,
        symbol,
        params.operationId || "content-only-development",
      ].join(":")
    );

    return Object.freeze({
      actionId,
      operationId: params.operationId,
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
      priceUSDMicros,
      usdMicros,
      priceUpdatedAt,
      priceSource: asset.priceSource!,
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
    assertNormalizedActionIntegrity(action);
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
