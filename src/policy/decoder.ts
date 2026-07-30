import { ethers } from "ethers";
import { NormalizedAction } from "../types/action.js";

export const TOKEN_PRICES_USD: Record<string, number> = {
  BTC: 96500.0,
  USDC: 1.0,
  GOAT: 0.85,
  ETH: 3450.0,
  USDT: 1.0,
};

const ERC20_INTERFACE = new ethers.Interface([
  "function transfer(address to, uint256 value)",
  "function transferFrom(address from, address to, uint256 value)",
  "function approve(address spender, uint256 value)",
  "function transferWithAuthorization(address from, address to, uint256 value, uint256 validAfter, uint256 validBefore, bytes32 nonce, uint8 v, bytes32 r, bytes32 s)",
]);

export class TransactionDecoder {
  public static decodeAndNormalize(params: {
    from: string;
    to: string;
    value?: string | number | bigint;
    data?: string;
    asset?: string;
    chainId?: number;
  }): NormalizedAction {
    const chainId = params.chainId || 48816;
    const fromAddr = ethers.getAddress(params.from);
    let toAddr = ethers.getAddress(params.to);
    let rawValueBigInt = BigInt(params.value || 0);
    let tokenAddress: string | null = null;
    let calldataSelector = "0x00000000";
    let decimals = 18;
    let symbol = (params.asset || "GOAT").toUpperCase();

    if (params.data && params.data !== "0x" && params.data.length >= 10) {
      calldataSelector = params.data.slice(0, 10);
      try {
        const parsed = ERC20_INTERFACE.parseTransaction({ data: params.data });
        if (!parsed) {
          throw new Error(`INVALID_TRANSACTION: Unknown selector ${calldataSelector}`);
        }
        tokenAddress = toAddr; // contract address being called

        if (parsed.name === "transfer") {
          toAddr = ethers.getAddress(parsed.args[0]);
          rawValueBigInt = BigInt(parsed.args[1]);
          decimals = symbol === "USDC" || symbol === "USDT" ? 6 : 18;
        } else if (parsed.name === "transferFrom") {
          toAddr = ethers.getAddress(parsed.args[1]);
          rawValueBigInt = BigInt(parsed.args[2]);
          decimals = symbol === "USDC" || symbol === "USDT" ? 6 : 18;
        } else if (parsed.name === "approve") {
          toAddr = ethers.getAddress(parsed.args[0]);
          rawValueBigInt = BigInt(parsed.args[1]);
          decimals = symbol === "USDC" || symbol === "USDT" ? 6 : 18;
        } else if (parsed.name === "transferWithAuthorization") {
          toAddr = ethers.getAddress(parsed.args[1]);
          rawValueBigInt = BigInt(parsed.args[2]);
          decimals = 6;
        }
      } catch (err: any) {
        throw new Error(`INVALID_TRANSACTION: Failed to decode calldata (${err.message})`);
      }
    }

    const price = TOKEN_PRICES_USD[symbol] ?? 1.0;
    const formattedAmount = Number(ethers.formatUnits(rawValueBigInt, decimals));
    if (isNaN(formattedAmount) || formattedAmount < 0) {
      throw new Error("INVALID_AMOUNT: Transaction value is negative or NaN");
    }

    const usdValue = formattedAmount * price;
    const actionId = ethers.id(`${chainId}:${fromAddr.toLowerCase()}:${toAddr.toLowerCase()}:${rawValueBigInt.toString()}:${calldataSelector}:${Date.now()}`);

    return {
      actionId,
      chainId,
      from: fromAddr,
      to: toAddr,
      value: rawValueBigInt,
      tokenAddress,
      calldataSelector,
      decimals,
      usdValue,
      rawCalldata: params.data,
    };
  }
}
