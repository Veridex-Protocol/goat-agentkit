/**
 * Utility for safe JSON serialization that handles BigInt values gracefully.
 */
export function safeStringify(obj: any, space?: number | string): string {
  return JSON.stringify(
    obj,
    (_key, value) => (typeof value === "bigint" ? value.toString() : value),
    space
  );
}
