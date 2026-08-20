/**
 * VD-GOAT-013 fix: Simple in-memory rate limiter to prevent DoS attacks.
 *
 * Production deployments should use Redis or similar for distributed rate limiting.
 */

interface RateLimitEntry {
  count: number;
  resetAt: number;
}

export class RateLimiter {
  private limits: Map<string, RateLimitEntry> = new Map();
  private maxRequests: number;
  private windowMs: number;
  private cleanupTimer: ReturnType<typeof setInterval>;

  constructor(maxRequests = 100, windowMs = 60_000) {
    this.maxRequests = maxRequests;
    this.windowMs = windowMs;

    // Cleanup expired entries every minute
    this.cleanupTimer = setInterval(() => this.cleanup(), 60_000);
    // Importing the SDK must not keep a CLI/test process alive indefinitely.
    this.cleanupTimer.unref?.();
  }

  /**
   * Check if request is allowed under rate limit.
   *
   * @param key - Identifier (IP address, agentId, etc.)
   * @returns true if allowed, false if rate limited
   */
  public check(key: string): boolean {
    const now = Date.now();
    const entry = this.limits.get(key);

    if (!entry || now > entry.resetAt) {
      // New window
      this.limits.set(key, {
        count: 1,
        resetAt: now + this.windowMs,
      });
      return true;
    }

    if (entry.count >= this.maxRequests) {
      // Rate limited
      return false;
    }

    // Increment counter
    entry.count++;
    return true;
  }

  /**
   * Get remaining requests for a key.
   */
  public remaining(key: string): number {
    const entry = this.limits.get(key);
    if (!entry || Date.now() > entry.resetAt) {
      return this.maxRequests;
    }
    return Math.max(0, this.maxRequests - entry.count);
  }

  /**
   * Reset rate limit for a key.
   */
  public reset(key: string): void {
    this.limits.delete(key);
  }

  public close(): void {
    clearInterval(this.cleanupTimer);
  }

  /**
   * Cleanup expired entries.
   */
  private cleanup(): void {
    const now = Date.now();
    for (const [key, entry] of this.limits.entries()) {
      if (now > entry.resetAt) {
        this.limits.delete(key);
      }
    }
  }

  /**
   * Get current stats.
   */
  public getStats(): { totalKeys: number; activeKeys: number } {
    const now = Date.now();
    let activeKeys = 0;

    for (const entry of this.limits.values()) {
      if (now <= entry.resetAt) {
        activeKeys++;
      }
    }

    return {
      totalKeys: this.limits.size,
      activeKeys,
    };
  }
}

// Singleton instances for common rate limits
export const evidenceRateLimiter = new RateLimiter(50, 60_000); // 50 req/min
export const x402RateLimiter = new RateLimiter(100, 60_000); // 100 req/min
export const policyRateLimiter = new RateLimiter(200, 60_000); // 200 req/min
