/**
 * VD-GOAT-012 fix: Session revocation list management.
 *
 * Tracks revoked session keys to prevent use after revocation.
 */

import { SignedStateFile } from "../utils/atomicFile.js";
import * as path from "path";

export interface RevokedSession {
  address: string;
  revokedAt: number;
  reason?: string;
  agentId?: string;
}

export interface RevocationListState {
  revoked: RevokedSession[];
  lastCleanup: number;
}

/**
 * Session revocation list with persistence and automatic cleanup.
 */
export class SessionRevocationList {
  private stateFile: SignedStateFile<RevocationListState>;
  private cache: Map<string, RevokedSession> = new Map();
  private maxAge: number;

  constructor(
    filePath: string = "veridex-session-revocations.json",
    secret?: string,
    maxAgeMs: number = 30 * 24 * 60 * 60 * 1000 // 30 days
  ) {
    this.stateFile = new SignedStateFile(path.resolve(filePath), secret);
    this.maxAge = maxAgeMs;
    this.load();
  }

  /**
   * Load revocation list from disk into memory cache.
   */
  private load(): void {
    const state = this.stateFile.read();
    if (state) {
      this.cache.clear();
      for (const session of state.revoked) {
        this.cache.set(session.address.toLowerCase(), session);
      }
    }
  }

  /**
   * Save revocation list to disk with atomic write.
   */
  private save(): void {
    const state: RevocationListState = {
      revoked: Array.from(this.cache.values()),
      lastCleanup: Date.now(),
    };
    this.stateFile.write(state);
  }

  /**
   * Check if a session is revoked.
   *
   * @param address - Session key address
   * @returns true if revoked, false otherwise
   */
  public isRevoked(address: string): boolean {
    return this.cache.has(address.toLowerCase());
  }

  /**
   * Revoke a session key.
   *
   * @param address - Session key address to revoke
   * @param reason - Optional reason for revocation
   * @param agentId - Optional agent ID
   */
  public revoke(address: string, reason?: string, agentId?: string): void {
    const normalized = address.toLowerCase();

    if (this.cache.has(normalized)) {
      // Already revoked
      return;
    }

    this.cache.set(normalized, {
      address: normalized,
      revokedAt: Date.now(),
      reason,
      agentId,
    });

    this.save();
  }

  /**
   * Remove a session from revocation list (un-revoke).
   * Use with caution - should only be called for administrative corrections.
   *
   * @param address - Session key address
   */
  public unrevoke(address: string): void {
    const normalized = address.toLowerCase();
    if (this.cache.delete(normalized)) {
      this.save();
    }
  }

  /**
   * Clean up old revoked sessions (older than maxAge).
   */
  public cleanup(): number {
    const cutoff = Date.now() - this.maxAge;
    let removed = 0;

    for (const [address, session] of this.cache.entries()) {
      if (session.revokedAt < cutoff) {
        this.cache.delete(address);
        removed++;
      }
    }

    if (removed > 0) {
      this.save();
    }

    return removed;
  }

  /**
   * Get all revoked sessions.
   */
  public getAll(): RevokedSession[] {
    return Array.from(this.cache.values());
  }

  /**
   * Get count of revoked sessions.
   */
  public count(): number {
    return this.cache.size;
  }

  /**
   * Clear all revocations (use with extreme caution).
   */
  public clear(): void {
    this.cache.clear();
    this.save();
  }
}

// Singleton instance
let globalRevocationList: SessionRevocationList | null = null;

/**
 * Get global session revocation list singleton.
 */
export function getGlobalRevocationList(): SessionRevocationList {
  if (!globalRevocationList) {
    globalRevocationList = new SessionRevocationList();
  }
  return globalRevocationList;
}
