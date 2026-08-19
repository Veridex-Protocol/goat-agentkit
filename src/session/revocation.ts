/**
 * VD-GOAT-012 fix: Session revocation list management.
 *
 * Tracks revoked session keys to prevent use after revocation.
 */

import { SignedStateFile } from "../utils/atomicFile.js";
import * as path from "path";
import { Pool, type PoolConfig } from "pg";

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

/** A revocation backend may be synchronous (development file) or durable. */
export interface SessionRevocationProvider {
  revoke(address: string, reason?: string, agentId?: string): void | Promise<void>;
  isRevoked(address: string, agentId?: string): boolean | Promise<boolean>;
}

/**
 * Session revocation list with persistence and automatic cleanup.
 */
export class SessionRevocationList implements SessionRevocationProvider {
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

/**
 * Transactional revocation backend for multi-replica deployments. Database
 * failures propagate to callers so a wallet operation fails closed instead of
 * trusting a stale in-process cache.
 */
export class PostgresSessionRevocationProvider implements SessionRevocationProvider {
  private readonly pool: Pool;
  private readonly namespace: string;
  private schemaReady?: Promise<void>;

  constructor(connection: string | PoolConfig, namespace: string) {
    if (!namespace || namespace.length > 200) throw new Error("revocation namespace must be 1-200 characters");
    this.pool = new Pool(typeof connection === "string" ? { connectionString: connection } : connection);
    this.namespace = namespace;
  }

  private async ensureSchema(): Promise<void> {
    if (!this.schemaReady) {
      this.schemaReady = this.pool.query(`
        CREATE TABLE IF NOT EXISTS veridex_session_revocations (
          namespace TEXT NOT NULL,
          agent_id TEXT NOT NULL,
          session_address TEXT NOT NULL,
          revoked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          reason TEXT,
          PRIMARY KEY (namespace, agent_id, session_address)
        );
        CREATE INDEX IF NOT EXISTS veridex_session_revocations_lookup_idx
          ON veridex_session_revocations (namespace, agent_id, session_address);
      `).then(() => undefined).catch((error) => {
        this.schemaReady = undefined;
        throw error;
      });
    }
    await this.schemaReady;
  }

  private normalized(address: string): string {
    if (!/^0x[a-fA-F0-9]{40}$/.test(address)) throw new Error("revoked session address must be an EVM address");
    return address.toLowerCase();
  }

  public async revoke(address: string, reason?: string, agentId?: string): Promise<void> {
    if (!agentId || agentId.length > 300) throw new Error("agentId is required for durable session revocation");
    await this.ensureSchema();
    await this.pool.query(
      `INSERT INTO veridex_session_revocations (namespace, agent_id, session_address, reason)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (namespace, agent_id, session_address) DO NOTHING`,
      [this.namespace, agentId, this.normalized(address), reason?.slice(0, 1024) || null],
    );
  }

  public async isRevoked(address: string, agentId?: string): Promise<boolean> {
    if (!agentId || agentId.length > 300) throw new Error("agentId is required for durable session revocation");
    await this.ensureSchema();
    const result = await this.pool.query(
      `SELECT 1 FROM veridex_session_revocations
       WHERE namespace = $1 AND agent_id = $2 AND session_address = $3 LIMIT 1`,
      [this.namespace, agentId, this.normalized(address)],
    );
    return result.rowCount === 1;
  }

  public async close(): Promise<void> {
    await this.pool.end();
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
