import { Pool, type PoolConfig } from "pg";
import { createHmac, timingSafeEqual } from "crypto";
import { canonicalizeJson } from "../evidence/builder.js";
import {
  type PolicyState,
  type TransactionalPolicyStateProvider,
  createDefaultPolicyState,
  sanitizePolicyState,
} from "./gate.js";

/**
 * PostgreSQL-backed policy state with a per-agent row lock.  `transact()` holds
 * `SELECT ... FOR UPDATE` until the reservation/commit/release is persisted,
 * preventing separate replicas from exceeding a shared daily limit.
 */
export class PostgresPolicyStateProvider implements TransactionalPolicyStateProvider {
  private readonly pool: Pool;
  private readonly namespace: string;
  private readonly integritySecret?: string;
  private schemaReady?: Promise<void>;

  constructor(connection: string | PoolConfig, namespace: string, integritySecret = process.env.STATE_SIGNING_SECRET) {
    if (!namespace || namespace.length > 200) throw new Error("Postgres policy-state namespace must be 1-200 characters");
    if (process.env.NODE_ENV === "production" && (!integritySecret || integritySecret.length < 32)) {
      throw new Error("STATE_SIGNING_SECRET is required to authenticate production PostgreSQL policy state");
    }
    this.pool = new Pool(typeof connection === "string" ? { connectionString: connection } : connection);
    this.namespace = namespace;
    this.integritySecret = integritySecret;
  }

  private authenticate(state: PolicyState): string | null {
    if (!this.integritySecret) return null;
    return createHmac("sha256", this.integritySecret).update(canonicalizeJson(state)).digest("hex");
  }

  private verifyAuthenticatedState(state: PolicyState, supplied: string | null): PolicyState {
    const parsed = sanitizePolicyState(state, true);
    const expected = this.authenticate(parsed);
    if (expected !== null) {
      const actualBytes = Buffer.from(supplied || "", "hex");
      const expectedBytes = Buffer.from(expected, "hex");
      if (actualBytes.length !== expectedBytes.length || !timingSafeEqual(actualBytes, expectedBytes)) {
        throw new Error("PostgreSQL policy state failed HMAC integrity verification");
      }
    }
    return parsed;
  }

  private async ensureSchema(): Promise<void> {
    if (!this.schemaReady) {
      this.schemaReady = this.pool.query(`
        CREATE TABLE IF NOT EXISTS veridex_policy_state (
          namespace TEXT PRIMARY KEY,
          state JSONB NOT NULL,
          state_hmac TEXT,
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        ALTER TABLE veridex_policy_state ADD COLUMN IF NOT EXISTS state_hmac TEXT
      `).then(() => undefined).catch((error) => {
        this.schemaReady = undefined;
        throw error;
      });
    }
    await this.schemaReady;
  }

  public async loadState(): Promise<PolicyState> {
    await this.ensureSchema();
    const result = await this.pool.query<{ state: PolicyState; state_hmac: string | null }>(
      "SELECT state, state_hmac FROM veridex_policy_state WHERE namespace = $1",
      [this.namespace],
    );
    return result.rows[0]
      ? this.verifyAuthenticatedState(result.rows[0].state, result.rows[0].state_hmac)
      : createDefaultPolicyState();
  }

  public async saveState(state: PolicyState): Promise<void> {
    await this.ensureSchema();
    const parsed = sanitizePolicyState(state, true);
    await this.pool.query(
      `INSERT INTO veridex_policy_state (namespace, state, state_hmac)
       VALUES ($1, $2::jsonb, $3)
       ON CONFLICT (namespace) DO UPDATE
         SET state = EXCLUDED.state, state_hmac = EXCLUDED.state_hmac, updated_at = NOW()`,
      [this.namespace, JSON.stringify(parsed), this.authenticate(parsed)],
    );
  }

  public async transact<T>(mutate: (state: PolicyState) => { state: PolicyState; result: T }): Promise<T> {
    await this.ensureSchema();
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      // Ensure a row exists before locking it. ON CONFLICT makes concurrent
      // first-use safe without weakening the row lock that follows.
      const initialState = createDefaultPolicyState();
      await client.query(
        `INSERT INTO veridex_policy_state (namespace, state, state_hmac)
         VALUES ($1, $2::jsonb, $3) ON CONFLICT (namespace) DO NOTHING`,
        [this.namespace, JSON.stringify(initialState), this.authenticate(initialState)],
      );
      const locked = await client.query<{ state: PolicyState; state_hmac: string | null }>(
        "SELECT state, state_hmac FROM veridex_policy_state WHERE namespace = $1 FOR UPDATE",
        [this.namespace],
      );
      const current = locked.rows[0];
      if (!current) throw new Error("PostgreSQL policy state row disappeared while locked");
      const outcome = mutate(this.verifyAuthenticatedState(current.state, current.state_hmac));
      const nextState = sanitizePolicyState(outcome.state, true);
      await client.query(
        `UPDATE veridex_policy_state
         SET state = $2::jsonb, state_hmac = $3, updated_at = NOW() WHERE namespace = $1`,
        [this.namespace, JSON.stringify(nextState), this.authenticate(nextState)],
      );
      await client.query("COMMIT");
      return outcome.result;
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  public async close(): Promise<void> {
    await this.pool.end();
  }
}
