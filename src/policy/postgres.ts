import { Pool, type PoolConfig } from "pg";
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
  private schemaReady?: Promise<void>;

  constructor(connection: string | PoolConfig, namespace: string) {
    if (!namespace || namespace.length > 200) throw new Error("Postgres policy-state namespace must be 1-200 characters");
    this.pool = new Pool(typeof connection === "string" ? { connectionString: connection } : connection);
    this.namespace = namespace;
  }

  private async ensureSchema(): Promise<void> {
    if (!this.schemaReady) {
      this.schemaReady = this.pool.query(`
        CREATE TABLE IF NOT EXISTS veridex_policy_state (
          namespace TEXT PRIMARY KEY,
          state JSONB NOT NULL,
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
      `).then(() => undefined).catch((error) => {
        this.schemaReady = undefined;
        throw error;
      });
    }
    await this.schemaReady;
  }

  public async loadState(): Promise<PolicyState> {
    await this.ensureSchema();
    const result = await this.pool.query<{ state: PolicyState }>(
      "SELECT state FROM veridex_policy_state WHERE namespace = $1",
      [this.namespace],
    );
    return sanitizePolicyState(result.rows[0]?.state || createDefaultPolicyState());
  }

  public async saveState(state: PolicyState): Promise<void> {
    await this.ensureSchema();
    await this.pool.query(
      `INSERT INTO veridex_policy_state (namespace, state)
       VALUES ($1, $2::jsonb)
       ON CONFLICT (namespace) DO UPDATE SET state = EXCLUDED.state, updated_at = NOW()`,
      [this.namespace, JSON.stringify(sanitizePolicyState(state))],
    );
  }

  public async transact<T>(mutate: (state: PolicyState) => { state: PolicyState; result: T }): Promise<T> {
    await this.ensureSchema();
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      // Ensure a row exists before locking it. ON CONFLICT makes concurrent
      // first-use safe without weakening the row lock that follows.
      await client.query(
        "INSERT INTO veridex_policy_state (namespace, state) VALUES ($1, $2::jsonb) ON CONFLICT (namespace) DO NOTHING",
        [this.namespace, JSON.stringify(createDefaultPolicyState())],
      );
      const locked = await client.query<{ state: PolicyState }>(
        "SELECT state FROM veridex_policy_state WHERE namespace = $1 FOR UPDATE",
        [this.namespace],
      );
      const outcome = mutate(sanitizePolicyState(locked.rows[0]?.state));
      await client.query(
        "UPDATE veridex_policy_state SET state = $2::jsonb, updated_at = NOW() WHERE namespace = $1",
        [this.namespace, JSON.stringify(sanitizePolicyState(outcome.state))],
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
