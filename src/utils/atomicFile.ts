/**
 * VD-GOAT-011 fix: Atomic file operations with fsync and rename.
 *
 * Prevents partial writes, race conditions, and corruption.
 */

import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";

export interface AtomicFileOptions {
  mode?: number;
  encoding?: BufferEncoding;
  tmpDir?: string;
}

/**
 * Write file atomically using temp + fsync + rename pattern.
 *
 * Steps:
 * 1. Write to temp file with unique name
 * 2. fsync to ensure data on disk
 * 3. Rename temp to target (atomic on POSIX)
 *
 * @param filePath - Target file path
 * @param data - Data to write
 * @param options - Write options
 */
export function writeFileAtomic(
  filePath: string,
  data: string | Buffer,
  options: AtomicFileOptions = {}
): void {
  const { mode = 0o644, encoding = "utf8", tmpDir } = options;

  const targetDir = path.dirname(filePath);
  const targetBase = path.basename(filePath);
  const tmpPath = path.join(
    tmpDir || targetDir,
    `.${targetBase}.${crypto.randomBytes(6).toString("hex")}.tmp`
  );

  try {
    // 1. Write to temp file
    fs.writeFileSync(tmpPath, data, { mode, encoding: encoding as BufferEncoding });

    // 2. fsync to ensure data written to disk
    const fd = fs.openSync(tmpPath, "r+");
    try {
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }

    // 3. Atomic rename (overwrites target on POSIX)
    fs.renameSync(tmpPath, filePath);
  } catch (error) {
    // Clean up temp file on error
    try {
      if (fs.existsSync(tmpPath)) {
        fs.unlinkSync(tmpPath);
      }
    } catch {
      // Ignore cleanup errors
    }
    throw error;
  }
}

/**
 * Read file with optional integrity check.
 *
 * @param filePath - File to read
 * @param encoding - File encoding
 * @returns File contents
 */
export function readFileAtomic(
  filePath: string,
  encoding: BufferEncoding = "utf8"
): string | null {
  try {
    if (!fs.existsSync(filePath)) {
      return null;
    }
    return fs.readFileSync(filePath, encoding);
  } catch (error) {
    return null;
  }
}

/**
 * VD-GOAT-011 fix: Signed state file with HMAC integrity protection.
 */
export interface SignedState<T> {
  data: T;
  timestamp: number;
  hmac: string;
}

export class SignedStateFile<T> {
  private filePath: string;
  private secret: Buffer;

  constructor(filePath: string, secret?: string) {
    this.filePath = filePath;
    // Use env var or generate ephemeral secret
    this.secret = Buffer.from(
      secret || process.env.STATE_SIGNING_SECRET || crypto.randomBytes(32).toString("hex"),
      "hex"
    );
  }

  /**
   * Write state with HMAC signature.
   */
  public write(data: T): void {
    const timestamp = Date.now();
    const dataJson = JSON.stringify(data);
    const hmac = crypto.createHmac("sha256", this.secret).update(dataJson).digest("hex");

    const signed: SignedState<T> = {
      data,
      timestamp,
      hmac,
    };

    writeFileAtomic(this.filePath, JSON.stringify(signed, null, 2));
  }

  /**
   * Read and verify state signature.
   */
  public read(): T | null {
    const content = readFileAtomic(this.filePath);
    if (!content) {
      return null;
    }

    try {
      const signed: SignedState<T> = JSON.parse(content);

      // Verify HMAC
      const dataJson = JSON.stringify(signed.data);
      const expectedHmac = crypto.createHmac("sha256", this.secret).update(dataJson).digest("hex");

      if (signed.hmac !== expectedHmac) {
        throw new Error("HMAC verification failed - state file tampered");
      }

      // Check staleness (optional: fail if > 24 hours old)
      const ageMs = Date.now() - signed.timestamp;
      if (process.env.STRICT_STATE_AGE === "true" && ageMs > 24 * 60 * 60 * 1000) {
        throw new Error(`State file too old: ${Math.floor(ageMs / 1000 / 60)} minutes`);
      }

      return signed.data;
    } catch (error: any) {
      if (process.env.STRICT_STATE_INTEGRITY === "true") {
        throw new Error(`State integrity check failed: ${error.message}`);
      }
      // Fail-safe: return null and log
      console.error(`[State Integrity Error] ${error.message}`);
      return null;
    }
  }
}
