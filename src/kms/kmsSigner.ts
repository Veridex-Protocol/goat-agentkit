import {
  AbstractSigner,
  Provider,
  TransactionRequest,
  TransactionResponse,
  Transaction,
  TypedDataDomain,
  TypedDataField,
  TypedDataEncoder,
  getBytes,
  hexlify,
  keccak256,
  hashMessage,
  computeAddress,
  SigningKey,
  Signature,
} from "ethers";

/**
 * Curve order N for SECP256k1
 * 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
 */
export const SECP256K1_N = BigInt(
  "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
);
export const SECP256K1_HALF_N = SECP256K1_N / 2n;

/**
 * Parses an ASN.1 DER-encoded ECDSA signature into canonical (r, s) values.
 *
 * ASN.1 DER format for ECDSA-Sig-Value:
 * SEQUENCE (0x30) + length + INTEGER (0x02) + r-len + r-bytes + INTEGER (0x02) + s-len + s-bytes
 */
export function parseAsn1DerSignature(der: Uint8Array | Buffer): { r: string; s: string } {
  const bytes = getBytes(der);
  let offset = 0;

  if (bytes[offset++] !== 0x30) {
    throw new Error("[KMS Signer] Invalid DER signature: missing SEQUENCE tag (0x30)");
  }

  let seqLen = bytes[offset++];
  if (seqLen & 0x80) {
    const lenBytes = seqLen & 0x7f;
    seqLen = 0;
    for (let i = 0; i < lenBytes; i++) {
      seqLen = (seqLen << 8) | bytes[offset++];
    }
  }

  // Parse r
  if (bytes[offset++] !== 0x02) {
    throw new Error("[KMS Signer] Invalid DER signature: missing INTEGER tag for r (0x02)");
  }
  let rLen = bytes[offset++];
  let rBytes = bytes.slice(offset, offset + rLen);
  offset += rLen;

  // Parse s
  if (bytes[offset++] !== 0x02) {
    throw new Error("[KMS Signer] Invalid DER signature: missing INTEGER tag for s (0x02)");
  }
  let sLen = bytes[offset++];
  let sBytes = bytes.slice(offset, offset + sLen);

  // Strip leading zero byte if present (used in ASN.1 to represent unsigned positive integers)
  if (rBytes.length === 33 && rBytes[0] === 0x00) {
    rBytes = rBytes.slice(1);
  }
  if (sBytes.length === 33 && sBytes[0] === 0x00) {
    sBytes = sBytes.slice(1);
  }

  if (rBytes.length > 32 || sBytes.length > 32) {
    throw new Error("[KMS Signer] Invalid DER signature: r or s exceeds 32 bytes");
  }

  // Pad to 32 bytes
  const rPadded = new Uint8Array(32);
  rPadded.set(rBytes, 32 - rBytes.length);

  const sPadded = new Uint8Array(32);
  sPadded.set(sBytes, 32 - sBytes.length);

  let rBigInt = BigInt(hexlify(rPadded));
  let sBigInt = BigInt(hexlify(sPadded));

  // Enforce EIP-2 low-s canonicalization: if s > N/2, s = N - s
  if (sBigInt > SECP256K1_HALF_N) {
    sBigInt = SECP256K1_N - sBigInt;
  }

  const rHex = "0x" + rBigInt.toString(16).padStart(64, "0");
  const sHex = "0x" + sBigInt.toString(16).padStart(64, "0");

  return { r: rHex, s: sHex };
}

/**
 * Extracts uncompressed public key (0x04...) from a SubjectPublicKeyInfo (SPKI) DER buffer.
 */
export function parseSpkiPublicKey(spkiDer: Uint8Array | Buffer): string {
  const bytes = getBytes(spkiDer);
  // Uncompressed secp256k1 public keys start with 0x04 and are 65 bytes long (0x04 + 32-byte X + 32-byte Y)
  // In SPKI DER format, the raw public key is at the end of the BIT STRING structure (last 65 bytes).
  const uncompressedKeyIndex = bytes.findIndex((byte, idx) => byte === 0x04 && bytes.length - idx === 65);
  if (uncompressedKeyIndex !== -1) {
    const rawPubKey = bytes.slice(uncompressedKeyIndex, uncompressedKeyIndex + 65);
    return hexlify(rawPubKey);
  }

  // If already 65 bytes starting with 0x04:
  if (bytes.length === 65 && bytes[0] === 0x04) {
    return hexlify(bytes);
  }

  // If 64 bytes (X || Y without 0x04 prefix):
  if (bytes.length === 64) {
    const prefixed = new Uint8Array(65);
    prefixed[0] = 0x04;
    prefixed.set(bytes, 1);
    return hexlify(prefixed);
  }

  throw new Error("[KMS Signer] Could not parse secp256k1 public key from SPKI DER");
}

/**
 * Recovers Ethereum recovery ID (yParity: 0 or 1) for a given digest and (r, s).
 */
export function determineRecoveryId(digest: string, r: string, s: string, expectedAddress: string): 0 | 1 {
  const digestBytes = getBytes(digest);
  const normalizedExpected = expectedAddress.toLowerCase();

  for (const yParity of [0, 1] as const) {
    try {
      const recoveredPubKey = SigningKey.recoverPublicKey(digestBytes, {
        r,
        s,
        yParity,
      });
      const recoveredAddr = computeAddress(recoveredPubKey).toLowerCase();
      if (recoveredAddr === normalizedExpected) {
        return yParity;
      }
    } catch {
      // try next parity
    }
  }

  throw new Error(
    `[KMS Signer] Failed to determine signature recovery ID: neither yParity (0, 1) matches address ${expectedAddress}`
  );
}

export interface KmsSignerOptions {
  provider?: Provider | null;
}

export type KmsDigestSignerFn = (digest: Uint8Array) => Promise<Uint8Array | { r: string; s: string }>;
export type KmsPublicKeyFetcherFn = () => Promise<string | Uint8Array>;

/**
 * Generic AWS KMS client interface compatible with @aws-sdk/client-kms
 */
export interface AwsKmsClientLike {
  send(command: any): Promise<any>;
}

/**
 * Base CloudKmsSigner implementing the ethers.js v6 Signer interface.
 * Can be used with AWS KMS, Azure Key Vault, Google Cloud KMS, or HashiCorp Vault.
 */
export class CloudKmsSigner extends AbstractSigner {
  protected _address?: string;
  protected _publicKey?: string;
  protected signDigestFn: KmsDigestSignerFn;
  protected getPublicKeyFn: KmsPublicKeyFetcherFn;

  constructor(
    getPublicKey: KmsPublicKeyFetcherFn,
    signDigest: KmsDigestSignerFn,
    provider?: Provider | null
  ) {
    super(provider);
    this.getPublicKeyFn = getPublicKey;
    this.signDigestFn = signDigest;
  }

  public connect(provider: Provider | null): CloudKmsSigner {
    const clone = new CloudKmsSigner(this.getPublicKeyFn, this.signDigestFn, provider);
    clone._address = this._address;
    clone._publicKey = this._publicKey;
    return clone;
  }

  public async getPublicKey(): Promise<string> {
    if (this._publicKey) return this._publicKey;
    const raw = await this.getPublicKeyFn();
    let pubKeyHex: string;
    if (typeof raw === "string" && raw.startsWith("0x04") && raw.length === 130) {
      pubKeyHex = raw;
    } else {
      pubKeyHex = parseSpkiPublicKey(typeof raw === "string" ? getBytes(raw) : raw);
    }
    this._publicKey = pubKeyHex;
    return pubKeyHex;
  }

  public async getAddress(): Promise<string> {
    if (this._address) return this._address;
    const pubKey = await this.getPublicKey();
    this._address = computeAddress(pubKey);
    return this._address;
  }

  /**
   * Signs a 32-byte hash digest using KMS and derives the Ethereum-compatible signature.
   */
  public async signDigest(digest: string): Promise<Signature> {
    const address = await this.getAddress();
    const digestBytes = getBytes(digest);
    const rawSignature = await this.signDigestFn(digestBytes);

    let r: string;
    let s: string;

    if (rawSignature instanceof Uint8Array || Buffer.isBuffer(rawSignature)) {
      const parsed = parseAsn1DerSignature(rawSignature);
      r = parsed.r;
      s = parsed.s;
    } else {
      r = rawSignature.r;
      s = rawSignature.s;
    }

    const yParity = determineRecoveryId(digest, r, s, address);
    return Signature.from({ r, s, yParity });
  }

  public async signTransaction(tx: TransactionRequest): Promise<string> {
    const populated = await this.populateTransaction(tx);
    delete populated.from;

    const txObj = Transaction.from(populated);
    const unsignedSerialized = txObj.unsignedSerialized;
    const digest = keccak256(unsignedSerialized);

    const sig = await this.signDigest(digest);
    txObj.signature = sig;

    return txObj.serialized;
  }

  public async sendTransaction(tx: TransactionRequest): Promise<TransactionResponse> {
    if (!this.provider) {
      throw new Error("[KMS Signer] Provider is required to sendTransaction");
    }
    const signedTx = await this.signTransaction(tx);
    return this.provider.broadcastTransaction(signedTx);
  }

  public async signMessage(message: string | Uint8Array): Promise<string> {
    const digest = hashMessage(message);
    const sig = await this.signDigest(digest);
    return sig.serialized;
  }

  public async signTypedData(
    domain: TypedDataDomain,
    types: Record<string, TypedDataField[]>,
    value: Record<string, any>
  ): Promise<string> {
    const digest = TypedDataEncoder.hash(domain, types, value);
    const sig = await this.signDigest(digest);
    return sig.serialized;
  }
}

/**
 * AWS KMS Signer Options
 */
export interface AwsKmsSignerConfig {
  keyId: string;
  region?: string;
  kmsClient?: AwsKmsClientLike;
  provider?: Provider | null;
}

/**
 * AWS KMS implementation of CloudKmsSigner.
 * Uses `@aws-sdk/client-kms` or compatible AWS KMS client.
 */
export class AwsKmsSigner extends CloudKmsSigner {
  public readonly keyId: string;
  public readonly region: string;

  constructor(config: AwsKmsSignerConfig) {
    if (!config.keyId || config.keyId.trim().length === 0) {
      throw new Error("[AwsKmsSigner] keyId is required");
    }

    const keyId = config.keyId.trim();
    const region = config.region || process.env.AWS_REGION || "us-east-1";
    let kmsClient = config.kmsClient;

    const loadAwsSdk = async (): Promise<any> => {
      try {
        const importModule = new Function("m", "return import(m)");
        return await importModule("@aws-sdk/client-kms");
      } catch (err: any) {
        throw new Error(
          `[AwsKmsSigner] Failed to load @aws-sdk/client-kms. ` +
          `Please install @aws-sdk/client-kms or pass an initialized kmsClient: ${err.message}`
        );
      }
    };

    const getKmsClient = async (): Promise<AwsKmsClientLike> => {
      if (kmsClient) return kmsClient;
      const awsSdk = await loadAwsSdk();
      kmsClient = new awsSdk.KMSClient({ region });
      return kmsClient!;
    };

    const getPublicKey = async (): Promise<Uint8Array> => {
      const client = await getKmsClient();
      const awsSdk = await loadAwsSdk();
      const response = await client.send(new awsSdk.GetPublicKeyCommand({ KeyId: keyId }));
      if (!response.PublicKey) {
        throw new Error(`[AwsKmsSigner] AWS KMS returned empty public key for KeyId: ${keyId}`);
      }
      return response.PublicKey;
    };

    const signDigest = async (digest: Uint8Array): Promise<Uint8Array> => {
      const client = await getKmsClient();
      const awsSdk = await loadAwsSdk();
      const response = await client.send(
        new awsSdk.SignCommand({
          KeyId: keyId,
          Message: digest,
          MessageType: "DIGEST",
          SigningAlgorithm: "ECDSA_SHA_256",
        })
      );
      if (!response.Signature) {
        throw new Error(`[AwsKmsSigner] AWS KMS returned empty signature for KeyId: ${keyId}`);
      }
      return response.Signature;
    };

    super(getPublicKey, signDigest, config.provider);
    this.keyId = keyId;
    this.region = region;
  }

  public override connect(provider: Provider | null): AwsKmsSigner {
    const clone = new AwsKmsSigner({
      keyId: this.keyId,
      region: this.region,
      provider,
    });
    clone._address = this._address;
    clone._publicKey = this._publicKey;
    return clone;
  }
}

/**
 * Custom / Mock KMS Signer useful for testing or integrating custom HSM / MPC providers.
 */
export class CustomKmsSigner extends CloudKmsSigner {
  constructor(
    publicKeyOrFetcher: string | Uint8Array | KmsPublicKeyFetcherFn,
    signDigest: KmsDigestSignerFn,
    provider?: Provider | null
  ) {
    const fetcher: KmsPublicKeyFetcherFn =
      typeof publicKeyOrFetcher === "function"
        ? publicKeyOrFetcher
        : async () => publicKeyOrFetcher;
    super(fetcher, signDigest, provider);
  }
}
