import { describe, it, expect } from "vitest";
import { ethers, Wallet, Transaction, TypedDataEncoder, hashMessage } from "ethers";
import {
  parseAsn1DerSignature,
  parseSpkiPublicKey,
  determineRecoveryId,
  CloudKmsSigner,
  CustomKmsSigner,
  AwsKmsSigner,
  SECP256K1_N,
  SECP256K1_HALF_N,
} from "../src/kms/kmsSigner.js";

/**
 * Helper to encode (r, s) as an ASN.1 DER signature for mock testing.
 */
function encodeAsn1Der(rHex: string, sHex: string): Uint8Array {
  let rBytes = ethers.getBytes(rHex);
  let sBytes = ethers.getBytes(sHex);

  // If high bit is set (>= 0x80), prepend 0x00 so it represents a positive integer in ASN.1
  if (rBytes[0] & 0x80) {
    const prefixed = new Uint8Array(rBytes.length + 1);
    prefixed.set(rBytes, 1);
    rBytes = prefixed;
  }
  if (sBytes[0] & 0x80) {
    const prefixed = new Uint8Array(sBytes.length + 1);
    prefixed.set(sBytes, 1);
    sBytes = prefixed;
  }

  const rTag = 0x02;
  const sTag = 0x02;
  const seqTag = 0x30;

  const totalLen = 2 + rBytes.length + 2 + sBytes.length;
  const out = new Uint8Array(2 + totalLen);
  let offset = 0;

  out[offset++] = seqTag;
  out[offset++] = totalLen;

  out[offset++] = rTag;
  out[offset++] = rBytes.length;
  out.set(rBytes, offset);
  offset += rBytes.length;

  out[offset++] = sTag;
  out[offset++] = sBytes.length;
  out.set(sBytes, offset);

  return out;
}

describe("KMS Signer: ASN.1 DER Parsing & Low-S Canonicalization", () => {
  it("should parse standard DER signature correctly", () => {
    const r = "0x" + "11".repeat(32);
    const s = "0x" + "22".repeat(32);
    const der = encodeAsn1Der(r, s);

    const parsed = parseAsn1DerSignature(der);
    expect(parsed.r.toLowerCase()).toBe(r.toLowerCase());
    expect(parsed.s.toLowerCase()).toBe(s.toLowerCase());
  });

  it("should enforce EIP-2 low-s canonicalization when s > N/2", () => {
    const r = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    // Construct high s: N - 1000
    const highS = SECP256K1_N - 1000n;
    const expectedLowS = 1000n;

    const highSHex = "0x" + highS.toString(16).padStart(64, "0");
    const der = encodeAsn1Der(r, highSHex);

    const parsed = parseAsn1DerSignature(der);
    expect(BigInt(parsed.s)).toBe(expectedLowS);
    expect(BigInt(parsed.s) <= SECP256K1_HALF_N).toBe(true);
  });

  it("should reject non-SEQUENCE DER bytes", () => {
    const badBytes = new Uint8Array([0x02, 0x04, 0x01, 0x02, 0x03, 0x04]);
    expect(() => parseAsn1DerSignature(badBytes)).toThrow("missing SEQUENCE tag");
  });
});

describe("KMS Signer: Public Key SPKI Parsing", () => {
  it("should parse 65-byte uncompressed public key (0x04...)", () => {
    const testWallet = Wallet.createRandom();
    const pubKey = testWallet.signingKey.publicKey; // 0x04... 65 bytes
    const parsed = parseSpkiPublicKey(ethers.getBytes(pubKey));
    expect(parsed.toLowerCase()).toBe(pubKey.toLowerCase());
  });

  it("should extract 65-byte public key embedded in SPKI DER header", () => {
    const testWallet = Wallet.createRandom();
    const pubKeyBytes = ethers.getBytes(testWallet.signingKey.publicKey);
    // Typical SPKI prefix for secp256k1 (23 bytes prefix)
    const spkiPrefix = new Uint8Array([
      0x30, 0x56, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
      0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a, 0x03, 0x42, 0x00,
    ]);
    const spkiDer = new Uint8Array(spkiPrefix.length + pubKeyBytes.length);
    spkiDer.set(spkiPrefix, 0);
    spkiDer.set(pubKeyBytes, spkiPrefix.length);

    const parsed = parseSpkiPublicKey(spkiDer);
    expect(parsed.toLowerCase()).toBe(testWallet.signingKey.publicKey.toLowerCase());
    expect(ethers.computeAddress(parsed).toLowerCase()).toBe(testWallet.address.toLowerCase());
  });
});

describe("KMS Signer: Recovery ID & Ethereum Signing with Mock KMS", () => {
  it("should accurately determine recovery ID for arbitrary digest", () => {
    const testWallet = Wallet.createRandom();
    const digest = ethers.keccak256(ethers.toUtf8Bytes("Test Digest for KMS"));

    const rawSig = testWallet.signingKey.sign(digest);
    const recoveryId = determineRecoveryId(digest, rawSig.r, rawSig.s, testWallet.address);

    expect(recoveryId).toBe(rawSig.yParity);
  });

  it("should sign EIP-191 personal message via CustomKmsSigner without private key access", async () => {
    const testWallet = Wallet.createRandom();
    const pubKey = testWallet.signingKey.publicKey;

    // Create KMS signer using a mock KMS sign function that returns DER
    const kmsSigner = new CustomKmsSigner(
      pubKey,
      async (digest: Uint8Array) => {
        const sig = testWallet.signingKey.sign(digest);
        return encodeAsn1Der(sig.r, sig.s);
      }
    );

    const derivedAddress = await kmsSigner.getAddress();
    expect(derivedAddress.toLowerCase()).toBe(testWallet.address.toLowerCase());

    const message = "Hello GOAT Network KMS Relayer!";
    const signature = await kmsSigner.signMessage(message);

    const recovered = ethers.verifyMessage(message, signature);
    expect(recovered.toLowerCase()).toBe(testWallet.address.toLowerCase());
  });

  it("should sign EIP-712 typed data via CustomKmsSigner", async () => {
    const testWallet = Wallet.createRandom();
    const pubKey = testWallet.signingKey.publicKey;

    const kmsSigner = new CustomKmsSigner(
      pubKey,
      async (digest: Uint8Array) => {
        const sig = testWallet.signingKey.sign(digest);
        return encodeAsn1Der(sig.r, sig.s);
      }
    );

    const domain = {
      name: "Veridex Test",
      version: "1",
      chainId: 48816,
      verifyingContract: "0x1111111111111111111111111111111111111111",
    };
    const types = {
      Order: [
        { name: "recipient", type: "address" },
        { name: "amount", type: "uint256" },
      ],
    };
    const value = {
      recipient: "0x2222222222222222222222222222222222222222",
      amount: 1000000n,
    };

    const signature = await kmsSigner.signTypedData(domain, types, value);
    const recovered = ethers.verifyTypedData(domain, types, value, signature);

    expect(recovered.toLowerCase()).toBe(testWallet.address.toLowerCase());
  });

  it("should sign EIP-1559 EVM transactions via CustomKmsSigner", async () => {
    const testWallet = Wallet.createRandom();
    const pubKey = testWallet.signingKey.publicKey;

    const mockProvider = {
      estimateGas: async () => 21000n,
      getFeeData: async () => ({
        maxFeePerGas: ethers.parseUnits("1.5", "gwei"),
        maxPriorityFeePerGas: ethers.parseUnits("0.1", "gwei"),
      }),
      getTransactionCount: async () => 5,
      getNetwork: async () => ({ chainId: 48816n }),
    } as any;

    const kmsSigner = new CustomKmsSigner(
      pubKey,
      async (digest: Uint8Array) => {
        const sig = testWallet.signingKey.sign(digest);
        return encodeAsn1Der(sig.r, sig.s);
      },
      mockProvider
    );

    const txReq = {
      to: "0x3333333333333333333333333333333333333333",
      value: ethers.parseEther("0.1"),
      type: 2,
    };

    const serializedSigned = await kmsSigner.signTransaction(txReq);
    expect(serializedSigned.startsWith("0x02")).toBe(true);

    const parsedTx = Transaction.from(serializedSigned);
    expect(parsedTx.from?.toLowerCase()).toBe(testWallet.address.toLowerCase());
    expect(parsedTx.to?.toLowerCase()).toBe("0x3333333333333333333333333333333333333333".toLowerCase());
    expect(parsedTx.value).toBe(ethers.parseEther("0.1"));
    expect(parsedTx.chainId).toBe(48816n);
  });
});

describe("AwsKmsSigner: Config Validation", () => {
  it("should reject empty keyId", () => {
    expect(() => new AwsKmsSigner({ keyId: "" })).toThrow("keyId is required");
    expect(() => new AwsKmsSigner({ keyId: "   " })).toThrow("keyId is required");
  });

  it("should initialize with valid keyId and custom region", () => {
    const signer = new AwsKmsSigner({
      keyId: "arn:aws:kms:us-west-2:123456789012:key/abcd-1234",
      region: "us-west-2",
    });
    expect(signer.keyId).toBe("arn:aws:kms:us-west-2:123456789012:key/abcd-1234");
    expect(signer.region).toBe("us-west-2");
  });
});
