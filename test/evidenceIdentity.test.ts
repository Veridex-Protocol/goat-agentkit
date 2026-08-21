import { describe, expect, it, vi } from "vitest";
import { ethers } from "ethers";
import {
  EvidenceBuilder,
  LocalSessionSigner,
  evidenceBundleDomain,
  parseERC8004AgentId,
} from "../src/index";

const AGENT_ID = "erc8004:48816:1042";
const REGISTRY = "0x1111111111111111111111111111111111111111";
const IDENTITY_REGISTRY = "0x2222222222222222222222222222222222222222";
const OWNER = "0x3333333333333333333333333333333333333333";
const ANCHORER = "0x4444444444444444444444444444444444444444";

describe("ERC-8004 evidence identity binding", () => {
  it("parses only a canonical chain and token namespace and derives the signing domain", () => {
    expect(parseERC8004AgentId(AGENT_ID)).toEqual({ chainId: 48816, tokenId: 1042n });
    expect(evidenceBundleDomain(AGENT_ID)).toEqual({
      name: "Veridex Evidence Bundle",
      version: "1",
      chainId: 48816,
    });
    expect(() => parseERC8004AgentId("erc8004:048816:1042")).toThrow("Invalid");
    expect(() => parseERC8004AgentId("erc8004:48816:1e3")).toThrow("Invalid");
  });

  async function fixture(identityOwner = OWNER, evidenceOwner = OWNER, chainId = 48816n) {
    const signer = new LocalSessionSigner("0x" + "7".repeat(64));
    const signerAddress = await signer.getAddress();
    const builder = new EvidenceBuilder(AGENT_ID, ethers.id(signerAddress));
    const bundle = builder.buildSuccess({
      payload: {
        to: "0x5555555555555555555555555555555555555555",
        asset: "USDC",
        amount: "1",
        chain: 48816,
      },
      evaluation: { verdict: "pass", reasons: ["test"] } as any,
      settlementTxHash: "0x" + "a".repeat(64),
      storageCid: "sha256:test-content",
    });
    bundle.storageUrl = `https://evidence.example/${bundle.bundleHash}`;
    await signer.signBundle(bundle);

    const registryInterface = new ethers.Interface([
      "function owner() view returns (address)",
      "function getEvidenceRecord(bytes32) view returns (tuple(string agentId, bytes32 bundleHash, address sessionSigner, uint256 timestamp, address anchorer, string storageUri, bool exists))",
    ]);
    const identityInterface = new ethers.Interface(["function ownerOf(uint256) view returns (address)"]);
    const provider = {
      getNetwork: vi.fn().mockResolvedValue({ chainId }),
      call: vi.fn().mockImplementation(async ({ to, data }: { to: string; data: string }) => {
        if (to.toLowerCase() === IDENTITY_REGISTRY.toLowerCase()) {
          return identityInterface.encodeFunctionResult("ownerOf", [identityOwner]);
        }
        const selector = data.slice(0, 10);
        if (selector === registryInterface.getFunction("owner")!.selector) {
          return registryInterface.encodeFunctionResult("owner", [evidenceOwner]);
        }
        return registryInterface.encodeFunctionResult("getEvidenceRecord", [[
          AGENT_ID,
          bundle.bundleHash,
          signerAddress,
          1n,
          ANCHORER,
          bundle.storageUrl,
          true,
        ]]);
      }),
    };
    return { bundle, provider };
  }

  it("accepts an immutable record only when the identity token owner governs it", async () => {
    const { bundle, provider } = await fixture();
    await expect(EvidenceBuilder.verifyBundleWithMandate(bundle, provider, REGISTRY, {
      identityRegistryAddress: IDENTITY_REGISTRY,
      expectedAgentOwner: OWNER,
    })).resolves.toEqual(expect.objectContaining({ valid: true, mandateVerified: true }));
  });

  it("rejects wrong-chain providers and evidence registries outside token-owner governance", async () => {
    const wrongChain = await fixture(OWNER, OWNER, 2345n);
    const chainResult = await EvidenceBuilder.verifyBundleWithMandate(wrongChain.bundle, wrongChain.provider, REGISTRY, {
      identityRegistryAddress: IDENTITY_REGISTRY,
      expectedAgentOwner: OWNER,
    });
    expect(chainResult).toEqual(expect.objectContaining({ valid: false, mandateVerified: false }));
    expect(chainResult.reason).toContain("chain mismatch");

    const wrongOwner = await fixture(OWNER, "0x6666666666666666666666666666666666666666");
    const ownerResult = await EvidenceBuilder.verifyBundleWithMandate(wrongOwner.bundle, wrongOwner.provider, REGISTRY, {
      identityRegistryAddress: IDENTITY_REGISTRY,
      expectedAgentOwner: OWNER,
    });
    expect(ownerResult).toEqual(expect.objectContaining({ valid: false, mandateVerified: false }));
    expect(ownerResult.reason).toContain("identity token owner");
  });
});
