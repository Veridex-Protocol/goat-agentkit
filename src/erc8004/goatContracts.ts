import { ethers } from "ethers";

/**
 * Canonical ERC-8004 Contract Addresses on GOAT Network
 */
export const GOAT_ERC8004_ADDRESSES = {
  mainnet: {
    chainId: 2345,
    identityRegistry: "0x8004A169FB4a3325136EB29fA0ceB6D2e539a432",
    reputationRegistry: "0x8004BAa17C55a88189AE136b182e5fdA19dE9b63",
    validationRegistry: "0x8004CAbcDe123456789012345678901234567890",
    evidenceRegistry: "0x0000000000000000000000000000000000000000", // To be deployed on mainnet launch
    agentRegistryId: "eip155:2345:0x8004A169FB4a3325136EB29fA0ceB6D2e539a432",
  },
  testnet3: {
    chainId: 48816,
    identityRegistry: "0x556089008Fc0a60cD09390Eca93477ca254A5522",
    reputationRegistry: "0xd9140951d8aE6E5F625a02F5908535e16e3af964",
    validationRegistry: "0x8004C0De00000000000000000000000000000000",
    evidenceRegistry: "0x07F608AFf6d63b68029488b726d895c4Bb593038", // Deployed Testnet3 Contract Address
    agentRegistryId: "eip155:48816:0x556089008Fc0a60cD09390Eca93477ca254A5522",
  },
};

export const ERC8004_IDENTITY_ABI = [
  "function register(string agentURI) external returns (uint256)",
  "function register(string agentURI, tuple(string metadataKey, bytes metadataValue)[] metadata) external returns (uint256)",
  "function setAgentURI(uint256 agentId, string calldata newURI) external",
  "function getAgentWallet(uint256 agentId) external view returns (address)",
  "function setAgentWallet(uint256 agentId, address newWallet, uint256 deadline, bytes calldata signature) external",
  "function getMetadata(uint256 agentId, string memory metadataKey) external view returns (bytes memory)",
  "function setMetadata(uint256 agentId, string memory metadataKey, bytes memory metadataValue) external",
];

export const ERC8004_REPUTATION_ABI = [
  "function giveFeedback(uint256 agentId, int128 value, uint8 valueDecimals, string calldata tag1, string calldata tag2, string calldata endpoint, string calldata feedbackURI, bytes32 feedbackHash) external",
  "function revokeFeedback(uint256 agentId, uint64 feedbackIndex) external",
  "function getSummary(uint256 agentId, address[] calldata clientAddresses, string tag1, string tag2) external view returns (uint64 count, int128 summaryValue, uint8 summaryValueDecimals)",
  "function readFeedback(uint256 agentId, address clientAddress, uint64 feedbackIndex) external view returns (int128 value, uint8 valueDecimals, string tag1, string tag2, bool isRevoked)",
];

export const ERC8004_VALIDATION_ABI = [
  "function validationRequest(address validatorAddress, uint256 agentId, string requestURI, bytes32 requestHash) external",
  "function validationResponse(bytes32 requestHash, uint8 response, string responseURI, bytes32 responseHash, string tag) external",
  "function getValidationStatus(bytes32 requestHash) external view returns (address validatorAddress, uint256 agentId, uint8 response, bytes32 responseHash, string tag, uint256 lastUpdate)",
];

export const EVIDENCE_REGISTRY_ABI = [
  "function recordEvidence(string calldata agentId, bytes32 bundleHash, string calldata storageUri) external",
  "function isEvidenceRecorded(bytes32 bundleHash) external view returns (bool)",
  "function getEvidenceRecord(bytes32 bundleHash) external view returns (string memory agentId, bytes32 hash, address sessionSigner, uint256 timestamp, bool exists)",
  "event EvidenceRecorded(string indexed agentId, bytes32 indexed bundleHash, address indexed sessionSigner, uint256 timestamp, string storageUri)",
];

export const EVIDENCE_REGISTRY_BYTECODE = "0x6080604052348015600f57600080fd5b506107918061001f6000396000f3fe608060405234801561001057600080fd5b506004361061004c5760003560e01c806301e64725146100515780633f2716d11461007e5780635e47d214146100935780636f2b2059146100a6575b600080fd5b61006461005f366004610455565b6100dc565b60405161007595949392919061046e565b60405180910390f35b61009161008c366004610538565b6101a0565b005b6100646100a1366004610455565b610333565b6100cc6100b4366004610455565b60009081526020819052604090206004015460ff1690565b6040519015158152602001610075565b6000602081905290815260409020805481906100f7906105b7565b80601f0160208091040260200160405190810160405280929190818152602001828054610123906105b7565b80156101705780601f1061014557610100808354040283529160200191610170565b820191906000526020600020905b81548152906001019060200180831161015357829003601f168201915b50505050600183015460028401546003850154600490950154939491936001600160a01b03909116925060ff1685565b60008381526020819052604090206004015460ff16156102065760405162461bcd60e51b815260206004820181905260248201527f45766964656e63652062756e646c6520616c7265616479207265636f72646564604482015260640160405180910390fd5b6040518060a0016040528086868080601f0160208091040260200160405190810160405280939291908181526020018383808284376000920182905250938552505050602080830187905233604080850191909152426060850152600160809094019390935286825281905220815181906102819082610656565b50602082015160018201556040808301516002830180546001600160a01b0319166001600160a01b03909216919091179055606083015160038301556080909201516004909101805460ff191691151591909117905551339084906102e99088908890610715565b60405180910390207f9d11d25025a758b6d6fc5c14d69c87c91398681c9b58e91e4b391b2c448321a142868660405161032493929190610725565b60405180910390a45050505050565b606060008060008060008060008881526020019081526020016000206040518060a001604052908160008201805461036a906105b7565b80601f0160208091040260200160405190810160405280929190818152602001828054610396906105b7565b80156103e35780601f106103b8576101008083540402835291602001916103e3565b820191906000526020600020905b8154815290600101906020018083116103c657829003601f168201915b5050509183525050600182015460208083019190915260028301546001600160a01b0316604080840191909152600384015460608085019190915260049094015460ff16151560809384015284519185015190850151938501519490920151909b919a50919850919650945092505050565b60006020828403121561046757600080fd5b5035919050565b60a08152600086518060a084015260005b8181101561049c576020818a0181015160c086840101520161047f565b50600060c0828501015260c0601f19601f8301168401019150508560208301526104d160408301866001600160a01b03169052565b8360608301526104e5608083018415159052565b9695505050505050565b60008083601f84011261050157600080fd5b50813567ffffffffffffffff81111561051957600080fd5b60208301915083602082850101111561053157600080fd5b9250929050565b60008060008060006060868803121561055057600080fd5b853567ffffffffffffffff81111561056757600080fd5b610573888289016104ef565b90965094505060208601359250604086013567ffffffffffffffff81111561059a57600080fd5b6105a6888289016104ef565b969995985093965092949392505050565b600181811c908216806105cb57607f821691505b6020821081036105eb57634e487b7160e01b600052602260045260246000fd5b50919050565b634e487b7160e01b600052604160045260246000fd5b601f82111561065157806000526020600020601f840160051c8101602085101561062e5750805b601f840160051c820191505b8181101561064e576000815560010161063a565b50505b505050565b815167ffffffffffffffff811115610670576106706105f1565b6106848161067e84546105b7565b84610607565b6020601f8211600181146106b857600083156106a05750848201515b600019600385901b1c1916600184901b17845561064e565b600084815260208120601f198516915b828110156106e857878501518255602094850194600190920191016106c8565b50848210156107065786840151600019600387901b60f8161c191681555b50505050600190811b01905550565b8183823760009101908152919050565b83815260406020820152816040820152818360608301376000818301606090810191909152601f909201601f191601019291505056fea26469706673582212201e50926a817dafa02299a7f241352e61d62be946928078644cb92e5d46c6ff8f64736f6c634300081a0033";

/**
 * Programmatically deploys EvidenceRegistry contract to any EVM network (GOAT Mainnet / Testnet3).
 */
export async function deployEvidenceRegistry(
  signer: any
): Promise<{ address: string; txHash: string; contract: ethers.Contract }> {
  let maxPriorityFeePerGas: bigint = ethers.parseUnits("0.00013", "gwei");
  let maxFeePerGas: bigint = ethers.parseUnits("0.00014", "gwei");

  if (signer?.provider && typeof signer.provider.getFeeData === "function") {
    try {
      const feeData = await signer.provider.getFeeData();
      maxPriorityFeePerGas = feeData.maxPriorityFeePerGas ?? maxPriorityFeePerGas;
      maxFeePerGas = (feeData.maxFeePerGas ?? 0n) || ((feeData.gasPrice ?? 0n) + maxPriorityFeePerGas);
    } catch {}
  }

  // Ensure bytecode is a clean 0x-prefixed hex string with even length
  let hexString = EVIDENCE_REGISTRY_BYTECODE.replace(/^0x/i, "").replace(/[^0-9a-fA-F]/g, "");
  if (hexString.length % 2 !== 0) {
    hexString = hexString.slice(0, -1);
  }
  const cleanBytecode = "0x" + hexString;

  const factory = new ethers.ContractFactory(EVIDENCE_REGISTRY_ABI, cleanBytecode, signer);
  const contract = await factory.deploy({
    gasLimit: 1000000n,
    maxPriorityFeePerGas,
    maxFeePerGas,
    type: 2,
  }) as ethers.Contract;

  const tx = contract.deploymentTransaction();
  await contract.waitForDeployment();
  const address = await contract.getAddress();
  return {
    address,
    txHash: tx ? tx.hash : "",
    contract,
  };
}

export interface ERC8004RegistrationJSON {
  type: string;
  name: string;
  description: string;
  image?: string;
  services: Array<{
    name: string;
    endpoint: string;
    version?: string;
    skills?: string[];
    domains?: string[];
  }>;
  x402Support: boolean;
  active: boolean;
  registrations: Array<{
    agentRegistry: string;
    agentId: number;
  }>;
  supportedTrust?: string[];
}

export function buildERC8004RegistrationJSON(params: {
  name: string;
  description: string;
  agentId: number;
  network?: "mainnet" | "testnet3";
  x402Endpoint?: string;
  a2aEndpoint?: string;
  mcpEndpoint?: string;
}): ERC8004RegistrationJSON {
  const env = params.network || "testnet3";
  const addresses = GOAT_ERC8004_ADDRESSES[env];

  const services = [];

  if (params.x402Endpoint) {
    services.push({
      name: "x402",
      endpoint: params.x402Endpoint,
      version: "1.0.0",
    });
  }

  if (params.a2aEndpoint) {
    services.push({
      name: "A2A",
      endpoint: params.a2aEndpoint,
      version: "0.3.0",
    });
  }

  if (params.mcpEndpoint) {
    services.push({
      name: "MCP",
      endpoint: params.mcpEndpoint,
      version: "2025-06-18",
    });
  }

  return {
    type: "https://eips.ethereum.org/EIPS/eip-8004#registration-v1",
    name: params.name,
    description: params.description,
    image: "https://goat.network/agent-avatar.png",
    services,
    x402Support: true,
    active: true,
    registrations: [
      {
        agentRegistry: addresses.agentRegistryId,
        agentId: params.agentId,
      },
    ],
    supportedTrust: ["reputation", "crypto-economic", "tee-attestation"],
  };
}

export class GoatERC8004Client {
  private identityContract: any;
  private reputationContract: any;
  private validationContract: any;
  private evidenceContract?: any;
  private signerOrProvider: any;

  constructor(
    signerOrProvider: any,
    network: "mainnet" | "testnet3" = "testnet3",
    customEvidenceRegistryAddress?: string
  ) {
    this.signerOrProvider = signerOrProvider;
    const config = GOAT_ERC8004_ADDRESSES[network];
    this.identityContract = new ethers.Contract(config.identityRegistry, ERC8004_IDENTITY_ABI, signerOrProvider);
    this.reputationContract = new ethers.Contract(config.reputationRegistry, ERC8004_REPUTATION_ABI, signerOrProvider);
    this.validationContract = new ethers.Contract(config.validationRegistry, ERC8004_VALIDATION_ABI, signerOrProvider);

    const evidenceAddr = customEvidenceRegistryAddress || config.evidenceRegistry;
    if (evidenceAddr && evidenceAddr !== "0x0000000000000000000000000000000000000000") {
      this.evidenceContract = new ethers.Contract(evidenceAddr, EVIDENCE_REGISTRY_ABI, signerOrProvider);
    }
  }

  /**
   * Registers an agent on GOAT Network Identity Registry.
   */
  public async registerAgent(agentURI: string): Promise<{ txHash: string; agentId?: number }> {
    const tx = await this.identityContract.register(agentURI);
    const receipt = await tx.wait();
    return {
      txHash: receipt.hash,
    };
  }

  /**
   * Anchors an Evidence Bundle hash on-chain in EvidenceRegistry.
   */
  public async recordEvidenceOnChain(params: {
    agentId: string;
    bundleHash: string;
    storageUri?: string;
  }): Promise<string> {
    if (!this.evidenceContract) {
      throw new Error("EvidenceRegistry contract address not configured for this network");
    }
    const hashBytes32 = (params.bundleHash.startsWith("0x") && params.bundleHash.length === 66)
      ? params.bundleHash
      : ethers.id(params.bundleHash);

    const alreadyRecorded = await this.isEvidenceRecordedOnChain(hashBytes32).catch(() => false);
    if (alreadyRecorded) {
      console.log(`[GOAT ERC-8004] Bundle hash ${hashBytes32} already recorded on-chain.`);
      return hashBytes32;
    }

    const targetAddress = await this.evidenceContract.getAddress();
    const iface = new ethers.Interface(EVIDENCE_REGISTRY_ABI);
    const encodedData = iface.encodeFunctionData("recordEvidence", [
      params.agentId,
      hashBytes32,
      params.storageUri || ""
    ]);

    let tx;
    if (typeof this.signerOrProvider?.sendTransaction === "function") {
      tx = await this.signerOrProvider.sendTransaction({
        to: targetAddress,
        data: encodedData,
        gasLimit: 300000,
      });
    } else {
      tx = await this.evidenceContract.recordEvidence(
        params.agentId,
        hashBytes32,
        params.storageUri || "",
        { gasLimit: 300000 }
      );
    }

    const receipt = await tx.wait();
    return receipt ? receipt.hash : tx.hash;
  }

  /**
   * Queries if an evidence bundle hash is recorded on-chain.
   */
  public async isEvidenceRecordedOnChain(bundleHash: string): Promise<boolean> {
    if (!this.evidenceContract) return false;
    const hashBytes32 = (bundleHash.startsWith("0x") && bundleHash.length === 66)
      ? bundleHash
      : ethers.id(bundleHash);
    return await this.evidenceContract.isEvidenceRecorded(hashBytes32);
  }

  /**
   * Submits audit feedback with evidence hash on GOAT Reputation Registry.
   */
  public async submitFeedback(params: {
    agentId: number;
    value: number;
    tag1: string;
    tag2?: string;
    feedbackURI?: string;
    feedbackHash?: string;
  }): Promise<string> {
    const feedbackHashBytes = params.feedbackHash
      ? params.feedbackHash
      : ethers.ZeroHash;

    const tx = await this.reputationContract.giveFeedback(
      params.agentId,
      params.value,
      0, // valueDecimals
      params.tag1,
      params.tag2 || "",
      "",
      params.feedbackURI || "",
      feedbackHashBytes
    );
    const receipt = await tx.wait();
    return receipt.hash;
  }

  /**
   * Submits a validation request on GOAT Validation Registry.
   */
  public async submitValidationRequest(params: {
    validatorAddress: string;
    agentId: number;
    requestURI: string;
    requestHash: string;
  }): Promise<string> {
    const tx = await this.validationContract.validationRequest(
      params.validatorAddress,
      params.agentId,
      params.requestURI,
      params.requestHash
    );
    const receipt = await tx.wait();
    return receipt.hash;
  }

  /**
   * Submits a validation response on GOAT Validation Registry.
   */
  public async submitValidationResponse(params: {
    requestHash: string;
    response: number;
    responseURI?: string;
    responseHash?: string;
    tag?: string;
  }): Promise<string> {
    const tx = await this.validationContract.validationResponse(
      params.requestHash,
      params.response,
      params.responseURI || "",
      params.responseHash || ethers.ZeroHash,
      params.tag || ""
    );
    const receipt = await tx.wait();
    return receipt.hash;
  }
}
