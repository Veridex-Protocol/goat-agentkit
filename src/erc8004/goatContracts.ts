import { ethers } from "ethers";

/**
 * Helper to safely checksum addresses regardless of input casing.
 */
function getChecksumAddress(addr: string): string {
  try {
    return ethers.getAddress(addr.toLowerCase());
  } catch {
    return addr;
  }
}

/**
 * Canonical ERC-8004 Contract Addresses on GOAT Network
 */
export const GOAT_ERC8004_ADDRESSES = {
  mainnet: {
    chainId: 2345,
    identityRegistry: getChecksumAddress("0x8004A169FB4a3325136EB29fA0ceB6D2e539a432"),
    reputationRegistry: getChecksumAddress("0x8004BAa17C55a88189AE136b182e5fdA19dE9b63"),
    validationRegistry: getChecksumAddress("0x8004cabcde123456789012345678901234567890"),
    evidenceRegistry: "0x0000000000000000000000000000000000000000",
    agentRegistryId: "eip155:2345:0x8004A169FB4a3325136EB29fA0ceB6D2e539a432",
  },
  testnet3: {
    chainId: 48816,
    identityRegistry: getChecksumAddress("0x556089008Fc0a60cD09390Eca93477ca254A5522"),
    reputationRegistry: getChecksumAddress("0xd9140951d8aE6E5F625a02F5908535e16e3af964"),
    validationRegistry: getChecksumAddress("0x556089008Fc0a60cD09390Eca93477ca254A5522"),
    evidenceRegistry: getChecksumAddress("0x07F608AFf6d63b68029488b726d895c4Bb593038"),
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
  "function setAuthorizedSigner(string calldata agentId, address signer) external",
  "function recordEvidence(string calldata agentId, bytes32 bundleHash, string calldata storageUri) external",
  "function isEvidenceRecorded(bytes32 bundleHash) external view returns (bool)",
  "function getEvidenceRecord(bytes32 bundleHash) external view returns (string memory agentId, bytes32 hash, address sessionSigner, uint256 timestamp, bool exists)",
  "event AuthorizedSignerSet(string indexed agentId, bytes32 indexed agentIdHash, address indexed signer)",
  "event EvidenceRecorded(string indexed agentId, bytes32 indexed bundleHash, address indexed sessionSigner, uint256 timestamp, string storageUri)",
];

export const EVIDENCE_REGISTRY_BYTECODE = "0x608060405234801561000f575f80fd5b50335f806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555061125d8061005c5f395ff3fe608060405234801561000f575f80fd5b506004361061007b575f3560e01c80635e47d214116100595780635e47d214146100ff5780636f2b2059146101335780638da5cb5b14610163578063e08b4761146101815761007b565b806301e647251461007f5780633f2716d1146100b357806340cd27d2146100cf575b5f80fd5b61009960048036038101906100949190610917565b61019d565b6040516100aa959493929190610a4c565b60405180910390f35b6100cd60048036038101906100c89190610b05565b610280565b005b6100e960048036038101906100e49190610917565b6105a4565b6040516100f69190610b96565b60405180910390f35b61011960048036038101906101149190610917565b6105d4565b60405161012a959493929190610a4c565b60405180910390f35b61014d60048036038101906101489190610917565b610737565b60405161015a9190610baf565b60405180910390f35b61016b610760565b6040516101789190610b96565b60405180910390f35b61019b60048036038101906101969190610bf2565b610783565b005b6002602052805f5260405f205f91509050805f0180546101bc90610c7c565b80601f01602080910402602001604051908101604052809291908181526020018280546101e890610c7c565b80156102335780601f1061020a57610100808354040283529160200191610233565b820191905f5260205f20905b81548152906001019060200180831161021657829003601f168201915b505050505090806001015490806002015f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff1690806003015490806004015f9054906101000a900460ff16905085565b5f8585604051610291929190610ce8565b604051809103902090505f60015f8381526020019081526020015f205f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff1690505f73ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff160361033d576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161033490610d70565b60405180910390fd5b8073ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff16146103ab576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016103a290610dfe565b60405180910390fd5b60025f8681526020019081526020015f206004015f9054906101000a900460ff161561040c576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161040390610e66565b60405180910390fd5b6040518060a0016040528088888080601f0160208091040260200160405190810160405280939291908181526020018383808284375f81840152601f19601f8201169050808301925050505050505081526020018681526020013373ffffffffffffffffffffffffffffffffffffffff1681526020014281526020016001151581525060025f8781526020019081526020015f205f820151815f0190816104b3919061104e565b50602082015181600101556040820151816002015f6101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550606082015181600301556080820151816004015f6101000a81548160ff0219169083151502179055509050503373ffffffffffffffffffffffffffffffffffffffff1685888860405161055892919061114b565b60405180910390207f9d11d25025a758b6d6fc5c14d69c87c91398681c9b58e91e4b391b2c448321a14288886040516105939392919061118f565b60405180910390a450505050505050565b6001602052805f5260405f205f915054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b60605f805f805f60025f8881526020019081526020015f206040518060a00160405290815f8201805461060690610c7c565b80601f016020809104026020016040519081016040528092919081815260200182805461063290610c7c565b801561067d5780601f1061065457610100808354040283529160200191610233565b820191905f5260205f20905b81548152906001019060200180831161021657829003601f168201915b505050505090806001015490806002015f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200160038201548152602001600482015f9054906101000a900460ff1615151515815250509050805f01518160200151826040015183606001518460800151955095509550955095505091939590929450565b5f60025f8381526020019081526020015f206004015f9054906101000a900460ff169050919050565b5f8054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b5f8054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614610810576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161080790611209565b60405180910390fd5b5f8383604051610821929190610ce8565b604051809103902090508160015f8381526020019081526020015f205f6101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055508173ffffffffffffffffffffffffffffffffffffffff168185856040516108a292919061114b565b60405180910390207f8b4ce089761ae739289dc833ddc1a0127b93eced32177dded77a6181a086104460405160405180910390a450505050565b5f80fd5b5f80fd5b5f819050919050565b6108f6816108e4565b8114610900575f80fd5b50565b5f81359050610911816108ed565b92915050565b5f6020828403121561092c5761092b6108dc565b5b5f61093984828501610903565b91505092915050565b5f81519050919050565b5f82825260208201905092915050565b5f5b8381101561097957808201518184015260208101905061095e565b5f8484015250505050565b5f601f19601f8301169050919050565b5f61099e82610942565b6109a8818561094c565b93506109b881856020860161095c565b6109c181610984565b840191505092915050565b6109d5816108e4565b82525050565b5f73ffffffffffffffffffffffffffffffffffffffff82169050919050565b5f610a04826109db565b9050919050565b610a14816109fa565b82525050565b5f819050919050565b610a2c81610a1a565b82525050565b5f8115159050919050565b610a4681610a32565b82525050565b5f60a0820190508181035f830152610a648188610994565b9050610a7360208301876109cc565b610a806040830186610a0b565b610a8d6060830185610a23565b610a9a6080830184610a3d565b9695505050505050565b5f80fd5b5f80fd5b5f80fd5b5f8083601f840112610ac557610ac4610aa4565b5b8235905067ffffffffffffffff811115610ae257610ae1610aa8565b5b602083019150836001820283011115610afe57610afd610aac565b5b9250929050565b5f805f805f60608688031215610b1e57610b1d6108dc565b5b5f86013567ffffffffffffffff811115610b3b57610b3a6108e0565b5b610b4788828901610ab0565b95509550506020610b5a88828901610903565b935050604086013567ffffffffffffffff811115610b7b57610b7a6108e0565b5b610b8788828901610ab0565b92509250509295509295909350565b5f602082019050610ba95f830184610a0b565b92915050565b5f602082019050610bc25f830184610a3d565b92915050565b610bd1816109fa565b8114610bdb575f80fd5b50565b5f81359050610bec81610bc8565b92915050565b5f805f60408486031215610c0957610c086108dc565b5b5f84013567ffffffffffffffff811115610c2657610c256108e0565b5b610c3286828701610ab0565b93509350506020610c4586828701610bde565b9150509250925092565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52602260045260245ffd5b5f6002820490506001821680610c9357607f821691505b602082108103610ca657610ca5610c4f565b5b50919050565b5f81905092915050565b828183375f83830152505050565b5f610ccf8385610cac565b9350610cdc838584610cb6565b82840190509392505050565b5f610cf4828486610cc4565b91508190509392505050565b7f4e6f20617574686f72697a6564207369676e65722073657420666f72206167655f8201527f6e74000000000000000000000000000000000000000000000000000000000000602082015250565b5f610d5a60228361094c565b9150610d6582610d00565b604082019050919050565b5f6020820190508181035f830152610d8781610d4e565b9050919050565b7f43616c6c6572206973206e6f7420617574686f72697a6564207369676e6572205f8201527f666f72206167656e740000000000000000000000000000000000000000000000602082015250565b5f610de860298361094c565b9150610df382610d8e565b604082019050919050565b5f6020820190508181035f830152610e1581610ddc565b9050919050565b7f45766964656e63652062756e646c6520616c7265616479207265636f726465645f82015250565b5f610e5060208361094c565b9150610e5b82610e1c565b602082019050919050565b5f6020820190508181035f830152610e7d81610e44565b9050919050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52604160045260245ffd5b5f819050815f5260205f209050919050565b5f6020601f8301049050919050565b5f82821b905092915050565b5f60088302610f0d7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff82610ed2565b610f178683610ed2565b95508019841693508086168417925050509392505050565b5f819050919050565b5f610f52610f4d610f4884610a1a565b610f2f565b610a1a565b9050919050565b5f819050919050565b610f6b83610f38565b610f7f610f7782610f59565b848454610ede565b825550505050565b5f90565b610f93610f87565b610f9e818484610f62565b505050565b5b81811015610fc157610fb65f82610f8b565b600181019050610fa4565b5050565b601f82111561100657610fd781610eb1565b610fe084610ec3565b81016020851015610fef578190505b611003610ffb85610ec3565b830182610fa3565b50505b505050565b5f82821c905092915050565b5f6110265f198460080261100b565b1980831691505092915050565b5f61103e8383611017565b9150826002028217905092915050565b61105782610942565b67ffffffffffffffff8111156110705761106f610e84565b5b61107a8254610c7c565b611085828285610fc5565b5f60209050601f8311600181146110b6575f84156110a4578287015190505b6110ae8582611033565b865550611115565b601f1984166110c486610eb1565b5f5b828110156110eb578489015182556001820191506020850194506020810190506110c6565b868310156111085784890151611104601f891682611017565b8355505b6001600288020188555050505b505050505050565b5f81905092915050565b5f611132838561111d565b935061113f838584610cb6565b82840190509392505050565b5f611157828486611127565b91508190509392505050565b5f61116e838561094c565b935061117b838584610cb6565b61118483610984565b840190509392505050565b5f6040820190506111a25f830186610a23565b81810360208301526111b5818486611163565b9050949350505050565b7f4f6e6c79206f776e65722063616e2063616c6c207468697300000000000000005f82015250565b5f6111f360188361094c565b91506111fe826111bf565b602082019050919050565b5f6020820190508181035f830152611220816111e7565b905091905056fea2646970667358221220c28eadb66e0cb75a292bd659267f08f7e7fd9cc816ffbe201ccbcd0fb3b384fe64736f6c63430008140033";

/**
 * Programmatically deploys EvidenceRegistry contract to any EVM network (GOAT Mainnet / Testnet3).
 * @deprecated Use official GOAT Testnet3 Evidence Registry at 0x07F608AFf6d63b68029488b726d895c4Bb593038 instead.
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
    gasLimit: 3000000n,
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
   * Updates agent URI on GOAT Network Identity Registry.
   */
  public async setAgentURI(agentId: number, newURI: string): Promise<{ txHash: string }> {
    const tx = await this.identityContract.setAgentURI(agentId, newURI);
    const receipt = await tx.wait();
    return { txHash: receipt.hash };
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
   * Fetches summary score and count from GOAT Reputation Registry.
   */
  public async getReputationSummary(params: {
    agentId: number;
    clientAddresses?: string[];
    tag1?: string;
    tag2?: string;
  }): Promise<{ count: bigint; summaryValue: bigint; summaryValueDecimals: number }> {
    const summary = await this.reputationContract.getSummary(
      params.agentId,
      params.clientAddresses || [],
      params.tag1 || "",
      params.tag2 || ""
    );
    return {
      count: BigInt(summary[0]),
      summaryValue: BigInt(summary[1]),
      summaryValueDecimals: Number(summary[2]),
    };
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
