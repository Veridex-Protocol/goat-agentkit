import { ethers, keccak256 } from "ethers";
import { deployEvidenceRegistry, EVIDENCE_REGISTRY_ABI } from "../src/erc8004/goatContracts.js";
import { AwsKmsSigner } from "../src/kms/kmsSigner.js";

async function main() {
  const rpcUrl = process.env.GOAT_NETWORK_RPC || "https://rpc.testnet3.goat.network";
  const provider = new ethers.JsonRpcProvider(rpcUrl);
  const net = await provider.getNetwork();
  const chainId = Number(net.chainId);

  console.log(`\n=============================================================`);
  console.log(`🚀 GOAT Network Evidence Registry Deployment Tool`);
  console.log(`Connected to RPC: ${rpcUrl} (Chain ID: ${chainId})`);
  console.log(`=============================================================\n`);

  let signer: ethers.Signer;
  const kmsKeyId = process.env.AWS_KMS_KEY_ID || process.env.KMS_KEY_ID;
  const privateKey = process.env.PRIVATE_KEY;

  if (kmsKeyId && kmsKeyId.trim().length > 0) {
    const region = process.env.AWS_REGION || "us-east-1";
    console.log(`[Signer] Using AWS KMS Hardware Key: ${kmsKeyId} (Region: ${region})`);
    signer = new AwsKmsSigner({
      keyId: kmsKeyId,
      region,
      provider,
    });
  } else if (privateKey && privateKey.trim().length > 0) {
    console.log(`[Signer] Using Local Private Key`);
    signer = new ethers.Wallet(privateKey.trim(), provider);
  } else {
    console.error("❌ ERROR: No deployment signer configured.");
    console.error("Provide either:");
    console.error("  1. AWS_KMS_KEY_ID=arn:aws:kms:... (Recommended for Production/Mainnet)");
    console.error("  2. PRIVATE_KEY=0x... (For Development/Testnet)");
    process.exit(1);
  }

  const deployerAddress = await signer.getAddress();
  console.log(`Deployer Address: ${deployerAddress}`);

  try {
    const balance = await provider.getBalance(deployerAddress);
    console.log(`Deployer Balance: ${ethers.formatEther(balance)} BTC`);
    if (balance === 0n) {
      console.warn("⚠️  WARNING: Balance is 0 BTC. Deployment will fail without gas.");
    }
  } catch (err: any) {
    console.warn(`Could not fetch balance: ${err.message}`);
  }

  console.log(`\nDeploying EvidenceRegistry contract to chain ${chainId}...`);
  const deployResult = await deployEvidenceRegistry(signer);
  const contractAddress = deployResult.address;
  const txHash = deployResult.txHash;

  console.log(`Contract Deployed at: ${contractAddress}`);
  console.log(`Deployment Tx Hash: ${txHash}`);

  // Fetch deployed runtime bytecode and compute verified code hash
  console.log(`Verifying deployed runtime bytecode on-chain...`);
  const runtimeBytecode = await provider.getCode(contractAddress);
  if (!runtimeBytecode || runtimeBytecode === "0x") {
    throw new Error(`Failed to retrieve deployed bytecode at ${contractAddress}`);
  }

  const codeHash = keccak256(runtimeBytecode);
  const contract = new ethers.Contract(contractAddress, EVIDENCE_REGISTRY_ABI, provider);
  const owner = await contract.owner();

  console.log(`\n=============================================================`);
  console.log(`🎉 EvidenceRegistry Successfully Deployed & Verified!`);
  console.log(`=============================================================`);
  console.log(`\nCopy and paste this exact block into your agent's .env:`);
  console.log(`-------------------------------------------------------------`);
  console.log(`EVIDENCE_REGISTRY_ADDRESS=${contractAddress}`);
  console.log(`EVIDENCE_REGISTRY_CODE_HASH=${codeHash}`);
  console.log(`EVIDENCE_REGISTRY_OWNER=${owner}`);
  console.log(`EVIDENCE_ANCHORING_ENABLED=true`);
  console.log(`-------------------------------------------------------------\n`);
}

main().catch((error) => {
  console.error("❌ Deployment failed:", error);
  process.exit(1);
});
