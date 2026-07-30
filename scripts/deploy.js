const { ethers } = require("ethers");
const fs = require("fs");
const path = require("path");

// Load the build output or the compiled bytecode and ABI
const goatContractsPath = path.join(__dirname, "../dist/index.js");
let deployEvidenceRegistry;
let EVIDENCE_REGISTRY_ABI;
let EVIDENCE_REGISTRY_BYTECODE;

try {
  const sdk = require(goatContractsPath);
  deployEvidenceRegistry = sdk.deployEvidenceRegistry;
  EVIDENCE_REGISTRY_ABI = sdk.EVIDENCE_REGISTRY_ABI;
  EVIDENCE_REGISTRY_BYTECODE = sdk.EVIDENCE_REGISTRY_BYTECODE;
} catch (err) {
  // If not built yet, load from source or build first
  console.error("SDK must be built before running the deployment script. Run 'npm run build' first.");
  process.exit(1);
}

// Config GOAT Network RPC
const GOAT_RPC = "https://rpc.testnet3.goat.network";
const PRIVATE_KEY = process.env.PRIVATE_KEY || "0xb4daccf91e251bc968dbbbbd1ecd689433a7797e7900e881e653bc3d20965a7c";

async function main() {
  const provider = new ethers.JsonRpcProvider(GOAT_RPC);
  const wallet = new ethers.Wallet(PRIVATE_KEY, provider);
  const address = await wallet.getAddress();
  
  console.log(`Connecting to GOAT Network Testnet3...`);
  console.log(`Using Wallet Address: ${address}`);
  
  try {
    const balance = await provider.getBalance(address);
    console.log(`Wallet Balance: ${ethers.formatEther(balance)} BTC`);
    
    if (balance === 0n) {
      console.warn("WARNING: Wallet has 0 BTC balance on GOAT Network Testnet3. Deployment will fail if gas cannot be paid.");
    }
  } catch (err) {
    console.error("Failed to check wallet balance:", err.message);
  }

  console.log("Deploying EvidenceRegistry contract...");
  try {
    const result = await deployEvidenceRegistry(wallet);
    console.log(`\n==================================================`);
    console.log(`🎉 EvidenceRegistry successfully deployed!`);
    console.log(`Contract Address: ${result.address}`);
    console.log(`Transaction Hash: ${result.txHash}`);
    console.log(`==================================================\n`);
  } catch (err) {
    console.error("Deployment failed:", err.message);
    process.exit(1);
  }
}

main();
