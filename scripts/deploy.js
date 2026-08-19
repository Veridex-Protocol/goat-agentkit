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
const PRIVATE_KEY = process.env.PRIVATE_KEY;

if (!PRIVATE_KEY || PRIVATE_KEY.trim().length === 0) {
  console.error("ERROR: PRIVATE_KEY environment variable is required for deployment.");
  console.error("Usage: PRIVATE_KEY=0x... node scripts/deploy.js");
  process.exit(1);
}

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
    const runtimeBytecode = await provider.getCode(result.address);
    const codeHash = ethers.keccak256(runtimeBytecode);
    const contract = new ethers.Contract(result.address, EVIDENCE_REGISTRY_ABI, provider);
    const owner = await contract.owner();

    console.log(`\n==================================================`);
    console.log(`🎉 EvidenceRegistry successfully deployed!`);
    console.log(`Contract Address: ${result.address}`);
    console.log(`Transaction Hash: ${result.txHash}`);
    console.log(`\nCopy and paste this exact block into your agent's .env:`);
    console.log(`--------------------------------------------------`);
    console.log(`EVIDENCE_REGISTRY_ADDRESS=${result.address}`);
    console.log(`EVIDENCE_REGISTRY_CODE_HASH=${codeHash}`);
    console.log(`EVIDENCE_REGISTRY_OWNER=${owner}`);
    console.log(`EVIDENCE_ANCHORING_ENABLED=true`);
    console.log(`==================================================\n`);
  } catch (err) {
    console.error("Deployment failed:", err.message);
    process.exit(1);
  }
}

main();
