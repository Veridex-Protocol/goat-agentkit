const fs = require("node:fs");
const path = require("node:path");
const solc = require("solc");

const sourcePath = path.join(__dirname, "..", "contracts", "EvidenceRegistry.sol");
const source = fs.readFileSync(sourcePath, "utf8");
const sourceName = "contracts/EvidenceRegistry.sol";
const input = {
  language: "Solidity",
  sources: { [sourceName]: { content: source } },
  settings: {
    optimizer: { enabled: false },
    outputSelection: { "*": { "*": ["evm.bytecode.object"] } },
  },
};

const output = JSON.parse(solc.compile(JSON.stringify(input)));
const errors = (output.errors || []).filter((entry) => entry.severity === "error");
if (errors.length > 0) {
  throw new Error(errors.map((entry) => entry.formattedMessage).join("\n"));
}

const compiled = `0x${output.contracts[sourceName].EvidenceRegistry.evm.bytecode.object}`;
const sdk = require(path.join(__dirname, "..", "dist", "index.js"));
if (compiled.toLowerCase() !== sdk.EVIDENCE_REGISTRY_BYTECODE.toLowerCase()) {
  throw new Error("Embedded EvidenceRegistry bytecode does not match contracts/EvidenceRegistry.sol");
}

console.log(`EvidenceRegistry v3 artifact verified (${(compiled.length - 2) / 2} creation bytes).`);
