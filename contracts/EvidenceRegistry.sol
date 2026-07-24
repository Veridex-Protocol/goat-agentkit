// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title EvidenceRegistry
 * @notice On-chain registry for anchoring Veridex Evidence Bundle hashes for GOAT Network Agents.
 * Compatible with ERC-8004 Identity & Reputation specs.
 */
contract EvidenceRegistry {
    address public owner;

    // Mapping from agent ID hash => authorized signer address
    mapping(bytes32 => address) public authorizedSigners;

    event AuthorizedSignerSet(string indexed agentId, bytes32 indexed agentIdHash, address indexed signer);
    event EvidenceRecorded(
        string indexed agentId,
        bytes32 indexed bundleHash,
        address indexed sessionSigner,
        uint256 timestamp,
        string storageUri
    );

    struct EvidenceRecord {
        string agentId;
        bytes32 bundleHash;
        address sessionSigner;
        uint256 timestamp;
        bool exists;
    }

    mapping(bytes32 => EvidenceRecord) public records;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this");
        _;
    }

    function setAuthorizedSigner(string calldata agentId, address signer) external onlyOwner {
        bytes32 agentHash = keccak256(bytes(agentId));
        authorizedSigners[agentHash] = signer;
        emit AuthorizedSignerSet(agentId, agentHash, signer);
    }

    /**
     * @notice Anchors an Evidence Bundle hash on-chain.
     * @param agentId ERC-8004 Agent ID string (e.g., erc8004:8453:1042)
     * @param bundleHash Keccak256 hash of the signed Evidence Bundle
     * @param storageUri Optional decentralized storage URI (Filecoin/IPFS)
     */
    function recordEvidence(
        string calldata agentId,
        bytes32 bundleHash,
        string calldata storageUri
    ) external {
        bytes32 agentHash = keccak256(bytes(agentId));
        address authorized = authorizedSigners[agentHash];
        require(authorized != address(0), "No authorized signer set for agent");
        require(msg.sender == authorized, "Caller is not authorized signer for agent");

        require(!records[bundleHash].exists, "Evidence bundle already recorded");

        records[bundleHash] = EvidenceRecord({
            agentId: agentId,
            bundleHash: bundleHash,
            sessionSigner: msg.sender,
            timestamp: block.timestamp,
            exists: true
        });

        emit EvidenceRecorded(agentId, bundleHash, msg.sender, block.timestamp, storageUri);
    }

    /**
     * @notice Verifies if a bundle hash has been anchored on-chain.
     */
    function isEvidenceRecorded(bytes32 bundleHash) external view returns (bool) {
        return records[bundleHash].exists;
    }

    /**
     * @notice Fetches evidence record details for a bundle hash.
     */
    function getEvidenceRecord(bytes32 bundleHash)
        external
        view
        returns (
            string memory agentId,
            bytes32 hash,
            address sessionSigner,
            uint256 timestamp,
            bool exists
        )
    {
        EvidenceRecord memory record = records[bundleHash];
        return (
            record.agentId,
            record.bundleHash,
            record.sessionSigner,
            record.timestamp,
            record.exists
        );
    }
}
