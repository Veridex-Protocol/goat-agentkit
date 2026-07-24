// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title EvidenceRegistry
 * @notice On-chain registry for anchoring Veridex Evidence Bundle hashes for GOAT Network Agents.
 * Compatible with ERC-8004 Identity & Reputation specs.
 */
contract EvidenceRegistry {
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
