// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title EvidenceRegistry
 * @notice Anchors Veridex Evidence Bundle hashes while separating the off-chain
 *         evidence authority from the gas-paying anchor relayer.
 *
 * An anchorer may submit an already-signed bundle but cannot manufacture one:
 * `recordEvidence` verifies a short-lived EIP-712 authorization signed by a
 * separately allowlisted evidence signer. This fixes the v1 single-signer
 * design, where setting a relayer as `authorizedSigner` made the anchored
 * record falsely identify the relayer as the evidence authority.
 */
contract EvidenceRegistry {
    address public owner;
    address public pendingOwner;

    mapping(bytes32 => mapping(address => bool)) public authorizedEvidenceSigners;
    mapping(bytes32 => mapping(address => bool)) public authorizedAnchorers;

    bytes32 private constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant EVIDENCE_AUTHORIZATION_TYPEHASH =
        keccak256("EvidenceAuthorization(bytes32 agentHash,bytes32 bundleHash,address sessionSigner,bytes32 storageUriHash,uint256 deadline)");
    bytes32 private constant SECP256K1N_DIV_2 =
        0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    event EvidenceSignerSet(string indexed agentId, bytes32 indexed agentIdHash, address indexed signer, bool allowed);
    event AnchorerSet(string indexed agentId, bytes32 indexed agentIdHash, address indexed anchorer, bool allowed);
    event OwnershipTransferStarted(address indexed previousOwner, address indexed pendingOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event EvidenceRecorded(
        string indexed agentId,
        bytes32 indexed bundleHash,
        address indexed sessionSigner,
        address anchorer,
        uint256 timestamp,
        string storageUri
    );

    struct EvidenceRecord {
        string agentId;
        bytes32 bundleHash;
        address sessionSigner;
        uint256 timestamp;
        address anchorer;
        string storageUri;
        bool exists;
    }

    mapping(bytes32 => EvidenceRecord) private records;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this");
        _;
    }

    function transferOwnership(address nextOwner) external onlyOwner {
        require(nextOwner != address(0) && nextOwner != owner, "Invalid next owner");
        pendingOwner = nextOwner;
        emit OwnershipTransferStarted(owner, nextOwner);
    }

    function acceptOwnership() external {
        require(msg.sender == pendingOwner, "Only pending owner can accept");
        address previousOwner = owner;
        owner = pendingOwner;
        pendingOwner = address(0);
        emit OwnershipTransferred(previousOwner, owner);
    }

    function setEvidenceSigner(string calldata agentId, address signer, bool allowed) external onlyOwner {
        require(signer != address(0), "Signer cannot be zero address");
        bytes32 agentHash = keccak256(bytes(agentId));
        authorizedEvidenceSigners[agentHash][signer] = allowed;
        emit EvidenceSignerSet(agentId, agentHash, signer, allowed);
    }

    /**
     * @notice Atomically hand evidence authority from one session key to the
     * next. A sequence of separate allow/revoke transactions briefly leaves
     * two keys trusted; this transition never does.
     */
    function rotateEvidenceSigner(
        string calldata agentId,
        address previousSigner,
        address nextSigner
    ) external onlyOwner {
        require(previousSigner != address(0) && nextSigner != address(0), "Signer cannot be zero address");
        require(previousSigner != nextSigner, "Signer unchanged");
        bytes32 agentHash = keccak256(bytes(agentId));
        require(authorizedEvidenceSigners[agentHash][previousSigner], "Previous signer is not authorized");
        authorizedEvidenceSigners[agentHash][previousSigner] = false;
        authorizedEvidenceSigners[agentHash][nextSigner] = true;
        emit EvidenceSignerSet(agentId, agentHash, previousSigner, false);
        emit EvidenceSignerSet(agentId, agentHash, nextSigner, true);
    }

    function setAnchorer(string calldata agentId, address anchorer, bool allowed) external onlyOwner {
        require(anchorer != address(0), "Anchorer cannot be zero address");
        bytes32 agentHash = keccak256(bytes(agentId));
        authorizedAnchorers[agentHash][anchorer] = allowed;
        emit AnchorerSet(agentId, agentHash, anchorer, allowed);
    }

    function recordEvidence(
        string calldata agentId,
        bytes32 bundleHash,
        string calldata storageUri,
        address sessionSigner,
        uint256 authorizationDeadline,
        bytes calldata authorizationSignature
    ) external {
        bytes32 agentHash = keccak256(bytes(agentId));
        require(authorizedAnchorers[agentHash][msg.sender], "Caller is not an authorized anchorer");
        require(!records[bundleHash].exists, "Evidence bundle already recorded");
        require(authorizationDeadline >= block.timestamp, "Evidence authorization expired");
        require(sessionSigner != address(0), "Session signer cannot be zero address");
        require(bytes(storageUri).length > 0 && bytes(storageUri).length <= 2048, "Invalid storage URI");

        bytes32 structHash = keccak256(abi.encode(
            EVIDENCE_AUTHORIZATION_TYPEHASH,
            agentHash,
            bundleHash,
            sessionSigner,
            keccak256(bytes(storageUri)),
            authorizationDeadline
        ));
        address recovered = _recover(_hashTypedDataV4(structHash), authorizationSignature);
        require(recovered == sessionSigner, "Authorization signer mismatch");
        require(authorizedEvidenceSigners[agentHash][recovered], "Session signer is not authorized");

        records[bundleHash] = EvidenceRecord({
            agentId: agentId,
            bundleHash: bundleHash,
            sessionSigner: recovered,
            timestamp: block.timestamp,
            anchorer: msg.sender,
            storageUri: storageUri,
            exists: true
        });

        emit EvidenceRecorded(agentId, bundleHash, recovered, msg.sender, block.timestamp, storageUri);
    }

    function isEvidenceRecorded(bytes32 bundleHash) external view returns (bool) {
        return records[bundleHash].exists;
    }

    function getEvidenceRecord(bytes32 bundleHash) external view returns (EvidenceRecord memory) {
        return records[bundleHash];
    }

    function domainSeparator() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    function _domainSeparatorV4() internal view returns (bytes32) {
        return keccak256(abi.encode(
            EIP712_DOMAIN_TYPEHASH,
            keccak256(bytes("Veridex Evidence Registry")),
            keccak256(bytes("3")),
            block.chainid,
            address(this)
        ));
    }

    function _hashTypedDataV4(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", _domainSeparatorV4(), structHash));
    }

    function _recover(bytes32 digest, bytes calldata signature) internal pure returns (address) {
        require(signature.length == 65, "Invalid authorization signature length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        if (v < 27) v += 27;
        require(v == 27 || v == 28, "Invalid authorization signature v");
        require(uint256(s) <= uint256(SECP256K1N_DIV_2), "Invalid authorization signature s");
        address signer = ecrecover(digest, v, r, s);
        require(signer != address(0), "Invalid authorization signature");
        return signer;
    }
}
