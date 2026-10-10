// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 * SaakshiRegistry - decentralised anchor for SAAKSHI cold-chain records. No owner, no admin.
 *
 * Every SAAKSHI record is hashed (SHA-256 over its first 78 bytes) and signed by the node's
 * ATECC608B with ECDSA P-256. Each record also holds the hash of the record before it, so one signed
 * record (a "head") locks in the whole history behind it.
 *
 * Anyone - exporter, buyer, regulator, insurer - can post a head here. The contract re-hashes the
 * record and checks the chip's signature itself, using Polygon's built-in P-256 verifier (RIP-7212,
 * address 0x100). A head that the chip did not sign is rejected, whoever sends it. So nobody has to
 * be trusted to post: not AEGIS_X, not the ledger, not the relayer.
 *
 *   register(x, y, body, r, s)   add a node's public key; proven with one record it signed
 *   submitHead(keyHash, body, r, s)   anchor a signed record; anyone may call
 *   isAnchored(recordHash)       when was this record fixed, and by which node
 *
 * keyHash = sha256(0x04 || x || y). Its first 4 bytes are the node ID printed on the box
 * (SAAKSHI-25D8016E), the same rule the firmware uses.
 *
 * Deploy once on Polygon Amoy (chain id 80002) with Remix, EVM version "paris". No constructor arguments.
 */
contract SaakshiRegistry {
    address private constant P256_VERIFIER = address(0x100);
    uint256 private constant BODY_LEN = 78;      // the Record struct up to (not including) its hash

    struct Node {
        bytes32 x;
        bytes32 y;
        uint64 registered;      // block time; 0 = not registered
    }

    struct Stamp {
        bytes32 keyHash;        // which node signed it
        uint32 seq;             // read from the record itself
        uint32 nodeTime;        // the node's own clock in the record (0 = not set)
        uint64 blockTime;       // when it was anchored: the record cannot be older-dated after this
        address relayer;        // who paid to post it (informational only)
    }

    mapping(bytes32 => Node) private nodes;          // keyHash => key
    mapping(bytes32 => Stamp) private stamps;        // record hash => stamp
    mapping(bytes32 => bytes32[]) private headList;  // keyHash => anchored record hashes, oldest first

    event NodeRegistered(bytes32 indexed keyHash, bytes4 nodeId, bytes32 x, bytes32 y, address by);
    event HeadAnchored(
        bytes32 indexed keyHash,
        bytes32 indexed recordHash,
        uint32 seq,
        uint32 nodeTime,
        uint256 index,
        address relayer
    );

    error BadBody(uint256 length);
    error BadSignature();
    error AlreadyRegistered(bytes32 keyHash);
    error NotRegistered(bytes32 keyHash);
    error AlreadyAnchored(bytes32 recordHash);

    // ---------------- writes (anyone) ----------------

    function register(bytes32 x, bytes32 y, bytes calldata body, bytes32 r, bytes32 s)
        external
        returns (bytes32 keyHash)
    {
        keyHash = keyHashOf(x, y);
        if (nodes[keyHash].registered != 0) revert AlreadyRegistered(keyHash);
        if (body.length != BODY_LEN) revert BadBody(body.length);
        if (!_p256(sha256(body), r, s, x, y)) revert BadSignature();   // proves the key is a live chip key

        _addNode(keyHash, x, y);
    }

    function submitHead(bytes32 keyHash, bytes calldata body, bytes32 r, bytes32 s) external {
        if (nodes[keyHash].registered == 0) revert NotRegistered(keyHash);
        if (body.length != BODY_LEN) revert BadBody(body.length);

        bytes32 h = sha256(body);
        if (stamps[h].blockTime != 0) revert AlreadyAnchored(h);
        if (!_p256(h, r, s, nodes[keyHash].x, nodes[keyHash].y)) revert BadSignature();

        _store(keyHash, h, _u32le(body, 0), _u32le(body, 12));   // seq at byte 0, node clock at 12
    }

    // ---------------- reads ----------------

    function keyHashOf(bytes32 x, bytes32 y) public pure returns (bytes32) {
        return sha256(abi.encodePacked(bytes1(0x04), x, y));
    }

    function node(bytes32 keyHash) external view returns (bytes32 x, bytes32 y, uint64 registered) {
        Node storage n = nodes[keyHash];
        return (n.x, n.y, n.registered);
    }

    function isAnchored(bytes32 recordHash)
        external
        view
        returns (bool anchored, bytes32 keyHash, uint32 seq, uint32 nodeTime, uint64 blockTime, address relayer)
    {
        Stamp storage t = stamps[recordHash];
        return (t.blockTime != 0, t.keyHash, t.seq, t.nodeTime, t.blockTime, t.relayer);
    }

    function headCount(bytes32 keyHash) external view returns (uint256) {
        return headList[keyHash].length;
    }

    function headAt(bytes32 keyHash, uint256 index) external view returns (bytes32) {
        return headList[keyHash][index];
    }

    /// Lets anyone confirm the P-256 check works on this chain.
    function verifySignature(bytes32 h, bytes32 r, bytes32 s, bytes32 x, bytes32 y) external view returns (bool) {
        return _p256(h, r, s, x, y);
    }

    // ---------------- internals ----------------

    /// True only on an explicit "valid" answer. On Polygon an invalid signature returns no data, the
    /// same as a missing verifier, so anything other than exactly 32 bytes == 1 counts as invalid.
    function _p256(bytes32 h, bytes32 r, bytes32 s, bytes32 x, bytes32 y) private view returns (bool) {
        (bool ok, bytes memory ret) = P256_VERIFIER.staticcall(abi.encodePacked(h, r, s, x, y));
        return ok && ret.length == 32 && abi.decode(ret, (uint256)) == 1;
    }

    function _addNode(bytes32 keyHash, bytes32 x, bytes32 y) private {
        nodes[keyHash] = Node(x, y, uint64(block.timestamp));
        emit NodeRegistered(keyHash, bytes4(keyHash), x, y, msg.sender);
    }

    /// Kept separate from submitHead so neither function holds too many values at once.
    function _store(bytes32 keyHash, bytes32 h, uint32 seq, uint32 nodeTime) private {
        stamps[h] = Stamp(keyHash, seq, nodeTime, uint64(block.timestamp), msg.sender);
        bytes32[] storage list = headList[keyHash];
        list.push(h);
        emit HeadAnchored(keyHash, h, seq, nodeTime, list.length - 1, msg.sender);
    }

    function _u32le(bytes calldata b, uint256 at) private pure returns (uint32) {
        return uint32(uint8(b[at]))
            | (uint32(uint8(b[at + 1])) << 8)
            | (uint32(uint8(b[at + 2])) << 16)
            | (uint32(uint8(b[at + 3])) << 24);
    }
}
