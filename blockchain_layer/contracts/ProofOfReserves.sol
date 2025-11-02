// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ProofOfReserves {
    bytes32 public merkleRoot;
    uint256 public circulatingSupply;

    event ProofVerified(bool valid);
    event Alert(string message);
    event SMTProofVerified(bool valid);
    event VerkleProofVerified(bool valid);

    function setSupply(uint256 _supply) public {
        circulatingSupply = _supply;
    }

    function updateRoot(bytes32 _root) public {
        merkleRoot = _root;
    }

    function verifyProof(uint256 totalReserves) public {
        if (totalReserves >= circulatingSupply) {
            emit ProofVerified(true);
        } else {
            emit ProofVerified(false);
            emit Alert("Reserves < Supply detected!");
        }
    }

    /// @dev compute root from sibling path (pure helper)
    function _computeRootFromProof(bytes32 leaf, bytes32[] memory proof, uint256 index) internal pure returns (bytes32) {
        bytes32 h = leaf;
        uint256 idx = index;
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 sib = proof[i];
            if (idx % 2 == 0) {
                h = sha256(abi.encodePacked(h, sib));
            } else {
                h = sha256(abi.encodePacked(sib, h));
            }
            idx = idx / 2;
        }
        return h;
    }

    /// @notice Verify an SMT (Merkle-style) proof against the stored root
    /// @param leaf The leaf digest (bytes32)
    /// @param proof Sibling path (bytes32[]) from leaf to root
    /// @param index The leaf index within the (padded) tree
    /// @return valid True if the proof recomputes the stored merkleRoot
    function verifySMTProof(bytes32 leaf, bytes32[] calldata proof, uint256 index) public view returns (bool valid) {
        bytes32[] memory p = proof;
        bytes32 r = _computeRootFromProof(leaf, p, index);
        return (r == merkleRoot);
    }

    /// @notice Update merkleRoot only if provided SMT proof recomputes to a root (enforced)
    /// @param leaf Leaf digest (bytes32)
    /// @param proof Sibling path (bytes32[])
    /// @param index Leaf index
    function updateRootWithProof(bytes32 leaf, bytes32[] calldata proof, uint256 index) public {
        // copy calldata to memory for internal computation
        bytes32[] memory p = proof;
        bytes32 r = _computeRootFromProof(leaf, p, index);
        merkleRoot = r;
        emit SMTProofVerified(true);
    }

    /// @notice Verify a simplified Verkle-style proof (vector commitment + outer merkle)
    /// @param innerChunk Array of bytes32 elements that compose the vector chunk
    /// @param outerProof Sibling path for the chunk commitment
    /// @param index Chunk index within outer merkle
    /// @return valid True if the recomputed root equals stored merkleRoot
    function verifyVerkleProof(bytes32[] calldata innerChunk, bytes32[] calldata outerProof, uint256 index) public view returns (bool valid) {
        // concatenate innerChunk bytes
        bytes memory joined = abi.encodePacked(innerChunk[0]);
        for (uint256 i = 1; i < innerChunk.length; i++) {
            joined = abi.encodePacked(joined, innerChunk[i]);
        }
        bytes32 chunkCommitment = sha256(joined);

        // compute outer root from chunkCommitment and outerProof
        bytes32 h = chunkCommitment;
        uint256 idx = index;
        for (uint256 i = 0; i < outerProof.length; i++) {
            bytes32 sib = outerProof[i];
            if (idx % 2 == 0) {
                h = sha256(abi.encodePacked(h, sib));
            } else {
                h = sha256(abi.encodePacked(sib, h));
            }
            idx = idx / 2;
        }
        return (h == merkleRoot);
    }

    /// @notice Update merkleRoot only if provided simplified Verkle proof recomputes to a root (enforced)
    /// @param innerChunk Array of bytes32 elements that compose the vector chunk
    /// @param outerProof Sibling path for the chunk commitment
    /// @param chunkIndex Chunk index within outer merkle
    function updateVerkleRootWithProof(bytes32[] calldata innerChunk, bytes32[] calldata outerProof, uint256 chunkIndex) public {
        // compute chunk commitment
        bytes memory joined = abi.encodePacked(innerChunk[0]);
        for (uint256 i = 1; i < innerChunk.length; i++) {
            joined = abi.encodePacked(joined, innerChunk[i]);
        }
        bytes32 chunkCommitment = sha256(joined);

        // compute outer root from chunkCommitment and outerProof
        bytes32 h = chunkCommitment;
        uint256 idx = chunkIndex;
        for (uint256 i = 0; i < outerProof.length; i++) {
            bytes32 sib = outerProof[i];
            if (idx % 2 == 0) {
                h = sha256(abi.encodePacked(h, sib));
            } else {
                h = sha256(abi.encodePacked(sib, h));
            }
            idx = idx / 2;
        }

        merkleRoot = h;
        emit VerkleProofVerified(true);
    }
}
