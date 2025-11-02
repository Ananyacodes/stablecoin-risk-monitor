// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ProofOfReserves {
    bytes32 public merkleRoot;
    uint256 public circulatingSupply;

    event ProofVerified(bool valid);
    event Alert(string message);
    event SMTProofVerified(bool valid);

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

    /// @notice Verify an SMT (Merkle-style) proof against the stored root
    /// @param leaf The leaf digest (bytes32)
    /// @param proof Sibling path (bytes32[]) from leaf to root
    /// @param index The leaf index within the (padded) tree
    /// @return valid True if the proof recomputes the stored merkleRoot
    function verifySMTProof(bytes32 leaf, bytes32[] calldata proof, uint256 index) public view returns (bool valid) {
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
        valid = (h == merkleRoot);
    }
}
