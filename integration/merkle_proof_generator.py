"""
merkle_proof_generator.py
Generates Merkle proofs from mock custodian balances for off-chain integration.
"""

from data_layer.collectors.mock_custodian import get_mock_reserves
from crypto_layer.merkle_tree import (
    sha256,
    get_smt_root,
    get_verkle_root,
    get_smt_proof,
    get_verkle_proof,
    verify_smt_proof,
    verify_verkle_proof,
)


class HybridProofGenerator:
    """Generates both SMT and simplified Verkle-style proofs for reserves.

    Notes:
    - Verkle here is a simplified vector commitment (chunked hashing + outer Merkle).
    - This provides compatible APIs for downstream integration scripts.
    """

    def __init__(self, chunk_size: int = 8):
        self.reserves = get_mock_reserves()
        self.chunk_size = chunk_size
        self.leaves = [self._leaf_hash(r) for r in self.reserves]

    def _leaf_hash(self, reserve):
        # Hash account and balance as a string
        return sha256(f"{reserve['account']}:{reserve['balance']}")

    def get_smt_root(self):
        return get_smt_root(self.leaves)

    def get_verkle_root(self):
        return get_verkle_root(self.leaves, chunk_size=self.chunk_size)

    def get_smt_proof(self, index: int):
        return get_smt_proof(self.leaves, index)

    def get_verkle_proof(self, index: int):
        return get_verkle_proof(self.leaves, index, chunk_size=self.chunk_size)


if __name__ == "__main__":
    mpg = HybridProofGenerator(chunk_size=8)
    print("SMT Root:", mpg.get_smt_root())
    print("Verkle Root:", mpg.get_verkle_root())
    # show proofs and basic verification
    for i, reserve in enumerate(mpg.reserves):
        smt_proof = mpg.get_smt_proof(i)
        verkle_proof = mpg.get_verkle_proof(i)
        leaf = mpg._leaf_hash(reserve)
        smt_ok = verify_smt_proof(leaf, smt_proof, i, mpg.get_smt_root())
        verkle_ok = verify_verkle_proof(leaf, verkle_proof, i, mpg.get_verkle_root(), chunk_size=8)
        print(f"Account {reserve['account']} index={i}")
        print("  SMT proof ok:", smt_ok)
        print("  Verkle proof ok:", verkle_ok)
        print("  SMT proof:", smt_proof)
        print("  Verkle proof (inner_chunk length):", len(verkle_proof.get("inner_chunk", [])))
