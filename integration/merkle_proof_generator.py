"""
merkle_proof_generator.py
Generates Merkle proofs from mock custodian balances for off-chain integration.
"""

from data_layer.collectors.mock_custodian import get_mock_reserves
from crypto_layer.merkle_tree import (
    sha256_bytes,
    get_smt_root,
    get_verkle_root,
    get_smt_proof,
    get_verkle_proof,
    verify_smt_proof,
    verify_verkle_proof,
)
import json
from pathlib import Path


class HybridProofGenerator:
    """Generates both SMT and simplified Verkle-style proofs for reserves.

    Notes:
    - Verkle here is a simplified vector commitment (chunked hashing + outer Merkle).
    - This provides compatible APIs for downstream integration scripts.
    """

    def __init__(self, chunk_size: int = 8):
        self.reserves = get_mock_reserves()
        self.chunk_size = chunk_size
        # leaves are hex-encoded sha256 digests (32 bytes -> 64 hex chars)
        self.leaves = [self._leaf_hash(r) for r in self.reserves]

    def _leaf_hash(self, reserve):
        # Hash account and balance as utf-8 bytes and return hex digest
        s = f"{reserve['account']}:{reserve['balance']}".encode("utf-8")
        return sha256_bytes(s)

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
    # Build proofs and write to JSON file for JS integration
    out = {
        "smt_root": mpg.get_smt_root(),
        "verkle_root": mpg.get_verkle_root(),
        "leaves": mpg.leaves,
        "entries": [],
    }
    for i, reserve in enumerate(mpg.reserves):
        smt_proof = mpg.get_smt_proof(i)
        verkle_proof = mpg.get_verkle_proof(i)
        leaf = mpg._leaf_hash(reserve)
        smt_ok = verify_smt_proof(leaf, smt_proof, i, mpg.get_smt_root())
        verkle_ok = verify_verkle_proof(leaf, verkle_proof, i, mpg.get_verkle_root(), chunk_size=8)
        out["entries"].append(
            {
                "account": reserve["account"],
                "index": i,
                "leaf": leaf,
                "smt_proof": smt_proof,
                "verkle_proof": verkle_proof,
                "smt_ok": smt_ok,
                "verkle_ok": verkle_ok,
            }
        )

    path = Path(__file__).parent / "merkle_proof.json"
    path.write_text(json.dumps(out, indent=2))
    print("Wrote proofs to:", str(path))
