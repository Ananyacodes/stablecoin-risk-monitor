import pytest

from crypto_layer import merkle_tree as mt


def test_smt_roundtrip_and_verification():
    leaves = [mt.sha256_bytes(f"a:{i}".encode("utf-8")) for i in range(5)]
    root = mt.get_smt_root(leaves)
    # pick index 3
    idx = 3
    proof = mt.get_smt_proof(leaves, idx)
    leaf = leaves[idx]
    assert mt.verify_smt_proof(leaf, proof, idx, root) is True


def test_verkle_simplified_roundtrip_and_negative():
    leaves = [mt.sha256_bytes(f"acct:{i}".encode("utf-8")) for i in range(10)]
    root = mt.get_verkle_root(leaves, chunk_size=4)
    idx = 7
    proof_obj = mt.get_verkle_proof(leaves, idx, chunk_size=4)
    leaf = leaves[idx]
    assert mt.verify_verkle_proof(leaf, proof_obj, idx, root, chunk_size=4) is True

    # negative test: tamper inner chunk
    bad = dict(proof_obj)
    bad_inner = list(bad.get("inner_chunk", []))
    bad_inner[0] = mt.sha256_bytes(b"tamper")
    bad["inner_chunk"] = bad_inner
    assert mt.verify_verkle_proof(leaf, bad, idx, root, chunk_size=4) is False
