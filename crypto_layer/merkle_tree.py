import hashlib
from typing import List, Tuple, Dict, Any


def sha256(data: str) -> str:
    """Return hex sha256 of the given string."""
    return hashlib.sha256(data.encode()).hexdigest()


# ------------------------------------------------------------------
# Sparse Merkle Tree (SMT) -- simple full-binary implementation
# - Keeps API similar to the previous Merkle tree but exposes SMT
#   proof generation/verification functions.
# ------------------------------------------------------------------

def _next_power_of_two(n: int) -> int:
    p = 1
    while p < n:
        p <<= 1
    return p


def build_smt_levels(leaves: List[str]) -> List[List[str]]:
    """Build full-binary SMT levels from leaf hex-hashes.

    Returns a list of levels where level 0 is leaves and last level is root.
    """
    if not leaves:
        return [[sha256("")]]

    size = _next_power_of_two(len(leaves))
    # pad by repeating last leaf (deterministic)
    padded = leaves + [leaves[-1]] * (size - len(leaves))
    levels = [padded]
    while len(levels[-1]) > 1:
        prev = levels[-1]
        nxt = []
        for i in range(0, len(prev), 2):
            left = prev[i]
            right = prev[i + 1]
            nxt.append(sha256(left + right))
        levels.append(nxt)
    return levels


def get_smt_root(leaves: List[str]) -> str:
    return build_smt_levels(leaves)[-1][0]


def get_smt_proof(leaves: List[str], index: int) -> List[str]:
    """Return the sibling path for the leaf at the given index.

    Proof is a list of sibling hashes from leaf level up to (but not including) root.
    """
    levels = build_smt_levels(leaves)
    proof = []
    idx = index
    for level in range(len(levels) - 1):
        nodes = levels[level]
        sibling = idx ^ 1
        if sibling < len(nodes):
            proof.append(nodes[sibling])
        else:
            proof.append(nodes[idx])
        idx //= 2
    return proof


def verify_smt_proof(leaf_hash: str, proof: List[str], index: int, root: str) -> bool:
    h = leaf_hash
    idx = index
    for sib in proof:
        if idx % 2 == 0:
            h = sha256(h + sib)
        else:
            h = sha256(sib + h)
        idx //= 2
    return h == root


# ------------------------------------------------------------------
# Simplified Verkle-like vector commitment
# - This is NOT a production Verkle implementation. It provides a
#   vector-commitment style interface: group leaves into fixed-sized
#   vectors, commit each vector with a hash, then build an outer Merkle
#   over vector commitments. Proofs contain the inner vector and the
#   outer merkle path for the vector commitment.
# ------------------------------------------------------------------

def build_vector_commitments(leaves: List[str], chunk_size: int = 8) -> Tuple[List[str], List[List[str]]]:
    """Return (chunk_commitments, outer_levels).

    - chunk_commitments: list of hex hashes, one per chunk
    - outer_levels: merkle levels built over the chunk_commitments
    """
    if chunk_size <= 0:
        chunk_size = 8
    chunks = [leaves[i : i + chunk_size] for i in range(0, len(leaves), chunk_size)]
    commitments = []
    for chunk in chunks:
        # vector commitment = hash of concatenated element hashes
        joined = "".join(chunk)
        commitments.append(sha256(joined))

    outer_levels = build_smt_levels(commitments)
    return commitments, outer_levels


def get_verkle_root(leaves: List[str], chunk_size: int = 8) -> str:
    _, outer = build_vector_commitments(leaves, chunk_size)
    return outer[-1][0]


def get_verkle_proof(leaves: List[str], index: int, chunk_size: int = 8) -> Dict[str, Any]:
    """Return a proof object containing:
    - 'inner_chunk': list of leaf hashes for the chunk
    - 'inner_index': position inside the chunk
    - 'outer_proof': sibling path for the chunk commitment
    - 'chunk_commitment': the commitment hash for the chunk
    """
    commitments, outer_levels = build_vector_commitments(leaves, chunk_size)
    chunk_idx = index // chunk_size
    inner_index = index % chunk_size
    # inner chunk (may be shorter than chunk_size for last chunk)
    start = chunk_idx * chunk_size
    inner_chunk = leaves[start : start + chunk_size]
    chunk_commitment = commitments[chunk_idx]
    # build proof for chunk_commitment in outer_levels
    proof = []
    idx = chunk_idx
    for level in range(len(outer_levels) - 1):
        nodes = outer_levels[level]
        sib = idx ^ 1
        if sib < len(nodes):
            proof.append(nodes[sib])
        else:
            proof.append(nodes[idx])
        idx //= 2
    return {
        "inner_chunk": inner_chunk,
        "inner_index": inner_index,
        "outer_proof": proof,
        "chunk_commitment": chunk_commitment,
    }


def verify_verkle_proof(leaf_hash: str, proof_obj: Dict[str, Any], index: int, root: str, chunk_size: int = 8) -> bool:
    # recompute chunk commitment
    inner = proof_obj.get("inner_chunk", [])
    inner_index = proof_obj.get("inner_index", 0)
    recomputed_chunk = sha256("".join(inner))
    if recomputed_chunk != proof_obj.get("chunk_commitment"):
        return False
    # verify outer proof
    h = recomputed_chunk
    idx = index // chunk_size
    for sib in proof_obj.get("outer_proof", []):
        if idx % 2 == 0:
            h = sha256(h + sib)
        else:
            h = sha256(sib + h)
        idx //= 2
    return h == root


# ------------------------------------------------------------------
# Backwards-compatible helpers
# ------------------------------------------------------------------

def build_merkle_tree(leaves: List[str]) -> List[List[str]]:
    """Compatibility wrapper: returns classical merkle levels (used by some callers)."""
    return build_smt_levels(leaves)


def get_merkle_root(leaves: List[str]) -> str:
    """Return the primary commitment root (we pick Verkle root as canonical).

    Keep the function name used by other code but return the new hybrid root.
    """
    return get_verkle_root(leaves)

