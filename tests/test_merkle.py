import pytest
from audit_log.merkle import MMR, hash_leaf, verify_proof


def make_mmr(n: int) -> MMR:
    mmr = MMR()
    for i in range(n):
        mmr.append(hash_leaf(f"leaf_{i}"))
    return mmr


def test_empty_raises():
    mmr = MMR()
    try:
        mmr.get_root()
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_single_leaf_root_equals_leaf_hash():
    leaf = hash_leaf("leaf_0")
    mmr = MMR()
    mmr.append(leaf)
    assert mmr.get_root() == leaf


def test_four_leaves_single_peak():
    mmr = make_mmr(4)
    assert len(mmr.nodes) == 7
    assert len(mmr.peaks) == 1


def test_three_leaves_two_peaks():
    mmr = make_mmr(3)
    assert len(mmr.peaks) == 2


def test_root_is_deterministic():
    assert make_mmr(8).get_root() == make_mmr(8).get_root()


def test_root_changes_when_leaf_changes():
    mmr_a = make_mmr(4)
    mmr_b = MMR()
    for i in range(3):
        mmr_b.append(hash_leaf(f"leaf_{i}"))
    mmr_b.append(hash_leaf("different_leaf"))
    assert mmr_a.get_root() != mmr_b.get_root()


def test_build_matches_incremental_append():
    hashes = [hash_leaf(f"leaf_{i}") for i in range(5)]
    built = MMR.build(hashes)
    incremental = make_mmr(5)
    assert built.get_root() == incremental.get_root()
    assert built.peaks == incremental.peaks


def test_build_empty_raises():
    with pytest.raises(ValueError):
        MMR.build([])


def test_append_returns_node_index():
    mmr = MMR()
    idx = mmr.append(hash_leaf("leaf_0"))
    assert idx == 0
    idx = mmr.append(hash_leaf("leaf_1"))
    assert idx == 1


def test_proof_verifies_for_all_leaves():
    mmr = make_mmr(7)
    root = mmr.get_root()
    for i in range(7):
        proof = mmr.get_proof(i)
        assert verify_proof(hash_leaf(f"leaf_{i}"), proof, root), f"proof failed for leaf {i}"


def test_proof_fails_for_wrong_leaf_hash():
    mmr = make_mmr(4)
    root = mmr.get_root()
    proof = mmr.get_proof(2)
    assert not verify_proof(hash_leaf("wrong_data"), proof, root)


def test_proof_out_of_range_raises():
    mmr = make_mmr(4)
    with pytest.raises(IndexError):
        mmr.get_proof(4)
    with pytest.raises(IndexError):
        mmr.get_proof(-1)


def test_proof_single_peak_has_no_other_peaks():
    mmr = make_mmr(4)
    proof = mmr.get_proof(0)
    assert proof.other_peaks == []
    assert len(proof.siblings) == 2


def test_proof_multi_peak_includes_other_peaks():
    mmr = make_mmr(5)
    proof = mmr.get_proof(4)
    assert len(proof.other_peaks) == 1
    assert proof.siblings == []
