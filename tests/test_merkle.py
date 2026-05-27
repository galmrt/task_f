import pytest
from audit_log.merkle import MMR, find_tamper, hash_leaf, verify_proof


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
    # 3 leaves → 2 peaks (heights 1 and 0)
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
    assert idx == 0  # first new node is the leaf at index 0
    idx = mmr.append(hash_leaf("leaf_1"))
    # leaf lands at index 1; merged parent at index 2.
    # append() returns first_new (leaf index = 1).
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
    # 4 leaves → 1 peak → other_peaks should be empty
    mmr = make_mmr(4)
    proof = mmr.get_proof(0)
    assert proof.other_peaks == []
    assert len(proof.siblings) == 2  # height-2 tree: 2 levels of siblings


def test_proof_multi_peak_includes_other_peaks():
    # 5 leaves → 2 peaks; leaf 4 is in the second (height-0) peak alone
    mmr = make_mmr(5)
    proof = mmr.get_proof(4)
    assert len(proof.other_peaks) == 1  # one other peak (the height-2 one)
    assert proof.siblings == []         # leaf 4 IS the peak, no siblings needed


# --- find_tamper tests ---

def _hashes(n: int) -> list[str]:
    return [hash_leaf(f"leaf_{i}") for i in range(n)]


def test_find_tamper_clean_returns_minus_one():
    h = _hashes(8)
    assert find_tamper(h, h) == -1


def test_find_tamper_first_leaf():
    stored = _hashes(8)
    recomputed = stored.copy()
    recomputed[0] = hash_leaf("corrupted")
    assert find_tamper(stored, recomputed) == 0


def test_find_tamper_last_leaf():
    stored = _hashes(8)
    recomputed = stored.copy()
    recomputed[7] = hash_leaf("corrupted")
    assert find_tamper(stored, recomputed) == 7


def test_find_tamper_middle():
    stored = _hashes(8)
    recomputed = stored.copy()
    recomputed[3] = hash_leaf("corrupted")
    assert find_tamper(stored, recomputed) == 3


def test_find_tamper_returns_first_divergence():
    # Two corrupted records — must return the earlier one
    stored = _hashes(8)
    recomputed = stored.copy()
    recomputed[2] = hash_leaf("corrupted_2")
    recomputed[5] = hash_leaf("corrupted_5")
    assert find_tamper(stored, recomputed) == 2


def test_find_tamper_1000_records_at_500():
    # Required by the task spec: 1000 records, tamper planted at record 500
    stored = _hashes(1000)
    recomputed = stored.copy()
    recomputed[500] = hash_leaf("tampered_record")
    assert find_tamper(stored, recomputed) == 500
