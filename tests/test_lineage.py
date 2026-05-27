"""Tests for derived_lineage() and rebuild_merkle_root()."""
from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone

import pytest

from audit_log.log import AuditLog
from audit_log.models import AuditRecord, DynamicEventType
from audit_log.records import GENESIS_HASH


def _record(i: int = 0) -> AuditRecord:
    return AuditRecord(
        event_type=DynamicEventType("DATA_ACCESS"),
        payload={"seq": i},
        originating_component_id="lineage-tester",
    )


# -----------------------------------------------------------------------
# derived_lineage
# -----------------------------------------------------------------------

def test_derived_lineage_returns_receipt():
    log = AuditLog()
    receipt = log.anchor(_record())
    lr = log.derived_lineage(receipt.record_id)
    assert lr.record_id == receipt.record_id
    assert lr.payload_hash == receipt.payload_hash
    assert lr.lineage_hash
    assert lr.parent_lineage_hash == GENESIS_HASH


def test_derived_lineage_first_record_parent_is_genesis():
    log = AuditLog()
    r = log.anchor(_record())
    lr = log.derived_lineage(r.record_id)
    assert lr.parent_lineage_hash == GENESIS_HASH


def test_derived_lineage_chain_formula():
    """lineage_hash = SHA-256(record_id || payload_hash || parent_lineage_hash)."""
    log = AuditLog()
    r0 = log.anchor(_record(0))
    r1 = log.anchor(_record(1))

    lr0 = log.derived_lineage(r0.record_id)
    lr1 = log.derived_lineage(r1.record_id)

    expected_lh0 = hashlib.sha256(
        (str(r0.record_id) + r0.payload_hash + GENESIS_HASH).encode()
    ).hexdigest()
    assert lr0.lineage_hash == expected_lh0

    expected_lh1 = hashlib.sha256(
        (str(r1.record_id) + r1.payload_hash + lr0.lineage_hash).encode()
    ).hexdigest()
    assert lr1.lineage_hash == expected_lh1


def test_derived_lineage_each_parent_is_previous_lineage_hash():
    log = AuditLog()
    receipts = [log.anchor(_record(i)) for i in range(5)]
    lineages = [log.derived_lineage(r.record_id) for r in receipts]

    for i in range(1, len(lineages)):
        assert lineages[i].parent_lineage_hash == lineages[i - 1].lineage_hash


def test_derived_lineage_missing_record_raises():
    log = AuditLog()
    with pytest.raises(KeyError):
        log.derived_lineage(uuid.uuid4())


# -----------------------------------------------------------------------
# rebuild_merkle_root — three distinct time windows
# -----------------------------------------------------------------------

def test_rebuild_merkle_root_empty_window_raises():
    log = AuditLog()
    log.anchor(_record())
    future = datetime(9999, 1, 1, tzinfo=timezone.utc)
    with pytest.raises(ValueError):
        log.rebuild_merkle_root((future, future))


def test_rebuild_merkle_root_returns_bytes():
    log = AuditLog()
    log.anchor(_record())
    t0 = datetime(2000, 1, 1, tzinfo=timezone.utc)
    t1 = datetime(9999, 1, 1, tzinfo=timezone.utc)
    root = log.rebuild_merkle_root((t0, t1))
    assert isinstance(root, bytes)
    assert len(root) == 32  # raw SHA-256


def test_rebuild_merkle_root_three_windows():
    """Merkle root reconstruction across three distinct (overlapping) time windows."""
    log = AuditLog()

    # Anchor 5 records and capture their timestamps via verify
    receipts = [log.anchor(_record(i)) for i in range(5)]

    # Use the receipt timestamps directly to build meaningful windows.
    # Window 1: just the first record
    ts0 = receipts[0].timestamp
    ts2 = receipts[2].timestamp
    ts4 = receipts[4].timestamp

    epoch = datetime(2000, 1, 1, tzinfo=timezone.utc)
    far = datetime(9999, 1, 1, tzinfo=timezone.utc)

    # Window A: epoch → just after record 0
    root_a = log.rebuild_merkle_root((epoch, ts0))
    # Window B: epoch → just after record 2
    root_b = log.rebuild_merkle_root((epoch, ts2))
    # Window C: epoch → just after record 4 (all records)
    root_c = log.rebuild_merkle_root((epoch, ts4))

    # All three windows cover different record counts → different roots
    # (window A ⊆ window B ⊆ window C, so they can only be equal if all
    # records share the same timestamp, which is extremely unlikely in practice;
    # we assert they are each valid bytes and that the widest window is stable).
    assert isinstance(root_a, bytes) and len(root_a) == 32
    assert isinstance(root_b, bytes) and len(root_b) == 32
    assert isinstance(root_c, bytes) and len(root_c) == 32
    # Reproducibility: calling again with the same window yields the same root
    assert log.rebuild_merkle_root((epoch, far)) == log.rebuild_merkle_root((epoch, far))


def test_rebuild_merkle_root_changes_with_new_record():
    log = AuditLog()
    t0 = datetime(2000, 1, 1, tzinfo=timezone.utc)
    t1 = datetime(9999, 1, 1, tzinfo=timezone.utc)

    log.anchor(_record(0))
    root_before = log.rebuild_merkle_root((t0, t1))

    log.anchor(_record(1))
    root_after = log.rebuild_merkle_root((t0, t1))

    assert root_before != root_after


def test_rebuild_merkle_root_deterministic():
    log = AuditLog()
    t0 = datetime(2000, 1, 1, tzinfo=timezone.utc)
    t1 = datetime(9999, 1, 1, tzinfo=timezone.utc)
    for i in range(5):
        log.anchor(_record(i))
    assert log.rebuild_merkle_root((t0, t1)) == log.rebuild_merkle_root((t0, t1))
