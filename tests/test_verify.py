"""Tests for AuditLog.verify()."""
from __future__ import annotations

import pytest

from audit_log.exceptions import AppendOnlyViolationError
from audit_log.log import AuditLog
from audit_log.models import AuditRecord, DynamicEventType


def _record(writer="svc") -> AuditRecord:
    return AuditRecord(
        event_type=DynamicEventType("LOGIN"),
        payload={"k": 1},
        originating_component_id=writer,
    )


def test_verify_single_record_valid():
    log = AuditLog()
    r = log.anchor(_record())
    result = log.verify(r.record_id)
    assert result.valid
    assert result.record_count == 1
    assert result.tampered_at_sequence is None


def test_verify_multiple_records_valid():
    log = AuditLog()
    receipts = [log.anchor(_record()) for _ in range(10)]
    result = log.verify(receipts[-1].record_id)
    assert result.valid
    assert result.record_count == 10


def test_verify_returns_merkle_root_on_success():
    log = AuditLog()
    r = log.anchor(_record())
    result = log.verify(r.record_id)
    assert result.merkle_root is not None
    assert len(result.merkle_root) == 64  # hex-encoded SHA-256


def test_verify_nonexistent_record_id_returns_invalid():
    import uuid
    log = AuditLog()
    result = log.verify(uuid.uuid4())
    assert not result.valid
    assert result.failure_reason is not None


def test_verify_merkle_root_deterministic():
    log = AuditLog()
    receipts = [log.anchor(_record()) for _ in range(5)]
    r1 = log.verify(receipts[-1].record_id)
    r2 = log.verify(receipts[-1].record_id)
    assert r1.merkle_root == r2.merkle_root


def test_append_only_blocks_update():
    import sqlalchemy as sa
    log = AuditLog()
    log.anchor(_record())
    with pytest.raises(AppendOnlyViolationError):
        with log._engine.begin() as conn:
            conn.execute(
                sa.text("UPDATE audit_records SET payload_hash = 'aabbcc' WHERE sequence = 0")
            )


def test_append_only_blocks_delete():
    import sqlalchemy as sa
    log = AuditLog()
    log.anchor(_record())
    with pytest.raises(AppendOnlyViolationError):
        with log._engine.begin() as conn:
            conn.execute(sa.text("DELETE FROM audit_records WHERE sequence = 0"))


def test_append_only_blocks_lineage_update():
    import sqlalchemy as sa
    log = AuditLog()
    log.anchor(_record())
    with pytest.raises(AppendOnlyViolationError):
        with log._engine.begin() as conn:
            conn.execute(
                sa.text("UPDATE lineage_records SET lineage_hash = 'aabbcc' WHERE sequence = 0")
            )
