"""Tamper-detection tests — primary chain, lineage chain, reconciliation."""
from __future__ import annotations

import hashlib
import sqlite3
import tempfile
import os

import pytest

from audit_log.log import AuditLog
from audit_log.models import AuditRecord, DynamicEventType


def _record(i: int = 0) -> AuditRecord:
    return AuditRecord(
        event_type=DynamicEventType("BIOMARKER_RECORDED"),
        payload={"i": i},
        originating_component_id="test-writer",
    )


def _make_log_with_db() -> tuple[AuditLog, str]:
    """Return (AuditLog, db_path) backed by a temp file so sqlite3 can mutate it."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    log = AuditLog(db_url=f"sqlite:///{path}")
    return log, path


def _tamper_primary(db_path: str, sequence: int, field: str, value: str) -> None:
    """Directly mutate a primary audit_records field, bypassing the SQLAlchemy guard."""
    conn = sqlite3.connect(db_path)
    conn.execute(
        f"UPDATE audit_records SET {field} = ? WHERE sequence = ?",  # noqa: S608
        (value, sequence),
    )
    conn.commit()
    conn.close()


def _tamper_lineage(db_path: str, sequence: int, field: str, value: str) -> None:
    conn = sqlite3.connect(db_path)
    conn.execute(
        f"UPDATE lineage_records SET {field} = ? WHERE sequence = ?",  # noqa: S608
        (value, sequence),
    )
    conn.commit()
    conn.close()


# -----------------------------------------------------------------------
# Primary chain tamper tests
# -----------------------------------------------------------------------

def test_tamper_at_record_500():
    """Write 1000 records, plant a mutation at sequence 500, verify must detect it."""
    log, db_path = _make_log_with_db()
    receipts = [log.anchor(_record(i)) for i in range(1000)]

    _tamper_primary(db_path, 500, "payload_hash", "a" * 64)

    # Force fresh connections so the engine doesn't see a stale cache
    log._engine.dispose()

    result = log.verify(receipts[500].record_id)
    assert not result.valid
    assert result.tampered_at_sequence == 500


def test_tamper_at_record_0():
    log, db_path = _make_log_with_db()
    receipts = [log.anchor(_record(i)) for i in range(20)]

    _tamper_primary(db_path, 0, "payload_hash", "b" * 64)
    log._engine.dispose()

    result = log.verify(receipts[0].record_id)
    assert not result.valid
    # Tamper at record 0 breaks the chain starting at sequence 0
    assert result.tampered_at_sequence == 0


def test_tamper_at_record_1():
    log, db_path = _make_log_with_db()
    receipts = [log.anchor(_record(i)) for i in range(10)]

    _tamper_primary(db_path, 1, "originating_component_id", "evil-writer")
    log._engine.dispose()

    result = log.verify(receipts[1].record_id)
    assert not result.valid
    assert result.tampered_at_sequence == 1


def test_tamper_last_but_one_record():
    log, db_path = _make_log_with_db()
    n = 50
    receipts = [log.anchor(_record(i)) for i in range(n)]

    _tamper_primary(db_path, n - 2, "payload_hash", "c" * 64)
    log._engine.dispose()

    result = log.verify(receipts[n - 2].record_id)
    assert not result.valid
    assert result.tampered_at_sequence == n - 2


def test_no_tamper_returns_valid():
    log, db_path = _make_log_with_db()
    receipts = [log.anchor(_record(i)) for i in range(100)]
    log._engine.dispose()

    result = log.verify(receipts[-1].record_id)
    assert result.valid
    assert result.tampered_at_sequence is None


# -----------------------------------------------------------------------
# Lineage chain tamper tests
# -----------------------------------------------------------------------

def test_lineage_tamper_detected_when_primary_intact():
    """Primary chain is clean; only lineage is tampered — verify must still fail."""
    log, db_path = _make_log_with_db()
    receipts = [log.anchor(_record(i)) for i in range(20)]

    _tamper_lineage(db_path, 10, "lineage_hash", "d" * 64)
    log._engine.dispose()

    result = log.verify(receipts[10].record_id)
    assert not result.valid
    assert result.tampered_at_sequence == 10


def test_lineage_parent_hash_tamper_detected():
    log, db_path = _make_log_with_db()
    receipts = [log.anchor(_record(i)) for i in range(10)]

    _tamper_lineage(db_path, 5, "parent_lineage_hash", "e" * 64)
    log._engine.dispose()

    result = log.verify(receipts[5].record_id)
    assert not result.valid


# -----------------------------------------------------------------------
# Reconciliation: primary OK but lineage disagrees (or vice versa)
# -----------------------------------------------------------------------

def test_reconciliation_failure_primary_ok_lineage_bad():
    log, db_path = _make_log_with_db()
    receipts = [log.anchor(_record(i)) for i in range(15)]

    # Corrupt only the lineage table
    _tamper_lineage(db_path, 7, "payload_hash", "f" * 64)
    log._engine.dispose()

    result = log.verify(receipts[7].record_id)
    assert not result.valid
    assert "lineage" in (result.failure_reason or "").lower()
