from __future__ import annotations

import hashlib
import json

import pytest

from audit_log.log import AuditLog
from audit_log.models import AuditRecord, DynamicEventType
from audit_log.records import GENESIS_HASH


def _record(event_type=None, payload=None, writer="svc-a") -> AuditRecord:
    return AuditRecord(
        event_type=event_type or DynamicEventType("LOGIN"),
        payload=payload or {"user": "alice"},
        originating_component_id=writer,
    )


def test_anchor_returns_receipt():
    log = AuditLog()
    receipt = log.anchor(_record())
    assert receipt.record_id is not None
    assert receipt.sequence == 0
    assert receipt.payload_hash
    assert receipt.parent_hash == GENESIS_HASH
    assert receipt.writer_signature_hash
    assert receipt.timestamp is not None


def test_anchor_first_record_has_genesis_parent_hash():
    log = AuditLog()
    receipt = log.anchor(_record())
    assert receipt.parent_hash == GENESIS_HASH


def test_anchor_sequence_increments():
    log = AuditLog()
    r0 = log.anchor(_record())
    r1 = log.anchor(_record())
    r2 = log.anchor(_record())
    assert r0.sequence == 0
    assert r1.sequence == 1
    assert r2.sequence == 2


def test_anchor_second_record_chains_parent_hash():
    log = AuditLog()
    r0 = log.anchor(_record())
    r1 = log.anchor(_record())
    assert r1.parent_hash != r0.parent_hash
    assert r1.parent_hash != GENESIS_HASH
    assert r1.parent_hash != r0.payload_hash


def test_anchor_payload_hash_is_sha256_of_sorted_json():
    log = AuditLog()
    payload = {"z": 1, "a": 2}
    receipt = log.anchor(_record(payload=payload))
    expected = hashlib.sha256(
        json.dumps(payload, sort_keys=True).encode()
    ).hexdigest()
    assert receipt.payload_hash == expected


def test_anchor_writer_signature_formula():
    log = AuditLog()
    receipt = log.anchor(_record(writer="my-writer"))
    expected = hashlib.sha256(
        ("my-writer" + str(receipt.record_id) + receipt.payload_hash).encode()
    ).hexdigest()
    assert receipt.writer_signature_hash == expected


def test_anchor_different_writers_different_signatures():
    log = AuditLog()
    r_a = log.anchor(_record(writer="writer-a"))
    r_b = log.anchor(_record(writer="writer-b"))
    assert r_a.writer_signature_hash != r_b.writer_signature_hash


def test_anchor_invalid_event_type_raises():
    with pytest.raises(Exception):
        AuditRecord(
            event_type="NOT_A_REAL_EVENT",
            payload={},
            originating_component_id="svc",
        )


def test_anchor_all_event_types_accepted():
    log = AuditLog()
    for et in DynamicEventType:
        receipt = log.anchor(_record(event_type=et))
        assert receipt.record_id is not None
