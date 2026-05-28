from __future__ import annotations

import hashlib
import json
from datetime import datetime
from uuid import UUID, uuid4

from audit_log.merkle import MMR, verify_proof
from audit_log.models import (
    AnchorReceipt,
    AuditRecord,
    LineageReceipt,
    StoredRecord,
    VerificationResult,
)
from audit_log.records import (
    GENESIS_HASH,
    AuditRecordStore,
    LineageRecordStore,
    make_engine,
)


def _record_hash(r: StoredRecord) -> str:
    """Canonical leaf hash for a stored record — used both in the MMR and as parent_hash."""
    data = (
        str(r.record_id)
        + str(r.sequence)
        + r.timestamp.isoformat()
        + r.event_type.value
        + r.originating_component_id
        + r.payload_hash
        + r.parent_hash
        + r.writer_signature_hash
    )
    return hashlib.sha256(data.encode()).hexdigest()


class AuditLog:
    def __init__(self, db_url: str = "sqlite:///:memory:") -> None:
        self._engine = make_engine(db_url)
        self._audit = AuditRecordStore(self._engine)
        self._lineage = LineageRecordStore(self._engine)
        self._mmr = MMR()
        self._lineage_mmr = MMR()

    def anchor(self, record: AuditRecord) -> AnchorReceipt:
        payload_str = json.dumps(record.payload, sort_keys=True)
        payload_hash = hashlib.sha256(payload_str.encode()).hexdigest()

        record_id = uuid4()

        latest = self._audit.get_latest()
        if latest is None:
            parent_hash = GENESIS_HASH
            sequence = 0
        else:
            parent_hash = _record_hash(latest)
            sequence = latest.sequence + 1

        writer_signature_hash = hashlib.sha256(
            (record.originating_component_id + str(record_id) + payload_hash).encode()
        ).hexdigest()

        stored = StoredRecord(
            record_id=record_id,
            sequence=sequence,
            event_type=record.event_type,
            payload=record.payload,
            originating_component_id=record.originating_component_id,
            payload_hash=payload_hash,
            parent_hash=parent_hash,
            writer_signature_hash=writer_signature_hash,
        )
        self._audit.insert(stored)

        # Secondary lineage chain
        latest_lineage = self._lineage.get_latest()
        parent_lineage_hash = (
            latest_lineage.lineage_hash if latest_lineage else GENESIS_HASH
        )
        lineage_hash = hashlib.sha256(
            (str(record_id) + payload_hash + parent_lineage_hash).encode()
        ).hexdigest()
        self._lineage.insert(
            record_id=record_id,
            sequence=sequence,
            payload_hash=payload_hash,
            lineage_hash=lineage_hash,
            parent_lineage_hash=parent_lineage_hash,
        )

        self._mmr.append(_record_hash(stored))
        self._lineage_mmr.append(lineage_hash)

        return AnchorReceipt(
            record_id=stored.record_id,
            sequence=stored.sequence,
            payload_hash=stored.payload_hash,
            parent_hash=stored.parent_hash,
            writer_signature_hash=stored.writer_signature_hash,
            timestamp=stored.timestamp,
        )

    def verify(self, record_id: UUID) -> VerificationResult:
        record = self._audit.get_by_id(record_id)
        if record is None:
            return VerificationResult(
                valid=False,
                record_count=0,
                failure_reason=f"Record {record_id} not found",
            )

        n = self._audit.count()
        stored_root = self._mmr.get_root()

        # Primary chain
        leaf_hash = _record_hash(record)
        proof = self._mmr.get_proof(record.sequence)
        if not verify_proof(leaf_hash, proof, stored_root):
            return VerificationResult(
                valid=False,
                record_count=n,
                tampered_at_sequence=record.sequence,
                failure_reason=f"Merkle proof failed for sequence {record.sequence}",
            )

        # Secondary chain
        lineage = self._lineage.get_by_record_id(record_id)
        if lineage is None:
            return VerificationResult(
                valid=False,
                record_count=n,
                tampered_at_sequence=record.sequence,
                failure_reason=f"No lineage record for {record_id}",
            )
        lineage_proof = self._lineage_mmr.get_proof(record.sequence)
        if not verify_proof(lineage.lineage_hash, lineage_proof, self._lineage_mmr.get_root()):
            return VerificationResult(
                valid=False,
                record_count=n,
                tampered_at_sequence=record.sequence,
                failure_reason=f"Lineage Merkle proof failed for sequence {record.sequence}",
            )
        expected_lh = hashlib.sha256(
            (str(record_id) + lineage.payload_hash + lineage.parent_lineage_hash).encode()
        ).hexdigest()
        if lineage.lineage_hash != expected_lh or lineage.payload_hash != record.payload_hash:
            return VerificationResult(
                valid=False,
                record_count=n,
                tampered_at_sequence=record.sequence,
                failure_reason=f"Lineage fields inconsistent for sequence {record.sequence}",
            )

        return VerificationResult(valid=True, record_count=n, merkle_root=stored_root)

    def rebuild_merkle_root(self, time_window: tuple[datetime, datetime]) -> bytes:
        records = self._audit.get_by_time_window(time_window[0], time_window[1])
        if not records:
            raise ValueError("No records found in the given time window")
        mmr = MMR.build([_record_hash(r) for r in records])
        return bytes.fromhex(mmr.get_root())

    def derived_lineage(self, record_id: UUID) -> LineageReceipt:
        result = self._lineage.get_by_record_id(record_id)
        if result is None:
            raise KeyError(f"No lineage record for record_id={record_id}")
        return result