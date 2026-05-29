from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy import Column, DateTime, Integer, String, Text
from sqlalchemy.engine import Engine

from audit_log.exceptions import AppendOnlyViolationError
from audit_log.models import DynamicEventType, LineageReceipt, StoredRecord

GENESIS_HASH: str = hashlib.sha256(b"").hexdigest()

_metadata = sa.MetaData()

_audit_records = sa.Table(
    "audit_records",
    _metadata,
    Column("record_id", String(36), primary_key=True),
    Column("sequence", Integer, nullable=False, unique=True),
    Column("timestamp", DateTime, nullable=False),
    Column("event_type", String(64), nullable=False),
    Column("originating_component_id", String(256), nullable=False),
    Column("payload", Text, nullable=False),
    Column("payload_hash", String(64), nullable=False),
    Column("parent_hash", String(64), nullable=False),
    Column("writer_signature_hash", String(64), nullable=False),
)

_lineage_records = sa.Table(
    "lineage_records",
    _metadata,
    Column("record_id", String(36), primary_key=True),
    Column("sequence", Integer, nullable=False, unique=True),
    Column("payload_hash", String(64), nullable=False),
    Column("lineage_hash", String(64), nullable=False),
    Column("parent_lineage_hash", String(64), nullable=False),
)


def make_engine(url: str = "sqlite:///:memory:") -> Engine:
    """Creates an append-only SQLAlchemy engine: attaches the UPDATE/DELETE guard, then initialises the schema."""
    engine = sa.create_engine(url)
    _attach_append_only_guard(engine)
    _metadata.create_all(engine)
    return engine


def _attach_append_only_guard(engine: Engine) -> None:
    @sa.event.listens_for(engine, "before_cursor_execute")
    def _block(conn, cursor, statement, parameters, context, executemany):
        if statement.lstrip().upper().startswith(("UPDATE", "DELETE")):
            raise AppendOnlyViolationError(
                f"Append-only violation: mutation blocked — {statement[:80]!r}"
            )


class AuditRecordStore:
    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def insert(self, record: StoredRecord) -> None:
        with self._engine.begin() as conn:
            conn.execute(
                _audit_records.insert().values(
                    record_id=str(record.record_id),
                    sequence=record.sequence,
                    timestamp=record.timestamp.replace(tzinfo=None),
                    event_type=record.event_type.value,
                    originating_component_id=record.originating_component_id,
                    payload=json.dumps(record.payload),
                    payload_hash=record.payload_hash,
                    parent_hash=record.parent_hash,
                    writer_signature_hash=record.writer_signature_hash,
                )
            )

    def get_latest(self) -> StoredRecord | None:
        with self._engine.connect() as conn:
            row = conn.execute(
                sa.select(_audit_records)
                .order_by(_audit_records.c.sequence.desc())
                .limit(1)
            ).fetchone()
        return _row_to_stored(row) if row else None

    def get_by_id(self, record_id: UUID) -> StoredRecord | None:
        with self._engine.connect() as conn:
            row = conn.execute(
                sa.select(_audit_records).where(
                    _audit_records.c.record_id == str(record_id)
                )
            ).fetchone()
        return _row_to_stored(row) if row else None

    def get_by_time_window(self, start: datetime, end: datetime) -> list[StoredRecord]:
        with self._engine.connect() as conn:
            rows = conn.execute(
                sa.select(_audit_records)
                .where(
                    _audit_records.c.timestamp >= start.replace(tzinfo=None),
                    _audit_records.c.timestamp <= end.replace(tzinfo=None),
                )
                .order_by(_audit_records.c.sequence)
            ).fetchall()
        return [_row_to_stored(r) for r in rows]

    def count(self) -> int:
        with self._engine.connect() as conn:
            return conn.execute(
                sa.select(sa.func.count()).select_from(_audit_records)
            ).scalar() or 0


class LineageRecordStore:
    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def insert(
        self,
        record_id: UUID,
        sequence: int,
        payload_hash: str,
        lineage_hash: str,
        parent_lineage_hash: str,
    ) -> None:
        with self._engine.begin() as conn:
            conn.execute(
                _lineage_records.insert().values(
                    record_id=str(record_id),
                    sequence=sequence,
                    payload_hash=payload_hash,
                    lineage_hash=lineage_hash,
                    parent_lineage_hash=parent_lineage_hash,
                )
            )

    def get_latest(self) -> LineageReceipt | None:
        with self._engine.connect() as conn:
            row = conn.execute(
                sa.select(_lineage_records)
                .order_by(_lineage_records.c.sequence.desc())
                .limit(1)
            ).fetchone()
        return _row_to_lineage(row) if row else None

    def get_by_record_id(self, record_id: UUID) -> LineageReceipt | None:
        with self._engine.connect() as conn:
            row = conn.execute(
                sa.select(_lineage_records).where(
                    _lineage_records.c.record_id == str(record_id)
                )
            ).fetchone()
        return _row_to_lineage(row) if row else None

    def count(self) -> int:
        with self._engine.connect() as conn:
            return conn.execute(
                sa.select(sa.func.count()).select_from(_lineage_records)
            ).scalar() or 0


def _row_to_stored(row: sa.engine.Row) -> StoredRecord:
    ts = row.timestamp
    if isinstance(ts, str):
        ts = datetime.fromisoformat(ts)
    return StoredRecord(
        record_id=UUID(row.record_id),
        sequence=row.sequence,
        timestamp=ts.replace(tzinfo=timezone.utc),
        event_type=DynamicEventType(row.event_type),
        originating_component_id=row.originating_component_id,
        payload=json.loads(row.payload),
        payload_hash=row.payload_hash,
        parent_hash=row.parent_hash,
        writer_signature_hash=row.writer_signature_hash,
    )


def _row_to_lineage(row: sa.engine.Row) -> LineageReceipt:
    return LineageReceipt(
        record_id=UUID(row.record_id),
        sequence=row.sequence,
        payload_hash=row.payload_hash,
        lineage_hash=row.lineage_hash,
        parent_lineage_hash=row.parent_lineage_hash,
    )
