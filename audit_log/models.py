from __future__ import annotations

import json
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


_config_path = Path(__file__).parent.parent / "config" / "event_types.json"
_config_data = json.loads(_config_path.read_text())

DynamicEventType = Enum(
    "DynamicEventType",
    {event: event for event in _config_data["event_types"]},
    type=str,
)

class AuditRecord(BaseModel):
    """Caller-supplied input. Only what the caller knows — no computed fields."""

    event_type: DynamicEventType
    payload: dict[str, Any]
    originating_component_id: str


class StoredRecord(AuditRecord):
    """Full persisted form. Extends AuditRecord with computed fields. Immutable after creation."""

    model_config = {"frozen": True}

    record_id: UUID = Field(default_factory=uuid4)
    sequence: int
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    payload_hash: str
    parent_hash: str
    writer_signature_hash: str


class AnchorReceipt(BaseModel):
    """Returned to the caller after a successful anchor()."""

    record_id: UUID
    sequence: int
    payload_hash: str
    parent_hash: str
    writer_signature_hash: str
    timestamp: datetime


class VerificationResult(BaseModel):
    """Returned by verify(). Covers both hash chains and Merkle root."""

    valid: bool
    record_count: int
    merkle_root: str | None = None
    tampered_at_sequence: int | None = None
    failure_reason: str | None = None


class LineageReceipt(BaseModel):
    """One node in the secondary lineage chain, returned by derived_lineage()."""

    record_id: UUID
    sequence: int
    payload_hash: str
    lineage_hash: str
    parent_lineage_hash: str
