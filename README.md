# Task F — Dual-Anchored Append-Only Audit Log

A tamper-evident, append-only audit log where every record is anchored to two independent Merkle Mountain Range (MMR) trees. Both trees must reconcile for any record to verify. Tampering with a single record is detected in O(log n) time.

## Installation

```bash
# From the repo root
pip install -e "task_f/[dev]"
```

## Running Tests

```bash
pytest task_f/tests/                                        # all 52 tests
pytest task_f/tests/test_tamper_detection.py               # tamper suite only
pytest task_f/tests/test_tamper_detection.py::test_tamper_at_record_500
mypy task_f/audit_log/                                      # type check
```

## Public API

All interaction goes through `AuditLog`. The four required methods:

```python
from audit_log.log import AuditLog
from audit_log.models import AuditRecord, DynamicEventType

log = AuditLog()                             # in-memory SQLite (default)
log = AuditLog(db_url="sqlite:///audit.db")  # file-backed
```

### `anchor(record) -> AnchorReceipt`

Appends a record to both chains atomically. Assigns a UUID, sequence number, writer signature, and parent hash. Extends both in-memory MMRs.

```python
receipt = log.anchor(AuditRecord(
    event_type=DynamicEventType("BIOMARKER_RECORDED"),
    payload={"glucose_mmol": 5.4, "source": "cgm"},
    originating_component_id="biomarker-service",
))
# receipt.record_id, receipt.sequence, receipt.payload_hash, ...
```

### `verify(record_id) -> VerificationResult`

Verifies one specific record in **O(log n)** using Merkle proofs from both MMRs. Reads only the target record and its O(log n) proof siblings — no other records are touched.

```python
result = log.verify(receipt.record_id)
result.valid                   # bool
result.tampered_at_sequence    # int | None — sequence of the tampered record
result.failure_reason          # str | None
result.merkle_root             # str | None — hex-encoded primary MMR root on success
```

### `rebuild_merkle_root(time_window) -> bytes`

Recomputes the primary MMR root for all records whose timestamp falls within the given window. Useful for auditing a time-bounded slice of the log independently.

```python
from datetime import datetime, timezone
start = datetime(2025, 1, 1, tzinfo=timezone.utc)
end   = datetime(2025, 12, 31, tzinfo=timezone.utc)
root: bytes = log.rebuild_merkle_root((start, end))
```

### `derived_lineage(record_id) -> LineageReceipt`

Returns the secondary lineage record for the given record id.

```python
lr = log.derived_lineage(receipt.record_id)
lr.lineage_hash          # SHA-256(record_id || payload_hash || parent_lineage_hash)
lr.parent_lineage_hash
```

## Architecture

Five modules with a strict one-way import hierarchy:

```
exceptions.py   — AppendOnlyViolationError only, no internal imports
models.py       — Pydantic models + DynamicEventType (loaded from config/)
merkle.py       — MMR, Proof, verify_proof; no internal imports
records.py      — Two append-only SQLAlchemy store classes
log.py          — AuditLog: orchestrates records + merkle, sole public interface
```

### Two independent hash chains

**Primary chain** (`audit_records` table)

Every record commits to the previous via `parent_hash = SHA-256(all fields of previous StoredRecord)`. The MMR leaf hash is computed from the full `StoredRecord` (including `parent_hash`), so a field-level mutation breaks both the chain link and the Merkle proof simultaneously.

**Secondary lineage chain** (`lineage_records` table)

A separate chain with a different formula:

```
lineage_hash = SHA-256(record_id || payload_hash || parent_lineage_hash)
```

These `lineage_hash` values are the leaves of a second independent MMR (`self._lineage_mmr`). `verify()` checks both MMR proofs. Primary passing while lineage fails (or vice versa) is a failed verification.

**Writer signature**

```
writer_signature_hash = SHA-256(originating_component_id || record_id || payload_hash)
```

Stored in `audit_records`. Prevents a writer from anchoring a record under another writer's identity.

### MMR (Merkle Mountain Range)

Two append-only MMRs held in memory (`self._mmr` and `self._lineage_mmr`). Leaves are record hashes; internal nodes are `SHA-256(left || right)`. The root is `bag_peaks` — a right-to-left fold over mountain peaks.

`verify()` calls `mmr.get_proof(sequence)` which collects O(log n) sibling hashes by walking the in-memory node tree. `verify_proof()` then recomputes the root from that proof — if the result differs from the stored root, the record was tampered.

### Append-only invariant

A SQLAlchemy `before_cursor_execute` event listener in `make_engine()` intercepts every SQL statement and raises `AppendOnlyViolationError` before any `UPDATE` or `DELETE` reaches SQLite. The store classes (`AuditRecordStore`, `LineageRecordStore`) expose no `update` or `delete` methods — their absence is a static-analysis guarantee.

Tamper tests bypass this guard by connecting to the `.db` file directly via `sqlite3`, simulating a storage-layer attacker.

### Event types

`DynamicEventType` is built at import time from `config/event_types.json` (18 types: `LOGIN`, `LOGOUT`, `BIOMARKER_RECORDED`, `LAB_RESULT_RECEIVED`, etc.). Adding a new event type requires only editing that JSON file.

## Dependencies

`pydantic`, `sqlalchemy`, `numpy`, `hashlib` (stdlib). SQLite backend via SQLAlchemy; switching to Postgres is a `db_url` change — the DAO is backend-agnostic.