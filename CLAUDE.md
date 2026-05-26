# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Install (run from repo root)
pip install -e "task_f/[dev]"

# All tests
pytest task_f/tests/

# Single test file
pytest task_f/tests/test_tamper_detection.py

# Single test
pytest task_f/tests/test_tamper_detection.py::test_tamper_at_record_500

# Type check
mypy task_f/audit_log/
```

## Task Specification

Build a tamper-evident append-only audit log that any system component can write to. Every record is anchored to a primary Merkle-tree log and a derived secondary lineage log; both anchors must reconcile for any record to verify.

**Required interface:**
- `anchor(record: AuditRecord) -> AnchorReceipt`
- `verify(record_id: RecordId) -> VerificationResult`
- `rebuild_merkle_root(time_window: tuple[datetime, datetime]) -> bytes`
- `derived_lineage(record_id: RecordId) -> LineageReceipt`

**Every record carries:** `record_id` (uuid4), `timestamp` (ISO-8601 UTC), `originating_component_id` (str), `event_type` (closed enumeration from JSON config, ≥10 types), `payload_hash` (SHA-256), `parent_hash` (SHA-256 of previous record's hash), `writer_signature_hash` (prevents a writer anchoring a record on behalf of another writer).

**Append-only invariant:** DAO exposes no UPDATE or DELETE primitive. Any mutation attempt raises `AppendOnlyViolationError`. Must be verifiable by static analysis of the DAO module.

**Tamper-evidence:** Any modified record breaks the Merkle proof. `verify()` must detect and identify a tampered record at position p > 0 in O(log n). Required fixture: write 1000 records, mutate record 500 at the storage layer, verify identifies record 500 as the tamper point.

**Secondary anchor:** For every anchored record a derived lineage record is created with `lineage_hash = SHA-256(record_id || payload_hash || parent_lineage_hash)` in a separate table with its own append-only invariant. Verification fails if primary reconciles but lineage does not, or vice versa.

**Dependencies:** `pydantic`, `sqlalchemy`, `hashlib` (stdlib), `numpy` only. SQLite backend, clean DAO so Postgres is a config swap.

**Tests:** ≥20 pytest tests covering happy path, append-only invariant on UPDATE/DELETE, tamper detection at primary and secondary anchors, Merkle-root reconstruction at three time windows, reconciliation failure when anchors disagree.

**Deliverable:** Python package + README + passing pytest suite + one-page report demonstrating tamper detection on the planted-mutation fixture.

## Architecture

Five modules with strict layering — no module may import from a layer above it:

```
exceptions.py  ← no internal imports
models.py      ← exceptions.py
merkle.py      ← no internal imports
records.py     ← models.py, exceptions.py   (was originally dao.py)
log.py         ← records.py, merkle.py, models.py
utils.py       ← merkle.py  (re-export shim)
```

`log.py` (`AuditLog`) is the sole public interface. Tests interact exclusively through it, except tamper tests which use `sqlite3` directly to bypass the SQLAlchemy guard.

### Two independent hash chains

Both live in separate DB tables and must both pass for `verify()` to succeed:

- **Primary** (`audit_records`): `parent_hash = SHA-256(all fields of previous StoredRecord)` via `_record_hash()`. Standard blockchain-style chain. The chain walks forward in sequence order; a mismatch at record[i] means record[i-1] was tampered.
- **Lineage** (`lineage_records`): `lineage_hash = SHA-256(record_id || payload_hash || parent_lineage_hash)`. Different formula, different table, same append-only posture.

Writer identity: `writer_signature_hash = SHA-256(originating_component_id || record_id || payload_hash)`.

Genesis sentinel: `GENESIS_HASH = SHA-256(b"")` — used as `parent_hash` and `parent_lineage_hash` for sequence 0.

### MMR (merkle.py)

Stateful `MMR` class, append-only by design. Key internals:

- `self.nodes` — flat append-only list of every node (leaves + internal). Index = node position. Never modified after insertion.
- `self.peaks` — indices into `self.nodes` for the current mountain peaks. Mutates on every `append()`.
- `self.leaf_indices` — maps `leaf_num → node index`, used by `get_proof()`.

`Node` stores `height` explicitly (avoids error-prone position-math). `append()` merges the last two peaks whenever their heights are equal, walking upward until no more merges are possible. **`append()` must return the leaf index (first new node), not the final merged parent** — `log.py` uses `range(leaf_idx, len(nodes))` to collect all new nodes for persistence.

`find_tamper(stored, recomputed)` is a standalone function: builds two MMRs, compares peaks left-to-right to locate the divergent mountain, binary-searches within that subtree — O(log n).

`bag_peaks` folds right-to-left: `hash(peak[n-2] || hash(peak[n-1]))`. Convention must never change or historical roots become invalid.

### records.py (DAO layer)

Four store classes — all append-only, no `update`/`delete` methods anywhere in the file:

- `AuditRecordStore` — primary chain CRUD (insert + reads only)
- `LineageRecordStore` — secondary chain CRUD
- `MMRNodeStore` — persists every MMR node (leaf + internal) so the in-memory MMR can be reconstructed across restarts via `MMR.from_persisted()`
- `MMRCheckpointStore` — stores `(sequence, root_hash, peaks_json)` after each anchor for fast MMR restoration

The append-only guard is enforced at the engine level via a SQLAlchemy `before_cursor_execute` event listener in `make_engine()` — any `UPDATE` or `DELETE` statement raises `AppendOnlyViolationError` before it reaches SQLite. Tamper tests bypass this by connecting to the `.db` file directly via `sqlite3`.

### Event types

`DynamicEventType` in `models.py` is built at import time from `config/event_types.json`. Adding a new event type requires only editing that JSON file — no code changes.

## What's still missing / broken

1. **`verify_proof(leaf_hash, proof, expected_root) -> bool` in `merkle.py`** — `log.py` imports it (`from audit_log.merkle import MMR, verify_proof`) but the function does not exist there yet. It is currently defined locally inside `test_merkle.py`. Moving it to `merkle.py` unblocks `log.py` and `verify_record_proof()`.

2. **`MMR.from_persisted(node_rows, peaks)` classmethod in `merkle.py`** — `log.py` calls `MMR.from_persisted(node_rows, peaks)` in `_restore_mmr()` to reconstruct the in-memory tree from persisted `mmr_nodes` rows. This classmethod does not exist yet.

3. **`append()` return value bug** — currently returns `current_idx` (the final merged parent after the while loop). `log.py` treats the return value as the leaf index (first new node) and uses `range(return_value, len(self.nodes))` to slice newly-added nodes for batch persistence. Fix: save `leaf_idx = len(self.nodes)` before the loop and return `leaf_idx`.

4. **`README.md` is empty** — required deliverable.

5. **One-page tamper detection report** — required deliverable demonstrating the planted-mutation fixture.
