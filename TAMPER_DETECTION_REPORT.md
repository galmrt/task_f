# Tamper Detection Report — Planted-Mutation Fixture

## Setup

1,000 records are anchored to the log. Record 500 is then mutated directly at the SQLite storage layer — bypassing the SQLAlchemy append-only guard — and `verify()` is called on that record's ID.

```python
log = AuditLog(db_url=f"sqlite:///{path}")
receipts = [log.anchor(record(i)) for i in range(1000)]

# Bypass the engine guard and corrupt record 500 at the storage layer
conn = sqlite3.connect(path)
conn.execute("UPDATE audit_records SET payload_hash = ? WHERE sequence = 500", ("a" * 64,))
conn.commit()

log._engine.dispose()   # flush connection pool so the mutation is visible
result = log.verify(receipts[500].record_id)
```

## Result

```
Before tamper — verify(record_500): valid=True
  merkle_root=5a3b60f56e5876bd...

After tamper  — verify(record_500): valid=False
  tampered_at_sequence=500
  failure_reason='Merkle proof failed for sequence 500'
  detection time: 0.37 ms

verify(record_499) [untampered]:   valid=True
```

Tamper detected and pinned to sequence 500. Adjacent record 499 continues to verify cleanly.

## How Detection Works

`verify(record_id)` runs two independent O(log n) MMR proof checks.

**1. Primary — O(log n) Merkle proof**

`_record_hash()` recomputes the leaf hash for the requested record from its current DB contents. For record 500, the planted `payload_hash = "a" * 64` produces a different leaf hash than the one committed at anchor time.

`self._mmr.get_proof(500)` walks the in-memory primary MMR and collects the sibling hashes on the path from leaf 500 to the root (tree depth = ⌈log₂ 1000⌉ = 10).

`verify_proof(tampered_leaf_hash, proof, stored_root)` attempts to recompute the MMR root by hashing upward through the siblings. Because the starting leaf hash is wrong, the recomputed root diverges from the stored root and the proof returns `False`.

No other records are read. The sibling hashes come entirely from the in-memory `self._mmr` — the attacker only touched the DB.

**2. Lineage — O(log n) Merkle proof + field consistency**

Each record also has a leaf in the secondary lineage MMR (`self._lineage_mmr`), where the leaf is `lineage_hash = SHA-256(record_id || payload_hash || parent_lineage_hash)`.

`verify_proof(lineage.lineage_hash, lineage_proof, lineage_root)` checks the lineage MMR proof independently. Additionally, the stored `lineage_hash` is recomputed from the lineage record's fields to catch partial tampering (e.g. `parent_lineage_hash` changed without updating `lineage_hash`).

In this fixture the primary check fires first and the result is returned immediately.

## Why the Proof Fails

| Field | Value |
|---|---|
| Original `payload_hash` | `48abb9ef9e3e28058ebf72c6e636c433f50f3e391e19aa49a43c5d3232a3d7b5` |
| Planted `payload_hash` | `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa` |
| Proof siblings consulted | ~10 |
| Records read from DB | 1 |

The MMR root is a cryptographic commitment to the hash of every record at anchor time. Changing any byte in any record changes its leaf hash, which cascades through the proof path and produces a root that does not match the stored value. There is no way to forge a passing proof without also controlling the in-memory MMR state.

## Test Coverage

| Test | Mutation | Verified record | Outcome |
|---|---|---|---|
| `test_tamper_at_record_500` | `audit_records[500].payload_hash` | record 500 | `tampered_at_sequence=500` |
| `test_tamper_at_record_0` | `audit_records[0].payload_hash` | record 0 | `tampered_at_sequence=0` |
| `test_tamper_at_record_1` | `audit_records[1].originating_component_id` | record 1 | `tampered_at_sequence=1` |
| `test_tamper_last_but_one_record` | `audit_records[n-2].payload_hash` | record n-2 | `tampered_at_sequence=n-2` |
| `test_no_tamper_returns_valid` | none | record n-1 | `valid=True` |
| `test_verify_unknown_record_id_returns_invalid` | none (empty log) | unknown ID | `valid=False` |
| `test_single_record_no_tamper` | none | single record | `valid=True` |
| `test_single_record_tampered` | `audit_records[0].payload_hash` | single record | `tampered_at_sequence=0` |
| `test_lineage_tamper_detected_when_primary_intact` | `lineage_records[10].lineage_hash` | record 10 | lineage proof fails |
| `test_lineage_parent_hash_tamper_detected` | `lineage_records[5].parent_lineage_hash` | record 5 | lineage fields inconsistent |
| `test_reconciliation_failure_primary_ok_lineage_bad` | `lineage_records[7].payload_hash` | record 7 | lineage fields inconsistent |

All 11 tests pass. The dual-anchor design means a successful attack requires simultaneous consistent corruption of both `audit_records` and `lineage_records` AND the in-memory MMR state — two separately guarded DB tables plus runtime memory.