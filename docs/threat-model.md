# Threat model

What `tamper-evident-ledger` does and doesn't protect, written for the senior
engineer who's going to integrate it.

## TL;DR

This repo gives you **tamper-evidence** for a single-host Postgres ledger,
implemented in two layers:

1. **Python** — a repository guard that catches well-behaved app code.
2. **PL/pgSQL** — a `BEFORE UPDATE` trigger that catches raw SQL.

The hash chain is the long-term safety net: it detects any after-the-fact
edit, even when both layers above are bypassed. **It does not prevent**
edits, and it does not let you recover the original values — only prove
that *something* changed and pinpoint where.

## Defends against

| Threat | Mechanism |
|---|---|
| **DBA editing rows directly** in `psql` | Hash chain — even with `session_replication_role = replica`, the audit log no longer matches the ledger. |
| **Post-incident evidence destruction** | Off-site `verify_chain` runs prove the chain broke at row #N. The before/after diff stays in the chain itself. |
| **Silent application-level fraud** (e.g. compromised admin UI changing amounts) | Repository guard refuses the update; if attacker patches the repo, the chain still notices the audit row is missing or stale. |
| **Compromised app credentials issuing UPDATE** through SQLAlchemy | PL/pgSQL trigger raises `check_violation` — works regardless of which ORM is on the other side. |
| **Race condition** producing forked chains | `SELECT ... FOR UPDATE` on the chain tip serialises concurrent appenders within a single transaction. |
| **Replay of an old audit body** | `UNIQUE(organization_id, current_hash)` rejects duplicate links. |

## Does *not* defend against

| Threat | Why |
|---|---|
| **The original writer** | You can always append any *future* history that's internally consistent. The chain only protects the past. |
| **Full database drop or restore from backup** | If the entire DB is replaced, there's no longer a chain to verify. Pair with off-site chain anchoring (below). |
| **Physical seizure of DB + KMS key together** | An attacker who has both can decrypt everything and write a new chain from scratch. Geographic separation of key custody is out of scope here. |
| **Collusion between root + key holder** | Same as above — if both halves of the trust split agree, they can rewrite arbitrarily. |
| **A bug in the verifier** | The verifier is one source-controlled file. Treat it like any other security-critical code: review, test, and re-deploy as a unit. |
| **Repudiation of *that an event happened*** | The chain proves the event was *logged*; it doesn't prove an event in the real world actually occurred. Pair with external evidence (signed receipts, third-party callbacks). |

## Suggested complements

The hash chain is necessary but not sufficient for a regulated workload.
Pick what matches your threat profile:

- **WORM storage for `audit_log`** — Postgres on a write-once filesystem,
  or replicate the table into S3 Object Lock / Azure Immutable Blob /
  GCS Bucket Lock. Stops the attacker who already has root.
- **RFC 3161 timestamps** — periodically take `SHA-256(latest current_hash)`
  to a trusted timestamping authority. Locks the chain head to a wall-clock
  moment that even a future root attacker can't roll back.
- **Off-site verification cron** — a second, read-only machine pulls the
  chain and runs `verify_chain` every N minutes. Alert on first failure.
- **Merkle tree on top of the chain** — once you outgrow O(n) verification,
  build a Merkle tree over batches of rows. Lets you publish a single root
  hash externally and prove inclusion of any past row in O(log n).
- **Per-row signing** — sign each `current_hash` with a private key held in
  a separate HSM. Now to forge history you need both the DB *and* the HSM.
- **Append-only revocation/audit at the OS layer** — `chattr +a`, ZFS
  snapshots, or `pg_audit` to a separate, hardened cluster.

## What this demo deliberately omits

For clarity these are **left out** so the audit-chain story is the only
moving part:

- AuthN/AuthZ (no JWTs, no RBAC).
- Multi-tenant ACL beyond `organization_id` as a column.
- Soft delete / mark-deleted bookkeeping.
- Idempotency keys / dedupe windows.
- Rate limiting, observability, structured logging.
- KMS / envelope encryption.

These are well-understood and would clutter the showcase. The source
project this was extracted from has them; this demo doesn't.
