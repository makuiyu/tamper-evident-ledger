# Architecture

A bird's-eye view of how `tamper-evident-ledger` produces — and verifies —
tamper-evident audit logs.

## Component map

```mermaid
flowchart LR
    Client[HTTP client]
    API[FastAPI router<br/>app/api.py]
    Repo[LedgerRepository<br/>app/repositories/ledger.py]
    Enc[AES-256-GCM<br/>app/security/encryption.py]
    Chain[append_audit<br/>app/audit/chain.py]
    Verify[verify_chain<br/>app/audit/verifier.py]
    DB[(Postgres<br/>ledger + audit_log)]
    Trig[PL/pgSQL trigger<br/>prevent_ledger_amount_update]

    Client -->|POST /ledger| API
    API --> Enc
    API --> Repo
    Repo --> DB
    API --> Chain
    Chain --> DB
    Client -->|GET /ledger/verify| API
    API --> Verify
    Verify --> DB
    DB -. BEFORE UPDATE .-> Trig
```

The repo guard (Python) and the trigger (PL/pgSQL) protect the **same**
columns. The repo gives a friendly error to honest callers; the trigger
catches everyone else.

## Hash chain — one link per row

```mermaid
flowchart LR
    G([genesis<br/>prev_hash = NULL])
    R1[row 1<br/>prev = NULL<br/>curr = H1]
    R2[row 2<br/>prev = H1<br/>curr = H2]
    R3[row 3<br/>prev = H2<br/>curr = H3]
    R4[row N-1<br/>prev = ...<br/>curr = Hn-1]
    R5[row N<br/>prev = Hn-1<br/>curr = Hn]

    G --> R1 --> R2 --> R3 --> R4 --> R5
```

For each link:

```
current_hash = SHA-256( prev_hash || canonical_json(body) )
```

`canonical_json` is `json.dumps(body, sort_keys=True, separators=(",",":"), default=str)`.

## Append flow — one row, one transaction

```mermaid
sequenceDiagram
    autonumber
    participant API as POST /ledger
    participant Repo as LedgerRepository
    participant Enc as AES-256-GCM
    participant Chain as append_audit
    participant PG as Postgres

    API->>Enc: encrypt_field(note)
    Enc-->>API: nonce|ciphertext|tag
    API->>Repo: create(Ledger)
    Repo->>PG: INSERT INTO ledger (...)
    API->>Chain: append_audit(payload)
    Chain->>PG: SELECT ... FOR UPDATE (chain tip)
    PG-->>Chain: last row (or none)
    Chain->>Chain: current_hash = SHA-256(prev || body)
    Chain->>PG: INSERT INTO audit_log
    API->>PG: COMMIT
    API-->>Client: 201 LedgerOut
```

`SELECT ... FOR UPDATE` on the chain tip is what guarantees two parallel
appenders can't fork the chain. Both writes are in the same transaction, so
an audit row can never exist without its ledger row.

## Tamper detection flow

```mermaid
sequenceDiagram
    autonumber
    participant DBA as Privileged user
    participant PG as Postgres
    participant Aud as verify_chain

    DBA->>PG: SET session_replication_role = replica
    DBA->>PG: UPDATE ledger SET amount = ... (bypassing app)
    Note over PG: trigger skipped because of replica mode<br/>(simulates a real DBA / leaked credential)

    Aud->>PG: SELECT * FROM audit_log ORDER BY created_at
    loop for each row
        Aud->>Aud: recomputed = SHA-256(prev || body)
        Aud->>Aud: if recomputed != stored: BROKEN at i
    end
    Aud-->>Caller: { ok: false, broken_at_index: 5, ... }
```

Even when the trigger is bypassed, the chain still detects the edit: the
audit-log row for the tampered ledger row remains the same, so its body no
longer matches reality — and even if the attacker also tampers with the
audit row, the next link's `prev_hash` no longer matches.

To hide *one* edit cleanly, the attacker has to rewrite every audit-log row
from that point forward. That's a much taller bar — and pairs naturally
with off-site verification, WORM storage, or RFC 3161 timestamps. See
[threat-model.md](threat-model.md).
