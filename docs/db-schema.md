# scoreboard SQLite schema

Authoritative source: `internal/store/store.go`. This document mirrors
that source — if they disagree, **the Go code wins**. Update both in
the same PR.

## Connection

```
file = $SCOREBOARD_DB                                   default /var/lib/scoreboard/scoreboard.db
DSN  = <file>?_pragma=journal_mode(WAL)
                &_pragma=synchronous(NORMAL)
                &_pragma=busy_timeout(5000)
```

- WAL → reader-writer concurrency, durable on crash
- `synchronous=NORMAL` → trade a small durability risk on power loss for
  ~10× write throughput. Acceptable: a CTF run is short and the
  authoritative state (`/api/state`) is recomputed from this DB
- `busy_timeout=5000` → block up to 5 s on contention before erroring
  (single-writer process so this rarely matters in practice)

## Driver

`modernc.org/sqlite` — pure-Go translation of SQLite C. CGO not
required. Static binary builds with `CGO_ENABLED=0` work. Performance
is acceptable at CTF scale (50 users, < 100 events/s peak). For a
significant scale-up, switch to mattn/go-sqlite3 or migrate to
PostgreSQL (see "Migration paths" below).

## Tables

### `solved`

One row per (user, challenge) — the user-visible "Alice solved
`01-read-shadow` at 2026-05-11T10:00Z" record. **First-solve wins**:
re-firing the same trigger does not update `at`.

```sql
CREATE TABLE solved (
  user      TEXT NOT NULL,
  challenge TEXT NOT NULL,
  at        TEXT NOT NULL,             -- RFC3339Nano UTC
  PRIMARY KEY (user, challenge)
);
```

| column      | type | semantics                                                       |
|-------------|------|-----------------------------------------------------------------|
| `user`      | TEXT | extracted from `ctf-<username>` namespace                       |
| `challenge` | TEXT | catalog id (e.g. `01-read-shadow`)                              |
| `at`        | TEXT | **scoreboard receipt time** for trigger solves; **submit time** for evade solves. Falco's `time` field is **not** used here on purpose — see ADR below |

Writes: `INSERT OR IGNORE` (idempotent — first solve wins).
Reads: full table scan into memory at startup, then incremental
updates kept in `Store.solved` in process memory. Snapshots come from
the in-memory map (the DB is the persistence backing store, not a
query target).

### `events_per_user`

Lifetime Falco-event count per user. Drives the dashboard's "Events"
column and the rate-limit-style heuristics.

```sql
CREATE TABLE events_per_user (
  user  TEXT PRIMARY KEY,
  count INTEGER NOT NULL DEFAULT 0
);
```

Writes: upsert (`ON CONFLICT(user) DO UPDATE SET count = excluded.count`).
Reads: also fully loaded into memory at startup.

## In-memory only (NOT in SQLite)

`Store.ruleFires` — a `map[user] -> []ruleFire{rule, unix_seconds}`,
bounded to the last `RetentionSeconds` (= 300) **per user**.

This is the rolling window the evade-challenge submission check looks
at: "did any forbidden rule fire in the last N seconds (Falco time)?"

Why not persisted:
- It's a sliding window — re-loading from disk on restart would have
  to filter out anything older than the cutoff anyway
- Pod restart is rare (`strategy: Recreate`, single replica). For the
  few seconds after restart, evade submissions are slightly more
  lenient until events start flowing again. Acceptable trade-off
- Writes happen on **every** Falco event — keeping that on the hot
  path SQLite path would hurt throughput

## ADR: solve `at` is receipt time, not Falco time

Original design (Python era, ported initially to Go) used Falco's
`time` field for `solved.at`. Falco / falcosidekick can buffer or
batch events; with a stale `time`, the dashboard would show "20m ago"
right after a successful trigger.

Now: `at` = `time.Now()` at receipt (`ingest.receive` in Go).
Evade-windowing still keys off Falco's `time` because the semantic
there is "did a forbidden rule fire in the last N seconds **of Falco
time**", and that is correct.

Test: `TestFalcoEvents_SolveTimestampUsesReceiptTime`.

## Invariants

1. **Single writer.** Scoreboard runs with `replicas: 1, strategy:
   Recreate`. Multiple writers would corrupt the in-memory state and
   conflict on `INSERT OR IGNORE` semantics for first-solve tracking
2. `solved` rows are append-only. We never `UPDATE solved` after
   insert (use `INSERT OR IGNORE` to enforce first-solve-wins)
3. `events_per_user.count` is monotonic non-decreasing
4. `at` strings are RFC3339Nano UTC — string comparison gives correct
   chronological ordering (relied on by the leaderboard tiebreaker)
5. Catalog ids (`solved.challenge`) are case-sensitive matches against
   the keys of `internal/catalog.Catalog`. Renaming a challenge
   directory orphans rows — handle via a one-off SQL migration in the
   release notes

## Migration history

| Version | Date       | Change                                                        |
|---------|------------|---------------------------------------------------------------|
| v1      | 2026-05-08 | Initial schema (`solved`, `events_per_user`). Inherited from the Python implementation; Go port preserves the schema exactly so existing PVC data carries over without migration |

## Migration paths (when scale demands)

| Trigger                                | Move to                                    |
|----------------------------------------|--------------------------------------------|
| Need > 1 scoreboard replica            | PostgreSQL + extract `ruleFires` to Redis  |
| Read-path latency > 100ms p99          | SQLite snapshot + read-replica process     |
| Multi-tenant (multiple CTF instances)  | DB-per-tenant or schema-per-tenant         |

None of these are needed today.

## Inspecting live data

```bash
# Inside the running pod (read-only — DON'T modify the live DB by hand):
kubectl exec -n scoreboard deploy/scoreboard -- \
  sh -c 'apk add --no-cache sqlite >/dev/null 2>&1 || true; \
         sqlite3 /var/lib/scoreboard/scoreboard.db ".tables"'

# Pull a copy locally:
kubectl cp scoreboard/<pod>:/var/lib/scoreboard/scoreboard.db ./scoreboard.db
sqlite3 ./scoreboard.db 'SELECT user, challenge, at FROM solved ORDER BY at;'
```

The `apk add sqlite` only works on the Alpine final stage — fine for
debug but not part of the image build.
