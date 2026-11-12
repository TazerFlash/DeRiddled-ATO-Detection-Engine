# Serving latency (replay against the running API)

Setup: `uvicorn deriddled.api:app` on 127.0.0.1:8000, single process; `python -m replay.replay` sends validation logins in timestamp order, one request at a time, after `POST /warm_start`. Client latency = full HTTP round trip including the SQLite log write; server latency = `latency_ms` (scoring only). Results also saved as JSON in `data/ops/replay_*.json`.

## Paced replays (6,000 logins, 15 Sep 2020 from 11:00)

| Target rate | Version | Achieved | Client p50 / p95 / p99 | Server p95 | Fail-opens |
| --- | --- | --- | --- | --- | --- |
| 50 /s | first version | 50.0 /s | 26.0 / 29.1 / 30.8 ms | 25.4 ms | 0 |
| 200 /s | first version | **51.2 /s** | 25.7 / 28.5 / 30.0 ms | 24.8 ms | 0 |
| 50 /s | fast path | 50.0 /s | 4.1 / 6.3 / 7.1 ms | 2.4 ms | 0 |
| 200 /s | fast path | **200.0 /s** | 2.8 / 4.0 / 5.0 ms | 1.6 ms | 0 |

### The input bottleneck

Profile of the scoring path (1,000 logins, p50 / p95):

| Step | p50 | p95 |
| --- | --- | --- |
| Online state (39 features) | 0.29 ms | 0.36 ms |
| One-row pandas DataFrame + DMatrix | **21.3 ms** | 23.6 ms |
| `predict`, default threads | 1.26 ms | 1.54 ms |
| `predict`, 1 thread | 0.81 ms | 1.03 ms |
| TreeSHAP reasons (flagged only) | 1.36 ms | 1.63 ms |

Fix: NumPy float32 row with `device_type` as its category code, `inplace_predict`, `nthread=1`, and a DMatrix built from that array only for TreeSHAP. Verified identical on 1,000 logins (margin and SHAP max |difference| = 0); `tests/test_api.py` still passes (exact decision parity).

## Full validation week (8–15 Sep 2020, 503,676 logins, maximum speed): Week 5 gate

| | Before GC fix | After GC fix |
| --- | --- | --- |
| Warm start | 87 s | 93 s |
| Throughput | 337.5 /s | **393.2 /s** |
| Client p50 / p95 / p99 | 2.7 / 4.5 / 6.3 ms | **2.5 / 3.3 / 4.5 ms** |
| Server p50 / p95 / p99 | 1.1 / 1.8 / 2.5 ms | **1.0 / 1.4 / 1.8 ms** |
| Client max | 2,550 ms | 2,963 ms (one request; see below) |
| Fail-opens | 4 (timeouts of 409, 592, 726, 1,065 ms) | **0** |
| Actions | 503,518 ALLOW / 155 CHALLENGE / 3 BLOCK | identical |

### The garbage-collector pauses

The 4 timeouts were spaced minutes apart and grew longer as state grew: Python's cycle collector scanning ~2 GB of state objects in full (generation-2) passes. Fix in `Scorer.warm_start`: `gc.collect()`, `gc.freeze()` (1.72M warm-start objects excluded from scanning; the state has no reference cycles, so reference counting still frees it), and `gc.set_threshold(10_000, 50, 1_000)`. `/health` reports collector pauses: 24 generation-2 collections by the 100k mark and still 24 at the end, so none ran during scoring; the 648 ms maximum is the deliberate collection at warm start.

### Remaining outlier

One request (of 503,676) took 2.96 s client-side with normal server scoring time, so the stall was outside scoring (SQLite write or OS scheduling). Remedy, now in place: `ops.py` queues decisions in memory and a background thread writes them to SQLite in batches of up to 1,000 per transaction; reads (`/health`, `/alerts`) flush the queue first. Re-check at 200 /s (6,000 logins): p50 / p95 / p99 2.7 / 3.9 / 4.9 ms, max 24 ms, 0 fail-opens.

## Re-check with champion D (`ato_xgb_mono`), background writer in place

Same full week, maximum speed: 413.1 /s; client p50 / p95 / p99 2.4 / 3.2 / 4.0 ms, **max 42 ms**; server p95 1.35 ms; 0 fail-opens; 503,501 ALLOW / 172 CHALLENGE / 3 BLOCK. The multi-second outlier is gone.

**Gate: passed** (p95 3.3 ms vs < 200 ms, 0 fail-opens, decisions identical to the offline policy).
