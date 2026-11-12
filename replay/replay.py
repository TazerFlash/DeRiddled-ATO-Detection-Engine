"""Replay logins from Parquet to the running API in timestamp order at a target rate and report latency percentiles."""
import argparse
import json
import math
import time
from collections import Counter

import httpx
import numpy as np
import pandas as pd

from deriddled.config import connect, load_config, path
from deriddled.parity import replay_events


def payloads(events: pd.DataFrame) -> list[dict]:
    out = []
    for e in events.to_dict("records"):
        p = {k: (None if isinstance(v, float) and math.isnan(v) else v) for k, v in e.items()}
        p["ts"] = pd.Timestamp(p["ts"]).isoformat()
        out.append(p)
    return out


def run(url: str, start: str, hours: float, rate: float, limit: int | None) -> dict:
    events = replay_events(connect(), pd.Timestamp(start), hours)
    if limit:
        events = events.head(limit)
        hours = (events.ts.max() - pd.Timestamp(start)).total_seconds() / 3600 + 1e-6
    body = payloads(events)
    with httpx.Client(base_url=url, timeout=None) as client:
        t = time.perf_counter()
        warm = client.post("/warm_start", json={"start": start, "hours": hours}).json()
        print(f"warm start: {warm} ({time.perf_counter() - t:.0f}s); replaying {len(body):,} events at "
              f"{'max speed' if not rate else f'{rate:g}/s'}", flush=True)
        client_ms, server_ms, actions, fail_open = [], [], Counter(), 0
        t0 = time.perf_counter()
        for i, p in enumerate(body):
            if rate:
                wait = t0 + i / rate - time.perf_counter()
                if wait > 0:
                    time.sleep(wait)
            s = time.perf_counter()
            r = client.post("/score", json=p).json()
            client_ms.append((time.perf_counter() - s) * 1000)
            server_ms.append(r["latency_ms"])
            actions[r["action"]] += 1
            fail_open += r["fail_open"]
            if (i + 1) % 50_000 == 0:
                print(f"  {i + 1:,} events, {(i + 1) / (time.perf_counter() - t0):,.0f}/s", flush=True)
        elapsed = time.perf_counter() - t0

    pct = lambda xs, q: float(np.percentile(xs, q))
    result = {
        "start": start, "events": len(body), "target_rate": rate or None, "achieved_rate": round(len(body) / elapsed, 1),
        "client_p50_ms": round(pct(client_ms, 50), 2), "client_p95_ms": round(pct(client_ms, 95), 2),
        "client_p99_ms": round(pct(client_ms, 99), 2), "client_max_ms": round(max(client_ms), 2),
        "server_p50_ms": round(pct(server_ms, 50), 2), "server_p95_ms": round(pct(server_ms, 95), 2),
        "server_p99_ms": round(pct(server_ms, 99), 2), "fail_open": fail_open, "actions": dict(actions),
    }
    out = path(load_config()["data"]["models_dir"]).parent / "ops" / f"replay_{start[:10]}_{int(rate or 0)}.json"
    out.write_text(json.dumps(result, indent=2))
    return result


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8000")
    ap.add_argument("--start", default="2020-09-15T11:00:00")
    ap.add_argument("--hours", type=float, default=3.0)
    ap.add_argument("--rate", type=float, default=0, help="events per second; 0 = as fast as possible")
    ap.add_argument("--limit", type=int, default=None)
    a = ap.parse_args()
    print(json.dumps(run(a.url, a.start, a.hours, a.rate, a.limit), indent=2))
