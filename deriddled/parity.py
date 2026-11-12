"""Warm-start the online state at time T, replay the following hours, and compare every feature with the offline tables."""
import math
import sys
import time
from collections import Counter

import numpy as np
import pandas as pd

from deriddled.config import connect, load_config, path
from deriddled import novelty_ok
from deriddled.likelihood import log_lr
from deriddled.state import OnlineState, prepare, to_us

RAW_COLS = "login_id, ts, user_id, ip, asn, country, browser, os, device_type, rtt_ms, login_successful, is_attack_ip, is_ato, is_non_account"
EXPR = {
    "subnet": "regexp_extract(ip, '^(\\d+\\.\\d+\\.\\d+)\\.', 1)",
    "ua": "concat_ws(' | ', browser, os)",
    "device_key": "concat_ws(' | ', browser, os, device_type)",
    "asn": "asn::VARCHAR", "ip": "ip", "country": "country",
}


def _logins():
    return f"read_parquet('{path(load_config()['data']['logins_dir']).as_posix()}/**/*.parquet', hive_partitioning = true)"


def replay_events(con, start: pd.Timestamp, hours: float) -> pd.DataFrame:
    end = start + pd.Timedelta(hours=hours)
    return con.execute(f"""SELECT {RAW_COLS} FROM {_logins()}
                           WHERE ts >= TIMESTAMP '{start}' AND ts < TIMESTAMP '{end}' ORDER BY ts, login_id""").df()


def warm_start(con, T: pd.Timestamp, ev: pd.DataFrame) -> OnlineState:
    s = OnlineState()
    L = _logins()
    con.register("ev", ev.assign(asn=ev.asn.astype(str)))
    s.global_n, s.global_attack = con.execute(
        f"SELECT COUNT(*), SUM(is_attack_ip::INT) FROM {L} WHERE ts < TIMESTAMP '{T}'").fetchone()
    s.global_attack = int(s.global_attack or 0)

    for k in ("ip", "asn", "country", "ua"):
        s.vocab[k] = con.execute(f"SELECT COUNT(DISTINCT {EXPR[k]}) FROM {L} WHERE ts < TIMESTAMP '{T}'").fetchone()[0]
        touched = f"SELECT DISTINCT {EXPR[k]} AS v FROM ev"
        rows = con.execute(f"""
            SELECT {EXPR[k]} AS v, COUNT(*), SUM(is_attack_ip::INT), SUM((NOT login_successful)::INT)
            FROM {L} WHERE ts < TIMESTAMP '{T}' AND {EXPR[k]} IN ({touched}) GROUP BY 1""").fetchall()
        for v, n, att, fail in rows:
            s.pop[k][v] = [n, int(att), int(fail)]
            s.seen_value[k].add(v)

    users = ev.loc[~ev.is_non_account, "user_id"].unique()
    con.register("users", pd.DataFrame({"user_id": users}))
    for uid, n, succ, last, last_succ in con.execute(f"""
            SELECT user_id, COUNT(*), SUM(login_successful::INT), MAX(ts), MAX(CASE WHEN login_successful THEN ts END)
            FROM {L} JOIN users USING (user_id) WHERE ts < TIMESTAMP '{T}' AND NOT is_non_account GROUP BY 1""").fetchall():
        u = s.user[uid]
        u.update(n=n, succ=int(succ), last=to_us(last), last_succ=None if last_succ is None else to_us(last_succ))
    for k in ("country", "asn", "device_key", "ip", "subnet", "ua"):
        for uid, v, n in con.execute(f"""
                SELECT user_id, {EXPR[k]}, COUNT(*) FROM {L} JOIN users USING (user_id)
                WHERE ts < TIMESTAMP '{T}' AND NOT is_non_account GROUP BY 1, 2""").fetchall():
            s.user[uid]["values"][k][v] = n
        for uid, v, n in con.execute(f"""
                SELECT user_id, {EXPR[k]}, COUNT(*) FROM {L} JOIN users USING (user_id)
                WHERE ts < TIMESTAMP '{T}' AND NOT is_non_account AND login_successful GROUP BY 1, 2""").fetchall():
            s.user[uid]["ok"][k][v] = n

    day = con.execute(f"""SELECT {RAW_COLS} FROM {L} WHERE ts >= TIMESTAMP '{T - pd.Timedelta(days=1)}'
                          AND ts < TIMESTAMP '{T}' ORDER BY ts, login_id""").df()
    keys = {k: set(prepare_frame(ev)[k]) for k in ("ip", "subnet", "asn")}
    for e in prepare_frame(day).to_dict("records"):
        for k in ("ip", "subnet", "asn"):
            if e[k] in keys[k]:
                s.win[k][e[k]].add(e["t"], e["user_id"], not e["login_successful"])
        if not e["is_non_account"] and e["user_id"] in s.user:
            s.user[e["user_id"]]["recent"].append((e["t"], not e["login_successful"]))

    cutoff = T - pd.Timedelta(microseconds=s.delay)
    for k in ("asn", "ip", "subnet"):
        vals = pd.DataFrame({"v": list(keys[k])})
        con.register("vals", vals)
        for v, n, kk in con.execute(f"""SELECT {EXPR[k]} AS v, COUNT(*), SUM(is_ato::INT) FROM {L}
                                        WHERE ts <= TIMESTAMP '{cutoff}' AND {EXPR[k]} IN (SELECT v FROM vals) GROUP BY 1""").fetchall():
            s.rep[k][v] = [n, int(kk)]
    week = con.execute(f"""SELECT {RAW_COLS} FROM {L} WHERE ts > TIMESTAMP '{cutoff}' AND ts < TIMESTAMP '{T}'
                           ORDER BY ts, login_id""").df()
    for e in prepare_frame(week).to_dict("records"):
        if e["asn"] in keys["asn"] or e["ip"] in keys["ip"] or e["subnet"] in keys["subnet"]:
            s.pending.append((e["t"], e["asn"], e["ip"], e["subnet"], bool(e["is_ato"])))
    return s


def prepare_frame(df: pd.DataFrame) -> pd.DataFrame:
    return pd.DataFrame([prepare(r) for r in df.to_dict("records")]) if len(df) else df


def replay(s: OnlineState, ev: pd.DataFrame) -> pd.DataFrame:
    rows = []
    events = prepare_frame(ev).to_dict("records")
    i = 0
    while i < len(events):
        j = i
        while j < len(events) and events[j]["t"] == events[i]["t"]:
            j += 1
        group = events[i:j]
        for e, f in zip(group, s.process_group(group)):
            if not e["is_non_account"]:
                rows.append({"login_id": e["login_id"], **f})
        i = j
    return pd.DataFrame(rows)


def offline(con, login_ids) -> pd.DataFrame:
    cfg = load_config()["data"]
    con.register("ids", pd.DataFrame({"login_id": list(login_ids)}))
    df = con.execute(f"""
        SELECT f.*, l.* EXCLUDE (login_id), r.* EXCLUDE (login_id), o.* EXCLUDE (login_id)
        FROM read_parquet('{path(cfg['features_dir']).as_posix()}/**/*.parquet', hive_partitioning = true) f
        JOIN ids USING (login_id)
        JOIN read_parquet('{path(cfg['likelihood_dir']).as_posix()}/*.parquet') l USING (login_id)
        JOIN read_parquet('{path(cfg['reputation_dir']).as_posix()}/*.parquet') r USING (login_id)
        JOIN read_parquet('{novelty_ok.out_dir("full").as_posix()}/*.parquet') o USING (login_id)
    """).df()
    df["lr_score"] = log_lr(df, "attack_informed", 1.0, ("ip", "asn", "country", "ua"))
    return novelty_ok.derive(df)


def compare(online: pd.DataFrame, off: pd.DataFrame, features: list[str]) -> pd.DataFrame:
    m = online.merge(off[["login_id"] + features], on="login_id", suffixes=("_on", "_off"))
    out = []
    for f in features:
        a, b = m[f"{f}_on"], m[f"{f}_off"]
        if f == "device_type":
            bad = a.fillna("<NA>").astype(str) != b.fillna("<NA>").astype(str)
        else:
            a, b = a.astype(float), b.astype(float)
            both_nan = a.isna() & b.isna()
            bad = ~both_nan & ~np.isclose(a.fillna(-1e18), b.fillna(-1e18), rtol=1e-7, atol=1e-9)
        out.append({"feature": f, "rows": len(m), "mismatches": int(bad.sum()),
                    "example": "" if not bad.any() else f"login {m.loc[bad, 'login_id'].iat[0]}: online={a[bad].iat[0]} offline={b[bad].iat[0]}"})
    return pd.DataFrame(out)


def run(start: str = "2020-09-15 00:00:00", hours: float = 3.0) -> pd.DataFrame:
    import json
    T = pd.Timestamp(start)
    features = json.loads((path(load_config()["data"]["models_dir"]) / f"{load_config()['models']['ato']}_meta.json")
                          .read_text())["features"]
    features += [f for f in novelty_ok.SWAP.values() if f not in features]
    con = connect()
    t0 = time.time()
    ev = replay_events(con, T, hours)
    s = warm_start(con, T, ev)
    t1 = time.time()
    online = replay(s, ev)
    t2 = time.time()
    report = compare(online, offline(con, online.login_id), features)
    print(f"replay window {T} + {hours}h: {len(ev):,} events ({len(online):,} real-account logins); "
          f"warm start {t1 - t0:.0f}s, replay {t2 - t1:.1f}s ({len(ev) / max(t2 - t1, 1e-9):,.0f} events/s)")
    return report


if __name__ == "__main__":
    pd.set_option("display.width", 250)
    pd.set_option("display.max_colwidth", 120)
    start = sys.argv[1] if len(sys.argv) > 1 else "2020-09-15 00:00:00"
    hours = float(sys.argv[2]) if len(sys.argv) > 2 else 3.0
    rep = run(start, hours)
    print(rep.to_string(index=False))
    print(f"\nTOTAL MISMATCHES: {int(rep.mismatches.sum())}")
