"""Data access for the analyst dashboard: decision-log KPIs, alert queue with labels, case details, user history, and label-feedback re-scoring."""
import json
import sqlite3

import numpy as np
import pandas as pd

from deriddled.config import connect, load_config, path
from deriddled.explain import load_policy, score
from deriddled.splits import windows
from deriddled.train import load

REPUTATION_KEYS = {"asn": ("asn_ato_prior", "asn_ato_rate"), "subnet": ("subnet_ato_prior", "subnet_ato_rate"),
                   "ip": ("ip_ato_prior", "ip_ato_rate")}


def _ops() -> sqlite3.Connection:
    return sqlite3.connect(path(load_config()["ops"]["sqlite_path"]))


def kpis() -> dict:
    with _ops() as c:
        actions = dict(c.execute("SELECT action, COUNT(*) FROM decisions GROUP BY action").fetchall())
        fail_open, first, last = c.execute("SELECT SUM(fail_open), MIN(event_ts), MAX(event_ts) FROM decisions").fetchone()
        lat = np.array([r[0] for r in c.execute("SELECT latency_ms FROM decisions WHERE latency_ms IS NOT NULL")])
        version = c.execute("SELECT model_version FROM decisions ORDER BY logged_at DESC LIMIT 1").fetchone()
    n = sum(actions.values())
    return {"logins": n, "challenge": actions.get("CHALLENGE", 0), "block": actions.get("BLOCK", 0),
            "fail_open": int(fail_open or 0), "first": first, "last": last,
            "p50_ms": float(np.percentile(lat, 50)) if len(lat) else None,
            "p95_ms": float(np.percentile(lat, 95)) if len(lat) else None,
            "model_version": version[0] if version else None}


def daily() -> pd.DataFrame:
    with _ops() as c:
        return pd.read_sql("""SELECT substr(event_ts, 1, 10) AS day, action, COUNT(*) AS logins
                              FROM decisions GROUP BY day, action ORDER BY day""", c)


def alerts() -> pd.DataFrame:
    with _ops() as c:
        df = pd.read_sql("""SELECT d.login_id, d.event_ts, d.user_id, d.country, d.score, d.action, d.reasons,
                                   d.model_version, l.label, l.analyst, l.labelled_at
                            FROM decisions d LEFT JOIN labels l USING (login_id)
                            WHERE d.action != 'ALLOW' ORDER BY d.score DESC""", c)
    df["event_ts"] = pd.to_datetime(df["event_ts"], format="ISO8601")
    df["reasons"] = df["reasons"].map(json.loads)
    return df


def labels() -> pd.DataFrame:
    with _ops() as c:
        return pd.read_sql("SELECT * FROM labels", c)


def _months(ts: pd.Series) -> str:
    return ", ".join(f"'{m}'" for m in sorted(ts.dt.strftime("%Y-%m").unique()))


def login_details(alert_df: pd.DataFrame) -> pd.DataFrame:
    src = path(load_config()["data"]["logins_dir"]).as_posix()
    ids = ", ".join(str(int(i)) for i in alert_df["login_id"])
    return connect().execute(f"""
        SELECT login_id, ip, asn, region, city, browser, os, device_type, login_successful, is_ato, is_attack_ip,
               regexp_extract(ip, '^(\\d+\\.\\d+\\.\\d+)\\.', 1) AS subnet
        FROM read_parquet('{src}/**/*.parquet', hive_partitioning = true)
        WHERE month IN ({_months(alert_df['event_ts'])}) AND login_id IN ({ids})
    """).df()


def user_history(user_id: int, before: pd.Timestamp, limit: int = 200) -> pd.DataFrame:
    src = path(load_config()["data"]["logins_dir"]).as_posix()
    return connect().execute(f"""
        SELECT ts, country, city, asn, ip, browser, os, device_type, login_successful
        FROM read_parquet('{src}/**/*.parquet', hive_partitioning = true)
        WHERE month <= '{before:%Y-%m}' AND user_id = ? AND ts <= ?
        ORDER BY ts DESC LIMIT {limit}
    """, [int(user_id), before.to_pydatetime()]).df()


def _split_of(ts: pd.Timestamp) -> str | None:
    for name, (start, end) in windows("ato").items():
        if pd.Timestamp(start) <= ts < pd.Timestamp(end):
            return name
    return None


def alert_features(alert_df: pd.DataFrame) -> pd.DataFrame:
    parts = []
    for split, group in alert_df.groupby(alert_df["event_ts"].map(_split_of)):
        parts.append(load("ato", split, ids=group["login_id"].tolist()))
    return pd.concat(parts, ignore_index=True) if parts else pd.DataFrame()


def rescore_with_labels(feats: pd.DataFrame, details: pd.DataFrame, confirmed: set[int]) -> pd.DataFrame:
    rep = load_config()["reputation"]
    m, p0 = rep["m"], rep["p0"]
    booster, meta, cal = load_policy()
    df = feats.merge(details[["login_id", "asn", "subnet", "ip"]].rename(columns={"asn": "asn_key"}), on="login_id")
    before = score(df.copy(), booster, meta, cal)[["login_id", "p", "action"]]
    hits = df[df["login_id"].isin(confirmed)]
    after = df.copy()
    for key, (prior, rate) in REPUTATION_KEYS.items():
        col = "asn_key" if key == "asn" else key
        added = pd.Series(0.0, index=after.index)
        for _, h in hits.iterrows():
            added += ((after[col] == h[col]) & (after["login_id"] != h["login_id"])).astype(float)
        k = after[prior].astype(float)
        n = (k + m * p0) / after[rate].astype(float) - m
        after[prior] = k + added
        after[rate] = (k + added + m * p0) / (n + added + m)
        after[f"added_{key}"] = added
    out = score(after, booster, meta, cal)[["login_id", "p", "action", "added_asn", "added_subnet", "added_ip"]]
    return before.merge(out, on="login_id", suffixes=("_before", "_after"))


def shadow_summary() -> pd.DataFrame | None:
    f = path(load_config()["data"]["models_dir"]).parent / "ops" / "shadow_valid.json"
    return pd.DataFrame(json.loads(f.read_text())["summary"]) if f.exists() else None


def psi() -> pd.DataFrame | None:
    f = path(load_config()["data"]["models_dir"]).parent / "ops" / "psi_by_month.csv"
    return pd.read_csv(f, index_col=0) if f.exists() else None


def registry_versions() -> pd.DataFrame:
    from deriddled.registry import setup
    client = setup()
    rows = []
    for name in ("deriddled-ato", "deriddled-attack-ip"):
        champion = client.get_model_version_by_alias(name, "champion").version
        for v in client.search_model_versions(f"name='{name}'"):
            rows.append({"model": name, "version": int(v.version), "champion": v.version == champion,
                         "run_id": v.run_id})
    return pd.DataFrame(rows).sort_values(["model", "version"])
