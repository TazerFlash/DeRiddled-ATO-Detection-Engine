"""Recompute ~140 sample rows' features from raw history in pandas and assert they match features.sql."""
import math

import numpy as np
import pandas as pd
import pytest

from deriddled.config import connect, load_config, path

N_RANDOM = 100
SEED = 7

cfg = load_config()["data"]
SAMPLE = path(cfg["sample_dir"])
FEATURES = path(cfg["features_sample_dir"])

pytestmark = pytest.mark.skipif(not FEATURES.exists(), reason="sample features not built")


def _concat_ws(df: pd.DataFrame, cols: list[str], sep: str = " | ") -> pd.Series:
    out = pd.Series("", index=df.index)
    for c in cols:
        has = df[c].notna()
        joiner = np.where((out != "") & has, sep, "")
        out = out + joiner + df[c].where(has, "").astype(str)
    return out


@pytest.fixture(scope="module")
def data():
    con = connect()
    raw = con.execute(f"""
        SELECT login_id, ts, user_id, ip, country, asn, browser, os, device_type,
               login_successful, is_attack_ip, is_non_account,
               regexp_extract(ip, '^(\\d+\\.\\d+\\.\\d+)\\.', 1) AS subnet24
        FROM read_parquet('{SAMPLE.as_posix()}/**/*.parquet', hive_partitioning = true)
    """).df()
    raw["device_key"] = _concat_ws(raw, ["browser", "os", "device_type"])
    raw["ua_key"] = _concat_ws(raw, ["browser", "os"])
    feats = con.execute(f"""
        SELECT * FROM read_parquet('{FEATURES.as_posix()}/**/*.parquet', hive_partitioning = true)
    """).df()

    tie_ts = raw.loc[raw.duplicated("ts", keep=False), "ts"].unique()
    picks = pd.concat([
        feats.sample(N_RANDOM, random_state=SEED),
        feats[feats.is_ato],
        feats[feats.ts.isin(tie_ts)].sample(min(20, feats.ts.isin(tie_ts).sum()), random_state=SEED),
    ]).drop_duplicates("login_id")
    return raw, picks


def _expected(raw: pd.DataFrame, row) -> dict:
    t = row.ts
    before = raw[raw.ts < t]
    me = raw[raw.login_id == row.login_id].iloc[0]
    user = before[(before.user_id == row.user_id) & ~before.is_non_account]
    ip, subnet, asn = before[before.ip == me.ip], before[before.subnet24 == me.subnet24], before[before.asn == me.asn]
    day = lambda df: df[df.ts >= t - pd.Timedelta(hours=24)]
    secs = lambda prev: None if pd.isna(prev) else (t - prev).total_seconds()

    return {
        "user_prior_logins": len(user),
        "user_prior_successes": int(user.login_successful.sum()),
        "secs_since_prev": secs(user.ts.max()),
        "secs_since_prev_success": secs(user.loc[user.login_successful, "ts"].max()),
        "user_logins_1m": int((user.ts >= t - pd.Timedelta(minutes=1)).sum()),
        "user_logins_1h": int((user.ts >= t - pd.Timedelta(hours=1)).sum()),
        "user_fails_1h": int(((user.ts >= t - pd.Timedelta(hours=1)) & ~user.login_successful).sum()),
        "user_logins_24h": len(day(user)),
        "user_fails_24h": int((~day(user).login_successful).sum()),
        "new_country": not (user.country == me.country).any(),
        "new_asn": not (user.asn == me.asn).any(),
        "new_device": not (user.device_key == me.device_key).any(),
        "new_ip": not (user.ip == me.ip).any(),
        "new_subnet24": not (user.subnet24 == me.subnet24).any(),
        "global_prior_logins": len(before),
        "asn_prior_logins": len(asn),
        "asn_prior_attack_ip": int(asn.is_attack_ip.sum()),
        "asn_prior_fails": int((~asn.login_successful).sum()),
        "country_prior_logins": int((before.country == me.country).sum()),
        "ua_prior_logins": int((before.ua_key == me.ua_key).sum()),
        "ip_prior_logins": len(ip),
        "ip_prior_attack_ip": int(ip.is_attack_ip.sum()),
        "ip_prior_fails": int((~ip.login_successful).sum()),
        "ip_logins_24h": len(day(ip)),
        "ip_fails_24h": int((~day(ip).login_successful).sum()),
        "ip_users_24h": day(ip).user_id.nunique(),
        "subnet_logins_24h": len(day(subnet)),
        "subnet_users_24h": day(subnet).user_id.nunique(),
        "asn_users_24h": day(asn).user_id.nunique(),
    }


def _same(a, b) -> bool:
    a_missing = a is None or (isinstance(a, float) and math.isnan(a))
    b_missing = b is None or (isinstance(b, float) and math.isnan(b)) or b is pd.NA
    if a_missing or b_missing:
        return a_missing and b_missing
    if isinstance(a, (bool, np.bool_)):
        return bool(a) == bool(b)
    return math.isclose(float(a), float(b), rel_tol=1e-9, abs_tol=1e-6)


def test_picks_cover_hard_cases(data):
    raw, picks = data
    assert picks.is_ato.sum() > 0
    assert picks.ts.isin(raw.loc[raw.duplicated("ts", keep=False), "ts"]).any()


def test_features_match_raw_history(data):
    raw, picks = data
    failures = []
    for row in picks.itertuples(index=False):
        for name, want in _expected(raw, row).items():
            got = getattr(row, name)
            if not _same(want, got):
                failures.append(f"login {row.login_id} {name}: sql={got} expected={want}")
    assert not failures, f"{len(failures)} mismatches:\n" + "\n".join(failures[:30])
