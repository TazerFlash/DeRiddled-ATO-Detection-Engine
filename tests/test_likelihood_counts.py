"""Recompute likelihood counts for sampled rows from raw history in pandas and assert they match likelihood.sql."""
import numpy as np
import pandas as pd
import pytest

from deriddled.config import connect, load_config, path

N_RANDOM = 80
SEED = 11

cfg = load_config()["data"]
SAMPLE = path(cfg["sample_dir"])
COUNTS = path(cfg["likelihood_sample_dir"])

pytestmark = pytest.mark.skipif(not COUNTS.exists(), reason="sample likelihood counts not built")


@pytest.fixture(scope="module")
def data():
    con = connect()
    raw = con.execute(f"""
        SELECT login_id, ts, user_id, is_non_account, is_attack_ip,
               ip, asn::VARCHAR AS asn, country, concat_ws(' | ', browser, os) AS ua
        FROM read_parquet('{SAMPLE.as_posix()}/**/*.parquet', hive_partitioning = true)
    """).df()
    counts = con.execute(f"SELECT * FROM read_parquet('{COUNTS.as_posix()}/*.parquet')").df()
    ato_ids = con.execute(f"""
        SELECT login_id FROM read_parquet('{SAMPLE.as_posix()}/**/*.parquet', hive_partitioning = true) WHERE is_ato
    """).df().login_id
    picks = pd.concat([counts.sample(N_RANDOM, random_state=SEED), counts[counts.login_id.isin(ato_ids)]])
    return raw, picks.drop_duplicates("login_id")


def test_row_count_is_real_accounts(data):
    raw, _ = data
    n = connect().execute(f"SELECT COUNT(*) FROM read_parquet('{COUNTS.as_posix()}/*.parquet')").fetchone()[0]
    assert n == int((~raw.is_non_account).sum())


def test_counts_match_raw_history(data):
    raw, picks = data
    failures = []
    for row in picks.itertuples(index=False):
        me = raw[raw.login_id == row.login_id].iloc[0]
        before = raw[raw.ts < me.ts]
        user = before[(before.user_id == me.user_id) & ~before.is_non_account]
        want = {"user_n": len(user), "global_n": len(before), "global_attack": int(before.is_attack_ip.sum())}
        for f in ("ip", "asn", "country", "ua"):
            same = before[before[f] == me[f]]
            want |= {
                f"{f}_user": int((user[f] == me[f]).sum()),
                f"{f}_pop": len(same),
                f"{f}_attack": int(same.is_attack_ip.sum()),
                f"{f}_vocab": before[f].nunique(),
            }
        for name, w in want.items():
            got = getattr(row, name)
            if not (pd.notna(got) and int(got) == w):
                failures.append(f"login {row.login_id} {name}: sql={got} expected={w}")
    assert not failures, f"{len(failures)} mismatches:\n" + "\n".join(failures[:30])
