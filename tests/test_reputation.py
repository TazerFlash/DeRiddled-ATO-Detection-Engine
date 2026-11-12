"""Recompute delayed ATO reputation for sampled rows from raw history in pandas and assert they match reputation.sql."""
import pandas as pd
import pytest

from deriddled.config import connect, load_config, path

SEED = 13
cfg = load_config()
SAMPLE = path(cfg["data"]["sample_dir"])
REP = path(cfg["data"]["reputation_sample_dir"])
DELAY = pd.Timedelta(days=cfg["reputation"]["label_delay_days"])
M, P0 = float(cfg["reputation"]["m"]), float(cfg["reputation"]["p0"])

pytestmark = pytest.mark.skipif(not REP.exists(), reason="sample reputation features not built")


@pytest.fixture(scope="module")
def data():
    con = connect()
    raw = con.execute(f"""
        SELECT login_id, ts, is_ato, asn, country, ip, regexp_extract(ip, '^(\\d+\\.\\d+\\.\\d+)\\.', 1) AS subnet24
        FROM read_parquet('{SAMPLE.as_posix()}/**/*.parquet', hive_partitioning = true)
    """).df()
    rep = con.execute(f"SELECT * FROM read_parquet('{REP.as_posix()}/*.parquet')").df()
    ato_keys = raw[raw.is_ato]
    near_ato = raw[raw.asn.isin(ato_keys.asn) | raw.ip.isin(ato_keys.ip)].login_id
    picks = pd.concat([rep.sample(60, random_state=SEED),
                       rep[rep.login_id.isin(near_ato)].sample(60, random_state=SEED)])
    return raw, picks.drop_duplicates("login_id")


def test_picks_include_nonzero_reputation(data):
    _, picks = data
    assert (picks.asn_ato_prior > 0).any()


def test_reputation_matches_raw_history(data):
    raw, picks = data
    failures = []
    for row in picks.itertuples(index=False):
        me = raw[raw.login_id == row.login_id].iloc[0]
        old = raw[raw.ts <= me.ts - DELAY]
        for key in ("asn", "country", "ip", "subnet24"):
            same = old[old[key] == me[key]]
            k, n = int(same.is_ato.sum()), len(same)
            prefix = "subnet" if key == "subnet24" else key
            for name, want in ((f"{prefix}_ato_prior", k), (f"{prefix}_ato_rate", (k + M * P0) / (n + M))):
                got = getattr(row, name)
                if abs(float(got) - want) > 1e-12:
                    failures.append(f"login {row.login_id} {name}: sql={got} expected={want}")
    assert not failures, f"{len(failures)} mismatches:\n" + "\n".join(failures[:30])
