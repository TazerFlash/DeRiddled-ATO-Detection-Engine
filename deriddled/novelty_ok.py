"""Build success-only history counts (sql/novelty_ok.sql) and derive the new_*_ok flags and lr_score_ok used by the red-team-hardened model."""
import shutil
import sys
import time

import numpy as np
import pandas as pd

from deriddled.config import ROOT, connect, load_config, path

DIRS = {"sample": ("sample_dir", "data/features/novelty_ok_sample"), "full": ("logins_dir", "data/features/novelty_ok")}
FLAGS = {"new_country_ok": "country_user_ok", "new_asn_ok": "asn_user_ok", "new_device_ok": "device_user_ok",
         "new_ip_ok": "ip_user_ok", "new_subnet24_ok": "subnet_user_ok"}
SWAP = {"new_country": "new_country_ok", "new_asn": "new_asn_ok", "new_device": "new_device_ok",
        "new_ip": "new_ip_ok", "new_subnet24": "new_subnet24_ok", "lr_score": "lr_score_ok"}


def out_dir(which: str):
    return path(DIRS[which][1])


def build(which: str) -> None:
    src_key, _ = DIRS[which]
    out = out_dir(which)
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    sql = (ROOT / "sql" / "novelty_ok.sql").read_text(encoding="utf-8")
    sql = sql.replace("{source}", f"{path(load_config()['data'][src_key]).as_posix()}/**/*.parquet")
    t0 = time.time()
    connect().execute(f"COPY ({sql}) TO '{(out / 'novelty_ok.parquet').as_posix()}' (FORMAT parquet, COMPRESSION zstd)")
    print(f"{which} success-only history counts written to {out} in {time.time() - t0:.0f}s")


def derive(df: pd.DataFrame, features=("ip", "asn", "country", "ua")) -> pd.DataFrame:
    for flag, count in FLAGS.items():
        df[flag] = df[count] == 0
    total = np.zeros(len(df))
    n_ok = df["user_n_ok"].to_numpy(float)
    for f in features:
        vocab = df[f"{f}_vocab"].to_numpy(float)
        p_pop = (df[f"{f}_pop"].to_numpy(float) + 1) / (df["global_n"].to_numpy(float) + vocab + 1)
        p_user = (df[f"{f}_user_ok"].to_numpy(float) + p_pop) / (n_ok + 1)
        p_attack = (df[f"{f}_attack"].to_numpy(float) + 1) / (df["global_attack"].to_numpy(float) + vocab + 1)
        total += np.log(p_attack) - np.log(p_user)
    df["lr_score_ok"] = total
    return df


if __name__ == "__main__":
    build(sys.argv[1] if len(sys.argv) > 1 else "sample")
