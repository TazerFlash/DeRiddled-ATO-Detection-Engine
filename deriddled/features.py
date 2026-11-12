"""Run sql/features.sql on the sample or full logins and write month-partitioned feature Parquet."""
import shutil
import sys
import time

from deriddled.config import ROOT, connect, load_config, path

TARGETS = {
    "sample": ("sample_dir", "features_sample_dir"),
    "full": ("logins_dir", "features_dir"),
}


def feature_sql(source_dir: str) -> str:
    sql = (ROOT / "sql" / "features.sql").read_text(encoding="utf-8")
    return sql.replace("{source}", f"{source_dir}/**/*.parquet")


def build(which: str) -> None:
    cfg = load_config()["data"]
    src_key, out_key = TARGETS[which]
    src = path(cfg[src_key]).as_posix()
    out_dir = path(cfg[out_key])
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.parent.mkdir(parents=True, exist_ok=True)

    con = connect()
    t0 = time.time()
    con.execute(f"""
        COPY ({feature_sql(src)})
        TO '{out_dir.as_posix()}'
        (FORMAT parquet, PARTITION_BY (month), COMPRESSION zstd)
    """)
    print(f"{which} features written to {out_dir} in {time.time() - t0:.0f}s")


if __name__ == "__main__":
    build(sys.argv[1] if len(sys.argv) > 1 else "sample")
