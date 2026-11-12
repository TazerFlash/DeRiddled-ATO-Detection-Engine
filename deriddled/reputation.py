"""Build point-in-time ATO reputation features (sql/reputation.sql) with the configured or a given label delay."""
import shutil
import sys
import time
from pathlib import Path

from deriddled.config import ROOT, connect, load_config, path

SOURCES = {"sample": ("sample_dir", "reputation_sample_dir"), "full": ("logins_dir", "reputation_dir")}


def reputation_sql(source_dir: str, delay_days: int | None = None) -> str:
    rep = load_config()["reputation"]
    delay = int(rep["label_delay_days"] if delay_days is None else delay_days)
    sql = (ROOT / "sql" / "reputation.sql").read_text(encoding="utf-8")
    return (sql.replace("{source}", f"{source_dir}/**/*.parquet")
               .replace("{delay_days}", str(delay))
               .replace("{m}", str(float(rep["m"])))
               .replace("{p0}", str(float(rep["p0"]))))


def delay_dir(delay_days: int) -> Path:
    base = path(load_config()["data"]["reputation_dir"])
    return base if delay_days == load_config()["reputation"]["label_delay_days"] else base.with_name(f"{base.name}_d{delay_days}")


def build(which: str, delay_days: int | None = None) -> Path:
    cfg = load_config()["data"]
    src_key, out_key = SOURCES[which]
    out_dir = path(cfg[out_key]) if delay_days is None else delay_dir(delay_days)
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)
    t0 = time.time()
    connect().execute(f"""COPY ({reputation_sql(path(cfg[src_key]).as_posix(), delay_days)})
                          TO '{(out_dir / 'reputation.parquet').as_posix()}' (FORMAT parquet, COMPRESSION zstd)""")
    print(f"{which} reputation features (delay {delay_days or load_config()['reputation']['label_delay_days']}d) "
          f"written to {out_dir} in {time.time() - t0:.0f}s", flush=True)
    return out_dir


if __name__ == "__main__":
    build(sys.argv[1] if len(sys.argv) > 1 else "sample", int(sys.argv[2]) if len(sys.argv) > 2 else None)
