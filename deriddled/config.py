"""Load config.yaml, resolve paths against the repo (or DERIDDLED_ROOT, used by the hosted demo), and open DuckDB with the configured memory and spill limits."""
import os
from pathlib import Path

import duckdb
import yaml

ROOT = Path(os.environ.get("DERIDDLED_ROOT") or Path(__file__).resolve().parent.parent)


def load_config() -> dict:
    with open(ROOT / "config.yaml", encoding="utf-8") as f:
        return yaml.safe_load(f)


def path(relative: str) -> Path:
    return ROOT / relative


def connect(read_only: bool = False) -> duckdb.DuckDBPyConnection:
    cfg = load_config()["duckdb"]
    con = duckdb.connect(read_only=read_only)
    con.execute(f"SET memory_limit = '{cfg['memory_limit']}'")
    tmp = path(cfg["temp_directory"])
    tmp.mkdir(parents=True, exist_ok=True)
    con.execute(f"SET temp_directory = '{tmp.as_posix()}'")
    if cfg.get("threads"):
        con.execute(f"SET threads = {int(cfg['threads'])}")
    return con
