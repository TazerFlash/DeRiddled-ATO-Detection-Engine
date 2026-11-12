"""Build the analyst agent's DuckDB file: hashed logins and decisions only, up to the end of the replayed decision week."""
import sqlite3

import pandas as pd

from deriddled import privacy
from deriddled.config import connect, load_config, path

DB = path("data/analyst/analyst.duckdb")
START, END = "2020-02-01", "2020-09-15"

LOGINS = """
CREATE TABLE logins AS
SELECT login_id, ts, CAST(ts AS DATE) AS day,
       'U-'   || substr(sha256($salt || '|U|'   || CAST(user_id AS VARCHAR)), 1, 10) AS user_hash,
       'IP-'  || substr(sha256($salt || '|IP|'  || ip), 1, 10) AS ip_hash,
       'NET-' || substr(sha256($salt || '|NET|' || regexp_extract(ip, '^(\\d+\\.\\d+\\.\\d+)\\.', 1)), 1, 10) AS subnet_hash,
       country, region, city, asn, browser, os, device_type, rtt_ms,
       login_successful, is_attack_ip, is_ato, is_non_account
FROM read_parquet($src, hive_partitioning = true)
WHERE month BETWEEN '2020-02' AND '2020-09' AND ts >= $start AND ts < $end
ORDER BY ts
"""

TABLES = ("logins", "decisions")


def _decisions() -> pd.DataFrame:
    with sqlite3.connect(path(load_config()["ops"]["sqlite_path"])) as c:
        d = pd.read_sql("""SELECT login_id, event_ts, user_id, country, score, action, reasons,
                                  model_version, latency_ms, fail_open FROM decisions""", c)
    d["event_ts"] = pd.to_datetime(d["event_ts"], format="ISO8601")
    d.insert(2, "user_hash", d.pop("user_id").map(privacy.user))
    d["fail_open"] = d["fail_open"].astype(bool)
    return d


def build() -> None:
    DB.parent.mkdir(parents=True, exist_ok=True)
    tmp = DB.with_suffix(".tmp.duckdb")
    tmp.unlink(missing_ok=True)
    src = (path(load_config()["data"]["logins_dir"]) / "**" / "*.parquet").as_posix()
    con = connect()
    con.execute(f"ATTACH '{tmp.as_posix()}' AS a")
    con.execute("USE a")
    con.execute(LOGINS, {"salt": privacy._salt(), "src": src, "start": START, "end": END})
    con.register("dec", _decisions())
    con.execute("CREATE TABLE decisions AS SELECT * FROM dec ORDER BY event_ts")
    counts = {t: con.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in TABLES}
    con.execute("USE memory")
    con.execute("DETACH a")
    con.close()
    DB.unlink(missing_ok=True)
    tmp.rename(DB)
    print(f"wrote {DB}: {counts}")


if __name__ == "__main__":
    build()
