"""Convert the raw RBA CSV into cleaned month-partitioned Parquet and build the 10% user sample."""
import shutil
import sys
import time

from deriddled.config import connect, load_config, path

COLUMNS = {
    "index": "login_id",
    "Login Timestamp": "ts",
    "User ID": "user_id",
    "Round-Trip Time [ms]": "rtt_ms",
    "IP Address": "ip",
    "Country": "country",
    "Region": "region",
    "City": "city",
    "ASN": "asn",
    "User Agent String": "user_agent",
    "Browser Name and Version": "browser",
    "OS Name and Version": "os",
    "Device Type": "device_type",
    "Login Successful": "login_successful",
    "Is Attack IP": "is_attack_ip",
    "Is Account Takeover": "is_ato",
}

DASH_MEANS_NULL = {"region", "city"}


def select_list() -> str:
    parts = []
    for raw, clean in COLUMNS.items():
        col = f'"{raw}"'
        if clean in DASH_MEANS_NULL:
            expr = f"NULLIF({col}, '-')"
        elif clean == "rtt_ms":
            expr = f"CASE WHEN isnan({col}) THEN NULL ELSE {col} END"
        elif clean == "device_type":
            expr = f"NULLIF({col}, '')"
        else:
            expr = col
        parts.append(f"{expr} AS {clean}")
    return ",\n        ".join(parts)


def build_parquet() -> None:
    cfg = load_config()
    raw_csv = path(cfg["data"]["raw_csv"]).as_posix()
    out_dir = path(cfg["data"]["logins_dir"])
    rule = cfg["non_accounts"]["rule"]

    if out_dir.exists():
        shutil.rmtree(out_dir)

    con = connect()
    t0 = time.time()
    con.execute(f"""
        CREATE VIEW raw AS
        SELECT {select_list()}
        FROM read_csv('{raw_csv}', header = true, sample_size = 200000)
    """)
    con.execute(f"""
        COPY (
            WITH per_user AS (
                SELECT user_id,
                       COUNT(*) AS n_logins,
                       AVG(login_successful::INT) AS success_rate
                FROM raw
                GROUP BY user_id
            )
            SELECT r.*,
                   (u.n_logins > {int(rule['min_logins'])}
                    AND u.success_rate < {float(rule['max_success_rate'])}) AS is_non_account,
                   strftime(r.ts, '%Y-%m') AS month
            FROM raw r
            JOIN per_user u USING (user_id)
            ORDER BY r.ts, r.login_id
        )
        TO '{out_dir.as_posix()}'
        (FORMAT parquet, PARTITION_BY (month), COMPRESSION zstd)
    """)
    print(f"Parquet written to {out_dir} in {time.time() - t0:.0f}s")


def build_sample() -> None:
    cfg = load_config()
    src = path(cfg["data"]["logins_dir"]).as_posix()
    out_dir = path(cfg["data"]["sample_dir"])
    pct = round(cfg["data"]["sample_frac_users"] * 100)
    if out_dir.exists():
        shutil.rmtree(out_dir)

    con = connect()
    t0 = time.time()
    con.execute(f"""
        COPY (
            SELECT *
            FROM read_parquet('{src}/**/*.parquet', hive_partitioning = true)
            WHERE CASE WHEN is_non_account
                       THEN md5_number(login_id::VARCHAR) % 100 < {pct}
                       ELSE md5_number(user_id::VARCHAR)  % 100 < {pct}
                  END
            ORDER BY ts, login_id
        )
        TO '{out_dir.as_posix()}'
        (FORMAT parquet, PARTITION_BY (month), COMPRESSION zstd)
    """)
    print(f"Sample written to {out_dir} in {time.time() - t0:.0f}s")


if __name__ == "__main__":
    step = sys.argv[1] if len(sys.argv) > 1 else "all"
    if step in ("all", "parquet"):
        build_parquet()
    if step in ("all", "sample"):
        build_sample()
