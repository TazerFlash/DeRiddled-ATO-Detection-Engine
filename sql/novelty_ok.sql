-- Point-in-time counts of each account's earlier SUCCESSFUL logins per attribute value, so failed attempts cannot make an attacker's attributes look familiar.
WITH src AS (
    SELECT login_id, ts, user_id, login_successful,
           country, asn::VARCHAR AS asn, ip,
           regexp_extract(ip, '^(\d+\.\d+\.\d+)\.', 1) AS subnet24,
           concat_ws(' | ', browser, os, device_type)  AS device_key,
           concat_ws(' | ', browser, os)               AS ua
    FROM read_parquet('{source}', hive_partitioning = true)
    WHERE NOT is_non_account
)
SELECT
    login_id,
    COALESCE(SUM(login_successful::INT) OVER (PARTITION BY user_id ORDER BY ts
             RANGE BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW EXCLUDE GROUP), 0) AS user_n_ok,
    COALESCE(SUM(login_successful::INT) OVER (PARTITION BY user_id, country ORDER BY ts
             RANGE BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW EXCLUDE GROUP), 0) AS country_user_ok,
    COALESCE(SUM(login_successful::INT) OVER (PARTITION BY user_id, asn ORDER BY ts
             RANGE BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW EXCLUDE GROUP), 0) AS asn_user_ok,
    COALESCE(SUM(login_successful::INT) OVER (PARTITION BY user_id, ip ORDER BY ts
             RANGE BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW EXCLUDE GROUP), 0) AS ip_user_ok,
    COALESCE(SUM(login_successful::INT) OVER (PARTITION BY user_id, subnet24 ORDER BY ts
             RANGE BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW EXCLUDE GROUP), 0) AS subnet_user_ok,
    COALESCE(SUM(login_successful::INT) OVER (PARTITION BY user_id, device_key ORDER BY ts
             RANGE BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW EXCLUDE GROUP), 0) AS device_user_ok,
    COALESCE(SUM(login_successful::INT) OVER (PARTITION BY user_id, ua ORDER BY ts
             RANGE BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW EXCLUDE GROUP), 0) AS ua_user_ok
FROM src
