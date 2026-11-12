-- Point-in-time ATO reputation per ASN / country / IP / subnet, counting only ATOs confirmed at least {delay_days} days earlier.
WITH src AS (
    SELECT login_id, ts, is_non_account, is_ato, asn::VARCHAR AS asn, country, ip,
           regexp_extract(ip, '^(\d+\.\d+\.\d+)\.', 1) AS subnet24
    FROM read_parquet('{source}', hive_partitioning = true)
),
keyed AS (
    SELECT login_id, ts, is_non_account, is_ato, 'asn' AS key_type, asn AS key FROM src
    UNION ALL
    SELECT login_id, ts, is_non_account, is_ato, 'country', country FROM src
    UNION ALL
    SELECT login_id, ts, is_non_account, is_ato, 'ip', ip FROM src
    UNION ALL
    SELECT login_id, ts, is_non_account, is_ato, 'subnet', subnet24 FROM src
),
snapshots AS (
    SELECT key_type, key, ts, MAX(cum_logins) AS cum_logins, MAX(cum_ato) AS cum_ato
    FROM (
        SELECT key_type, key, ts,
               COUNT(*)          OVER w AS cum_logins,
               SUM(is_ato::INT)  OVER w AS cum_ato
        FROM keyed
        WINDOW w AS (PARTITION BY key_type, key ORDER BY ts, login_id ROWS UNBOUNDED PRECEDING)
    )
    GROUP BY key_type, key, ts
),
queries AS (
    SELECT login_id, key_type, key, ts - INTERVAL {delay_days} DAYS AS as_of
    FROM keyed
    WHERE NOT is_non_account
),
delayed AS (
    SELECT q.login_id, q.key_type,
           COALESCE(s.cum_logins, 0) AS n,
           COALESCE(s.cum_ato, 0)    AS k
    FROM queries q
    ASOF LEFT JOIN snapshots s
      ON q.key_type = s.key_type AND q.key = s.key AND q.as_of >= s.ts
)
SELECT login_id,
       MAX(k) FILTER (WHERE key_type = 'asn')                                          AS asn_ato_prior,
       MAX((k + {m} * {p0}) / (n + {m})) FILTER (WHERE key_type = 'asn')              AS asn_ato_rate,
       MAX(k) FILTER (WHERE key_type = 'country')                                      AS country_ato_prior,
       MAX((k + {m} * {p0}) / (n + {m})) FILTER (WHERE key_type = 'country')          AS country_ato_rate,
       MAX(k) FILTER (WHERE key_type = 'ip')                                           AS ip_ato_prior,
       MAX((k + {m} * {p0}) / (n + {m})) FILTER (WHERE key_type = 'ip')               AS ip_ato_rate,
       MAX(k) FILTER (WHERE key_type = 'subnet')                                       AS subnet_ato_prior,
       MAX((k + {m} * {p0}) / (n + {m})) FILTER (WHERE key_type = 'subnet')           AS subnet_ato_rate
FROM delayed
GROUP BY login_id
