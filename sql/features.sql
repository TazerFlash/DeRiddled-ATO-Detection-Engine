-- Point-in-time features (history = strictly earlier ts) for every real-account login.

WITH src AS (
    SELECT *,
           regexp_extract(ip, '^(\d+\.\d+\.\d+)\.', 1) AS subnet24,
           concat_ws(' | ', browser, os, device_type)  AS device_key,
           concat_ws(' | ', browser, os)               AS ua_key
    FROM read_parquet('{source}', hive_partitioning = true)
),

population AS (
    SELECT
        login_id,
        COUNT(*)                         OVER w_global      AS global_prior_logins,
        COUNT(*)                         OVER w_asn         AS asn_prior_logins,
        COALESCE(SUM(is_attack_ip::INT)           OVER w_asn, 0)         AS asn_prior_attack_ip,
        COALESCE(SUM((NOT login_successful)::INT) OVER w_asn, 0)         AS asn_prior_fails,
        COUNT(*)                         OVER w_country     AS country_prior_logins,
        COUNT(*)                         OVER w_ua          AS ua_prior_logins,
        COUNT(*)                         OVER w_ip          AS ip_prior_logins,
        COALESCE(SUM(is_attack_ip::INT)           OVER w_ip, 0)          AS ip_prior_attack_ip,
        COALESCE(SUM((NOT login_successful)::INT) OVER w_ip, 0)          AS ip_prior_fails,
        COUNT(*)                         OVER w_ip_24h      AS ip_logins_24h,
        COALESCE(SUM((NOT login_successful)::INT) OVER w_ip_24h, 0)      AS ip_fails_24h,
        COUNT(*)                         OVER w_subnet_24h  AS subnet_logins_24h
    FROM src
    WINDOW
        w_global     AS (ORDER BY ts RANGE BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW EXCLUDE GROUP),
        w_asn        AS (PARTITION BY asn ORDER BY ts RANGE BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW EXCLUDE GROUP),
        w_country    AS (PARTITION BY country ORDER BY ts RANGE BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW EXCLUDE GROUP),
        w_ua         AS (PARTITION BY ua_key ORDER BY ts RANGE BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW EXCLUDE GROUP),
        w_ip         AS (PARTITION BY ip ORDER BY ts RANGE BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW EXCLUDE GROUP),
        w_ip_24h     AS (PARTITION BY ip ORDER BY ts RANGE BETWEEN INTERVAL 24 HOURS PRECEDING AND CURRENT ROW EXCLUDE GROUP),
        w_subnet_24h AS (PARTITION BY subnet24 ORDER BY ts RANGE BETWEEN INTERVAL 24 HOURS PRECEDING AND CURRENT ROW EXCLUDE GROUP)
),

keyed AS (
    SELECT login_id, ts, user_id, 'ip' AS key_type, ip AS key FROM src
    UNION ALL
    SELECT login_id, ts, user_id, 'subnet', subnet24 FROM src
    UNION ALL
    SELECT login_id, ts, user_id, 'asn', asn::VARCHAR FROM src
),
span_ids AS (
    SELECT key_type, key, user_id, ts,
           SUM(CASE WHEN prev_ts IS NULL OR ts > prev_ts + INTERVAL 24 HOURS THEN 1 ELSE 0 END)
               OVER (PARTITION BY key_type, key, user_id ORDER BY ts ROWS UNBOUNDED PRECEDING) AS span_id
    FROM (
        SELECT key_type, key, user_id, ts,
               LAG(ts) OVER (PARTITION BY key_type, key, user_id ORDER BY ts) AS prev_ts
        FROM keyed
    )
),
spans AS (
    SELECT key_type, key, MIN(ts) AS start_ts, MAX(ts) + INTERVAL 24 HOURS AS end_ts
    FROM span_ids
    GROUP BY key_type, key, user_id, span_id
),
events AS (
    SELECT key_type, key, start_ts AS t, 1 AS ord, 1 AS delta, NULL::BIGINT AS login_id FROM spans
    UNION ALL
    SELECT key_type, key, end_ts, 1, -1, NULL FROM spans
    UNION ALL
    SELECT key_type, key, ts, 0, 0, login_id FROM keyed
),
distinct_users AS (
    SELECT login_id,
           MAX(users) FILTER (WHERE key_type = 'ip')     AS ip_users_24h,
           MAX(users) FILTER (WHERE key_type = 'subnet') AS subnet_users_24h,
           MAX(users) FILTER (WHERE key_type = 'asn')    AS asn_users_24h
    FROM (
        SELECT key_type, login_id,
               SUM(delta) OVER (PARTITION BY key_type, key ORDER BY t, ord ROWS UNBOUNDED PRECEDING) AS users
        FROM events
    )
    WHERE login_id IS NOT NULL
    GROUP BY login_id
),

accounts AS (
    SELECT * FROM src WHERE NOT is_non_account
),

per_user AS (
    SELECT
        login_id,
        COUNT(*)                                          OVER w_hist AS user_prior_logins,
        COALESCE(SUM(login_successful::INT)                        OVER w_hist, 0) AS user_prior_successes,
        epoch(ts - MAX(ts)                                OVER w_hist) AS secs_since_prev,
        epoch(ts - MAX(CASE WHEN login_successful THEN ts END) OVER w_hist) AS secs_since_prev_success,
        COUNT(*)                                          OVER w_1m   AS user_logins_1m,
        COUNT(*)                                          OVER w_1h   AS user_logins_1h,
        COALESCE(SUM((NOT login_successful)::INT)                  OVER w_1h, 0)   AS user_fails_1h,
        COUNT(*)                                          OVER w_24h  AS user_logins_24h,
        COALESCE(SUM((NOT login_successful)::INT)                  OVER w_24h, 0)  AS user_fails_24h,
        ts = MIN(ts) OVER (PARTITION BY user_id, country)    AS new_country,
        ts = MIN(ts) OVER (PARTITION BY user_id, asn)        AS new_asn,
        ts = MIN(ts) OVER (PARTITION BY user_id, device_key) AS new_device,
        ts = MIN(ts) OVER (PARTITION BY user_id, ip)         AS new_ip,
        ts = MIN(ts) OVER (PARTITION BY user_id, subnet24)   AS new_subnet24
    FROM accounts
    WINDOW
        w_hist AS (PARTITION BY user_id ORDER BY ts RANGE BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW EXCLUDE GROUP),
        w_1m   AS (PARTITION BY user_id ORDER BY ts RANGE BETWEEN INTERVAL 1 MINUTE PRECEDING AND CURRENT ROW EXCLUDE GROUP),
        w_1h   AS (PARTITION BY user_id ORDER BY ts RANGE BETWEEN INTERVAL 1 HOUR PRECEDING AND CURRENT ROW EXCLUDE GROUP),
        w_24h  AS (PARTITION BY user_id ORDER BY ts RANGE BETWEEN INTERVAL 24 HOURS PRECEDING AND CURRENT ROW EXCLUDE GROUP)
)

SELECT
    r.login_id, r.ts, r.user_id, r.month,
    r.is_ato, r.is_attack_ip, r.login_successful,

    r.country, r.asn, r.device_type,
    hour(r.ts)                    AS hour,
    isodow(r.ts)                  AS weekday,
    r.rtt_ms IS NOT NULL          AS rtt_present,

    u.user_prior_logins, u.user_prior_successes,
    u.secs_since_prev, u.secs_since_prev_success,
    u.user_logins_1m, u.user_logins_1h, u.user_fails_1h,
    u.user_logins_24h, u.user_fails_24h,
    u.user_fails_24h / NULLIF(u.user_logins_24h, 0) AS user_fail_ratio_24h,

    u.new_country, u.new_asn, u.new_device, u.new_ip, u.new_subnet24,

    p.global_prior_logins,
    p.asn_prior_logins,     p.asn_prior_logins     / NULLIF(p.global_prior_logins, 0) AS asn_freq,
    p.country_prior_logins, p.country_prior_logins / NULLIF(p.global_prior_logins, 0) AS country_freq,
    p.ua_prior_logins,      p.ua_prior_logins      / NULLIF(p.global_prior_logins, 0) AS ua_freq,
    p.asn_prior_attack_ip, (p.asn_prior_attack_ip + 1) / (p.asn_prior_logins + 2)     AS asn_attack_rate,
    p.asn_prior_fails,     (p.asn_prior_fails + 1)     / (p.asn_prior_logins + 2)     AS asn_fail_rate,
    p.ip_prior_logins, p.ip_prior_attack_ip, p.ip_prior_fails,
    p.ip_logins_24h, d.ip_users_24h, p.ip_fails_24h,
    p.subnet_logins_24h, d.subnet_users_24h,
    d.asn_users_24h
FROM accounts r
JOIN per_user       u USING (login_id)
JOIN population     p USING (login_id)
JOIN distinct_users d USING (login_id)
ORDER BY r.ts, r.login_id
