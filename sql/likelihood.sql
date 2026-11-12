-- Point-in-time user, population and attack counts per (ip, asn, country, ua) value for the likelihood-ratio score.
WITH src AS (
    SELECT login_id, ts, user_id, is_non_account, is_attack_ip,
           ip, asn::VARCHAR AS asn, country, concat_ws(' | ', browser, os) AS ua
    FROM read_parquet('{source}', hive_partitioning = true)
),
long AS (
    SELECT login_id, ts, user_id, is_non_account, is_attack_ip, 'ip' AS feature, ip AS value FROM src
    UNION ALL
    SELECT login_id, ts, user_id, is_non_account, is_attack_ip, 'asn', asn FROM src
    UNION ALL
    SELECT login_id, ts, user_id, is_non_account, is_attack_ip, 'country', country FROM src
    UNION ALL
    SELECT login_id, ts, user_id, is_non_account, is_attack_ip, 'ua', ua FROM src
),
by_value AS (
    SELECT *,
           COUNT(*)                                OVER w_value AS pop_count,
           COALESCE(SUM(is_attack_ip::INT)         OVER w_value, 0) AS attack_count,
           ROW_NUMBER() OVER (PARTITION BY feature, value ORDER BY ts, login_id) = 1 AS first_of_value
    FROM long
    WINDOW w_value AS (PARTITION BY feature, value ORDER BY ts
                       RANGE BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW EXCLUDE GROUP)
),
by_feature AS (
    SELECT *,
           COUNT(*)                                OVER w_feature AS global_count,
           COALESCE(SUM(is_attack_ip::INT)         OVER w_feature, 0) AS global_attack,
           COALESCE(SUM(first_of_value::INT)       OVER w_feature, 0) AS vocab
    FROM by_value
    WINDOW w_feature AS (PARTITION BY feature ORDER BY ts
                         RANGE BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW EXCLUDE GROUP)
),
by_user AS (
    SELECT *,
           COUNT(*) OVER (PARTITION BY feature, user_id, value ORDER BY ts
                          RANGE BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW EXCLUDE GROUP) AS user_count,
           COUNT(*) OVER (PARTITION BY feature, user_id ORDER BY ts
                          RANGE BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW EXCLUDE GROUP) AS user_n
    FROM by_feature
    WHERE NOT is_non_account
)
SELECT
    login_id,
    ANY_VALUE(user_n)        AS user_n,
    ANY_VALUE(global_count)  AS global_n,
    ANY_VALUE(global_attack) AS global_attack,
    MAX(user_count)   FILTER (WHERE feature = 'ip')      AS ip_user,
    MAX(pop_count)    FILTER (WHERE feature = 'ip')      AS ip_pop,
    MAX(attack_count) FILTER (WHERE feature = 'ip')      AS ip_attack,
    MAX(vocab)        FILTER (WHERE feature = 'ip')      AS ip_vocab,
    MAX(user_count)   FILTER (WHERE feature = 'asn')     AS asn_user,
    MAX(pop_count)    FILTER (WHERE feature = 'asn')     AS asn_pop,
    MAX(attack_count) FILTER (WHERE feature = 'asn')     AS asn_attack,
    MAX(vocab)        FILTER (WHERE feature = 'asn')     AS asn_vocab,
    MAX(user_count)   FILTER (WHERE feature = 'country') AS country_user,
    MAX(pop_count)    FILTER (WHERE feature = 'country') AS country_pop,
    MAX(attack_count) FILTER (WHERE feature = 'country') AS country_attack,
    MAX(vocab)        FILTER (WHERE feature = 'country') AS country_vocab,
    MAX(user_count)   FILTER (WHERE feature = 'ua')      AS ua_user,
    MAX(pop_count)    FILTER (WHERE feature = 'ua')      AS ua_pop,
    MAX(attack_count) FILTER (WHERE feature = 'ua')      AS ua_attack,
    MAX(vocab)        FILTER (WHERE feature = 'ua')      AS ua_vocab
FROM by_user
GROUP BY login_id
