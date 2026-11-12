# Analyst dashboard

Run: `.venv\Scripts\python.exe -m streamlit run dashboard/app.py` → http://localhost:8501. Code: `dashboard/app.py` (UI) and `deriddled/casework.py` (data access). It reads the SQLite decision log `data/ops/ops.db` written by the scoring API (currently the validation week 8–15 Sep 2020 replayed with champion `ato_xgb_mono`: 503,676 decisions, 172 CHALLENGE, 3 BLOCK; the earlier champion's log is kept in `data/ops/ops_ato_xgb_main_backup.db`), the login Parquet files for case details, and the MLflow registry. The API does not need to be running.

| View | Contents |
| --- | --- |
| Overview | logins scored, challenge / block counts, fail-opens, scoring p50 / p95, alerts per day, shadow-mode table |
| Alert queue | alerts sorted by probability, filter by label status and action; case view with the stored TreeSHAP reasons, login details, map of the user's earlier login countries (red = this login), last 20 logins; **Confirm takeover** / **False alarm** buttons write to the `labels` table |
| Feedback loop | label counts and measured alert precision; *fast path*: every alert re-scored as if the confirmed takeovers were already in the ASN / subnet / IP reputation counters; *slow path*: retrain trigger progress (9 new confirmed takeovers ≈ 10% more positives, or monthly, or an output-drift alarm) and the model registry |
| Monitoring | score and `lr_score` PSI by month with the 0.2 line; feature-by-month PSI heatmap |

The sidebar toggle "Show dataset label" reveals `is_ato` for evaluation; a real analyst would not see it.

Telemetry is off (`.streamlit/config.toml`, `gatherUsageStats = false`).

## Finding: reputation response was not monotonic (fixed)

The fast-path re-scoring exposed a model defect. Confirming the week's 3 real takeovers adds one takeover to the ASN counters of 9 other alerts, and **all 9 scores went down** (by 2–7%; one CHALLENGE fell to ALLOW). Probing one alert (ASN 41560) by varying only `asn_ato_prior`:

| asn_ato_prior | 0 | 1 | 2 | 3 | 4 | 5+ |
| --- | --- | --- | --- | --- | --- | --- |
| p(takeover) | 0.022 | 0.137 | 0.137 | 0.106 | 0.102 | 0.098 |

`asn_ato_rate` has no effect at all on this login. Why: with 86 training takeovers, networks with several earlier takeovers are mostly large ISPs with lots of legitimate traffic, so the trees learned "more past takeovers → slightly safer" above 1. That pattern is real in the training data but wrong as a policy: it means analyst feedback weakens the defence. Fix: retrain with XGBoost `monotone_constraints` (+1) on the reputation features, then re-check validation recall, cost and the thresholds.

**Status: fixed.** Champion D `ato_xgb_mono` constrains the six network / IP takeover-history features to be non-decreasing (`docs/monotonicity.md`). With D and the same three confirmations, 8 alerts share a network with them: 0 scores go down, and 0 go up either, because all 8 networks already had an earlier takeover and D's response is flat above one prior takeover. Confirmations now raise scores only on networks with no takeover history yet, and can never lower one.
