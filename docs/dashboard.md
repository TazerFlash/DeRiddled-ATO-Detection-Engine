# Analyst dashboard

Run: `.venv\Scripts\python.exe -m streamlit run dashboard/app.py` → http://localhost:8501. Code: `dashboard/app.py` (UI) and `deriddled/casework.py` (data access). It reads the SQLite decision log `data/ops/ops.db` written by the scoring API (currently the validation week 8–15 Sep 2020 replayed with champion E `ato_xgb_ok`: 503,676 decisions, 153 CHALLENGE, 3 BLOCK; earlier champions' logs are kept in `data/ops/ops_ato_xgb_mono_backup.db` (D) and `data/ops/ops_ato_xgb_main_backup.db` (C)), the login Parquet files for case details, and the MLflow registry. The API does not need to be running.

| View | Contents |
| --- | --- |
| Overview | logins scored, challenge / block counts, fail-opens, scoring p50 / p95, alerts per day, shadow-mode table |
| Alert queue | alerts sorted by probability, filter by label status and action; case view with the stored TreeSHAP reasons, login details, map of the user's earlier login countries (red = this login), last 20 logins; **Confirm takeover** / **False alarm** buttons write to the `labels` table |
| Feedback loop | label counts and measured alert precision; *fast path*: every alert re-scored as if the confirmed takeovers were already in the ASN / subnet / IP reputation counters; *slow path*: retrain trigger progress (9 new confirmed takeovers ≈ 10% more positives, or monthly, or an output-drift alarm) and the model registry |
| Monitoring | score and `lr_score` PSI by month with the 0.2 line; feature-by-month PSI heatmap |
| Ask the data | type a question or pick an example; the SQL analyst agent (Claude Haiku) answers with its result table, final SQL and every tool call, over a hashed read-only database (see `docs/analyst_agent.md`) |

The case view also has an **AI case summary**: cited claims and a suggested next step from the case narrator (see `docs/narrator.md`). Summaries are written on request (about $0.001 each) and cached per login, model version and prompt version.

The sidebar toggle "Show dataset label" reveals `is_ato` for evaluation; a real analyst would not see it.

Telemetry is off (`.streamlit/config.toml`, `gatherUsageStats = false`).

## Public demo

A hosted copy runs at https://tazerflash-deriddled.streamlit.app/ (Streamlit Community Cloud, entry point `demo/streamlit_app.py`). It downloads a hashed bundle from the Hugging Face dataset `TazerFlash/de-riddled-demo-data`, built by `python -m deriddled.demo_bundle all` and published with `python -m deriddled.demo_bundle publish`.

- **Data:** the same week's decisions and the 156 alerts with their features and account histories. Every account ID, IP and /24 range is a salted hash.
- **Demo mode** (`demo.enabled` in the bundle's config): a banner, hashed account labels, pre-written summaries for all 156 alerts, a registry table instead of MLflow, and 10 example questions with saved answers.
- **Live questions:** 3 per visitor and 100 per day in total, at most 300 characters each, and only when an `ANTHROPIC_API_KEY` secret is set.
- **Labels** visitors add are shared and reset when the app restarts.

## Finding: reputation response was not monotonic (fixed)

The fast-path re-scoring exposed a model defect. Confirming the week's 3 real takeovers adds one takeover to the ASN counters of 9 other alerts, and **all 9 scores went down** (by 2–7%; one CHALLENGE fell to ALLOW). Probing one alert (ASN 41560) by varying only `asn_ato_prior`:

| asn_ato_prior | 0 | 1 | 2 | 3 | 4 | 5+ |
| --- | --- | --- | --- | --- | --- | --- |
| p(takeover) | 0.022 | 0.137 | 0.137 | 0.106 | 0.102 | 0.098 |

`asn_ato_rate` has no effect at all on this login. Why: with 86 training takeovers, networks with several earlier takeovers are mostly large ISPs with lots of legitimate traffic, so the trees learned "more past takeovers → slightly safer" above 1. That pattern is real in the training data but wrong as a policy: it means analyst feedback weakens the defence. Fix: retrain with XGBoost `monotone_constraints` (+1) on the reputation features, then re-check validation recall, cost and the thresholds.

**Status: fixed.** Champion D `ato_xgb_mono` constrains the six network / IP takeover-history features to be non-decreasing (`docs/monotonicity.md`). With D and the same three confirmations, 8 alerts share a network with them: 0 scores go down, and 0 go up either, because all 8 networks already had an earlier takeover and D's response is flat above one prior takeover. Confirmations now raise scores only on networks with no takeover history yet, and can never lower one. The current champion E keeps the same constraints.
