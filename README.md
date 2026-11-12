# De-Riddled

**Every impostor leaves a riddle in the logs.** De-Riddled scores every login attempt for account-takeover (ATO) risk and returns **ALLOW**, **CHALLENGE** (OTP) or **BLOCK** in under 200 ms, with the top 3 reasons behind each decision.

It is built on 33M real-world-derived logins from the public [RBA dataset](https://github.com/das-group/rba-dataset), compared honestly against rule and statistical baselines, and paired with a GenAI layer that briefs analysts and red-teams the model.

> **Status:** setup complete, Week 1 (data foundation and EDA) in progress. Target finish: 20 Dec 2026.

## The result

> At a 1% challenge rate, De-Riddled catches **X%** (95% CI a–b) of takeovers versus **Y%** for the rule baseline.

_Filled in after the final test-window evaluation._

## First facts

| Question | Answer |
| --- | --- |
| ATO rows / distinct users | _TBD_ |
| ATO ∩ attack IP | _TBD_ |
| Median logins per user | _TBD_ |

## Why

Static rules ("block after 5 failed attempts") annoy real users who travel or switch phones, and miss low-and-slow attacks and botnets on residential proxies. De-Riddled tests whether a learned, explainable risk score can do better on both at once: **catch more takeovers while challenging no more than 1% of legitimate logins.**

## How it works

```
Offline (DuckDB)                                   Online (FastAPI)
────────────────                                   ────────────────
RBA CSV → Parquet → features.sql ─┐                replay.py → POST /score
                                  ├→ baselines     state.py (online features,
                                  ├→ anomaly layer   held to features.sql by
                                  ├→ XGBoost         a parity test)
                                  └→ calibration      → score, action, top 3 reasons
                                     + cost-model         ↓
                                       thresholds    SQLite decision log
                                          │               ↓
                                          └─ MLflow ─→ Streamlit dashboard → analyst labels
                                             registry      (feed the monthly retrain)
```

The only bridge between the two halves is the promoted model plus its thresholds. The LLM never makes the ALLOW/CHALLENGE/BLOCK decision.

### The cast

| Codename | Component |
| --- | --- |
| The Tells | `features.sql`: velocity, novelty, geography, RTT, population and graph features |
| True Form | Per-user behavioural profile (home location, usual devices, normal RTT) |
| The Old Ways | Static rule baseline + Freeman et al. (2016) likelihood-ratio score |
| The Hunter | XGBoost + Isolation Forest anomaly layer |
| The Pack | IP–account graph features (credential stuffing) |
| The Unmasking | `POST /score`: score, action, top 3 reasons, model version |
| The Watchtower | Streamlit analyst dashboard |
| Silver Bullet | Monthly retrain from analyst labels |
| The Oracle | LLM case narrator + "Ask the Watchtower" analyst agent |
| The Mimic | LLM red-team simulator |

## Methodology principles

- **Point-in-time features only.** Every feature uses only data from before that login, enforced by a leakage test.
- **Time-based splits.** Train on the first ~70% of time, validate on the next ~15%, test once on the last ~15%.
- **Honest metrics.** The headline is recall at a fixed challenge rate, with bootstrap CIs resampled by user. PR-AUC and ROC-AUC are reported but never headlined.
- **Thresholds from a cost model**, not picked by hand: missed ATO × C_miss + challenge × C_otp + wrongly blocked user × C_block.
- **Baseline first.** Each layer is justified by an ablation table: rules → likelihood ratio → + anomaly → + graph → full model.

## Tech stack

| Layer | Choice |
| --- | --- |
| Environment | Python 3.11, `uv` |
| Storage | Parquet + DuckDB (offline), SQLite WAL (decisions, labels) |
| Modelling | scikit-learn, XGBoost, SHAP |
| Tracking | MLflow (SQLite backend) |
| Serving | FastAPI + Docker |
| Dashboard | Streamlit + pydeck |
| Monitoring | Hand-written PSI |
| GenAI | Hosted LLM with tool use + Pydantic structured output; Ollama comparison |

## Repo layout

```
config.yaml            split dates, thresholds, costs
sql/features.sql       all point-in-time features
notebooks/             01_eda … 05_shadow_mode
deriddled/
  baseline.py          rule + likelihood ratio
  train.py             XGBoost, calibration, MLflow
  evaluate.py          recall@rate, bootstrap CIs, cost curve
  state.py             per-user state + online features
  ops.py               SQLite decision log and labels
  drift.py             PSI
  api.py               FastAPI /score
replay/replay.py       time-ordered event stream
dashboard/app.py       Streamlit analyst view
tests/                 leakage and online/offline parity tests
data/                  junction to local storage (git-ignored)
```

## Setup

The repo lives in OneDrive, so the bulky local-only folders are directory junctions to paths outside it (OneDrive does not sync them):

- `data/` → `C:\Users\rohan\deriddled-data` (raw CSV, Parquet, GeoNames, DuckDB temp, `ops/` SQLite + MLflow stores)
- `.venv/` → `C:\Users\rohan\.venvs\de-riddled`

On a fresh clone, recreate them (PowerShell), adjusting the targets to your machine:

```powershell
New-Item -ItemType Junction -Path data -Target C:\Users\rohan\deriddled-data
New-Item -ItemType Junction -Path .venv -Target C:\Users\rohan\.venvs\de-riddled
```

Then install dependencies:

```bash
python -m pip install --user uv
python -m uv sync
```

Download `rba-dataset.zip` from [Zenodo](https://zenodo.org/record/6782156) and extract it to `data/raw/rba-dataset.csv`. Copy `.env.example` to `.env` and set `IP_HASH_SALT`.

## Roadmap

- [ ] Week 1: data foundation and EDA
- [ ] Week 2: point-in-time features in SQL, leakage test, rule baseline
- [ ] Week 3: likelihood-ratio baseline, XGBoost, calibration, cost model
- [ ] Week 4: anomaly layer, graph features, SHAP reason codes, ablations
- [ ] Week 5: FastAPI serving, parity test, replay, MLflow registry, drift
- [ ] Week 6: shadow-mode experiment, dashboard, write-up
- [ ] Week 7: GenAI layer (narrator, analyst agent, red-team simulator)

## Data and attribution

Login Data Set for Risk-Based Authentication, Wiefling et al., licensed [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). The data is simulated from real logins on a large Norwegian online service and is already pseudonymised; IP addresses are additionally salted-hashed in any artefact published from this repo.

## References

- Wiefling et al., [large-scale RBA analysis](https://www.riskbasedauthentication.org/analysis/largescale/)
- Freeman, Jain, Dürmuth, Biggio, Giacinto, "Who Are You? A Statistical Approach to Measuring User Authenticity", NDSS 2016
