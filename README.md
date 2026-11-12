# De-Riddled: ATO Detection Engine

**Every impostor leaves a riddle in the logs.** De-Riddled scores every login attempt for account-takeover (ATO) risk and returns **ALLOW**, **CHALLENGE** (OTP) or **BLOCK** in under 200 ms, with the top 3 reasons behind each decision.

**[Live dashboard demo](https://tazerflash-deriddled.streamlit.app/)** · **[Project page](https://tazerflash.github.io/DeRiddled-ATO-Detection-Engine/)**

It is built on 31M real-world-derived logins from the public [RBA dataset](https://github.com/das-group/rba-dataset), compared honestly against rule and statistical baselines, served by a real-time API, and paired with a GenAI layer that briefs analysts, answers their questions and red-teams the model.

## The result

> At a 1% challenge rate, De-Riddled catches **X%** (95% CI a–b) of takeovers versus **Y%** for the rule baseline.

_Filled in after the final test-window evaluation (Oct–Nov 2020, 22 takeovers). The test window has not been touched; every number below is from validation._

### Validation (Aug–Sep 2020, 2.63M logins, 33 takeovers)

Shadow mode: every policy decides every validation login, so the comparison is paired.

| Policy | Legit logins challenged | Takeovers stopped | Expected cost per 1,000 logins |
| --- | --- | --- | --- |
| Allow everything | 0 | 0 / 33 | 6.26 |
| Rule: challenge after 5 failed passwords in an hour | 0.30% | 0 / 33 | 7.77 |
| Likelihood ratio (Freeman et al.), same challenge budget | 0.052% | 15 / 33 | 3.96 |
| **De-Riddled** | **0.051%** | **28 / 33** | **1.66** |

- At equal friction, De-Riddled stops **39 points more takeovers** than the best non-ML baseline (95% day-block bootstrap CI 18–59; exact McNemar p = 0.001: 14 takeovers stopped only by the model, 1 only by the baseline). It challenges 6× fewer legitimate users than the rule.
- The rule stops nothing because these attackers enter the correct password on the first try.
- Ranked by risk, all 33 validation takeovers fall in the riskiest 1% of logins.
- Serving: a full week (503,676 logins) replayed through the API at 349 logins/s, p95 5.3 ms end to end (2.3 ms scoring), 0 fail-opens, decisions identical to the offline policy on all 307,562 real-account logins.
- The model and thresholds were chosen on this window, so these numbers are optimistic until the test window confirms them.

### What each layer adds

Each feature family was added one at a time to the same XGBoost model. Takeovers caught when challenging the riskiest 1% of validation logins:

| Step | All takeovers | Outside the Romanian campaign |
| --- | --- | --- |
| Static rule | 0 / 33 | 0 / 14 |
| Likelihood ratio alone | 22 / 33 | 8 / 14 |
| User behaviour (19 features) | 23 / 33 | 9 / 14 |
| + population frequencies | 30 / 33 | 11 / 14 |
| + IP–account graph | 30 / 33 | 11 / 14 |
| + likelihood score as a feature | 30 / 33 | 11 / 14 |
| + Isolation Forest anomaly score | 30 / 33 | 11 / 14 |
| + delayed network / IP takeover reputation | 32 / 33 | 13 / 14 |
| **Final model** (no country features, monotone reputation) | **33 / 33** | **14 / 14** |

Population frequencies and delayed reputation do the work. The graph features help a different target, credential-stuffing IPs (+29 points), but not takeovers; the anomaly score adds nothing and is not used.

### Fixes found along the way

| Finding | Fix | Effect |
| --- | --- | --- |
| Genuine Romanian users were challenged at 131× the average rate, because "takeovers from this country so far" made every Romanian a suspect | Dropped the country-reputation features | Genuine Romanian friction 4.0% → 1.0%, every takeover still in the top 1% |
| Confirming a takeover in the dashboard *lowered* other scores on the same network: the learned response to network takeover history was not monotonic | XGBoost monotone constraints on the six takeover-history features | Score can never fall as history rises; better on all three seeds |
| Training rows loaded in a different order each run, so "retraining noise" was really nondeterminism | Ordered the loader | Same seed is now bit-identical |
| Online and offline features disagreed on float timestamps | Integer-microsecond timestamps | Parity test: streamed features identical to SQL on ~382,000 values |
| Reputation must not use labels before they would be known | Only takeovers confirmed at least 7 days earlier count | Delay of 1 / 7 / 14 / 30 days: 29 / 28 / 28 / 27 stopped, robust |

### Red team: a blind spot found and fixed

An LLM wrote 5 attack campaigns as simulator parameters; a deterministic generator turned them into synthetic logins on real victim accounts (30 per campaign per day), injected among two real validation days and scored by the same online code the API runs.

The previous champion stopped **2 of 300** synthetic takeovers. The cause: "new country / network / device for this account" counted *every* earlier attempt, so an attacker's own failed password guesses made their location look familiar by the time the takeover succeeded. The real takeovers in the data almost never fail first, so historical data could not show this.

The fix measures novelty and the likelihood score against the account's **successful** logins only. Takeovers stopped, out of 300 per seed:

| Campaign | Before | After |
| --- | --- | --- |
| Noisy credential stuffing from attack-listed networks | 0 / 3 | 35 / 51 |
| Rented servers abroad at night | 2 / 9 | 43 / 47 |
| Residential proxies abroad, one failure, hours apart | 0 / 0 | 0 / 2 |
| Residential proxies in the victim's country | 0 / 0 | 0 / 0 |
| Victim's own ISP and device, copied | 0 / 0 | 0 / 0 |
| **Total (seed 0 / seed 1)** | **2 / 12** | **78 / 100** |

The cost: on the real validation takeovers it stops 28 instead of 31 (mean over 3 seeds 28.7 vs 30.3), and expected cost rises from 1.16 to 1.66 per 1,000 logins, at the same friction. The fixed model was adopted because the old one could be beaten by any attacker who fails once. Attackers that copy the victim's country, network and device remain undetectable from login metadata alone; that needs other signals such as MFA or behavioural biometrics.

### GenAI layer

The LLM never makes the ALLOW / CHALLENGE / BLOCK decision. It explains, answers and attacks; the calibrated model decides.

| Component | Result |
| --- | --- |
| Case narrator (Claude Haiku 5.5) | Turns each alert's evidence into 4–6 cited claims and a suggested next step; about $1 per 1,000 alerts, median 6 s. A code check drops any claim whose numbers aren't in the evidence it cites (2.8% of claims). Prompt v5 on 56 held-out alerts, AI-judged: **93.4% strict / 100% lenient faithfulness, 0 unsupported claims**, 48 / 56 recommendations reasonable (prompt v3: 79.1% / 95.6%). Human spot-check pending. |
| "Ask the Watchtower" SQL agent (Claude Haiku 5.5) | 27 / 30 before tuning; after one interface fix 30 / 30 on the tuned set and 9–10 / 10 on held-out questions; scored by comparing result tables, not SQL; $0.77 per 1,000 questions, median 3.5 s |
| Red-team writer (Claude Sonnet 5.5) | 5 campaigns for $0.02 |

- **Privacy:** account IDs and IPs are salted-hashed before anything reaches a hosted LLM.
- **Agent guards:** a separate database holding only hashed identifiers, a read-only connection with file access disabled, a single-SELECT check, a 30 s timeout and a 200-row cap.
- **Narrator evaluation:** prompt versions are compared on the same alerts with blinded AI judges and a paired case bootstrap; the improvement from v3 to v4 was +9.6 points strict (CI 6.3–12.8). Later versions are scored on alerts no prompt was tuned on.

## First facts

| Question | Answer |
| --- | --- |
| ATO rows / distinct users | 141 rows / 138 users (of 31,269,264 logins, 4,304,857 users) |
| ATO ∩ attack IP | 77 of 141 (55%); attack-IP rows overall: 3,096,977 (9.9%) |
| Median logins per user | 2 (p90: 9; 39.7% of users log in once) |
| Largest campaign | 79 of 141 takeovers come from one Romanian campaign, so recall is also reported outside it |

## Why

Static rules ("block after 5 failed attempts") annoy real users who travel or switch phones, and miss low-and-slow attacks and botnets on residential proxies. De-Riddled tests whether a learned, explainable risk score can do better on both at once: **catch more takeovers while challenging no more than 1% of legitimate logins.**

## How it works

```
Offline (DuckDB)                                   Online (FastAPI)
────────────────                                   ────────────────
RBA CSV → Parquet → features.sql ─┐                replay.py → POST /score
                                  ├→ baselines     state.py (online features,
                                  ├→ reputation      held to the SQL by
                                  ├→ XGBoost         a parity test)
                                  └→ calibration      → score, action, top 3 reasons
                                     + cost-model         ↓
                                       thresholds    SQLite decision log
                                          │               ↓
                                          └─ MLflow ─→ Streamlit dashboard → analyst labels
                                             registry      ↑         (feed the retrain)
                                                    LLM narrator + SQL agent
```

The only bridge between the two halves is the promoted model plus its thresholds.

### The cast

| Codename | Component |
| --- | --- |
| The Tells | Point-in-time SQL features: velocity, novelty, population, IP and subnet activity, reputation |
| True Form | Per-user history: novelty against the account's own successful logins |
| The Old Ways | Static rule baseline + Freeman et al. (2016) likelihood-ratio score |
| The Hunter | Calibrated XGBoost with monotone reputation features |
| The Pack | IP–account graph features (credential stuffing) |
| The Unmasking | `POST /score`: score, action, top 3 reasons, model version |
| The Watchtower | Streamlit analyst dashboard |
| Silver Bullet | Retrain from analyst labels |
| The Oracle | LLM case narrator + "Ask the Watchtower" analyst agent |
| The Mimic | LLM red-team simulator |

### Models and decisions

- **Takeover model:** XGBoost on 39 point-in-time features, sigmoid-calibrated, monotone constraints on the takeover-history features, novelty measured against successful logins. Champion `ato_xgb_ok` in the MLflow registry; earlier champions are kept for rollback.
- **Credential-stuffing (attack-IP) model:** a separate XGBoost on behaviour and graph features, 73% of attack-IP logins in the riskiest 10%.
- **Thresholds from a cost model**, not picked by hand: missed takeover 500, OTP challenge 0.5, wrongly blocked user 20, with OTP stopping 90% of attackers. CHALLENGE at p ≥ 0.00111, BLOCK at p ≥ 0.28.
- **Reasons:** the top 3 per-feature contributions (TreeSHAP), turned into plain sentences such as "No earlier successful login from RO for this user".
- **Fail-open:** if scoring takes longer than 200 ms the login is allowed and the event is logged.

### Model registry (MLflow)

Every candidate is logged with its parameters, validation metrics, feature list and calibration, and registered under `deriddled-ato` or `deriddled-attack-ip`. The `champion` alias marks the model the API serves; rollback means moving the alias back.

| Version | Model | What changed | Takeovers stopped (of 33) | In riskiest 1% | Legit challenged | Cost per 1,000 | Registered |
| --- | --- | --- | --- | --- | --- | --- | --- |
| v1 | `ato_xgb_reputation` (A) | Behaviour + network / IP / country reputation | 29 | 32 | 0.067% | 1.48 | 9 Nov |
| v2 | `ato_xgb_main` (C) | Country features removed (bias fix) | 28 | 33 | 0.051% | 1.70 | 9 Nov |
| v3 | `ato_xgb_mono` (D) | C + monotone takeover-history features | 31 | 33 | 0.052% | 1.16 | 10 Nov |
| **v4** | **`ato_xgb_ok` (E), champion** | D + novelty measured against successful logins (red-team fix) | **28** | **33** | **0.051%** | **1.66** | 10 Nov |
| v5 | `ato_xgb_reputation` (A) | Re-log of v1 | 29 | 32 | 0.067% | 1.48 | 12 Nov |
| v6 | `ato_xgb_main` (C) | Re-log of v2 | 28 | 33 | 0.051% | 1.70 | 12 Nov |
| v7 | `ato_xgb_mono` (D) | Re-log of v3 | 31 | 33 | 0.052% | 1.16 | 12 Nov |

`deriddled-attack-ip` has one version, v1 (`attack_ip_xgb`, champion): 73% of credential-stuffing logins in the riskiest 10% of validation logins, at 73% precision.

**About v5–v7.** They were created on 12 Nov by an accidental run of `python -m deriddled.registry` with no arguments, which re-logs every candidate. The run was stopped before it reached E or moved the champion alias, so v4 is still the champion. Their validation metrics match v1–v3 exactly, which confirms that the saved models and the evaluation are reproducible. They are kept, not deleted. To log a single new model without duplicates, use `python -m deriddled.registry add <model_name>`.

Browse the registry with:

```bash
python -m mlflow ui --backend-store-uri sqlite:///data/ops/mlflow.db
```

### Dashboard

A [public demo](https://tazerflash-deriddled.streamlit.app/) runs on Streamlit Community Cloud from `demo/streamlit_app.py`. On start it downloads a hashed data bundle from the [`TazerFlash/de-riddled-demo-data`](https://huggingface.co/datasets/TazerFlash/de-riddled-demo-data) dataset on Hugging Face: the replayed week's decisions, the 156 alerts and their account histories, with every account ID, IP and IP range salted-hashed. Case summaries are pre-written, 10 example questions have saved answers, and visitors can ask 3 questions of their own per visit (100 per day in total). Rebuild and republish the bundle with `python -m deriddled.demo_bundle all` and `python -m deriddled.demo_bundle publish`.


| Page | What it shows |
| --- | --- |
| Overview | Logins scored, challenge and block rates, latency, alerts per day, shadow-mode table |
| Alert queue | Each alert with its reasons, login details, a map of where the account logged in before, account history, confirm / false-alarm buttons, and an AI case summary on request |
| Feedback loop | How confirmed takeovers raise network reputation straight away, and progress towards the retrain trigger |
| Monitoring | Population stability index of the model output and features by month |
| Ask the data | Type a question; the SQL agent answers with its result table, SQL and every tool call |

## Methodology principles

- **Point-in-time features only.** Every feature uses only data from before that login, enforced by a leakage test.
- **Time-based splits.** Train Feb–Jul 2020, validate Aug–Sep, test once on Oct–Nov. Takeover labels stop in late November, so later months are unlabelled, not negative.
- **Delayed labels.** Reputation features only count takeovers confirmed at least 7 days earlier.
- **Honest metrics.** The headline is recall at a fixed challenge rate, with bootstrap confidence intervals. PR-AUC and ROC-AUC are reported but never headlined.
- **Baseline first.** Each layer is justified by an ablation.
- **Online = offline.** The streaming features and the API's decisions are tested to be identical to the offline ones.
- **LLM features are evaluated like models.** Fixed eval sets, held-out sets after tuning, blinded comparisons, intervals, and cost per unit measured from logged tokens.

## Tech stack

| Layer | Choice |
| --- | --- |
| Environment | Python 3.11, `uv` |
| Storage | Parquet + DuckDB (offline), SQLite WAL (decisions, labels) |
| Modelling | scikit-learn, XGBoost, SHAP, NetworkX |
| Tracking | MLflow (SQLite backend), champion alias |
| Serving | FastAPI + Uvicorn, Docker |
| Dashboard | Streamlit + Plotly |
| Monitoring | Hand-written PSI |
| GenAI | Claude (Haiku 5.5, Sonnet 5.5) via the Anthropic SDK; Gemini as an optional free-tier backend; tool use, JSON-schema structured output validated with Pydantic |
| Testing | pytest (45 tests) |

## Repo layout

```
config.yaml            split dates, costs, model names, storage paths
pyproject.toml, uv.lock
sql/                   point-in-time features, likelihood counts, reputation, success-only history
deriddled/
  ingest.py            CSV → monthly Parquet + sample
  splits.py            time-based split windows
  features.py          builds the feature tables from sql/features.sql
  baseline.py          static rule baseline
  likelihood.py        Freeman et al. likelihood-ratio baseline
  reputation.py        delayed-label network / IP takeover reputation
  novelty_ok.py        novelty and likelihood against successful logins only
  graph.py             IP–account graph features and cluster plots
  anomaly.py           Isolation Forest experiment
  train.py             XGBoost training and feature sets
  monotone.py          monotone-constraint check and retrain
  decision.py          calibration and cost-model thresholds
  evaluate.py          recall at a challenge rate, bootstrap and Wilson CIs
  ablation.py          feature-family ablation
  explain.py           TreeSHAP reason codes
  errors.py            error analysis of misses and false blocks
  country_bias.py      country-feature bias test
  delay_test.py        label-delay sensitivity
  shadow.py            shadow mode: McNemar, bootstrap CIs, power
  state.py             per-user state and online features
  parity.py            online vs offline feature parity
  api.py               FastAPI /score, /label, /alerts, /warm_start, /health
  ops.py               SQLite decision log and labels (background writer)
  registry.py          MLflow tracking and registry
  drift.py             PSI and challenge-rate monitoring
  casework.py          dashboard data access
  privacy.py           salted hashing before anything reaches a hosted LLM
  narrator.py          LLM case narrator with citation-based grounding check
  label_sheet.py       faithfulness labelling sheet, scoring and judge agreement
  analyst_db.py        hashed analyst database
  analyst.py           "Ask the Watchtower" agent with guarded SQL tools
  analyst_eval.py      execution-accuracy eval (dev and held-out sets)
  redteam.py           LLM-written attack scenarios, generator, recall per scenario
  harden.py            red-team fix: train, compare and calibrate
  writeup_figures.py   figures for the write-up
  demo_bundle.py       hashed demo bundle: build, record example answers, publish to Hugging Face
replay/replay.py       time-ordered event stream into the API
dashboard/app.py       Streamlit analyst dashboard
demo/                  Streamlit Community Cloud entry point and requirements for the live demo
notebooks/01_eda.ipynb exploratory analysis
docs/                  results write-ups, figures, portfolio write-up and walkthrough
eval/                  analyst questions, red-team scenarios, narrator labelling sheets
tests/                 leakage, likelihood, reputation, parity, API, narrator, analyst and red-team tests
work logs/             a detailed log for each week of the build
Dockerfile, docker-compose.yml
data/                  local storage (git-ignored)
```

## Setup

`data/` (raw CSV, Parquet, feature tables, models, `ops/` SQLite and MLflow stores) and `.venv/` are git-ignored. If the repo sits in a synced folder such as OneDrive or Dropbox, make them directory junctions or symlinks to a local folder outside it so they are not synced:

```powershell
New-Item -ItemType Junction -Path data -Target <local-data-folder>
New-Item -ItemType Junction -Path .venv -Target <local-venv-folder>
```

Install dependencies:

```bash
python -m pip install --user uv
python -m uv sync
```

Download `rba-dataset.zip` from [Zenodo](https://zenodo.org/record/6782156) and extract it to `data/raw/rba-dataset.csv`. Copy `.env.example` to `.env` and set `IP_HASH_SALT` to a random string. The GenAI layer also needs `ANTHROPIC_API_KEY` (and `GEMINI_API_KEY` for the optional Gemini backend).

## How to run

Commands run from the repo root with the project's virtual environment (`.venv/Scripts/python.exe` on Windows, `.venv/bin/python` elsewhere). Times are for a 4-core laptop.

**1. Data and features**

```bash
python -m deriddled.ingest
python -m deriddled.features full          # ~75 min
python -m deriddled.likelihood build full  # ~22 min
python -m deriddled.reputation full
python -m deriddled.novelty_ok full        # ~2 min
```

**2. Baselines, model and thresholds**

```bash
python -m deriddled.baseline valid
python -m deriddled.likelihood evaluate full
python -m deriddled.harden                 # trains and calibrates the champion, ~10 min
python -m deriddled.decision
python -m deriddled.registry add ato_xgb_ok
python -m deriddled.shadow valid
```

**3. Serve and replay** (API in its own terminal)

```bash
python -m uvicorn deriddled.api:app --host 127.0.0.1 --port 8000
python -m replay.replay --start 2020-09-08T00:00:00 --hours 168
```

**4. Dashboard**

```bash
python -m streamlit run dashboard/app.py
```

**5. GenAI layer** (calls a hosted API; about $0.001 per case or question)

```bash
python -m deriddled.narrator run --provider claude --model claude-haiku-5-5 --limit 100
python -m deriddled.analyst_db
python -m deriddled.analyst "Which ASNs touched more than 50 accounts yesterday?"
python -m deriddled.analyst_eval --set holdout
python -m deriddled.redteam run --seed 0 --policies ato_xgb_ok
```

**Tests**

```bash
python -m pytest -q
```

## Project status

| Stage | Status |
| --- | --- |
| Data foundation and EDA | Done |
| Point-in-time features and leakage test | Done |
| Baselines and first model | Done |
| Anomaly layer, graph features, explanations, error analysis | Done |
| Serving, parity, replay, MLflow registry, drift monitoring | Done |
| Shadow mode, dashboard, write-up | Done |
| GenAI layer: narrator, SQL agent, red team, dashboard panels | Done |
| Human spot-check of the narrator's AI-judged faithfulness | In progress |
| Agent on a local model vs hosted | Not started |
| Docker images tested end to end | Not started (files written) |
| Final test-window evaluation and headline result | Not started, by design: run once, last |
| Stretch: login-sequence transformer | Not started |

## Limits

- **Few positives.** 86 training and 33 validation takeovers; one Romanian campaign accounts for most of them, so intervals are wide and recall outside the campaign is reported separately.
- **Simulated data.** The RBA dataset is synthesised from real logins; there are no cookies, device fingerprints, session behaviour or MFA outcomes.
- **Undetectable attackers.** An attacker who copies the victim's country, ISP and device leaves no trace in login metadata.
- **Validation was used for choices.** Until the test window is run, all numbers are optimistic.
- **AI-judged faithfulness.** The narrator's scores come from LLM judges; a human spot-check is needed before they can be trusted.

## Data and attribution

Login Data Set for Risk-Based Authentication, Wiefling et al., licensed [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). The data is simulated from real logins on a large Norwegian online service and is already pseudonymised; account IDs and IP addresses are additionally salted-hashed in anything sent to a hosted LLM or published from this repo.

## References

- Wiefling et al., [large-scale RBA analysis](https://www.riskbasedauthentication.org/analysis/largescale/)
- Freeman, Jain, Dürmuth, Biggio, Giacinto, "Who Are You? A Statistical Approach to Measuring User Authenticity", NDSS 2016
