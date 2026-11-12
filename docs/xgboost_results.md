# XGBoost results (validation)

Code: `deriddled/train.py`, reputation features `sql/reputation.sql` + `deriddled/reputation.py` (tested by `tests/test_reputation.py`). Validation windows only (ATO: Aug–Sep 2020, 33 ATOs; attack IP: Nov–Dec 2020, 267,044 positives). Test windows untouched.

## Setup

- Training: ATO train window (86 ATOs) / attack-IP train window; 15% of negatives kept by hash of `login_id`, weighted 1/0.15.
- XGBoost: 300 trees, learning rate 0.05, `min_child_weight` 5, subsample / column sample 0.8, `hist`.
- Dropped non-stationary raw global counts (`global_prior_logins`, raw ASN/country/UA counts); kept frequencies and rates.
- `lr_score` = attack-informed likelihood ratio (β = 1) as a feature.
- Attack-IP target excludes `ip_prior_attack_ip` and the IP term of `lr_score`.
- Ranking by raw margin; recall at fixed challenge rates with random tie-breaking.

## ATO: model comparison

| Model | @ 0.5% | @ 1% | 95% CI @ 1% | @ 2% | Campaign @ 1% | Other @ 1% |
| --- | --- | --- | --- | --- | --- | --- |
| Static rule (k ≥ 5) | — | 0 / 33 | 0–10% | — | — | — |
| Likelihood ratio (attack-informed, β = 1) | 22 | 22 / 33 | 50–80% | 23 | 14 / 19 | 8 / 14 |
| Behaviour-only (depth 3, spw 1) | 30 | 30 / 33 | 76–97% | 30 | 19 / 19 | 11 / 14 |
| Identity: + raw country, ASN (depth 3, spw 20) | 33 | 33 / 33 | 90–100% | 33 | 19 / 19 | 14 / 14 |
| **Reputation: behaviour + delayed ATO reputation (depth 3, spw 1)** | 31 | **32 / 33** | 85–99% | 33 | 19 / 19 | 13 / 14 |
| Reputation (depth 3, spw 20) | 32 | 32 / 33 | 85–99% | 33 | 19 / 19 | 13 / 14 |
| Ensemble: rank average of behaviour + identity | 31 | 31 / 33 | 80–98% | 33 | 19 / 19 | 12 / 14 |

Behaviour grid (depth 3/6 × spw 1/20): 30–31 / 33 at 1%. Identity grid: 30–33 / 33.

**Chosen ATO model: reputation, depth 3, spw 1** (`data/models/ato_xgb_reputation.json`). It nearly matches identity without memorising network IDs, generalises to networks that turn bad after training, and gives analyst-readable reasons. All CIs overlap; with 33 positives the choice rests on robustness.

Top gain (reputation model): `asn_freq`, `lr_score`, `asn_ato_rate`, `asn_attack_rate`, `country_ato_rate`, `device_type`, `ua_freq`, `country_freq`.

## ATO: leakage ablation (behaviour model, depth 3, spw 1)

| Feature set | @ 1% | Campaign | Other | Median ATO rank | Worst ATO rank |
| --- | --- | --- | --- | --- | --- |
| All behaviour (34) | 30 / 33 | 19 / 19 | 11 / 14 | top 0.002% | top 6.0% |
| No label-derived features (31) | 30 / 33 | 19 / 19 | 11 / 14 | top 0.008% | top 7.8% |
| User behaviour only (19) | 23 / 33 | 15 / 19 | 8 / 14 | top 0.18% | top 51% |

Removing features built from earlier attack-IP labels changes nothing, so performance doesn't come from label leakage. Network context (rarity, users per network) adds 7 ATOs over user behaviour alone.

## Reputation features

For each login and each of ASN, country, IP and /24 subnet:

- `*_ato_prior`: ATOs on that key at least **7 days** before the login (`config.yaml: reputation.label_delay_days`), modelling the delay before a takeover is confirmed
- `*_ato_rate` = (k + m·p₀) / (n + m), an m-estimate with m = 1000, p₀ = 10⁻⁵, shrinking toward the overall ATO rate

Built with running totals per key plus an ASOF join (15 min on full data). A first version with `RANGE … INTERVAL 7 DAYS PRECEDING` frames was stopped after 31 min.

## Attack IP: the 1% metric is saturated

All 8 configurations caught exactly 26,931 attack-IP logins at a 1% challenge rate, with 100% precision. With a 9.9% base rate, the maximum possible recall at 1% is 1 / 9.9 ≈ 10.1%, and every model reaches it. The metric can't rank models; attack-IP needs precision and recall at challenge rates near its base rate (5–20%).

Top gain (behaviour model): `asn_attack_rate`, `subnet_logins_24h`, `ip_prior_fails`, `country_freq`, `subnet_users_24h`, `asn_fail_rate`.

## Attack IP: model comparison at higher challenge rates

| Model | @ 1% | @ 5% | @ 10% | @ 20% | Precision @ 10% |
| --- | --- | --- | --- | --- | --- |
| **Behaviour, depth 3, spw 1 (chosen)** | 10.1% | 46.9% | **75.2%** | 80.2% | 74.6% |
| Identity, depth 3, spw 1 | 10.1% | 46.8% | 76.2% | 80.3% | 75.6% |
| Other 6 configurations (depth 6 or spw 20) | 10.1% | — | 64.6–65.3% | — | — |

- Selected at a 10% challenge rate (near the 9.9% base rate). Deeper trees and class weighting lose ~10 points.
- Identity is 1 point better (statistically real with 267k positives), but behaviour is kept for consistency: raw ASN largely re-learns attacker-list networks that `asn_attack_rate` already tracks over time. Saved as `data/models/attack_ip_xgb.json`.
- Recall plateaus near 80%: ~20% of attack-IP logins look entirely normal (usual country, device and network for the user).

## ATO decision policy (calibration + cost model)

Code: `deriddled/decision.py`. Calibrators are evaluated by temporal cross-fitting (fit on August, test on September, and the reverse).

| Calibrator | Log loss | Σ p vs 33 ATOs |
| --- | --- | --- |
| Raw model | 0.000047 | 42.8 |
| **Sigmoid (chosen)** | 0.000047 | 41.2 |
| Isotonic | 0.000061 | 31.1 (overfits: 6 ATOs fell in a bin it set near zero) |

Top bin (p > 0.1): 22.5 expected vs 21 observed ATOs.

Costs: C_miss = 500, C_otp = 0.5, C_block = 20, OTP stops 90% of attackers (`otp_stop_rate`, an added assumption). Thresholds follow from minimising expected cost:

- CHALLENGE if p ≥ C_otp / (s·C_miss + C_otp) = **0.00111**
- BLOCK if p ≥ (C_block − C_otp) / ((1 − s)·C_miss + C_block − C_otp) = **0.281**

| Validation outcome | Value |
| --- | --- |
| Challenge rate | 0.067% |
| Block rate | 0.0012% |
| Legit block rate | 0.0006% (target < 0.1%) |
| ATO blocked / challenged / allowed | 15 / 14 / 4 (29 of 33 stopped) |
| Cost per 1,000 logins | **1.48** (allow all: 6.26; static rule: ~7.8) |

Sensitivity (each cost × 0.5 / × 2, OTP stop rate 0.8 / 0.95): ATO allowed stays at 4 in every scenario, and cost stays at 22–27% of allow-all; only the BLOCK / CHALLENGE split moves.

New users (< 3 prior logins): 44.8% of logins, 16 ATOs, 15 stopped. The model handles them directly, so FR-5's separate baseline-only path isn't needed.

Saved: `data/models/ato_xgb_reputation_calibration.json` (calibration curve, thresholds, costs).

## Caveats

- 33 validation ATOs: one ATO ≈ 3 points of recall; CIs of all XGBoost variants overlap.
- Model selection used validation, so validation recall is mildly optimistic; the test set is the unbiased check.
- Reputation assumes takeovers are confirmed within 7 days; longer real delays weaken it (to test with 14 / 30 days).
