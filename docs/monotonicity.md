# Monotone takeover-history features (champion D)

Code: `deriddled/monotone.py` (`python -m deriddled.monotone`), `train.fit(..., monotone=TAKEOVER_HISTORY)`. Results in `data/ops/monotone_comparison.json`.

## Problem

Found through the dashboard's feedback loop (`docs/dashboard.md`): confirming takeovers on a network *lowered* the scores of other alerts on that network. In the previous champion `ato_xgb_main` (C), raising one login's `asn_ato_prior` while holding everything else fixed gave:

| asn_ato_prior | 0 | 1 | 2 | 3 | 4 | 5+ |
| --- | --- | --- | --- | --- | --- | --- |
| p(takeover), model C | 0.022 | 0.137 | 0.137 | 0.106 | 0.102 | 0.098 |

With only 86 training takeovers, networks with several earlier takeovers are mostly large ISPs with lots of legitimate traffic, so the trees learned "more past takeovers → slightly safer" above 1. That is wrong as a policy: analyst feedback would weaken the defence, and an attacker would benefit from a network's bad history.

## Fix

XGBoost `monotone_constraints` = +1 on the six network and IP takeover-history features:
- `asn_ato_prior`, `asn_ato_rate`
- `subnet_ato_prior`, `subnet_ato_rate`
- `ip_ato_prior`, `ip_ato_rate`

How it works: a split on a constrained feature is only accepted if the higher-value branch predicts at least as high as the lower one, and the bounds are passed down the tree. The score is therefore guaranteed never to fall when one of these features rises. Behavioural features stay unconstrained because they have no safe direction.

## A reproducibility bug found on the way

Refitting model C with the same seed did not reproduce it: margins differed by up to 1.95.
- **Cause:** `train.load` had no `ORDER BY`, so DuckDB's parallel scan returned rows in a different order on each run. With `subsample = 0.8`, XGBoost samples rows by position, so a new order produced a different model.
- **Check:** same seed and same order → max difference 0.0; same seed with shuffled rows → 1.64.
- **Fix:** `ORDER BY f.login_id` in `train.load`. Training is now bit-for-bit reproducible.
- **What it explains:** the "retraining noise" seen in Week 4 (A 29 vs C 28 stopped) was this row-order effect, not seed variation.

## Comparison (ordered data, 3 seeds each, validation)

| Variant | Seed | Caught @ 1% | Stopped (policy) | Challenge rate | Cost per 1,000 |
| --- | --- | --- | --- | --- | --- |
| unconstrained | 0 | 33 | 30 | 0.0552% | 1.34 |
| unconstrained | 1 | 33 | 28 | 0.0561% | 1.67 |
| unconstrained | 2 | 33 | 30 | 0.0566% | 1.36 |
| **monotone** | 0 | 33 | **31** | 0.0522% | **1.16** |
| **monotone** | 1 | 33 | **29** | 0.0543% | **1.46** |
| **monotone** | 2 | 33 | **31** | 0.0553% | **1.13** |

The constraint is better on every seed: one more takeover stopped, lower challenge rate, mean cost 1.25 vs 1.46. Removing the spurious "big ISP" pattern acted as regularisation.

Monotonicity check: each constrained feature was swept over its training quantiles for the 33 validation ATOs plus 3,000 random logins, counting rows whose score drops at any step.

| Feature | Unconstrained: rows with a drop (max margin drop) | Monotone |
| --- | --- | --- |
| asn_ato_prior | 100% (0.35) | 0% |
| asn_ato_rate | 100% (0.10) | 0% |
| subnet_ato_prior | 34% (0.31) | 0% |
| subnet_ato_rate | 100% (0.25) | 0% |
| ip_ato_prior / ip_ato_rate | 0% | 0% |

Probe login 15686673, margin as `asn_ato_prior` goes 0 → 9:
- **Unconstrained:** −3.96, −1.98, −2.05, −2.27, −2.27, −2.62, … It falls after 1.
- **Monotone:** −3.50, −1.92, then flat. It never falls.

## Adoption

The seed-0 monotone model was saved as `ato_xgb_mono`. Adoption steps:
- `config.yaml` now has `models.ato: ato_xgb_mono`.
- Recalibrated with `python -m deriddled.decision`: sigmoid again; thresholds unchanged, since they come from costs.
- Registered as **deriddled-ato v3**, now champion. v2 (C) and v1 (A) are kept, so a rollback is just a config change.

| Champion | Stopped (of 33) | Challenge rate | Cost per 1,000 | vs lr_matched |
| --- | --- | --- | --- | --- |
| C `ato_xgb_main` | 28 | 0.051% | 1.70 | +39 pts, p = 0.001 |
| **D `ato_xgb_mono`** | **31** (19 campaign + 12 other) | 0.052% | **1.16** | +48 pts, p = 3 × 10⁻⁵ |

Caveat: the constraint and the choice of D were both made on validation, so the gain is subject to the same winner's-curse discount as every other validation number. The test window is still untouched.
