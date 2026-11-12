# Shadow mode: rule vs De-Riddled (validation)

Code: `deriddled/shadow.py` (`python -m deriddled.shadow valid`). Results saved to `data/ops/shadow_valid.json`. Model: champion `ato_xgb_ok` (deriddled-ato v4). It is the red-team fix: novelty and the likelihood score are measured against the account's successful logins only, and the takeover-history features are monotone (see `docs/monotonicity.md`).

Setup: every validation login (1 Aug – 30 Sep 2020, 2,633,850 logins, 33 ATOs on 33 distinct users, 19 in the Romanian campaign) is scored by every policy, so the comparison is **paired**: same logins, same attacks, different decisions.

| Policy | Role | Decision |
| --- | --- | --- |
| `rule` | control (what a bank runs today) | CHALLENGE if the user had ≥ 5 failed attempts in the past hour |
| `lr_matched` | second control (best non-ML baseline) | attack-informed likelihood ratio (β = 1), CHALLENGE on the top logins at **the same flag budget** as the model |
| `model` | treatment | `ato_xgb_ok`, cross-fitted sigmoid calibration, cost thresholds (CHALLENGE p ≥ 0.00111, BLOCK p ≥ 0.281) |

## Outcomes

| Policy | Legit friction | ATO stopped | Campaign / other | Cost per 1,000 logins |
| --- | --- | --- | --- | --- |
| allow everything | 0 | 0 / 33 | 0 / 0 | 6.26 |
| rule | 0.301% | 0 / 33 | 0 / 0 | **7.77** (worse than doing nothing) |
| lr_matched | 0.052% | 15 / 33 | 8 / 7 | 3.96 |
| **model** | **0.051%** | **28 / 33** | **19 / 9** | **1.66** |

Stopped = CHALLENGE or BLOCK. The model flags 1,382 logins: 1,350 CHALLENGE and 32 BLOCK (0.001% of logins).

Precision and recall at this operating point:
- **Recall:** 28 / 33 = 84.8% (Wilson 95% CI about 69–93%).
- **Precision:** 28 / 1,382 = 2.0%, about 1,600× the 0.00125% base rate.
- **BLOCK tier:** 37.5% precision (12 of 32). 29 of the 32 blocks are takeovers or known attack IPs.
- **Ranking quality:** PR-AUC 0.341 (likelihood ratio: 0.009), ROC-AUC 0.9997.

## Paired significance tests (exact McNemar)

McNemar's test only uses the **discordant** pairs, where exactly one policy stopped the login.

| Comparison | Population | Both stop | Model only | Control only | Neither | p-value |
| --- | --- | --- | --- | --- | --- | --- |
| model vs rule | ATO | 0 | 28 | 0 | 5 | 7.5 × 10⁻⁹ |
| model vs rule | legit | 1 | 1,353 | 7,938 | 2.62 M | < 10⁻³⁰⁰ |
| model vs lr_matched | ATO | 14 | 14 | 1 | 4 | 0.001 |
| model vs lr_matched | legit | 227 | 1,127 | 1,140 | 2.63 M | 0.80 |

The model and the rule challenge almost completely different people: they share only 1 legitimate challenge out of about 9,300. Against the likelihood ratio at the same budget, legitimate friction is statistically indistinguishable (p = 0.80, by construction). The model stops 14 of the 15 attacks the baseline stops, plus 14 more.

## Effect sizes with 95% bootstrap CIs

Two resampling units:
- **Day blocks**, 61 days: these keep the within-day correlation of campaign bursts.
- **ATO users**, 33 users: here identical to resampling ATOs, since every ATO is a different user.

10,000 resamples.

| Model minus … | Recall (stopped share) | Legit friction | Cost per 1,000 |
| --- | --- | --- | --- |
| rule | **+84.8 pts** [70.4, 96.4] day · [72.7, 97.0] user | −0.250 pts [−0.266, −0.234] | −6.11 [−8.15, −4.23] |
| lr_matched | **+39.4 pts** [17.6, 59.3] day · [21.2, 57.6] user | −0.0005 pts [−0.005, +0.004] | −2.30 [−3.99, −0.86] |

No interval crosses zero except the friction difference against the matched baseline, which is equal by design.

## Power: is the test window big enough?

Exact power of a two-sided McNemar test (α = 0.05) as a function of the number of ATOs. Here *p10* is the share of ATOs that only the model stops and *p01* the share that only the control stops. ATOs arrive at about 16.7 per month, and the untouched test window holds 22.

| Scenario | p10 | p01 | Power at 22 ATOs (test) | Power at 33 | ATOs for 80% | Months of shadow |
| --- | --- | --- | --- | --- | --- | --- |
| model vs rule (observed) | 0.85 | 0.015* | 1.00 | 1.00 | 8 | 0.5 |
| model vs lr_matched (observed) | 0.42 | 0.03 | 0.80 | 0.96 | 22 | 1.3 |
| planning: +25 pts net | 0.30 | 0.05 | 0.38 | 0.63 | 45 | 2.7 |
| planning: +15 pts net | 0.20 | 0.05 | 0.12 | 0.28 | 92 | 5.5 |
| planning: +10 pts net | 0.15 | 0.05 | 0.04 | 0.12 | 168 | 10.0 |
| planning: +5 pts net | 0.10 | 0.05 | 0.01 | 0.03 | > 400 | > 24 |

\* The observed count is 0, replaced by 0.5 because a zero discordance rate makes the power calculation degenerate.

How to read the power table:
- **Against the rule**, any window is enough. Eight ATOs give 80% power.
- **Against the best baseline**, the 22-ATO test window has about 80% power **if** the validation gap of +39 points holds. The model, its features and thresholds were chosen on validation, so that gap is optimistic (winner's curse). If the real gap is +25 points, power falls to about 40%. A non-significant test-window result against the baseline would therefore be inconclusive, not a failure.
- A smaller real-world improvement of +10 points would need about 170 ATOs, roughly ten months of shadow traffic at this bank's attack rate. Shadow mode is cheap because it does not touch users, so the honest plan is to fix the required count in advance and run until it is reached.

## Takeaways

- The rule is worse than no control at all here. It adds 0.30% friction and stops nothing, because 88% of these takeovers have no failed attempt before them.
- De-Riddled stops 28 of 33 takeovers while challenging **6× fewer** legitimate logins than the rule, cutting expected cost from 7.77 to 1.66 per 1,000 logins.
- At equal friction it beats the strongest non-ML baseline by about 39 recall points (CI 18–59), p = 0.001.
- These are validation results, and the model, its features and the thresholds were all chosen on this window. The final confirmation is the untouched test window.

## History of champions on this comparison

| Champion | Change | ATO stopped | Cost per 1,000 | vs lr_matched |
| --- | --- | --- | --- | --- |
| C `ato_xgb_main` | country features removed | 28 / 33 | 1.70 | +39 pts (CI 18–59), p = 0.001 |
| D `ato_xgb_mono` | + monotone takeover history | 31 / 33 | 1.16 | +48 pts (CI 30–66), p = 3 × 10⁻⁵ |
| **E `ato_xgb_ok`** | + novelty against successful logins (red-team fix) | **28 / 33** | **1.66** | **+39 pts (CI 18–59), p = 0.001** |

E gives up 3 historical takeovers compared with D. It was adopted anyway, because D could be beaten by any attacker who fails once: on 300 synthetic takeovers per seed, D stopped 2 / 12 and E stopped 78 / 100 (see `docs/red_team.md`).
