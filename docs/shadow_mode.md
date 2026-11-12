# Shadow mode: rule vs De-Riddled (validation)

Code: `deriddled/shadow.py` (`python -m deriddled.shadow valid`). Results saved to `data/ops/shadow_valid.json`. Model: champion `ato_xgb_mono` (deriddled-ato v3, see `docs/monotonicity.md`).

Setup: every validation login (1 Aug – 30 Sep 2020, 2,633,850 logins, 33 ATOs on 33 distinct users, 19 in the Romanian campaign) is scored by every policy, so the comparison is **paired**: same logins, same attacks, different decisions.

| Policy | Role | Decision |
| --- | --- | --- |
| `rule` | control (what a bank runs today) | CHALLENGE if the user had ≥ 5 failed attempts in the past hour |
| `lr_matched` | second control (best non-ML baseline) | attack-informed likelihood ratio (β = 1), CHALLENGE on the top logins at **the same flag budget** as the model |
| `model` | treatment | `ato_xgb_mono`, cross-fitted sigmoid calibration, cost thresholds (CHALLENGE p ≥ 0.00111, BLOCK p ≥ 0.281) |

## Outcomes

| Policy | Legit friction | ATO stopped | Campaign / other | Cost per 1,000 logins |
| --- | --- | --- | --- | --- |
| allow everything | 0 | 0 / 33 | 0 / 0 | 6.26 |
| rule | 0.301% | 0 / 33 | 0 / 0 | **7.77** (worse than doing nothing) |
| lr_matched | 0.053% | 15 / 33 | 8 / 7 | 3.97 |
| **model** | **0.052%** | **31 / 33** | **19 / 12** | **1.16** |

Stopped = CHALLENGE or BLOCK; the model blocks about 0.001% of logins.

## Paired significance tests (exact McNemar)

McNemar's test only uses the **discordant** pairs, where exactly one policy stopped the login.

| Comparison | Population | Both stop | Model only | Control only | Neither | p-value |
| --- | --- | --- | --- | --- | --- | --- |
| model vs rule | ATO | 0 | 31 | 0 | 2 | 9.3 × 10⁻¹⁰ |
| model vs rule | legit | 1 | 1,373 | 7,938 | 2.62 M | < 10⁻³⁰⁰ |
| model vs lr_matched | ATO | 15 | 16 | 0 | 2 | 3.1 × 10⁻⁵ |
| model vs lr_matched | legit | 240 | 1,134 | 1,150 | 2.63 M | 0.75 |

The model and the rule challenge almost completely different people: they share only 1 legitimate challenge out of about 9,300. Against the likelihood ratio at the same budget, legitimate friction is statistically indistinguishable (p = 0.75, by construction). The model stops every attack the baseline stops, plus 16 more.

## Effect sizes with 95% bootstrap CIs

Two resampling units:
- **Day blocks**, 61 days: these keep the within-day correlation of campaign bursts.
- **ATO users**, 33 users: here identical to resampling ATOs, since every ATO is a different user.

10,000 resamples.

| Model minus … | Recall (stopped share) | Legit friction | Cost per 1,000 |
| --- | --- | --- | --- |
| rule | **+93.9 pts** [84.0, 100] day · [84.8, 100] user | −0.249 pts [−0.265, −0.234] | −6.61 [−8.67, −4.66] |
| lr_matched | **+48.5 pts** [29.6, 65.6] day · [30.3, 63.6] user | −0.0006 pts [−0.005, +0.004] | −2.80 [−4.48, −1.39] |

No interval crosses zero except the friction difference against the matched baseline, which is equal by design.

## Power: is the test window big enough?

Exact power of a two-sided McNemar test (α = 0.05) as a function of the number of ATOs. Here *p10* is the share of ATOs that only the model stops and *p01* the share that only the control stops. ATOs arrive at about 16.7 per month, and the untouched test window holds 22.

| Scenario | p10 | p01 | Power at 22 ATOs (test) | Power at 33 | ATOs for 80% | Months of shadow |
| --- | --- | --- | --- | --- | --- | --- |
| model vs rule (observed) | 0.94 | 0.015* | 1.00 | 1.00 | 7 | 0.4 |
| model vs lr_matched (observed) | 0.48 | 0.015* | 0.95 | 1.00 | 17 | 1.0 |
| planning: +25 pts net | 0.30 | 0.05 | 0.38 | 0.63 | 45 | 2.7 |
| planning: +15 pts net | 0.20 | 0.05 | 0.12 | 0.28 | 92 | 5.5 |
| planning: +10 pts net | 0.15 | 0.05 | 0.04 | 0.12 | 168 | 10.0 |
| planning: +5 pts net | 0.10 | 0.05 | 0.01 | 0.03 | > 400 | > 24 |

\* The observed count is 0, replaced by 0.5 because a zero discordance rate makes the power calculation degenerate.

How to read the power table:
- **Against the rule**, any window is enough. Seven ATOs give 80% power.
- **Against the best baseline**, the 22-ATO test window has about 95% power **if** the validation gap of +48 points holds. The model and its constraint were chosen on validation, so that gap is optimistic (winner's curse). If the real gap is +25 points, power falls to about 40%. A non-significant test-window result against the baseline would therefore be inconclusive, not a failure.
- A smaller real-world improvement of +10 points would need about 170 ATOs, roughly ten months of shadow traffic at this bank's attack rate. Shadow mode is cheap because it does not touch users, so the honest plan is to fix the required count in advance and run until it is reached.

## Takeaways

- The rule is worse than no control at all here. It adds 0.30% friction and stops nothing, because these takeovers use the correct password on the first try.
- De-Riddled stops 31 of 33 takeovers while challenging **6× fewer** legitimate logins than the rule, cutting expected cost from 7.77 to 1.16 per 1,000 logins.
- At equal friction it beats the strongest non-ML baseline by about 48 recall points (CI 30–66), p ≈ 3 × 10⁻⁵.
- These are validation results, and the model, its constraint and the thresholds were all chosen on this window. The final confirmation is the untouched test window.

History: the first run of this comparison used the earlier champion `ato_xgb_main`: 28 / 33 stopped, cost 1.70, +39 pts vs lr_matched (CI 18–59), p = 0.001.
