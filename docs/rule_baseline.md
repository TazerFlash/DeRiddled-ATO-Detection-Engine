# Static rule baseline

Rule: **challenge a login if the user had ≥ k failed attempts in the past hour** (`user_fails_1h >= k`, point-in-time). Standard setting k = 5 (`config.yaml: rule_baseline`). Code: `deriddled/baseline.py`, metrics in `deriddled/evaluate.py`.

Evaluated on the **validation** windows (ATO: Aug–Sep 2020, attack IP: Nov–Dec 2020), real accounts only. Test windows are untouched until the final evaluation.

| k | Challenge rate | ATO recall (33) | 95% CI (Wilson) | Attack-IP recall (267,044) | 95% CI (user bootstrap) |
| --- | --- | --- | --- | --- | --- |
| ≥ 1 | 12.74% | 4 / 33 = 12.1% | 4.8–27.3% | 19.04% | 18.6–19.4% |
| ≥ 2 | 3.22% | 2 / 33 = 6.1% | 1.7–19.6% | 5.44% | 5.2–5.6% |
| ≥ 3 | 1.18% | 0 / 33 | 0–10.4% | 2.25% | 2.1–2.4% |
| ≥ 4 | 0.56% | 0 / 33 | 0–10.4% | 1.19% | 1.1–1.3% |
| **≥ 5** | **0.30%** | **0 / 33** | **0–10.4%** | **0.71%** | **0.63–0.80%** |

Challenge rates are for the ATO window; the attack-IP window's rates are similar (0.38% at k = 5).

ATO by segment: all 4 catches at k = 1, and both at k = 2, are from the Romanian campaign; the rule catches 0 of the 14 other ATOs at every k.

## Takeaways

- **The standard rule catches no takeovers.** 140 of 141 ATOs are successful logins with no preceding failures.
- **For attack IPs it is barely better than random:** 0.71% recall at a 0.38% challenge rate (random would give ~0.38%).
- **Loosening it is not a fix:** k ≥ 1 challenges 12.7% of logins and still catches 4 of 33 ATOs.
- With 0 positives caught, the user bootstrap interval collapses to (0, 0); the Wilson interval (0–10.4%) is the one to quote.

Reference points for the model, at a 1% challenge rate: the rule interpolates to roughly **0% ATO recall** and **~1.7% attack-IP recall** (interpolating k = 3 and k = 4 in the attack-IP window); a random flagger gives ~1%.
