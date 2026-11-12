# Likelihood-ratio baseline (Freeman et al., 2016)

Code: `sql/likelihood.sql` (point-in-time counts), `deriddled/likelihood.py` (scoring), `tests/test_likelihood_counts.py`. Evaluated on the **validation** windows (ATO: Aug–Sep 2020, attack IP: Nov–Dec 2020); test windows untouched.

## Score

log Risk(x, u) = Σ_k [ log p(x_k | attack) − log p(x_k | u) ] over k ∈ {IP, ASN, country, browser+OS}

- p(x) = (c(x) + 1) / (N + V + 1): population rate so far, Laplace-smoothed (V = distinct values seen so far)
- p(x | u) = (c_u(x) + β·p(x)) / (n_u + β): the user's own rate, shrunk toward the population; equals p(x) for a new user
- **Freeman original:** p(x | attack) = p(x)
- **Attack-informed:** p(x | attack) = (a(x) + 1) / (A + V + 1), from earlier attack-IP logins; IP excluded for the attack-IP target (it would restate the label)

## Results at a 1% challenge rate

| Method | ATO recall (33) | 95% CI (Wilson) | Attack-IP recall (267,044) |
| --- | --- | --- | --- |
| Static rule, k ≥ 5 (reference) | 0 / 33 | 0–10.4% | ~1.7% (interpolated) |
| Freeman original, β = 1 | 9 / 33 = 27.3% | 15.1–44.2% | 0.34% |
| Freeman original, β = 5 | 9 / 33 = 27.3% | 15.1–44.2% | 0.29% |
| Attack-informed, β = 1 | **22 / 33 = 66.7%** | 49.6–80.3% | 4.61% |
| Attack-informed, β = 5 | 20 / 33 = 60.6% | 43.7–75.3% | **4.66%** |
| Attack-informed, β = 20 | 14 / 33 = 42.4% | 27.2–59.2% | 4.67% |

Attack-informed, β = 1, ATO by segment: campaign 14 / 19 (73.7%), other 8 / 14 (57.1%).

Other challenge rates (attack-informed, β = 1): ATO 66.7% at 0.5%, 69.7% at 2%; attack IP 2.75% at 0.5%, 7.65% at 2%.

## Takeaways

- Per-user novelty already beats the rule on ATO (27% vs 0%).
- Freeman's assumption p(x | attack) = p(x) fails here: takeovers come from rare, attack-heavy networks, which the original scores as low risk. On attack IP it's worse than random (0.34% vs 1%).
- Estimating p(x | attack) from earlier attack traffic lifts ATO recall to 67% and attack-IP recall to 4.6%.
- Smaller β (trusting the user's own history more) is better for ATO; β barely matters for attack IP.
- β was chosen on the same 33 validation ATOs, so 67% is mildly optimistic; the untouched test set gives the unbiased number.

**Bar for the ML model at 1%:** ~67% ATO recall, ~4.6% attack-IP recall.
