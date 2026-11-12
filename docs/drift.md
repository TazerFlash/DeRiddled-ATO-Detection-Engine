# Drift monitoring (label-free)

Code: `deriddled/drift.py`. Main ATO model scored on all 17.2M real-account logins, month by month. PSI per month vs the reference window (ATO train, 3 Feb – 31 Jul 2020), on 150k-login samples per month; 10 quantile bins from the reference plus a missing-value bin; flag at PSI > 0.2. Weekly challenge-or-block rate compared with the validation level (0.0514%), flagged if it moves more than 50%. No labels are used. Outputs: `data/ops/psi_by_month.csv`, `docs/figures/weekly_challenge_rate.png`.

## Model output

| Month | Challenge-or-block rate | Score (margin) PSI |
| --- | --- | --- |
| 2020-02 | 0.097% | 0.118 |
| 2020-03 – 2020-07 | 0.039–0.047% | 0.004–0.022 |
| 2020-08 – 2020-11 | 0.048–0.053% | 0.016–0.031 |
| 2020-12 – 2021-02 | 0.040–0.046% | 0.046–0.051 |

- Score PSI stays below 0.2 every month; weekly challenge rate stays within ±50% of validation in 48 of 50 weeks.
- The two flagged weeks are 3 and 10 Feb 2020 (+217%, +129%): the warm-up period, when population features have little history.

## Feature PSI (top 10 features by gain)

| Feature | Range across months | Reading |
| --- | --- | --- |
| `lr_score` | 0.004–0.089 | stable |
| `margin` (score) | 0.004–0.118 | stable |
| `asn_freq` | 0.78–4.42 | mostly artefact (see below) |
| `asn_attack_rate` | 0.30–2.77 | mostly artefact; some real rise in attack share |
| `asn_ato_rate` | 0.53–1.61 | cumulative labels, expected by design |
| `asn_ato_prior` | 0.02–2.78 | high only in Feb–Mar (warm-up) |
| `ua_freq` | 0.09–1.79, rising | **real drift**: browser versions age |
| `asn_users_24h` | 0.03–1.80, jump Dec–Feb | **real drift**: credential-stuffing surge |
| `subnet_logins_24h` | 0.00–0.34, jump Dec–Feb | **real drift**: same surge |
| `new_country`, `subnet_ato_prior` | 0 | binary / mostly zero |

61 feature-month cells exceed 0.2.

**The PSI artefact:** running-share features such as `asn_freq` have large point masses (one Norwegian ISP is ~37% of logins), so several reference decile edges fall inside a very narrow band. A slow shift of that ISP's share moves a third of all logins across several thin bins, and PSI explodes without meaningful change. Quantile-bin PSI is unreliable for such features; monitor the traffic share of top networks instead.

## Takeaways

- Alert on the model output (score PSI, challenge rate); use feature PSI as a diagnostic when an output alarm fires.
- `ua_freq` drifts steadily as browser versions age: an argument for the planned monthly retrain.
- The Dec–Feb stuffing surge shows in the graph features but not in the challenge rate.
