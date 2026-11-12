# Week 4: anomaly layer, IP–account graph and ablation (validation)

Validation windows only (ATO: Aug–Sep 2020, 33 ATOs; attack IP: Nov–Dec 2020, 267,044 positives). Test windows untouched. Code: `deriddled/anomaly.py`, `deriddled/graph.py`, `deriddled/ablation.py`.

## Anomaly layer (FR-4.1)

Isolation Forest (200 trees, 256 rows per tree) fitted on 200k training-window logins, label-free features only (novelty flags, log-transformed counts, log frequencies, fail ratio, hour). Per-user deviation score: `novelty_count` = number of new attributes (0–5). Model saved as `data/models/isolation_forest.joblib`.

| Score alone | ATO @ 1% | ATO @ 2% | Attack IP @ 10% |
| --- | --- | --- | --- |
| Random | ~1% | ~2% | 10% |
| Isolation Forest | 4 / 33 (12%) | 11 / 33 (33%) | 14.4% |
| Novelty count | 1 / 33 | 1 / 33 | 18.4% |
| Reputation XGBoost (reference) | 32 / 33 | 33 / 33 | — |

Inside XGBoost, the reputation model with and without `anomaly_score` + `novelty_count` gives identical ATO results at every rate and segment (32 / 33 at 1%).

- Most anomalies are benign (travellers, new devices, unusual hours); takeovers are unusual in specific ways that only labels reveal.
- `novelty_count` fails standalone: a user's first-ever login is new on all 5 attributes, so the top 1% fills with first logins tied at 5.
- **Not used in the model.** Possible role: monitoring for unlabelled new attack types.

## IP–account graph (August 2020)

Bipartite graph of IPs and real accounts, restricted to IPs that touched ≥ 5 accounts in the month: 22,750 IPs, 307,727 accounts, 381,874 edges, 1,732 connected components. Figure: `docs/figures/ip_account_clusters_2020-08.png`.

| Cluster | Accounts | IPs | Main network | Success | Attack-IP share | Reading |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 161,367 | 17,612 | NO, ASN 29695 | 81% | 2% | Shared ISP / carrier NAT infrastructure, benign |
| 2 | 133,645 | 3,277 | US, ASN 393398 | 51% | 32% | Credential-stuffing operation |
| 3–10 | 31–107 | 1–3 | GB, FR, NO, BR | 70–98% | 0% | Offices, campuses, shared Wi-Fi |

**No ATO occurs in any of these clusters.** The infrastructure that tests stolen credentials at scale is different from the low-and-slow infrastructure that uses them.

## Cumulative ablation (FR-4.4)

XGBoost, depth 3, `scale_pos_weight` 1, same settings throughout.

| Step (cumulative) | Features | ATO @ 1% | Other ATOs @ 1% | Attack IP @ 10% | Precision @ 10% |
| --- | --- | --- | --- | --- | --- |
| Static rule | — | 0 / 33 | 0 / 14 | ~2% | — |
| Likelihood ratio alone | — | 22 / 33 | 8 / 14 | — | — |
| User behaviour | 19 | 23 / 33 | 9 / 14 | 26.7% | 26.5% |
| + population | 27 | 30 / 33 | 11 / 14 | 39.6% | 39.3% |
| + graph | 33 | 30 / 33 | 11 / 14 | 68.4% | 67.8% |
| + likelihood score | 34 | 30 / 33 | 11 / 14 | 68.4% | 67.9% |
| + anomaly | 36 | 30 / 33 | 11 / 14 | 77.3%* | 76.6% |
| + reputation (ATO only) | 44 | 32 / 33 | 13 / 14 | — | — |

\* Not a real gain; see below.

- **ATO:** population features (+7) and reputation (+2) do all the work; graph, likelihood and anomaly add nothing.
- **Attack IP:** graph features are the largest gain (+29 points), then population (+13).
- Credential stuffing is a graph pattern; takeovers are not.

## Run-to-run variance (attack IP)

The same feature set trained with seeds 0, 1, 2:

| Attack IP @ 10% | Seed 0 | Seed 1 | Seed 2 | Mean |
| --- | --- | --- | --- | --- |
| Without anomaly | 72.3% | 71.3% | 73.0% | 72.2% |
| With anomaly | 71.0% | 66.7% | 71.7% | 69.8% |

- The ablation's +9 points for anomaly was seed noise; anomaly doesn't help attack IP.
- Across all runs with near-identical features, attack-IP recall @ 10% ranged 66.7–77.3%. **Differences under ~5 points are not meaningful** (including Week 3's 1-point identity vs behaviour gap).
- The large effects (graph +29, population +13 for attack IP; population +7 for ATO) are well above the noise. ATO counts were identical across ablation steps, so ATO results are stable.
