# Week 1 EDA summary

Source: `notebooks/01_eda.ipynb`, full data (not the sample). Population = real accounts, i.e. non-account IDs excluded (`config.yaml: non_accounts`).

## The data

| | |
| --- | --- |
| Logins (all / real accounts) | 31,269,264 / 17,169,861 |
| Real user IDs | 4,304,852 |
| Time span | 3 Feb 2020 – 28 Feb 2021 |
| ATO labels | 141 on 138 users, **3 Feb – 23 Nov 2020 only** |
| Attack-IP labels | 3,096,977 rows (all 13 months) |
| Logins per user | median 2; 41% of users have ≥ 3, 8.6% have ≥ 10 |
| Missing | RTT 96%, region 45%, city 44% |

## Findings and the decisions they drive

**1. ATO labels stop on 23 Nov 2020; attacks don't.** Attack-IP share rises from ~7.5% to ~10.5% from November, and non-account traffic (attacks on usernames that don't exist) doubles.
→ Two split windows (`config.yaml: splits`). Dec–Feb is unlabelled for ATO, never negative. The attack-IP base rate shifts, so calibrate on the validation window.

**2. One campaign supplies most ATO labels.** 79 of 141 ATOs (56%) come from Romania, a country with 0.1% of logins: 78 victims over 10 months, 59 IPs on 27 ASNs, mostly one browser fingerprint (`Chrome 79.0.3945.192.218`, `Mac OS X 10.14.6`), 84% from attack IPs. It provides **16 of the 22 test ATOs**.
→ Report ATO recall **separately for the campaign and for other ATOs**, alongside the overall number. A model that only learns "Romania + this fingerprint" must not look like a general ATO detector.

**3. Novelty is the strongest signal, and survives without the campaign.** Among logins where the user has earlier history (93 ATOs):

| Flag | ATO | Legit (successful) | Lift |
| --- | --- | --- | --- |
| New country for user | 73% | 0.70% | 105× |
| New ASN | 80% | 9.6% | 8.3× |
| New device (browser + OS + type) | 69% | 36% | 1.9× |
| New IP | 88% | 37% | 2.4× |
| Country, ASN and device all new | 65% | 0.49% | 132× |

Without Romania (44 ATOs): new country 70% vs 0.68%, new ASN 75% vs 9.5%.
→ Novelty features and the likelihood-ratio baseline are the right core. Country and ASN novelty first; device and IP novelty are weaker.

**4. A third of ATOs have no history to compare against.** 48 of 141 ATOs are the user's first login in the data (partly left-censoring: history before Feb 2020 is not visible), and 64% of ATOs happen with fewer than 3 prior logins. Half of all logins fall on that new-user path.
→ The new-user path (FR-5) is a main path, not an edge case. Population features (country/ASN risk, attack-IP history of the IP, IP–account graph) carry it, and slice metrics must report new vs returning users.

**5. Attack traffic is concentrated in networks.** The top ASN (393398, US) carries 71% of all attack-IP logins; the top 10 ASNs carry 91%. US logins are 24% of traffic but 82% of attack logins.
→ ASN- and IP-level risk features are strong for the attack-IP target. They must be computed point-in-time (only labels from earlier logins), because `is_attack_ip` is itself an IP property: computing them over all data would leak the label.

**6. Takeovers look different from normal logins.** ATO vs legit successful: 85% vs 34% desktop, 7% vs 70% Norway, 55% vs 6% attack IP. Only 1 of 141 ATOs is a failed login.
→ Device type and attack-IP history are useful features. Failed-attempt ratios will help the attack-IP target more than ATO.

**7. RTT carries almost no signal.** It's bimodal (~25 ms and ~500 ms clusters) with near-identical shapes for attack and legit traffic, and only 1 ATO has a value.
→ Drop RTT values from the core features; keep `rtt_present` as a weak flag (6.7% of legit vs 1.1% of attack logins). The RTT z-score feature in FR-2 becomes optional.

**8. Region/city are often missing.**
→ Geography features (distance, impossible travel) use city coordinates when present and fall back to country centroids otherwise. The GeoNames lookup is still needed but matters less than planned.

## Week 1 gate

- ATO count is 141, above the ~100 cutoff: **ATO stays the primary target.** With 22 test ATOs (16 from one campaign), attack-IP recall carries the statistical claims.
- Leakage traps found: label cutoff, campaign concentration, point-in-time population/ASN risk.
- Ready for Week 2 (`features.sql`), prioritising: novelty (country, ASN, device), population/ASN risk (point-in-time), velocity, device type, `rtt_present`.
