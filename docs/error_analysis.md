# Error analysis (validation)

Code: `deriddled/errors.py`. ATO policy = reputation model + sigmoid calibration + cost thresholds (CHALLENGE p ≥ 0.00111, BLOCK p ≥ 0.281). Validation: Aug–Sep 2020, 2,633,850 logins, 33 ATOs. Attack IP: behaviour model at a 10% challenge rate, Nov–Dec 2020.

## Missed ATOs (4 of 33)

| Login | Country | Device | p | Prior logins | New country / ASN / device | Rank (top %) |
| --- | --- | --- | --- | --- | --- | --- |
| 17212026 | NO | desktop | 0.000061 | 11 | no / no / no | 0.64% |
| 17289437 | NO | desktop | 0.000304 | 11 | no / no / no | 0.18% |
| 15235736 | ID | mobile | 0.000367 | 9 | yes / yes / yes | 0.16% |
| 16486150 | BR | mobile | 0.000030 | 0 | yes / yes / yes | 1.16% |

- **Two are behaviourally invisible:** the attacker used the victim's usual country, network and device (likelihood score −29 and −21). Likely same-household access or a compromised device; login features can't catch these.
- **Two are near misses:** ranked in the top 0.16–1.2%, but below the cost-optimal threshold. At a 1% challenge rate, 3 of the 4 would be caught.

## False alarms: many are unlabelled attacker logins

1,761 legitimate-labelled logins flagged (16 BLOCK, 1,745 CHALLENGE). Signs of an unlabelled takeover:

| | BLOCK (16) | CHALLENGE (1,745) |
| --- | --- | --- |
| Campaign fingerprint (`Chrome 79.0.3945.192.218`, `Mac OS X 10.14.6`) | 15 (94%) | 106 (6.1%) |
| User has a labelled ATO at another time | 8 (50%) | 113 (6.5%) |
| IP used in a labelled ATO | 6 (38%) | 35 (2.0%) |
| Any sign | **15 (94%)** | 143 (8.2%) |

The campaign fingerprint appears in **0.023%** of all legitimate validation logins: ~4,000× enrichment among false-alarm BLOCKs.

- Labels mark one login per takeover; the attacker's repeat sessions into the same account are unlabelled, so they count as "legitimate".
- **Corrected false-block count: ~1 of 2.6M logins** (the one BLOCK with no sign, a Danish login with fingerprint `…192.198`).
- Measured precision and false-block rates are therefore **pessimistic**.

False alarms by country: ID 342, CA 241, RO 194 (12 BLOCKs, 97 with a sign), IT 184, DK 135, NL 128, NO 82, BR 57.

## Slice metrics (legitimate logins)

Average challenge-or-block rate: **0.0669%**. PRD flag: slices over 2× average.

| Slice | Legit logins | Challenge or block | Block | × average | Over 2× |
| --- | --- | --- | --- | --- | --- |
| New user (< 3 prior) | 1,179,065 | 0.0595% | 0.0008% | 0.9 | |
| Returning user | 1,454,752 | 0.0729% | 0.0004% | 1.1 | |
| Mobile | 1,764,433 | 0.0301% | 0.0000% | 0.5 | |
| Desktop | 781,625 | 0.1516% | 0.0020% | 2.3 | **yes** |
| Norway | 1,760,371 | 0.0047% | 0.0000% | 0.1 | |
| US | 547,463 | 0.0009% | 0.0000% | 0.0 | |
| Brazil | 72,503 | 0.0786% | 0.0000% | 1.2 | |
| Poland | 63,540 | 0.0331% | 0.0000% | 0.5 | |
| UK | 36,904 | 0.0190% | 0.0000% | 0.3 | |
| **Romania** | 2,206 | **8.79%** | **0.54%** | **131** | **yes** |

- **Romania:** excluding the 97 flagged logins with campaign signs still leaves ~5% of Romanian legitimate logins challenged (~80× average). Cause: country-level takeover reputation (`country_ato_*`) learned from one campaign. This is the PRD's regional-bias risk.
- **Desktop (2.3×):** the campaign uses desktop browsers; milder, and partly unlabelled attacker logins.

## Attack IP: missed logins (@ 10% challenge)

195,874 caught, 71,170 missed of 267,044.

| | Missed | Caught | All legit |
| --- | --- | --- | --- |
| New country | 35.9% | 38.8% | 18.5% |
| New ASN | 37.8% | 42.7% | 24.9% |
| Successful login | 53.2% | 52.2% | 73.1% |
| ASN attack rate (median) | 0.280 | 0.281 | 0.007 |
| IP prior logins (median) | 1,932 | 1,680 | 16 |
| Users on subnet, 24 h (median) | 536 | 421 | 4 |

80% of missed attack-IP logins come from ASN 393398, the stuffing network, which is only ~28% attack IPs. Missed and caught logins look alike: within that network, attacker-list membership isn't separable from the features. Non-listed IPs on that network may also be attackers (incomplete labels).

## Takeaways

1. Label incompleteness is the largest source of apparent error: most false BLOCKs are attacker sessions without a label.
2. Two misses need non-login signals (device fingerprinting, transaction monitoring).
3. Country reputation causes heavy friction for real Romanian users; needs a mitigation decision.
4. Attack-IP recall is capped by how the attacker list labels IPs within one network, not by missing features.
