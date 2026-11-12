"""Export narrator claims to an Excel sheet for hand-labelling, and score faithfulness from the labelled sheet."""
import argparse
import json

import numpy as np
import pandas as pd
from openpyxl import Workbook, load_workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.worksheet.datavalidation import DataValidation

from deriddled.config import ROOT
from deriddled.evaluate import wilson
from deriddled.narrator import PROMPT_VERSION, PROVIDERS, log_path

OUT = ROOT / "eval" / "narrator_labels.xlsx"
CLAIM_LABELS = ("supported", "partly", "unsupported")
REC_LABELS = ("reasonable", "questionable", "wrong")
FONT = "Arial"
INPUT_FILL = PatternFill("solid", start_color="FFFF00")
HEADER_FILL = PatternFill("solid", start_color="D9D9D9")


def _rows(model: str, version: int) -> list[dict]:
    rows = [json.loads(l) for l in log_path().read_text(encoding="utf-8").splitlines() if l.strip()]
    return [r for r in rows if r["model"] == model and r.get("prompt_version", 1) == version and "grounded" in r]


def _style(ws, widths: dict, input_cols: set, n: int) -> None:
    for col, w in widths.items():
        ws.column_dimensions[col].width = w
    for row in ws.iter_rows(min_row=1, max_row=n + 1):
        for c in row:
            c.font = Font(name=FONT, bold=c.row == 1, size=10)
            c.alignment = Alignment(wrap_text=True, vertical="top")
            if c.row == 1:
                c.fill = HEADER_FILL
            elif c.column_letter in input_cols:
                c.fill = INPUT_FILL
    ws.freeze_panes = "A2"


def build(model: str, version: int, out=OUT) -> None:
    rows = _rows(model, version)
    if out.exists():
        raise FileExistsError(f"{out} exists; it may hold your labels. Move it away to rebuild.")
    out.parent.mkdir(parents=True, exist_ok=True)
    wb = Workbook()
    wb.calculation.fullCalcOnLoad = True

    readme = wb.active
    readme.title = "Read me"
    lines = [
        ("Narrator faithfulness labelling", True),
        (f"Model {model}, prompt version {version}, {len(rows)} cases. Fill in only the yellow cells.", False),
        ("", False),
        ("Claims tab: for each claim, read the cited evidence next to it and choose a label in column E.", True),
        ("supported - every fact in the claim is stated in the cited evidence (rounding such as 63.6% -> 64% is fine).", False),
        ("partly - the main fact is supported, but some detail is not (a wrong qualifier, an unsupported 'because', a merged fact).", False),
        ("unsupported - the claim states something the cited evidence does not say, or says the opposite.", False),
        ("Judge only against the cited evidence, not against what you think is true about the case.", False),
        ("", False),
        ("Cases tab: judge the recommended action given all the claims and evidence (column F).", True),
        ("reasonable - an analyst could sensibly follow it.  questionable - defensible but weak.  wrong - the evidence points elsewhere.", False),
        ("", False),
        ("Example (not counted):", True),
        ("Claim: '96.5% of earlier logins from network ASN 57423 came from known attack IPs.'   Cited: F13 'share of this network's earlier logins that came from known attack IPs: 96.5%'   Label: supported", False),
        ("Claim: 'The rare network yielded a likelihood-ratio score of 8.4.'   Cited: F11, F12   Label: partly (the score is right; 'yielded' is a link no evidence states)", False),
        ("", False),
        ("Then run:  .venv/Scripts/python.exe -m deriddled.label_sheet score", True),
    ]
    for i, (text, bold) in enumerate(lines, 1):
        readme.cell(i, 1, text).font = Font(name=FONT, bold=bold, size=11 if i == 1 else 10)
    readme.column_dimensions["A"].width = 150

    claims = wb.create_sheet("Claims")
    claims.append(["case_id", "claim_no", "claim", "cited evidence", "label", "note"])
    for r in rows:
        ev = r["evidence"]
        for k, c in enumerate(r["grounded"]["claims"], 1):
            cited = "\n".join(f"[{i}] {ev[i]}" for i in c["evidence_ids"])
            claims.append([r["case_id"], k, c["text"], cited, None, None])
    n_claims = claims.max_row - 1
    dv = DataValidation(type="list", formula1=f'"{",".join(CLAIM_LABELS)}"', allow_blank=True)
    claims.add_data_validation(dv)
    dv.add(f"E2:E{n_claims + 1}")
    _style(claims, {"A": 12, "B": 8, "C": 60, "D": 80, "E": 14, "F": 30}, {"E", "F"}, n_claims)

    cases = wb.create_sheet("Cases")
    cases.append(["case_id", "model decision", "recommended action", "confidence", "action evidence", "recommendation", "note"])
    for r in rows:
        g, ev = r["grounded"], r["evidence"]
        cases.append([r["case_id"], ev["A1"], g["recommended_action"], g["confidence"],
                      "\n".join(f"[{i}] {ev[i]}" for i in g["action_evidence_ids"]), None, None])
    n_cases = cases.max_row - 1
    dv2 = DataValidation(type="list", formula1=f'"{",".join(REC_LABELS)}"', allow_blank=True)
    cases.add_data_validation(dv2)
    dv2.add(f"F2:F{n_cases + 1}")
    _style(cases, {"A": 12, "B": 50, "C": 24, "D": 11, "E": 80, "F": 15, "G": 30}, {"F", "G"}, n_cases)

    s = wb.create_sheet("Summary")
    rng, rec = f"Claims!E2:E{n_claims + 1}", f"Cases!F2:F{n_cases + 1}"
    table = [
        ("Claims shown to analysts", f"=COUNTA(Claims!C2:C{n_claims + 1})"),
        ("Claims labelled", f"=COUNTA({rng})"),
        ("supported", f'=COUNTIF({rng},"supported")'),
        ("partly", f'=COUNTIF({rng},"partly")'),
        ("unsupported", f'=COUNTIF({rng},"unsupported")'),
        ("Faithfulness, strict (supported / labelled)", "=IFERROR(B4/B3,\"-\")"),
        ("Faithfulness, lenient ((supported + partly) / labelled)", "=IFERROR((B4+B5)/B3,\"-\")"),
        ("Target (PRD FR-9.2)", 0.95),
        ("Cases labelled", f"=COUNTA({rec})"),
        ("Recommendation reasonable", f'=IFERROR(COUNTIF({rec},"reasonable")/B10,"-")'),
    ]
    s.append(["Metric", "Value"])
    for label, value in table:
        s.append([label, value])
    for cell in ("B7", "B8", "B9", "B11"):
        s[cell].number_format = "0.0%"
    s["C9"] = "Target from the PRD, FR-9.2"
    _style(s, {"A": 55, "B": 12, "C": 30}, set(), len(table))
    wb.save(out)
    print(f"wrote {out}: {len(rows)} cases, {n_claims} claims")


def _cluster_ci(df: pd.DataFrame, n_boot: int = 5000, seed: int = 0) -> tuple[float, float]:
    g = df.groupby("case_id")["ok"].agg(["sum", "count"])
    idx = np.random.default_rng(seed).integers(0, len(g), size=(n_boot, len(g)))
    rates = g["sum"].to_numpy()[idx].sum(1) / g["count"].to_numpy()[idx].sum(1)
    return tuple(np.percentile(rates, [2.5, 97.5]))


def score(path=OUT) -> dict:
    claims = pd.read_excel(path, sheet_name="Claims")
    cases = pd.read_excel(path, sheet_name="Cases")
    lab = claims[claims["label"].isin(CLAIM_LABELS)].copy()
    out = {"claims": len(claims), "labelled": len(lab), **lab["label"].value_counts().reindex(CLAIM_LABELS, fill_value=0).to_dict()}
    for name, ok in (("strict", lab["label"] == "supported"), ("lenient", lab["label"] != "unsupported")):
        lab["ok"] = ok
        k, n = int(ok.sum()), len(lab)
        out[f"faithfulness_{name}"] = k / n if n else float("nan")
        out[f"{name}_ci_wilson"] = wilson(k, n)
        out[f"{name}_ci_case_bootstrap"] = _cluster_ci(lab) if n else (float("nan"),) * 2
    rec = cases[cases["recommendation"].isin(REC_LABELS)]
    out["cases_labelled"] = len(rec)
    out["recommendation"] = rec["recommendation"].value_counts().reindex(REC_LABELS, fill_value=0).to_dict()
    bad = lab[lab["label"] != "supported"][["case_id", "claim_no", "label", "claim", "note"]]
    for k, v in out.items():
        print(f"{k}: {np.round(v, 4) if isinstance(v, (float, tuple)) else v}")
    if len(bad):
        print("\nnot fully supported:\n" + bad.to_string(index=False))
    return out


AI = ROOT / "eval" / "narrator_labels_claude.xlsx"
SPOT = ROOT / "eval" / "narrator_spotcheck.xlsx"


def spotcheck(n_supported: int = 25, n_other: int = 15, seed: int = 0, src=AI, out=SPOT) -> None:
    if out.exists():
        raise FileExistsError(f"{out} exists; it may hold your labels. Move it away to rebuild.")
    ai = pd.read_excel(src, sheet_name="Claims")
    other = ai[ai["label"] != "supported"]
    pick = pd.concat([ai[ai["label"] == "supported"].sample(n_supported, random_state=seed),
                      other.sample(min(n_other, len(other)), random_state=seed)]).sample(frac=1, random_state=seed)
    wb = Workbook()
    readme = wb.active
    readme.title = "Read me"
    lines = [("Narrator spot-check: do you agree with the AI judge?", True),
             (f"{len(pick)} claims, mixed so you can't tell which way the AI labelled them. Fill in only the yellow cells.", False),
             ("Same rules as narrator_labels.xlsx: supported / partly / unsupported, judged only against the cited evidence.", False),
             ("Then run:  .venv/Scripts/python.exe -m deriddled.label_sheet agree", True)]
    for i, (text, bold) in enumerate(lines, 1):
        readme.cell(i, 1, text).font = Font(name=FONT, bold=bold, size=11 if i == 1 else 10)
    readme.column_dimensions["A"].width = 120
    ws = wb.create_sheet("Claims")
    ws.append(["case_id", "claim_no", "claim", "cited evidence", "label", "note"])
    for _, r in pick.iterrows():
        ws.append([r["case_id"], r["claim_no"], r["claim"], r["cited evidence"], None, None])
    dv = DataValidation(type="list", formula1=f'"{",".join(CLAIM_LABELS)}"', allow_blank=True)
    ws.add_data_validation(dv)
    dv.add(f"E2:E{len(pick) + 1}")
    _style(ws, {"A": 12, "B": 8, "C": 60, "D": 80, "E": 14, "F": 30}, {"E", "F"}, len(pick))
    wb.save(out)
    print(f"wrote {out}: {len(pick)} claims ({n_supported} the AI called supported, {len(pick) - n_supported} it did not)")


def agree(src=AI, spot=SPOT) -> dict:
    key = ["case_id", "claim_no"]
    human = pd.read_excel(spot, sheet_name="Claims")
    human = human[human["label"].isin(CLAIM_LABELS)]
    m = human[key + ["label", "note"]].merge(pd.read_excel(src, sheet_name="Claims")[key + ["label", "claim"]],
                                             on=key, suffixes=("_human", "_ai"))
    n = len(m)
    obs = (m["label_human"] == m["label_ai"]).mean() if n else float("nan")
    ph, pa = (m[f"label_{w}"].value_counts(normalize=True).reindex(CLAIM_LABELS, fill_value=0) for w in ("human", "ai"))
    exp = float((ph * pa).sum())
    out = {"labelled": n, "agreement": obs, "agreement_ci_wilson": wilson(int(obs * n), n) if n else None,
           "cohen_kappa": (obs - exp) / (1 - exp) if n and exp < 1 else float("nan"),
           "agreement_supported_vs_not": ((m["label_human"] == "supported") == (m["label_ai"] == "supported")).mean() if n else float("nan")}
    for k, v in out.items():
        print(f"{k}: {np.round(v, 3) if isinstance(v, (float, tuple)) else v}")
    print("\n" + pd.crosstab(m["label_human"], m["label_ai"], rownames=["you"], colnames=["AI"]).to_string())
    diff = m[m["label_human"] != m["label_ai"]]
    if len(diff):
        print("\ndisagreements:\n" + diff[key + ["label_human", "label_ai", "claim", "note"]].to_string(index=False))
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["build", "score", "spotcheck", "agree"])
    ap.add_argument("--model", default=PROVIDERS["gemini"])
    ap.add_argument("--version", type=int, default=PROMPT_VERSION)
    ap.add_argument("--file", default=None, help="sheet to score (default: your narrator_labels.xlsx)")
    a = ap.parse_args()
    if a.cmd == "build":
        build(a.model, a.version)
    elif a.cmd == "score":
        score(a.file or OUT)
    elif a.cmd == "spotcheck":
        spotcheck()
    else:
        agree()
