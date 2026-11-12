"""De-Riddled analyst dashboard (Streamlit): overview, alert queue with case view and labelling, label-feedback loop, and monitoring."""
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import pycountry
import streamlit as st

from deriddled import analyst as sql_agent, narrator
from deriddled import casework as cw
from deriddled.ops import OpsStore

st.set_page_config(page_title="De-Riddled", layout="wide")


@st.cache_resource
def ops_store() -> OpsStore:
    return OpsStore()


@st.cache_data
def kpis():
    return cw.kpis()


@st.cache_data
def daily():
    return cw.daily()


@st.cache_data
def alert_frame():
    a = cw.alerts().drop(columns=["label", "analyst", "labelled_at"])
    d = cw.login_details(a)
    return a.merge(d, on="login_id", how="left")


@st.cache_data
def features(ids: tuple):
    return cw.alert_features(alert_frame().query("login_id in @ids"))


@st.cache_data
def history(user_id: int, before: pd.Timestamp):
    return cw.user_history(user_id, before)


@st.cache_data
def registry():
    return cw.registry_versions()


def iso3(code: str) -> str | None:
    c = pycountry.countries.get(alpha_2=code) if isinstance(code, str) else None
    return c.alpha_3 if c else None


def with_labels() -> pd.DataFrame:
    return alert_frame().merge(cw.labels(), on="login_id", how="left")


def country_map(hist: pd.DataFrame, current: str) -> go.Figure:
    counts = hist.groupby("country").size().rename("logins").reset_index()
    counts["iso3"] = counts["country"].map(iso3)
    fig = px.choropleth(counts.dropna(subset=["iso3"]), locations="iso3", color="logins",
                        color_continuous_scale="Blues", hover_name="country")
    cur = iso3(current)
    if cur:
        fig.add_trace(go.Choropleth(locations=[cur], z=[1], colorscale=[[0, "#d62728"], [1, "#d62728"]],
                                    showscale=False, marker_line_color="black", marker_line_width=1.5,
                                    hovertext=[f"this login: {current}"], hoverinfo="text"))
    fig.update_layout(margin=dict(l=0, r=0, t=0, b=0), height=320, coloraxis_colorbar=dict(title="past logins"))
    return fig


ACTION_TEXT = {"confirm_takeover": "Confirm takeover", "contact_user_out_of_band": "Contact the user out of band",
               "likely_false_alarm": "Likely false alarm", "needs_more_information": "Needs more information"}


def show_summary(r: dict) -> None:
    if "error" in r:
        st.error(r["error"])
        return
    g, ev = r["grounded"], r["evidence"]
    st.info(f"Suggested: **{ACTION_TEXT.get(g['recommended_action'], g['recommended_action'])}** "
            f"(confidence {g['confidence']}) · cites {', '.join(g['action_evidence_ids']) or 'nothing'}")
    for c in g["claims"]:
        st.markdown(f"- {c['text']} `{' '.join(c['evidence_ids'])}`")
    if g["removed"]:
        with st.expander(f"{len(g['removed'])} claim(s) removed by the grounding check"):
            for c in g["removed"]:
                st.markdown(f"- ~~{c['text']}~~ — {c['reason']}")
    with st.expander("Evidence sent to the model"):
        st.dataframe(pd.DataFrame({"id": list(ev), "evidence": list(ev.values())}), hide_index=True, width="stretch")
    st.caption(f"{r['model']} · ${r['cost_usd']:.4f} · {r['seconds']}s · written {r['logged_at'][:19]} UTC · "
               "the model's decision is not changed by this summary")


EXAMPLES = ["How many logins were blocked or challenged per day in the decision log?",
            "Which 5 countries had the most account takeovers?",
            "What share of logins from known attack IPs had the correct password?"]


@st.cache_resource
def analyst_con():
    return sql_agent.connect()


k = kpis()
st.title("De-Riddled: account-takeover alerts")
st.caption(f"Decision log {k['first'][:16]} → {k['last'][:16]} · model {k['model_version']} · "
           "replayed validation week served by the scoring API")

analyst = st.sidebar.text_input("Analyst name", value="analyst-1")
show_truth = st.sidebar.toggle("Show dataset label (evaluation only)", value=False,
                               help="In production the analyst never sees this; here it lets you check the queue.")

page = st.sidebar.radio("View", ["Overview", "Alert queue", "Feedback loop", "Monitoring", "Ask the data"])

if page == "Overview":
    c = st.columns(3) + st.columns(3)
    c[0].metric("Logins scored", f"{k['logins']:,}")
    c[1].metric(f"Challenged ({k['challenge'] / k['logins']:.3%})", f"{k['challenge']:,}")
    c[2].metric(f"Blocked ({k['block'] / k['logins']:.4%})", f"{k['block']:,}")
    c[3].metric("Fail-opens", k["fail_open"])
    c[4].metric("Scoring p50", f"{k['p50_ms']:.1f} ms")
    c[5].metric("Scoring p95", f"{k['p95_ms']:.1f} ms")

    d = daily()
    flagged = d[d["action"] != "ALLOW"]
    fig = px.bar(flagged, x="day", y="logins", color="action", barmode="stack",
                 color_discrete_map={"CHALLENGE": "#ff7f0e", "BLOCK": "#d62728"}, title="Alerts per day")
    fig.update_layout(height=320, margin=dict(t=40, b=0))
    st.plotly_chart(fig, width="stretch")

    shadow = cw.shadow_summary()
    if shadow is not None:
        st.subheader("Shadow mode, validation (Aug–Sep 2020, 33 takeovers)")
        show = shadow.rename(columns={"policy": "Policy", "legit_friction": "Legit users challenged",
                                      "ato_stopped": "Takeovers stopped", "cost_per_1000": "Cost per 1,000 logins"})
        show["Policy"] = show["Policy"].map({"rule": "Rule (≥5 fails / hour)", "lr_matched": "Likelihood ratio, same budget",
                                             "model": "De-Riddled", "allow_all": "Allow everything"})
        st.dataframe(show[["Policy", "Legit users challenged", "Takeovers stopped", "Cost per 1,000 logins"]]
                     .style.format({"Legit users challenged": "{:.3%}", "Takeovers stopped": "{:.0f} / 33",
                                    "Cost per 1,000 logins": "{:.2f}"}),
                     hide_index=True, width="stretch")

if page == "Alert queue":
    q = with_labels()
    f1, f2 = st.columns([1, 3])
    status = f1.radio("Show", ["Unlabelled", "All", "Labelled"], horizontal=True)
    acts = f2.multiselect("Action", ["BLOCK", "CHALLENGE"], default=["BLOCK", "CHALLENGE"])
    view = q[q["action"].isin(acts)]
    if status == "Unlabelled":
        view = view[view["label"].isna()]
    elif status == "Labelled":
        view = view[view["label"].notna()]
    view = view.reset_index(drop=True)
    st.caption(f"{len(view)} alerts · {q['label'].notna().sum()} of {len(q)} labelled")

    cols = ["event_ts", "action", "score", "country", "city", "asn", "device_type", "label"]
    if show_truth:
        cols.append("is_ato")
    pick = st.dataframe(view[cols].rename(columns={"score": "p(takeover)"}), hide_index=True, width="stretch",
                        on_select="rerun", selection_mode="single-row", height=300,
                        column_config={"p(takeover)": st.column_config.ProgressColumn(format="%.4f", min_value=0, max_value=1)})

    rows = pick.selection.rows
    if not rows:
        st.info("Select an alert to open the case.")
    else:
        a = view.iloc[rows[0]]
        st.subheader(f"Case {a['login_id']} · {a['action']} · p = {a['score']:.4f}")
        left, right = st.columns([1, 1])
        with left:
            st.markdown("**Why it was flagged**")
            for r in a["reasons"]:
                st.markdown(f"- {r}")
            st.markdown("**Login**")
            st.table(pd.DataFrame({"": [
                str(a["event_ts"])[:19], str(a["user_id"]), ", ".join(str(x) for x in (a["city"], a["region"], a["country"]) if pd.notna(x)),
                f"{a['ip']} (ASN {a['asn']})", f"{a['browser']} on {a['os']} ({a['device_type']})",
                "yes" if a["login_successful"] else "no"]},
                index=["Time", "User", "Location", "IP / network", "Browser", "Password correct"]))
            if show_truth:
                st.caption(f"Dataset label: {'TAKEOVER' if a['is_ato'] else 'not a labelled takeover'}"
                           f"{' · attack IP' if a['is_attack_ip'] else ''}")
        hist = history(int(a["user_id"]), a["event_ts"])
        past = hist[hist["ts"] < a["event_ts"]]
        with right:
            st.markdown(f"**Where this user logged in before** ({len(past)} earlier logins; red = this login)")
            st.plotly_chart(country_map(past, a["country"]), width="stretch")
        st.markdown("**Account history (most recent first)**")
        st.dataframe(hist.head(20), hide_index=True, width="stretch")

        st.markdown("**AI case summary** (Claude Haiku · hashed IDs only · every claim cites evidence)")
        summary = narrator.cached(int(a["login_id"]), a["model_version"])
        if summary is None and st.button("Write summary (~$0.001)"):
            with st.spinner("Writing summary…"):
                try:
                    summary = narrator.summarize_alert(a)
                except Exception as exc:
                    st.error(f"Summary failed: {type(exc).__name__}: {str(exc)[:200]}")
        if summary is not None:
            show_summary(summary)

        b1, b2, b3 = st.columns([1, 1, 4])
        if b1.button("Confirm takeover", type="primary"):
            ops_store().add_label(int(a["login_id"]), "confirmed_fraud", analyst)
            st.rerun()
        if b2.button("False alarm"):
            ops_store().add_label(int(a["login_id"]), "false_alarm", analyst)
            st.rerun()
        if pd.notna(a["label"]):
            b3.success(f"Labelled {a['label']} by {a['analyst']} at {str(a['labelled_at'])[:19]}")

if page == "Feedback loop":
    q = with_labels()
    lab = q[q["label"].notna()]
    c = st.columns(4)
    c[0].metric("Alerts labelled", f"{len(lab)} / {len(q)}")
    c[1].metric("Confirmed takeovers", int((lab["label"] == "confirmed_fraud").sum()))
    c[2].metric("False alarms", int((lab["label"] == "false_alarm").sum()))
    c[3].metric("Alert precision (labelled)", f"{(lab['label'] == 'confirmed_fraud').mean():.0%}" if len(lab) else "—")

    st.subheader("1. Fast path: labels update network reputation")
    st.markdown("Confirmed takeovers feed the ASN / subnet / IP takeover counters straight away instead of waiting for "
                "the 7-day chargeback delay. Below, every alert is re-scored as if your confirmations were already in "
                "those counters (each alert excludes its own label).")
    confirmed = set(lab.loc[lab["label"] == "confirmed_fraud", "login_id"].astype(int))
    if not confirmed:
        st.info("Confirm at least one takeover in the alert queue to see its effect.")
    else:
        ids = tuple(int(i) for i in q["login_id"])
        r = cw.rescore_with_labels(features(ids), alert_frame(), confirmed)
        moved = r[(r[["added_asn", "added_subnet", "added_ip"]].sum(axis=1) > 0)].copy()
        moved["change"] = moved["p_after"] / moved["p_before"] - 1
        st.caption(f"{len(moved)} other alerts share a network with your confirmations.")
        if len(moved):
            st.dataframe(moved.merge(alert_frame()[["login_id", "country", "asn"]], on="login_id")
                         [["login_id", "country", "asn", "added_asn", "added_subnet", "added_ip",
                           "p_before", "p_after", "change", "action_before", "action_after"]]
                         .style.format({"p_before": "{:.4f}", "p_after": "{:.4f}", "change": "{:+.1%}"}),
                         hide_index=True, width="stretch")
            if (moved["change"] < 0).any():
                st.warning("Some scores went **down** after a confirmation on the same network. The model's response "
                           "to `asn_ato_prior` is not monotonic (it rises from 0 to 1 prior takeover, then falls). "
                           "Fix: retrain with monotone constraints on the reputation features.")
            elif (moved["change"].abs() < 1e-9).all():
                st.info("No score changed: these networks already had an earlier takeover, and the champion's "
                        "takeover-history response is monotone and flat above one prior takeover. Confirmations "
                        "can never lower a score; they raise it for networks with no takeover history yet.")

    st.subheader("2. Slow path: labels become training data")
    new_pos = int((lab["label"] == "confirmed_fraud").sum())
    trigger = 9
    st.markdown(f"The champion was trained on **86** takeovers. Retrain policy: monthly, or early once **{trigger}** new "
                f"confirmed takeovers (about 10% more positives) have arrived, or when an output-drift alarm fires. "
                f"A candidate must beat the champion on the newest held-out month before its alias moves.")
    st.progress(min(new_pos / trigger, 1.0), text=f"{new_pos} / {trigger} new confirmed takeovers")
    if st.button("Load model registry (MLflow)"):
        st.dataframe(registry(), hide_index=True, width="stretch")

if page == "Monitoring":
    p = cw.psi()
    if p is not None:
        st.subheader("Population stability index by month (reference: Feb–Jul 2020)")
        st.caption("Alert on the model output (`margin`); features are diagnostics. PSI > 0.2 = significant shift.")
        out = p.loc[["margin", "lr_score"]].T.reset_index(names="month").melt("month", var_name="series", value_name="PSI")
        fig = px.line(out, x="month", y="PSI", color="series", markers=True)
        fig.add_hline(y=0.2, line_dash="dash", line_color="red")
        fig.update_layout(height=300, margin=dict(t=10, b=0))
        st.plotly_chart(fig, width="stretch")
        fig = px.imshow(p.drop(index=["margin"]), color_continuous_scale="Reds", zmin=0, zmax=1, aspect="auto",
                        text_auto=".2f")
        fig.update_layout(height=380, margin=dict(t=10, b=0))
        st.plotly_chart(fig, width="stretch")

if page == "Ask the data":
    st.subheader("Ask the data (SQL analyst agent)")
    st.caption("Claude Haiku writes read-only DuckDB SQL over hashed logins (Feb – 14 Sep 2020) and the decision log. "
               "Single SELECT only, 200-row cap, 30 s timeout. Held-out accuracy 9/10, about $0.001 per question.")
    pick = st.selectbox("Example", ["(type your own)"] + EXAMPLES)
    with st.form("ask"):
        q = st.text_area("Question", value="" if pick == "(type your own)" else pick, height=80)
        go_ask = st.form_submit_button("Ask", type="primary")
    if go_ask and q.strip():
        with st.spinner("Querying…"):
            try:
                st.session_state["answer"] = sql_agent.ask(q.strip(), con=analyst_con())
            except Exception as exc:
                st.error(f"Agent failed: {type(exc).__name__}: {str(exc)[:200]}")
    r = st.session_state.get("answer")
    if r:
        st.markdown(f"**Q:** {r['question']}")
        st.success(r["answer"] or "(no answer text)")
        if not r["declared"]:
            st.warning("The agent did not call final_answer; showing its last successful query.")
        if r["final_result"] is not None:
            st.dataframe(r["final_result"], hide_index=True, width="stretch")
        if r["final_sql"]:
            st.code(r["final_sql"], language="sql")
        with st.expander(f"{len(r['steps'])} tool call(s)"):
            for s in r["steps"]:
                st.markdown(f"**{s['tool']}** · {s['error'] or str(s.get('rows', '')) + ' rows'} · {s['seconds']}s")
                st.code(s.get("sql") or str(s["input"]), language="sql" if s.get("sql") else None)
        st.caption(f"{r['model']} · {r['input_tokens']:,} in / {r['output_tokens']:,} out tokens · "
                   f"${r['cost_usd']:.4f} · {r['seconds']}s")
