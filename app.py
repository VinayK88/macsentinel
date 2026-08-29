"""MacSentinel Streamlit analyst workbench."""

from __future__ import annotations

import io
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from macsentinel.core import (
    FEATURE_COLUMNS,
    aggregate_sessions,
    build_provenance_edges,
    evaluate_scores,
    fit_logistic,
    group_train_test_split,
    predict_logistic,
)
from macsentinel.visuals import BLUE, ORANGE, bar_chart, histogram, line_chart, provenance_graph

DATA_PATH = ROOT / "data" / "synthetic_macos_events.csv"
REQUIRED_COLUMNS = {
    "event_id","timestamp","host_id","user_hash","session_id","step","parent_process","process",
    "event_type","target","scenario","label","signed","notarized","gatekeeper_bypass",
    "xprotect_detection","privilege_escalation","persistence_write","sensitive_access","network_beacon",
    "file_write_count","bytes_out","command_risk",
}

st.set_page_config(page_title="MacSentinel", page_icon="⌘", layout="wide")
st.markdown("""
<style>
:root{--ink:#1d1d1f;--muted:#6e6e73;--soft:#f5f5f7;--line:#e8e8ed;--blue:#0071e3;--green:#248a3d}
html,body,[class*="css"]{font-family:-apple-system,BlinkMacSystemFont,"SF Pro Display","SF Pro Text","Helvetica Neue",Arial,sans-serif;color:var(--ink)}
.stApp{background:linear-gradient(180deg,#fff 0%,#fff 72%,#fafafa 100%)}
.block-container{max-width:1480px;padding-top:1.2rem;padding-bottom:5rem}
[data-testid="stSidebar"]{background:rgba(245,245,247,.94);backdrop-filter:blur(22px);border-right:1px solid rgba(0,0,0,.06)}
[data-testid="stMetric"]{background:rgba(245,245,247,.86);border:1px solid rgba(0,0,0,.04);border-radius:28px;padding:1.15rem 1.2rem;box-shadow:0 12px 34px rgba(0,0,0,.035);min-height:116px}
[data-testid="stMetricLabel"]{font-size:.72rem;color:var(--muted);font-weight:650}
[data-testid="stMetricValue"]{font-size:1.9rem;color:var(--ink);font-weight:650;letter-spacing:-.045em}
[data-testid="stDataFrame"], [data-testid="stTable"]{border:1px solid var(--line);border-radius:24px;overflow:hidden}
button[data-baseweb="tab"]{font-weight:600;border-radius:999px;padding:.45rem .9rem}
.hero{padding:4.2rem 1rem 2.8rem;text-align:center;max-width:1080px;margin:0 auto}
.eyebrow{color:var(--blue);font-size:.76rem;font-weight:700;letter-spacing:.12em;text-transform:uppercase;margin-bottom:.95rem}
.hero-title{font-size:4.9rem;line-height:.97;font-weight:650;letter-spacing:-.072em;color:var(--ink);margin:0}
.hero-sub{font-size:1.24rem;line-height:1.52;color:var(--muted);max-width:880px;margin:1.35rem auto 0;letter-spacing:-.012em}
.chips{display:flex;flex-wrap:wrap;gap:.5rem;justify-content:center;margin-top:1.35rem}.chip{background:var(--soft);border:1px solid rgba(0,0,0,.04);border-radius:999px;padding:.48rem .82rem;font-size:.74rem;color:#424245}.health{background:#eff8f1;color:var(--green);font-weight:650}
.source-note{background:linear-gradient(135deg,#f5f5f7,#fbfbfd);border:1px solid rgba(0,0,0,.04);padding:1.15rem 1.3rem;border-radius:22px;color:var(--muted);margin-bottom:1.8rem}
.section-title{font-size:1.85rem;font-weight:650;letter-spacing:-.045em;color:var(--ink);margin:.2rem 0}.section-sub{font-size:.95rem;color:#86868b;line-height:1.5;margin-bottom:1rem}
hr{border-color:var(--line)!important;margin:2.5rem 0!important}
@media(max-width:900px){.hero-title{font-size:3.3rem}.hero-sub{font-size:1.05rem}.hero{padding-top:2.4rem}}
</style>
""", unsafe_allow_html=True)

@st.cache_data
def load_default_events() -> pd.DataFrame:
    return pd.read_csv(DATA_PATH, parse_dates=["timestamp"])

def validate_upload(frame: pd.DataFrame) -> None:
    missing = sorted(REQUIRED_COLUMNS - set(frame.columns))
    if missing:
        raise ValueError(f"Uploaded data is missing required columns: {', '.join(missing)}")
    if frame.empty:
        raise ValueError("Uploaded data contains no rows")
    frame["timestamp"] = pd.to_datetime(frame["timestamp"], utc=True, errors="raise")
    if frame["session_id"].nunique() < 20 or frame["host_id"].nunique() < 2:
        raise ValueError("Upload at least 20 sessions across two hosts for a meaningful holdout")
    if frame["label"].nunique() < 2:
        raise ValueError("The portfolio evaluation upload requires both benign and attack benchmark labels")

@st.cache_data
def analyze_events(events: pd.DataFrame) -> tuple[pd.DataFrame, dict[str, float], list[int], list[int]]:
    sessions = aggregate_sessions(events)
    train_index, test_index = group_train_test_split(sessions, test_fraction=0.30)
    features = sessions[FEATURE_COLUMNS].to_numpy()
    labels = sessions.label.to_numpy()
    model = fit_logistic(features[train_index], labels[train_index], FEATURE_COLUMNS)
    sessions["ml_score"] = predict_logistic(model, features)
    holdout_metrics = evaluate_scores(labels[test_index], sessions.iloc[test_index].ml_score.to_numpy(), 0.50)
    return sessions, holdout_metrics, train_index.tolist(), test_index.tolist()

st.markdown("""
<div class="hero">
  <div class="eyebrow">MacSentinel · macOS Threat Analytics</div>
  <div class="hero-title">See the story behind<br/>an endpoint alert.</div>
  <div class="hero-sub">Privacy-preserving macOS threat analytics with provenance graphs, host-separated ML evaluation, streaming-style telemetry, and analyst-ready evidence.</div>
  <div class="chips"><span class="chip">macOS Telemetry</span><span class="chip">Provenance Graphs</span><span class="chip">Logistic ML</span><span class="chip">Host-separated Evaluation</span><span class="chip">ATT&amp;CK Context</span><span class="chip health">● Synthetic system healthy</span></div>
</div>
<div class="source-note"><b>Portfolio demo.</b> The default dataset is synthetic and offline. Labels are benchmark truth, not information normally available to an analyst.</div>
""", unsafe_allow_html=True)

with st.sidebar:
    st.markdown("### MacSentinel")
    st.caption("Detection controls")
    uploaded = st.file_uploader("Optional normalized event CSV", type=["csv"], help="Use only authorized, sanitized telemetry with the documented schema.")
    threshold = st.slider("Alert threshold", 0.05, 0.95, 0.50, 0.01)
    st.caption("Higher thresholds reduce queue volume and may miss stealthier behavior.")

if uploaded is None:
    events = load_default_events(); source_label = "Bundled synthetic fixture"
else:
    try:
        events = pd.read_csv(io.BytesIO(uploaded.getvalue())); validate_upload(events); source_label = f"Uploaded authorized fixture · {uploaded.name}"
    except Exception as exc:
        st.error(str(exc)); st.stop()

sessions, holdout_metrics, train_index, test_index = analyze_events(events)
scenario_options = sorted(sessions.scenario.unique()); host_options = sorted(sessions.host_id.unique())
with st.sidebar:
    scenarios = st.multiselect("Scenarios", scenario_options, default=scenario_options)
    hosts = st.multiselect("Hosts", host_options, default=host_options)
    st.divider(); st.caption(f"Source: {source_label}"); st.caption(f"UTC coverage: {events.timestamp.min()} → {events.timestamp.max()}")

filtered_sessions = sessions[sessions.scenario.isin(scenarios) & sessions.host_id.isin(hosts)].copy()
filtered_events = events[events.session_id.isin(filtered_sessions.session_id)].copy()
if filtered_sessions.empty:
    st.warning("No sessions match the selected host and scenario filters."); st.stop()
filtered_sessions["alert"] = filtered_sessions.ml_score.ge(threshold)

metric_columns = st.columns(5)
metric_columns[0].metric("Sessions", f"{len(filtered_sessions):,}")
metric_columns[1].metric("Events", f"{len(filtered_events):,}")
metric_columns[2].metric("Alerts", f"{int(filtered_sessions.alert.sum()):,}", f"{filtered_sessions.alert.mean():.1%} queue rate")
metric_columns[3].metric("Benchmark attacks", f"{int(filtered_sessions.label.sum()):,}")
metric_columns[4].metric("Holdout F1", f"{holdout_metrics['f1']:.2f}", "unseen hosts")

overview_tab, investigation_tab, lab_tab, methods_tab = st.tabs(["Overview", "Investigation", "Detection lab", "Methodology"])

with overview_tab:
    st.markdown('<div class="section-title">Detection overview</div><div class="section-sub">How synthetic attack and benign sessions separate under the current threshold and filters.</div>', unsafe_allow_html=True)
    chart_columns = st.columns(2)
    with chart_columns[0]:
        score_figure = histogram({"benign": filtered_sessions.loc[filtered_sessions.label.eq(0), "ml_score"],"attack": filtered_sessions.loc[filtered_sessions.label.eq(1), "ml_score"]},"Detection-score distribution","Filtered synthetic sessions; benchmark labels are shown for model evaluation")
        st.image(score_figure, use_container_width=True)
    with chart_columns[1]:
        scenario_alerts = filtered_sessions.groupby("scenario").alert.mean().sort_values()
        scenario_figure = bar_chart(scenario_alerts.index,scenario_alerts.values,"Alert rate by scenario",f"Share of filtered sessions scoring at least {threshold:.2f}",color=ORANGE)
        st.image(scenario_figure, use_container_width=True)
    hourly = filtered_sessions.assign(hour=filtered_sessions.timestamp.dt.floor("h")).groupby("hour").agg(mean_score=("ml_score","mean"),alert_rate=("alert","mean")).tail(36)
    timeline_figure = line_chart([timestamp.strftime("%d %Hh") for timestamp in hourly.index],{"mean score": hourly.mean_score,"alert rate": hourly.alert_rate},"Detection trend across the latest 36 observed hours","Session score and queue rate by UTC hour for current filters","rate / score")
    st.image(timeline_figure, use_container_width=True)

with investigation_tab:
    st.markdown('<div class="section-title">Analyst investigation</div><div class="section-sub">Move from a ranked session to its process, file, domain, and resource relationships.</div>', unsafe_allow_html=True)
    queue = filtered_sessions.sort_values(["alert","ml_score","rule_risk"], ascending=False)
    if queue.empty:
        st.info("No sessions match the selected filters.")
    else:
        selected_session = st.selectbox("Session", queue.session_id, format_func=lambda session_id: f"{session_id} · {queue.set_index('session_id').loc[session_id, 'host_id']} · score {queue.set_index('session_id').loc[session_id, 'ml_score']:.3f}")
        selected_row = queue.set_index("session_id").loc[selected_session]
        session_metrics = st.columns(4)
        session_metrics[0].metric("ML score", f"{selected_row.ml_score:.3f}"); session_metrics[1].metric("Rule risk", f"{selected_row.rule_risk:.1f}/100"); session_metrics[2].metric("Scenario", str(selected_row.scenario).replace("_", " ")); session_metrics[3].metric("Disposition", "Alert" if selected_row.ml_score >= threshold else "Below threshold")
        edges = build_provenance_edges(events, [selected_session])
        st.image(provenance_graph(edges,"Selected session provenance graph",f"{selected_session} · directed process, file, domain, and resource relationships"),use_container_width=True)
        details = events[events.session_id.eq(selected_session)][["timestamp","parent_process","process","event_type","target","mitre_technique"]].sort_values("timestamp")
        st.table(details)
    st.markdown('<div class="section-title">Prioritized investigation queue</div>', unsafe_allow_html=True)
    queue_table = queue[["session_id","timestamp","host_id","scenario","ml_score","rule_risk","alert"]].head(20).copy()
    queue_table["timestamp"] = queue_table.timestamp.dt.strftime("%Y-%m-%d %H:%M:%S UTC"); queue_table["ml_score"] = queue_table.ml_score.round(3); queue_table["rule_risk"] = queue_table.rule_risk.round(1)
    st.table(queue_table)

with lab_tab:
    st.markdown('<div class="section-title">Host-separated detection evaluation</div><div class="section-sub">Training and test rows are separated by host identity to reduce entity leakage.</div>', unsafe_allow_html=True)
    evaluation = pd.DataFrame({"metric":["precision","recall","F1","average precision","alert rate"],"value":[holdout_metrics["precision"],holdout_metrics["recall"],holdout_metrics["f1"],holdout_metrics["average_precision"],holdout_metrics["alert_rate"]]})
    evaluation["value"] = evaluation.value.map(lambda value: f"{value:.3f}"); st.table(evaluation)
    st.info("Synthetic performance is a regression benchmark—not evidence of production efficacy. Notebook 06 demonstrates severe recall degradation under attacker mimicry.")
    importance_labels=[name.replace("_"," ") for name in FEATURE_COLUMNS]; importance_values=filtered_sessions[FEATURE_COLUMNS].std().fillna(0).to_numpy()
    st.image(bar_chart(importance_labels,importance_values,"Feature variability in the current view","Standard deviation across filtered sessions; variability is not causal importance",color=BLUE),use_container_width=True)

with methods_tab:
    st.markdown('<div class="section-title">Architecture and safeguards</div>', unsafe_allow_html=True)
    st.markdown("""
1. Normalize authorized macOS event telemetry into process, file, network, and control signals.
2. Aggregate bounded six-event sessions and create a transparent rule score.
3. Evaluate robust anomaly, logistic, GRU-style sequence, and temporal graph approaches.
4. Split by host, tune against analyst capacity, and preserve evidence for every alert.
5. Stress-test concept drift and attacker mimicry before release.

**Privacy:** identifiers are pseudonymous; the schema intentionally excludes file contents, clipboard contents, message bodies, passwords, and secrets.

**Platform boundary:** a real Endpoint Security client requires Apple authorization and an entitlement. This public project uses `eslogger`-compatible concepts and synthetic fixtures only.
""")
    st.code("streamlit run app.py", language="bash")
