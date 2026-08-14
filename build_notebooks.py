"""Build the six reproducible MacSentinel portfolio notebooks."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

from macsentinel.core import generate_macos_events


ROOT = Path(__file__).resolve().parent
PROJECT = ROOT
NOTEBOOK_DIR = PROJECT / "notebooks"
DATA_DIR = PROJECT / "data"


def clean(text: str) -> str:
    return textwrap.dedent(text).strip() + "\n"


def markdown(text: str) -> dict:
    return {"cell_type": "markdown", "metadata": {}, "source": clean(text).splitlines(keepends=True)}


def code(text: str) -> dict:
    return {
        "cell_type": "code",
        "execution_count": None,
        "metadata": {},
        "outputs": [],
        "source": clean(text).splitlines(keepends=True),
    }


def notebook(cells: list[dict]) -> dict:
    for index, cell in enumerate(cells, start=1):
        cell["id"] = f"cell-{index:02d}"
    return {
        "cells": cells,
        "metadata": {
            "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
            "language_info": {"name": "python", "version": "3.11"},
        },
        "nbformat": 4,
        "nbformat_minor": 5,
    }


SETUP = """
from pathlib import Path

import numpy as np
import pandas as pd

from macsentinel.core import *
from macsentinel.visuals import *

SEED = 42
DATA_PATH = Path("data/synthetic_macos_events.csv")
events = pd.read_csv(DATA_PATH, parse_dates=["timestamp"])
FIGURES = []
pd.set_option("display.max_columns", 30)
pd.set_option("display.width", 140)

print(f"Loaded {len(events):,} synthetic events across {events.session_id.nunique():,} sessions and {events.host_id.nunique()} hosts.")
"""


def intro(title: str, tldr: str, goal: str) -> list[dict]:
    return [
        markdown(
            f"""
            # {title}

            ## tl;dr

            {tldr}

            ## Goal

            {goal}

            **Safety and scope:** all events are deterministic synthetic fixtures. Reserved `.example` domains and inert filenames are used; this project does not execute payloads, collect private data, or bypass platform controls.
            """
        ),
        markdown(
            """
            ## Setup

            Load the shared synthetic macOS telemetry fixture and dependency-light visualization helpers. The data source and seed are explicit so every result can be reproduced offline.
            """
        ),
        code(SETUP),
    ]


def notebook_01() -> dict:
    cells = intro(
        "MacSentinel 01 · macOS Telemetry Exploration",
        "The fixture contains six multi-step attack stories alongside benign user and administrator behavior. The analysis checks class balance, telemetry coverage, and the event patterns that will later drive detection models.",
        "Understand the structure, limitations, and observable signals in normalized macOS Endpoint Security-style telemetry.",
    )
    cells += [
        markdown("## Steps\n\n### 1. Validate source, grain, and coverage"),
        code(
            """
coverage = pd.Series({
    "events": len(events),
    "sessions": events.session_id.nunique(),
    "hosts": events.host_id.nunique(),
    "users": events.user_hash.nunique(),
    "attack_sessions": events.loc[events.label.eq(1), "session_id"].nunique(),
    "missing_required_values": int(events[["timestamp", "host_id", "session_id", "process", "event_type", "label"]].isna().sum().sum()),
})
print(coverage.to_string())
assert coverage["missing_required_values"] == 0
assert events.event_id.is_unique
"""
        ),
        markdown("### 2. Profile scenarios and event types"),
        code(
            """
scenario_sessions = events.groupby("scenario").session_id.nunique().sort_values(ascending=False)
event_mix = pd.crosstab(events.scenario, events.event_type)
print("Sessions by scenario:\\n", scenario_sessions.to_string())
print("\\nEvent mix by scenario:\\n", event_mix.to_string())

figure = bar_chart(
    scenario_sessions.index,
    scenario_sessions.values,
    "Synthetic sessions by scenario",
    "Session count; benign activity intentionally dominates the offline fixture",
)
FIGURES.append(figure)
figure
"""
        ),
        markdown("## Visual Insights & ML Extension\n\n### 3. Compare observable signal coverage"),
        code(
            """
signal_columns = ["gatekeeper_bypass", "xprotect_detection", "privilege_escalation", "persistence_write", "sensitive_access", "network_beacon"]
signal_matrix = events.groupby("scenario")[signal_columns].sum().reindex([name for name in SCENARIOS if name != "benign"]).fillna(0)
print(signal_matrix.astype(int).to_string())

figure = matrix_chart(
    signal_matrix.to_numpy(),
    signal_matrix.index,
    [name.replace("_", " ") for name in signal_columns],
    "Security-signal coverage by attack scenario",
    "Synthetic event counts; darker cells indicate stronger observable coverage",
)
FIGURES.append(figure)
figure
"""
        ),
        markdown("### 4. Inspect event volume over time"),
        code(
            """
timeline = (
    events.assign(hour=events.timestamp.dt.floor("h"))
    .groupby(["hour", "label"]).size().unstack(fill_value=0)
    .rename(columns={0: "benign", 1: "attack"})
)
for column in ["benign", "attack"]:
    if column not in timeline:
        timeline[column] = 0
timeline = timeline.tail(24)
figure = line_chart(
    [stamp.strftime("%H:%M") for stamp in timeline.index],
    {"benign": timeline["benign"].to_numpy(), "attack": timeline["attack"].to_numpy()},
    "Event volume during the latest 24 observed hours",
    "Counts per UTC hour; event labels are available only because this is a synthetic benchmark",
    "events",
)
FIGURES.append(figure)
figure
"""
        ),
        markdown("## Checks"),
        code(
            """
assert set(events.scenario.unique()) == set(SCENARIOS)
assert events.groupby("session_id").size().eq(6).all()
assert events.timestamp.dt.tz is not None
assert events.data_source.eq("synthetic macOS Endpoint Security-style fixture").all()
print("PASS: schema, session grain, timezone, scenario coverage, and synthetic-source labels are valid.")
"""
        ),
        markdown(
            """
            ## Next Steps

            - Replace the fixture reader with an authorized `eslogger` normalization adapter.
            - Keep pseudonymous user/host identifiers and avoid file-content collection.
            - Preserve the synthetic fixture as a deterministic regression suite.
            """
        ),
    ]
    return notebook(cells)


def notebook_02() -> dict:
    cells = intro(
        "MacSentinel 02 · Provenance Graph Investigation",
        "Process, file, domain, and resource relationships turn isolated events into an investigation story. The notebook builds a directed provenance graph and derives interpretable graph indicators without executing any suspicious content.",
        "Construct and inspect a process–file–network provenance graph for a synthetic macOS attack session.",
    )
    cells += [
        markdown("## Steps\n\n### 1. Select a representative investigation"),
        code(
            """
sessions = aggregate_sessions(events)
candidate = sessions[sessions.scenario.eq("launchagent_persistence")].sort_values("rule_risk", ascending=False).iloc[0]
investigation_events = events[events.session_id.eq(candidate.session_id)].sort_values("step")
print(investigation_events[["timestamp", "parent_process", "process", "event_type", "target", "mitre_technique"]].to_string(index=False))
"""
        ),
        markdown("### 2. Build a directed edge list"),
        code(
            """
edges = build_provenance_edges(events, [candidate.session_id])
print(edges[["source", "relation", "target"]].to_string(index=False))
print(f"\\nGraph: {len(set(edges.source) | set(edges.target))} nodes, {len(edges)} unique directed relationships")
"""
        ),
        markdown("## Visual Insights & ML Extension\n\n### 3. Render the investigation graph"),
        code(
            """
figure = provenance_graph(
    edges,
    "LaunchAgent persistence provenance graph",
    f"Synthetic investigation {candidate.session_id}; process, file, domain, and resource relationships",
)
FIGURES.append(figure)
figure
"""
        ),
        markdown("### 4. Rank graph entities for analyst review"),
        code(
            """
outgoing = edges.groupby("source").size().rename("outgoing")
incoming = edges.groupby("target").size().rename("incoming")
centrality = pd.concat([outgoing, incoming], axis=1).fillna(0)
centrality["degree"] = centrality.outgoing + centrality.incoming
centrality = centrality.sort_values(["degree", "outgoing"], ascending=False)
print(centrality.head(10).to_string())

figure = bar_chart(
    [index.split(":", 1)[-1] for index in centrality.head(8).index],
    centrality.head(8).degree,
    "Highest-connectivity entities in the investigation",
    "Directed degree is a triage heuristic, not proof of maliciousness",
    color=BLUE,
)
FIGURES.append(figure)
figure
"""
        ),
        markdown("### 5. Extract temporal graph features across all sessions"),
        code(
            """
graph_sessions = temporal_graph_features(events)
graph_columns = ["graph_node_count", "graph_edge_count", "graph_density", "process_influence", "file_influence", "domain_influence", "embedding_energy"]
summary = graph_sessions.groupby("label")[graph_columns].mean().rename(index={0: "benign", 1: "attack"})
print(summary.round(3).to_string())
"""
        ),
        markdown("## Checks"),
        code(
            """
assert not edges.empty
assert {"source", "target", "relation"}.issubset(edges.columns)
assert edges.source.str.contains(":").all() and edges.target.str.contains(":").all()
assert graph_sessions.session_id.is_unique
print("PASS: edge schema, entity typing, and one-row-per-session graph features are valid.")
"""
        ),
        markdown(
            """
            ## Next Steps

            - Add bounded sliding windows for live Endpoint Security events.
            - Store relation-level evidence alongside every graph alert.
            - Test graph growth, pruning, and memory limits before on-device use.
            """
        ),
    ]
    return notebook(cells)


def notebook_03() -> dict:
    cells = intro(
        "MacSentinel 03 · Streaming Anomaly Detection",
        "A transparent robust-z detector produces a review queue without requiring attack labels. Thresholds are selected against analyst capacity, then compared with a supervised logistic benchmark using a host-separated holdout.",
        "Detect unusual macOS sessions while making alert volume, false positives, and threshold trade-offs visible.",
    )
    cells += [
        markdown("## Steps\n\n### 1. Aggregate sessions and create a host-separated split"),
        code(
            """
sessions = aggregate_sessions(events)
train_index, test_index = group_train_test_split(sessions, test_fraction=0.30)
features = sessions[FEATURE_COLUMNS].to_numpy()
labels = sessions.label.to_numpy()
print(pd.Series({"train_sessions": len(train_index), "test_sessions": len(test_index), "test_hosts": sessions.iloc[test_index].host_id.nunique(), "test_attack_rate": labels[test_index].mean()}).to_string())
"""
        ),
        markdown("### 2. Score the test stream with a transparent anomaly baseline"),
        code(
            """
anomaly_scores = robust_anomaly_score(features)
test_scores = anomaly_scores[test_index]
capacity_threshold = float(np.quantile(test_scores, 0.86))
anomaly_metrics = evaluate_scores(labels[test_index], test_scores, capacity_threshold)
print(pd.Series(anomaly_metrics).round(4).to_string())
"""
        ),
        markdown("### 3. Compare a supervised detection model"),
        code(
            """
logistic_model = fit_logistic(features[train_index], labels[train_index], FEATURE_COLUMNS)
logistic_scores = predict_logistic(logistic_model, features[test_index])
logistic_metrics = evaluate_scores(labels[test_index], logistic_scores, 0.50)
comparison = pd.DataFrame([anomaly_metrics, logistic_metrics], index=["robust anomaly", "logistic"])
print(comparison[["precision", "recall", "f1", "average_precision", "alert_rate"]].round(3).to_string())
"""
        ),
        markdown("## Visual Insights & ML Extension\n\n### 4. Visualize score separation"),
        code(
            """
test_labels = labels[test_index]
figure = histogram(
    {"benign": logistic_scores[test_labels == 0], "attack": logistic_scores[test_labels == 1]},
    "Detection-score distribution on unseen hosts",
    "Host-separated test sessions; overlap represents analyst-review ambiguity",
)
FIGURES.append(figure)
figure
"""
        ),
        markdown("### 5. Tune precision, recall, and alert volume"),
        code(
            """
curve = precision_recall_curve(test_labels, logistic_scores)
feasible = curve[curve.alert_rate.le(0.20)].sort_values(["recall", "precision"], ascending=False)
selected = feasible.iloc[0]
print("Selected analyst-capacity operating point:\\n", selected[["threshold", "precision", "recall", "f1", "alert_rate"]].round(3).to_string())

figure = line_chart(
    [f"{value:.2f}" for value in curve.threshold],
    {"precision": curve.precision, "recall": curve.recall, "alert rate": curve.alert_rate},
    "Detection trade-offs across score thresholds",
    "Rates on unseen hosts; the operating threshold must match analyst capacity",
    "rate",
)
FIGURES.append(figure)
figure
"""
        ),
        markdown("## Checks"),
        code(
            """
train_hosts = set(sessions.iloc[train_index].host_id)
test_hosts = set(sessions.iloc[test_index].host_id)
assert train_hosts.isdisjoint(test_hosts)
assert np.all((logistic_scores >= 0) & (logistic_scores <= 1))
assert 0 < selected.alert_rate <= 0.20
print("PASS: entity leakage is blocked, scores are calibrated to [0, 1], and the queue respects capacity.")
"""
        ),
        markdown(
            """
            ## Next Steps

            - Calibrate thresholds from real analyst dispositions instead of synthetic labels.
            - Monitor alert rate and precision by macOS version and host role.
            - Use graph and sequence models only when they beat this transparent baseline under equal review budgets.
            """
        ),
    ]
    return notebook(cells)


def notebook_04() -> dict:
    cells = intro(
        "MacSentinel 04 · GRU-Style Sequence Detection",
        "A deterministic GRU cell converts ordered six-event sessions into compact embeddings, and a learned logistic head classifies unseen hosts. The architecture exposes the sequence representation without requiring a heavyweight deep-learning runtime.",
        "Evaluate whether ordered event context improves detection beyond flat session features.",
    )
    cells += [
        markdown("## Steps\n\n### 1. Build ordered session tensors"),
        code(
            """
sequence_tensor, sequence_labels, sequence_ids, sequence_features = make_sequence_tensor(events)
session_lookup = aggregate_sessions(events).set_index("session_id").loc[sequence_ids].reset_index()
train_index, test_index = group_train_test_split(session_lookup, test_fraction=0.30)
print(pd.Series({"sessions": len(sequence_ids), "steps": sequence_tensor.shape[1], "event_features": sequence_tensor.shape[2], "attack_rate": sequence_labels.mean()}).to_string())
print("Sequence features:", ", ".join(sequence_features))
"""
        ),
        markdown("### 2. Encode each event stream with an inspectable GRU cell"),
        code(
            """
gru_embeddings = gru_encode_sequences(sequence_tensor, hidden_size=12)
print(f"GRU embedding matrix: {gru_embeddings.shape[0]} sessions × {gru_embeddings.shape[1]} features")
print(pd.DataFrame(gru_embeddings[:4, :8]).round(3).to_string(index=False))
"""
        ),
        markdown("### 3. Learn and evaluate a lightweight detection head"),
        code(
            """
embedding_names = [f"gru_{index:02d}" for index in range(gru_embeddings.shape[1])]
gru_head = fit_logistic(gru_embeddings[train_index], sequence_labels[train_index], embedding_names, steps=2200)
gru_scores = predict_logistic(gru_head, gru_embeddings[test_index])
gru_metrics = evaluate_scores(sequence_labels[test_index], gru_scores, 0.50)

flat_features = session_lookup[FEATURE_COLUMNS].to_numpy()
flat_model = fit_logistic(flat_features[train_index], sequence_labels[train_index], FEATURE_COLUMNS)
flat_scores = predict_logistic(flat_model, flat_features[test_index])
flat_metrics = evaluate_scores(sequence_labels[test_index], flat_scores, 0.50)
comparison = pd.DataFrame([flat_metrics, gru_metrics], index=["flat logistic", "GRU encoder + logistic head"])
print(comparison[["precision", "recall", "f1", "average_precision", "alert_rate"]].round(3).to_string())
"""
        ),
        markdown("## Visual Insights & ML Extension\n\n### 4. Inspect the learned sequence representation"),
        code(
            """
standardized = (gru_embeddings - gru_embeddings.mean(axis=0)) / np.where(gru_embeddings.std(axis=0) < 1e-6, 1, gru_embeddings.std(axis=0))
_, _, components = np.linalg.svd(standardized, full_matrices=False)
projection = standardized @ components[:2].T
figure = scatter_chart(
    projection[:, 0], projection[:, 1], sequence_labels,
    "GRU sequence-embedding projection",
    "Two-dimensional SVD view of 420 session embeddings; color shows synthetic benchmark labels",
    "embedding dimension 1", "embedding dimension 2",
)
FIGURES.append(figure)
figure
"""
        ),
        markdown("### 5. Compare scenario recall"),
        code(
            """
test_results = session_lookup.iloc[test_index][["session_id", "scenario", "label"]].copy()
test_results["detected"] = (gru_scores >= 0.50).astype(int)
scenario_recall = test_results[test_results.label.eq(1)].groupby("scenario").detected.mean().sort_values()
print(scenario_recall.round(3).to_string())
figure = bar_chart(
    scenario_recall.index,
    scenario_recall.values,
    "GRU detection recall by attack scenario",
    "Recall on synthetic attack sessions from unseen hosts; small groups have high uncertainty",
    color=ORANGE,
    benchmark=0.80,
)
FIGURES.append(figure)
figure
"""
        ),
        markdown("## Checks"),
        code(
            """
assert sequence_tensor.shape[:2] == (events.session_id.nunique(), 6)
assert session_lookup.iloc[train_index].host_id.isin(session_lookup.iloc[test_index].host_id).sum() == 0
assert np.isfinite(gru_embeddings).all()
assert gru_metrics["average_precision"] > sequence_labels[test_index].mean()
print("PASS: sequence shape, host separation, finite embeddings, and lift over prevalence are valid.")
"""
        ),
        markdown(
            """
            ## Next Steps

            - Replace the fixed educational encoder with a trained GRU in PyTorch or MLX.
            - Benchmark quantized inference latency and memory on Apple silicon.
            - Add sequence explanations that identify which event transition changed the alert score.
            """
        ),
    ]
    return notebook(cells)


def notebook_05() -> dict:
    cells = intro(
        "MacSentinel 05 · Temporal Graph ML",
        "Iterative message passing summarizes each process–file–network provenance graph, then a logistic detection head combines graph context with transparent session features. Evaluation is host-separated and includes model-driver inspection.",
        "Test whether temporal provenance features improve session-level threat detection and analyst explanations.",
    )
    cells += [
        markdown("## Steps\n\n### 1. Build graph and session features"),
        code(
            """
graph_sessions = temporal_graph_features(events, rounds=3)
graph_columns = ["graph_node_count", "graph_edge_count", "graph_density", "process_influence", "file_influence", "domain_influence", "embedding_energy"]
model_columns = FEATURE_COLUMNS + graph_columns
train_index, test_index = group_train_test_split(graph_sessions, test_fraction=0.30)
features = graph_sessions[model_columns].fillna(0).to_numpy()
labels = graph_sessions.label.to_numpy()
print(graph_sessions[graph_columns].describe().round(3).to_string())
"""
        ),
        markdown("### 2. Fit graph-augmented and flat baselines"),
        code(
            """
graph_model = fit_logistic(features[train_index], labels[train_index], model_columns, steps=2200)
graph_scores = predict_logistic(graph_model, features[test_index])
graph_metrics = evaluate_scores(labels[test_index], graph_scores, 0.50)

flat_features = graph_sessions[FEATURE_COLUMNS].to_numpy()
flat_model = fit_logistic(flat_features[train_index], labels[train_index], FEATURE_COLUMNS)
flat_scores = predict_logistic(flat_model, flat_features[test_index])
flat_metrics = evaluate_scores(labels[test_index], flat_scores, 0.50)

comparison = pd.DataFrame([flat_metrics, graph_metrics], index=["flat telemetry", "temporal graph + telemetry"])
print(comparison[["precision", "recall", "f1", "average_precision", "alert_rate"]].round(3).to_string())
"""
        ),
        markdown("## Visual Insights & ML Extension\n\n### 3. Inspect the graph-feature space"),
        code(
            """
graph_values = graph_sessions[graph_columns].fillna(0).to_numpy()
standardized = (graph_values - graph_values.mean(axis=0)) / np.where(graph_values.std(axis=0) < 1e-6, 1, graph_values.std(axis=0))
_, _, components = np.linalg.svd(standardized, full_matrices=False)
projection = standardized @ components[:2].T
figure = scatter_chart(
    projection[:, 0], projection[:, 1], labels,
    "Temporal provenance feature projection",
    "Two-dimensional SVD view; each point is one synthetic macOS session",
    "graph dimension 1", "graph dimension 2",
)
FIGURES.append(figure)
figure
"""
        ),
        markdown("### 4. Explain the graph-augmented model"),
        code(
            """
importance = pd.Series(np.abs(graph_model.weights[1:]), index=model_columns).sort_values(ascending=False).head(10)
print(importance.round(3).to_string())
figure = bar_chart(
    importance.index[::-1], importance.values[::-1],
    "Largest standardized model coefficients",
    "Absolute logistic-head coefficients; magnitude indicates global influence, not causality",
    color=BLUE,
)
FIGURES.append(figure)
figure
"""
        ),
        markdown("### 5. Produce an explainable analyst queue"),
        code(
            """
queue = graph_sessions.iloc[test_index][["session_id", "host_id", "scenario", "rule_risk"]].copy()
queue["graph_ml_score"] = graph_scores
queue["top_reason"] = np.where(queue.rule_risk.ge(50), "high transparent rule risk", "unusual provenance structure")
queue = queue.sort_values("graph_ml_score", ascending=False).head(12)
print(queue.round({"rule_risk": 1, "graph_ml_score": 3}).to_string(index=False))
"""
        ),
        markdown("## Checks"),
        code(
            """
assert graph_sessions.session_id.is_unique
assert graph_sessions[graph_columns].notna().all().all()
assert set(graph_sessions.iloc[train_index].host_id).isdisjoint(set(graph_sessions.iloc[test_index].host_id))
assert graph_metrics["average_precision"] >= labels[test_index].mean()
print("PASS: graph completeness, host separation, and detection lift over prevalence are valid.")
"""
        ),
        markdown(
            """
            ## Next Steps

            - Move message passing to bounded event windows with explicit eviction policies.
            - Test temporal GNN, GRU, and transparent baselines at equal CPU/memory budgets.
            - Preserve every alert's subgraph and relation-level evidence for analyst review.
            """
        ),
    ]
    return notebook(cells)


def notebook_06() -> dict:
    cells = intro(
        "MacSentinel 06 · Adversarial Robustness & Drift",
        "A detector that looks strong on an ordinary holdout can degrade under benign software rollouts or attacker mimicry. This notebook measures that degradation and converts privacy, recall, false-positive, and drift requirements into release gates.",
        "Stress-test MacSentinel against concept drift and mimicry attacks before treating benchmark performance as deployment readiness.",
    )
    cells += [
        markdown("## Steps\n\n### 1. Train a baseline detector on original telemetry"),
        code(
            """
baseline_sessions = aggregate_sessions(events)
train_index, test_index = group_train_test_split(baseline_sessions, test_fraction=0.30)
features = baseline_sessions[FEATURE_COLUMNS].to_numpy()
labels = baseline_sessions.label.to_numpy()
model = fit_logistic(features[train_index], labels[train_index], FEATURE_COLUMNS)
test_ids = baseline_sessions.iloc[test_index].session_id.tolist()
baseline_scores = predict_logistic(model, features[test_index])
baseline_metrics = evaluate_scores(labels[test_index], baseline_scores, 0.50)
print(pd.Series(baseline_metrics).round(4).to_string())
"""
        ),
        markdown("### 2. Create benign concept drift and attacker mimicry stress sets"),
        code(
            """
drift_events = apply_concept_drift(events)
mimicry_events = apply_mimicry_attack(events)
drift_sessions = aggregate_sessions(drift_events).set_index("session_id").loc[test_ids].reset_index()
mimicry_sessions = aggregate_sessions(mimicry_events).set_index("session_id").loc[test_ids].reset_index()

drift_scores = predict_logistic(model, drift_sessions[FEATURE_COLUMNS].to_numpy())
mimicry_scores = predict_logistic(model, mimicry_sessions[FEATURE_COLUMNS].to_numpy())
drift_metrics = evaluate_scores(drift_sessions.label.to_numpy(), drift_scores, 0.50)
mimicry_metrics = evaluate_scores(mimicry_sessions.label.to_numpy(), mimicry_scores, 0.50)

evaluation = pd.DataFrame([baseline_metrics, drift_metrics, mimicry_metrics], index=["baseline", "benign concept drift", "attacker mimicry"])
evaluation["false_positive_rate"] = evaluation.fp / (evaluation.fp + evaluation.tn).clip(lower=1)
print(evaluation[["precision", "recall", "f1", "average_precision", "false_positive_rate", "alert_rate"]].round(3).to_string())
"""
        ),
        markdown("## Visual Insights & ML Extension\n\n### 3. Compare robustness outcomes"),
        code(
            """
figure = bar_chart(
    evaluation.index,
    evaluation.recall,
    "Recall under drift and adversarial stress",
    "Host-separated synthetic test sessions; 0.80 is the illustrative release threshold",
    color=ORANGE,
    benchmark=0.80,
)
FIGURES.append(figure)
figure
"""
        ),
        markdown("### 4. Quantify feature drift"),
        code(
            """
reference = baseline_sessions.iloc[test_index]
psi = pd.Series({
    feature: population_stability_index(reference[feature].to_numpy(), drift_sessions[feature].to_numpy())
    for feature in FEATURE_COLUMNS
}).sort_values(ascending=False)
print(psi.round(3).to_string())
figure = bar_chart(
    psi.head(8).index[::-1], psi.head(8).values[::-1],
    "Population stability index by feature",
    "Baseline test distribution vs benign software-rollout simulation; PSI above 0.25 warrants review",
    color=BLUE,
    benchmark=0.25,
)
FIGURES.append(figure)
figure
"""
        ),
        markdown("### 5. Define production-style release gates"),
        code(
            """
privacy_fields = {"event_id", "timestamp", "host_id", "user_hash", "session_id", "process", "event_type", "target"}
forbidden_content_fields = {"file_contents", "clipboard_contents", "message_body", "password", "secret"}
release_gates = pd.DataFrame([
    {"gate": "baseline recall ≥ 0.80", "value": baseline_metrics["recall"], "pass": baseline_metrics["recall"] >= 0.80},
    {"gate": "mimicry recall ≥ 0.65", "value": mimicry_metrics["recall"], "pass": mimicry_metrics["recall"] >= 0.65},
    {"gate": "drift false-positive rate ≤ 0.08", "value": evaluation.loc["benign concept drift", "false_positive_rate"], "pass": evaluation.loc["benign concept drift", "false_positive_rate"] <= 0.08},
    {"gate": "maximum PSI ≤ 0.25", "value": psi.max(), "pass": psi.max() <= 0.25},
    {"gate": "no content collection", "value": float(forbidden_content_fields.isdisjoint(events.columns)), "pass": forbidden_content_fields.isdisjoint(events.columns)},
])
print(release_gates.to_string(index=False, formatters={"value": "{:.3f}".format}))
"""
        ),
        markdown("## Checks"),
        code(
            """
assert baseline_sessions.session_id.tolist() == aggregate_sessions(events).session_id.tolist()
assert set(reference.session_id) == set(drift_sessions.session_id) == set(mimicry_sessions.session_id)
assert forbidden_content_fields.isdisjoint(events.columns)
assert evaluation.loc["attacker mimicry", "recall"] <= evaluation.loc["baseline", "recall"]
print("PASS: aligned stress populations, privacy schema, and expected mimicry degradation are valid.")
"""
        ),
        markdown(
            """
            ## Next Steps

            - Block release when robustness or privacy gates fail; do not average them away.
            - Retrain only after verifying that drift reflects legitimate product change rather than compromise.
            - Add latency, memory, model-signing, rollback, and human-override gates for Apple-silicon deployment.
            """
        ),
    ]
    return notebook(cells)


NOTEBOOKS = {
    "01_macos_telemetry_eda.ipynb": notebook_01,
    "02_provenance_graph_investigation.ipynb": notebook_02,
    "03_streaming_anomaly_detection.ipynb": notebook_03,
    "04_gru_sequence_detection.ipynb": notebook_04,
    "05_temporal_graph_ml.ipynb": notebook_05,
    "06_adversarial_robustness_and_drift.ipynb": notebook_06,
}


def main() -> None:
    NOTEBOOK_DIR.mkdir(parents=True, exist_ok=True)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    events = generate_macos_events()
    events.to_csv(DATA_DIR / "synthetic_macos_events.csv", index=False)
    for filename, factory in NOTEBOOKS.items():
        path = NOTEBOOK_DIR / filename
        path.write_text(json.dumps(factory(), indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"built {path.relative_to(ROOT)}")
    print(f"wrote {len(events):,} synthetic events to {DATA_DIR.relative_to(ROOT)}/synthetic_macos_events.csv")


if __name__ == "__main__":
    main()
