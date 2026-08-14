"""Shared synthetic telemetry and lightweight ML for MacSentinel.

The module intentionally performs no collection and executes no suspicious
payloads. It creates deterministic, non-sensitive fixtures shaped like the
high-level macOS security events an authorized Endpoint Security or eslogger
pipeline might normalize.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence

import numpy as np
import pandas as pd


SEED = 42

SCENARIOS = (
    "benign",
    "download_execute",
    "launchagent_persistence",
    "gatekeeper_bypass",
    "credential_access",
    "ransomware_burst",
    "data_exfiltration",
)

ATTACK_PATTERNS = {
    "download_execute": {
        "processes": ["Safari", "curl", "sh", "chmod", "sample.bin", "sample.bin"],
        "events": ["network_connect", "file_write", "exec", "file_write", "exec", "network_connect"],
        "targets": ["downloads.example", "/tmp/sample.bin", "/bin/sh", "/tmp/sample.bin", "/tmp/sample.bin", "control.example"],
        "techniques": ["T1105", "T1105", "T1059", "T1222", "T1204", "T1071"],
    },
    "launchagent_persistence": {
        "processes": ["Safari", "installer", "sh", "defaults", "launchctl", "helper"],
        "events": ["network_connect", "file_write", "exec", "file_write", "exec", "exec"],
        "targets": ["update.example", "/tmp/helper", "/bin/sh", "~/Library/LaunchAgents/com.demo.agent.plist", "com.demo.agent", "/tmp/helper"],
        "techniques": ["T1105", "T1105", "T1059", "T1543.001", "T1543.001", "T1204"],
    },
    "gatekeeper_bypass": {
        "processes": ["Safari", "Archive Utility", "xattr", "Finder", "unsigned-app", "unsigned-app"],
        "events": ["network_connect", "file_write", "exec", "gatekeeper_bypass", "exec", "network_connect"],
        "targets": ["download.example", "~/Downloads/demo.zip", "/usr/bin/xattr", "unsigned-app.app", "unsigned-app.app", "callback.example"],
        "techniques": ["T1105", "T1105", "T1222", "T1553.001", "T1204", "T1071"],
    },
    "credential_access": {
        "processes": ["Terminal", "zsh", "python3", "python3", "security", "python3"],
        "events": ["exec", "exec", "file_read", "file_read", "exec", "network_connect"],
        "targets": ["/bin/zsh", "/usr/bin/python3", "~/Library/Keychains/login.keychain-db", "~/.ssh/id_ed25519", "/usr/bin/security", "collector.example"],
        "techniques": ["T1059", "T1059", "T1555.001", "T1552.004", "T1555", "T1041"],
    },
    "ransomware_burst": {
        "processes": ["Mail", "Preview", "sh", "encryptor", "encryptor", "encryptor"],
        "events": ["file_write", "exec", "exec", "file_write", "file_write", "file_write"],
        "targets": ["~/Downloads/invoice.pdf", "invoice.pdf", "/bin/sh", "~/Documents", "~/Pictures", "~/Desktop"],
        "techniques": ["T1566", "T1204", "T1059", "T1486", "T1486", "T1486"],
    },
    "data_exfiltration": {
        "processes": ["Finder", "zip", "zip", "curl", "curl", "rm"],
        "events": ["file_read", "exec", "file_write", "network_connect", "network_connect", "file_delete"],
        "targets": ["~/Documents", "/usr/bin/zip", "/tmp/archive.zip", "upload.example", "upload.example", "/tmp/archive.zip"],
        "techniques": ["T1083", "T1560", "T1560", "T1041", "T1041", "T1070"],
    },
}

FEATURE_COLUMNS = [
    "unsigned_ratio",
    "not_notarized_ratio",
    "gatekeeper_bypass_count",
    "xprotect_detection_count",
    "privilege_escalation_count",
    "persistence_write_count",
    "sensitive_access_count",
    "network_beacon_count",
    "max_file_write_count",
    "log1p_bytes_out",
    "rare_process_ratio",
]


def _stable_hash(prefix: str, value: int) -> str:
    """Return a deterministic pseudonymous identifier, not a real user value."""

    return f"{prefix}-{(value * 2654435761) % 100000:05d}"


def generate_macos_events(
    session_count: int = 420,
    steps_per_session: int = 6,
    malicious_rate: float = 0.18,
    seed: int = SEED,
) -> pd.DataFrame:
    """Create deterministic synthetic macOS-style telemetry.

    Each session is a six-step process/file/network story. Malicious sessions
    use inert filenames and reserved ``.example`` domains. No commands are run.
    """

    if session_count < 20:
        raise ValueError("session_count must be at least 20")
    if steps_per_session != 6:
        raise ValueError("the documented synthetic scenarios use exactly six steps")
    if not 0.01 <= malicious_rate <= 0.60:
        raise ValueError("malicious_rate must be between 0.01 and 0.60")

    rng = np.random.default_rng(seed)
    start = pd.Timestamp("2026-01-15T08:00:00Z")
    benign_processes = np.array(
        ["Finder", "Safari", "Mail", "Notes", "Calendar", "Preview", "mdworker", "softwareupdated", "backupd", "WindowServer"]
    )
    benign_events = np.array(["exec", "file_read", "file_write", "network_connect", "auth"])
    malicious_sessions = set(
        rng.choice(session_count, size=max(1, int(session_count * malicious_rate)), replace=False).tolist()
    )
    attack_names = tuple(ATTACK_PATTERNS)
    rows: list[dict] = []

    for session_index in range(session_count):
        malicious = session_index in malicious_sessions
        benign_admin = (not malicious) and session_index % 19 == 0
        stealth = malicious and session_index % 4 == 0
        scenario = attack_names[session_index % len(attack_names)] if malicious else "benign"
        pattern = ATTACK_PATTERNS.get(scenario)
        host_number = int(rng.integers(1, 31))
        user_number = int(rng.integers(1, 121))
        session_id = f"session-{session_index:04d}"
        session_start = start + pd.Timedelta(minutes=int(session_index * 7 + rng.integers(0, 5)))
        previous_process = "launchd"

        for step in range(steps_per_session):
            if malicious and pattern is not None:
                process = pattern["processes"][step]
                event_type = pattern["events"][step]
                target = pattern["targets"][step]
                technique = pattern["techniques"][step]
                if stealth:
                    process = ["Safari", "softwareupdated", "Finder", "backupd", "mdworker", "Safari"][step]
            else:
                if benign_admin:
                    process = ["Terminal", "zsh", "brew", "softwareupdated", "security", "backupd"][step]
                    event_type = ["exec", "exec", "network_connect", "file_write", "file_read", "network_connect"][step]
                    target = ["/bin/zsh", "/usr/local/bin/brew", "packages.example", "/Library/Updates", "login.keychain-db", "backup.example"][step]
                else:
                    process = str(rng.choice(benign_processes))
                    event_type = str(rng.choice(benign_events, p=[0.25, 0.25, 0.18, 0.22, 0.10]))
                    if event_type == "network_connect":
                        target = str(rng.choice(["icloud.example", "updates.example", "calendar.example", "mail.example"]))
                    elif event_type in {"file_read", "file_write"}:
                        target = str(rng.choice(["~/Documents", "~/Library/Preferences", "/System/Library", "~/Pictures"]))
                    elif event_type == "exec":
                        target = str(rng.choice(["/System/Applications", "/usr/bin/open", "/System/Library/CoreServices"]))
                    else:
                        target = "loginwindow"
                technique = ""

            signed = int(not (malicious and step >= 2 and scenario != "data_exfiltration"))
            if benign_admin and step in {1, 2}:
                signed = 0
            notarized = int(signed and not (malicious and scenario == "gatekeeper_bypass" and step >= 3))
            gatekeeper_bypass = int(malicious and scenario == "gatekeeper_bypass" and step == 3)
            xprotect_detection = int(
                malicious and scenario in {"download_execute", "ransomware_burst"} and step == 4 and session_index % 3 == 0
            )
            privilege_escalation = int(malicious and scenario in {"download_execute", "launchagent_persistence"} and step == 4)
            persistence_write = int(malicious and scenario == "launchagent_persistence" and step in {3, 4})
            sensitive_access = int(malicious and scenario in {"credential_access", "data_exfiltration"} and step in {2, 3})
            network_beacon = int(malicious and event_type == "network_connect" and step >= 3)
            if benign_admin:
                persistence_write = int(step == 3)
                sensitive_access = int(step == 4)
                network_beacon = int(step == 5)
            file_write_count = int(
                rng.poisson(4)
                + (rng.integers(90, 180) if malicious and scenario == "ransomware_burst" and step >= 3 else 0)
                + (rng.integers(35, 80) if benign_admin and step == 3 else 0)
            )
            bytes_out = int(
                rng.lognormal(7.0, 0.8)
                * (70 if malicious and scenario == "data_exfiltration" and step in {3, 4} else 1)
                * (18 if benign_admin and step == 5 else 1)
            )
            if stealth:
                signed = 1
                notarized = 1
                gatekeeper_bypass = 0
                xprotect_detection = 0
                privilege_escalation = int(privilege_escalation and step == 4 and session_index % 8 == 0)
                persistence_write = int(persistence_write and step == 3)
                sensitive_access = int(sensitive_access and step == 3)
                network_beacon = int(network_beacon and step == 5)
                file_write_count = min(file_write_count, 36)
                bytes_out = int(bytes_out * 0.35)
            command_risk = float(
                np.clip(
                    0.04
                    + 0.22 * (1 - signed)
                    + 0.35 * gatekeeper_bypass
                    + 0.30 * persistence_write
                    + 0.22 * sensitive_access
                    + 0.20 * network_beacon
                    + rng.normal(0, 0.025),
                    0,
                    1,
                )
            )
            relation = {
                "exec": "executes",
                "file_read": "reads",
                "file_write": "writes",
                "file_delete": "deletes",
                "network_connect": "connects",
                "auth": "authenticates",
                "gatekeeper_bypass": "bypasses",
                "xprotect_detect": "detects",
            }.get(event_type, "touches")

            rows.append(
                {
                    "event_id": f"evt-{session_index:04d}-{step}",
                    "timestamp": session_start + pd.Timedelta(seconds=step * 19 + int(rng.integers(0, 5))),
                    "host_id": f"mac-{host_number:03d}",
                    "user_hash": _stable_hash("user", user_number),
                    "session_id": session_id,
                    "step": step,
                    "parent_process": previous_process,
                    "process": process,
                    "event_type": event_type,
                    "target": target,
                    "relation": relation,
                    "signed": signed,
                    "notarized": notarized,
                    "gatekeeper_bypass": gatekeeper_bypass,
                    "xprotect_detection": xprotect_detection,
                    "privilege_escalation": privilege_escalation,
                    "persistence_write": persistence_write,
                    "sensitive_access": sensitive_access,
                    "network_beacon": network_beacon,
                    "file_write_count": file_write_count,
                    "bytes_out": bytes_out,
                    "command_risk": command_risk,
                    "scenario": scenario,
                    "mitre_technique": technique,
                    "label": int(malicious),
                    "data_source": "synthetic macOS Endpoint Security-style fixture",
                }
            )
            previous_process = process

    events = pd.DataFrame(rows).sort_values("timestamp").reset_index(drop=True)
    events["timestamp"] = pd.to_datetime(events["timestamp"], utc=True)
    return events


def aggregate_sessions(events: pd.DataFrame) -> pd.DataFrame:
    """Aggregate event telemetry into one row per session for modeling."""

    process_frequency = events["process"].value_counts(normalize=True)
    enriched = events.copy()
    enriched["rare_process"] = enriched["process"].map(process_frequency).lt(0.02).astype(int)
    enriched["unsigned"] = 1 - enriched["signed"].astype(int)
    enriched["not_notarized"] = 1 - enriched["notarized"].astype(int)
    grouped = enriched.groupby("session_id", sort=True)
    sessions = grouped.agg(
        timestamp=("timestamp", "min"),
        host_id=("host_id", "first"),
        user_hash=("user_hash", "first"),
        scenario=("scenario", "first"),
        label=("label", "max"),
        event_count=("event_id", "count"),
        unsigned_ratio=("unsigned", "mean"),
        not_notarized_ratio=("not_notarized", "mean"),
        gatekeeper_bypass_count=("gatekeeper_bypass", "sum"),
        xprotect_detection_count=("xprotect_detection", "sum"),
        privilege_escalation_count=("privilege_escalation", "sum"),
        persistence_write_count=("persistence_write", "sum"),
        sensitive_access_count=("sensitive_access", "sum"),
        network_beacon_count=("network_beacon", "sum"),
        max_file_write_count=("file_write_count", "max"),
        bytes_out=("bytes_out", "sum"),
        rare_process_ratio=("rare_process", "mean"),
    ).reset_index()
    sessions["log1p_bytes_out"] = np.log1p(sessions["bytes_out"])
    sessions["rule_risk"] = np.clip(
        12 * sessions["unsigned_ratio"]
        + 9 * sessions["not_notarized_ratio"]
        + 19 * sessions["gatekeeper_bypass_count"]
        + 24 * sessions["xprotect_detection_count"]
        + 13 * sessions["privilege_escalation_count"]
        + 12 * sessions["persistence_write_count"]
        + 10 * sessions["sensitive_access_count"]
        + 9 * sessions["network_beacon_count"]
        + 0.10 * sessions["max_file_write_count"]
        + 3 * sessions["rare_process_ratio"],
        0,
        100,
    )
    return sessions


def build_provenance_edges(events: pd.DataFrame, session_ids: Sequence[str] | None = None) -> pd.DataFrame:
    """Build a compact process-to-object provenance edge list."""

    selected = events if session_ids is None else events[events["session_id"].isin(session_ids)]
    rows: list[dict] = []
    for row in selected.itertuples(index=False):
        process_node = f"process:{row.process}"
        parent_node = f"process:{row.parent_process}"
        if row.event_type in {"network_connect"}:
            target_node = f"domain:{row.target}"
            target_type = "domain"
        elif row.event_type in {"file_read", "file_write", "file_delete", "gatekeeper_bypass"}:
            target_node = f"file:{row.target}"
            target_type = "file"
        else:
            target_node = f"resource:{row.target}"
            target_type = "resource"
        rows.append(
            {
                "timestamp": row.timestamp,
                "session_id": row.session_id,
                "source": parent_node,
                "target": process_node,
                "relation": "spawns",
                "source_type": "process",
                "target_type": "process",
                "label": row.label,
            }
        )
        rows.append(
            {
                "timestamp": row.timestamp,
                "session_id": row.session_id,
                "source": process_node,
                "target": target_node,
                "relation": row.relation,
                "source_type": "process",
                "target_type": target_type,
                "label": row.label,
            }
        )
    return pd.DataFrame(rows).drop_duplicates(
        subset=["session_id", "source", "target", "relation"], keep="first"
    )


@dataclass
class LogisticModel:
    weights: np.ndarray
    mean: np.ndarray
    scale: np.ndarray
    feature_names: tuple[str, ...]


def sigmoid(values: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-np.clip(values, -30, 30)))


def fit_logistic(
    features: np.ndarray,
    labels: np.ndarray,
    feature_names: Iterable[str] | None = None,
    steps: int = 1800,
    learning_rate: float = 0.06,
    l2: float = 0.02,
) -> LogisticModel:
    """Fit deterministic L2-regularized logistic regression with NumPy."""

    x = np.asarray(features, dtype=float)
    y = np.asarray(labels, dtype=float)
    mean = x.mean(axis=0)
    scale = x.std(axis=0)
    scale = np.where(scale < 1e-9, 1.0, scale)
    standardized = (x - mean) / scale
    design = np.column_stack([np.ones(len(standardized)), standardized])
    weights = np.zeros(design.shape[1])
    positive_weight = len(y) / max(2 * y.sum(), 1)
    negative_weight = len(y) / max(2 * (1 - y).sum(), 1)
    sample_weight = np.where(y == 1, positive_weight, negative_weight)
    for _ in range(steps):
        probability = sigmoid(design @ weights)
        gradient = design.T @ ((probability - y) * sample_weight) / len(y)
        gradient[1:] += l2 * weights[1:]
        weights -= learning_rate * gradient
    names = tuple(feature_names or [f"feature_{index}" for index in range(x.shape[1])])
    return LogisticModel(weights=weights, mean=mean, scale=scale, feature_names=names)


def predict_logistic(model: LogisticModel, features: np.ndarray) -> np.ndarray:
    x = np.asarray(features, dtype=float)
    standardized = (x - model.mean) / model.scale
    return sigmoid(np.column_stack([np.ones(len(x)), standardized]) @ model.weights)


def group_train_test_split(
    frame: pd.DataFrame,
    group_column: str = "host_id",
    test_fraction: float = 0.30,
    seed: int = SEED,
) -> tuple[np.ndarray, np.ndarray]:
    """Split rows by entity so a host cannot leak across train and test."""

    groups = np.asarray(sorted(frame[group_column].astype(str).unique()))
    rng = np.random.default_rng(seed)
    shuffled = groups[rng.permutation(len(groups))]
    test_count = max(1, int(round(len(groups) * test_fraction)))
    test_groups = set(shuffled[:test_count])
    test_mask = frame[group_column].astype(str).isin(test_groups).to_numpy()
    return np.flatnonzero(~test_mask), np.flatnonzero(test_mask)


def classification_metrics(labels: np.ndarray, predictions: np.ndarray) -> dict[str, float]:
    y = np.asarray(labels, dtype=int)
    pred = np.asarray(predictions, dtype=int)
    tp = int(((y == 1) & (pred == 1)).sum())
    fp = int(((y == 0) & (pred == 1)).sum())
    tn = int(((y == 0) & (pred == 0)).sum())
    fn = int(((y == 1) & (pred == 0)).sum())
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    return {
        "precision": precision,
        "recall": recall,
        "f1": 2 * precision * recall / max(precision + recall, 1e-12),
        "accuracy": (tp + tn) / max(len(y), 1),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
    }


def average_precision(labels: np.ndarray, scores: np.ndarray) -> float:
    order = np.argsort(-np.asarray(scores))
    ranked = np.asarray(labels, dtype=int)[order]
    positive_positions = np.flatnonzero(ranked == 1)
    if len(positive_positions) == 0:
        return 0.0
    precisions = [ranked[: position + 1].mean() for position in positive_positions]
    return float(np.mean(precisions))


def evaluate_scores(labels: np.ndarray, scores: np.ndarray, threshold: float = 0.5) -> dict[str, float]:
    metrics = classification_metrics(labels, np.asarray(scores) >= threshold)
    metrics["average_precision"] = average_precision(labels, scores)
    metrics["threshold"] = threshold
    metrics["alert_rate"] = float((np.asarray(scores) >= threshold).mean())
    return metrics


def precision_recall_curve(labels: np.ndarray, scores: np.ndarray, points: int = 61) -> pd.DataFrame:
    rows = []
    for threshold in np.linspace(0, 1, points):
        metric = evaluate_scores(labels, scores, float(threshold))
        rows.append(metric)
    return pd.DataFrame(rows)


def robust_anomaly_score(features: np.ndarray) -> np.ndarray:
    """Return a transparent multivariate robust-z anomaly score in [0, 1]."""

    x = np.asarray(features, dtype=float)
    median = np.median(x, axis=0)
    mad = np.median(np.abs(x - median), axis=0)
    mad = np.where(mad < 1e-6, np.std(x, axis=0) + 1e-3, mad)
    z = np.abs((x - median) / (1.4826 * mad + 1e-6))
    distance = np.sqrt(np.mean(np.minimum(z, 12) ** 2, axis=1))
    return 1 - np.exp(-distance / 3.0)


def make_sequence_tensor(
    events: pd.DataFrame,
    feature_columns: Sequence[str] | None = None,
) -> tuple[np.ndarray, np.ndarray, list[str], list[str]]:
    """Return session x time x feature tensor for sequence modeling."""

    columns = list(
        feature_columns
        or [
            "signed",
            "notarized",
            "gatekeeper_bypass",
            "xprotect_detection",
            "privilege_escalation",
            "persistence_write",
            "sensitive_access",
            "network_beacon",
            "command_risk",
        ]
    )
    ordered = events.sort_values(["session_id", "step"])
    sessions = sorted(ordered["session_id"].unique())
    step_count = int(ordered["step"].max()) + 1
    tensor = np.zeros((len(sessions), step_count, len(columns)), dtype=float)
    labels = np.zeros(len(sessions), dtype=int)
    for index, session_id in enumerate(sessions):
        rows = ordered[ordered["session_id"] == session_id].sort_values("step")
        tensor[index, : len(rows)] = rows[columns].to_numpy(dtype=float)
        labels[index] = int(rows["label"].max())
    return tensor, labels, sessions, columns


def gru_encode_sequences(sequence_tensor: np.ndarray, hidden_size: int = 10, seed: int = SEED) -> np.ndarray:
    """Encode event sequences with a deterministic GRU cell.

    This educational baseline keeps the recurrent encoder fixed and learns a
    logistic detection head separately, making every step inspectable without
    a heavyweight deep-learning runtime.
    """

    x = np.asarray(sequence_tensor, dtype=float)
    feature_mean = x.mean(axis=(0, 1), keepdims=True)
    feature_std = x.std(axis=(0, 1), keepdims=True)
    normalized = (x - feature_mean) / np.where(feature_std < 1e-6, 1.0, feature_std)
    rng = np.random.default_rng(seed)
    input_size = normalized.shape[2]
    scale = 0.45 / np.sqrt(input_size + hidden_size)
    wz = rng.normal(0, scale, (input_size, hidden_size))
    uz = rng.normal(0, scale, (hidden_size, hidden_size))
    wr = rng.normal(0, scale, (input_size, hidden_size))
    ur = rng.normal(0, scale, (hidden_size, hidden_size))
    wh = rng.normal(0, scale, (input_size, hidden_size))
    uh = rng.normal(0, scale, (hidden_size, hidden_size))
    state = np.zeros((len(normalized), hidden_size))
    states = []
    for step in range(normalized.shape[1]):
        current = normalized[:, step, :]
        update = sigmoid(current @ wz + state @ uz + 0.5)
        reset = sigmoid(current @ wr + state @ ur)
        candidate = np.tanh(current @ wh + (reset * state) @ uh)
        state = (1 - update) * state + update * candidate
        states.append(state.copy())
    stacked = np.stack(states, axis=1)
    return np.column_stack([state, stacked.mean(axis=1), stacked.max(axis=1)])


def temporal_graph_features(events: pd.DataFrame, rounds: int = 3) -> pd.DataFrame:
    """Create streaming provenance features with iterative message passing."""

    base = aggregate_sessions(events)
    edges = build_provenance_edges(events)
    graph_rows = []
    for session_id, session_edges in edges.groupby("session_id"):
        nodes = sorted(set(session_edges["source"]) | set(session_edges["target"]))
        node_index = {node: index for index, node in enumerate(nodes)}
        adjacency = np.zeros((len(nodes), len(nodes)), dtype=float)
        for edge in session_edges.itertuples(index=False):
            source = node_index[edge.source]
            target = node_index[edge.target]
            adjacency[source, target] += 1
            adjacency[target, source] += 0.35
        row_sum = adjacency.sum(axis=1, keepdims=True)
        normalized = adjacency / np.where(row_sum == 0, 1.0, row_sum)
        types = np.array(
            [
                [node.startswith("process:"), node.startswith("file:"), node.startswith("domain:"), node.startswith("resource:")]
                for node in nodes
            ],
            dtype=float,
        )
        state = types
        for _ in range(rounds):
            state = 0.55 * state + 0.45 * normalized @ state
        graph_rows.append(
            {
                "session_id": session_id,
                "graph_node_count": len(nodes),
                "graph_edge_count": len(session_edges),
                "graph_density": float((adjacency > 0).sum() / max(len(nodes) ** 2, 1)),
                "process_influence": float(state[:, 0].max()),
                "file_influence": float(state[:, 1].max()),
                "domain_influence": float(state[:, 2].max()),
                "embedding_energy": float(np.sqrt((state**2).sum(axis=1)).mean()),
            }
        )
    graph_features = pd.DataFrame(graph_rows)
    return base.merge(graph_features, on="session_id", how="left")


def apply_concept_drift(events: pd.DataFrame, seed: int = 2026) -> pd.DataFrame:
    """Simulate a benign software rollout that changes baseline behavior."""

    rng = np.random.default_rng(seed)
    drifted = events.copy()
    benign_mask = drifted["label"].eq(0) & (rng.random(len(drifted)) < 0.34)
    drifted.loc[benign_mask, "process"] = "new-ai-helper"
    drifted.loc[benign_mask, "signed"] = 1
    drifted.loc[benign_mask, "notarized"] = 1
    drifted.loc[benign_mask, "command_risk"] = np.clip(
        drifted.loc[benign_mask, "command_risk"] + 0.08, 0, 1
    )
    drifted.loc[benign_mask, "bytes_out"] = (drifted.loc[benign_mask, "bytes_out"] * 2.3).astype(int)
    return drifted


def apply_mimicry_attack(events: pd.DataFrame) -> pd.DataFrame:
    """Reduce obvious malicious signals while preserving attack labels."""

    mimic = events.copy()
    malicious = mimic["label"].eq(1)
    mimic.loc[malicious, "signed"] = 1
    mimic.loc[malicious, "notarized"] = 1
    mimic.loc[malicious, "gatekeeper_bypass"] = 0
    mimic.loc[malicious, "xprotect_detection"] = 0
    mimic.loc[malicious, "privilege_escalation"] = 0
    mimic.loc[malicious, "persistence_write"] = 0
    mimic.loc[malicious, "sensitive_access"] = 0
    mimic.loc[malicious, "network_beacon"] = 0
    mimic.loc[malicious, "command_risk"] *= 0.52
    mimic.loc[malicious, "file_write_count"] = np.minimum(
        mimic.loc[malicious, "file_write_count"], 28
    )
    mimic.loc[malicious, "bytes_out"] = (mimic.loc[malicious, "bytes_out"] * 0.35).astype(int)
    common_processes = {0: "Safari", 1: "softwareupdated", 2: "Finder", 3: "backupd", 4: "mdworker", 5: "Safari"}
    mimic.loc[malicious, "process"] = mimic.loc[malicious, "step"].map(common_processes)
    return mimic


def population_stability_index(reference: np.ndarray, current: np.ndarray, bins: int = 10) -> float:
    """Compute PSI with quantile bins and smoothing."""

    reference_values = np.asarray(reference, dtype=float)
    current_values = np.asarray(current, dtype=float)
    boundaries = np.unique(np.quantile(reference_values, np.linspace(0, 1, bins + 1)))
    if len(boundaries) < 3:
        return 0.0
    boundaries[0] = -np.inf
    boundaries[-1] = np.inf
    reference_hist, _ = np.histogram(reference_values, bins=boundaries)
    current_hist, _ = np.histogram(current_values, bins=boundaries)
    reference_pct = (reference_hist + 0.5) / (reference_hist.sum() + 0.5 * len(reference_hist))
    current_pct = (current_hist + 0.5) / (current_hist.sum() + 0.5 * len(current_hist))
    return float(np.sum((current_pct - reference_pct) * np.log(current_pct / reference_pct)))
