from __future__ import annotations

import ast
import unittest
from pathlib import Path

import numpy as np

from macsentinel.core import (
    FEATURE_COLUMNS,
    aggregate_sessions,
    apply_mimicry_attack,
    evaluate_scores,
    fit_logistic,
    generate_macos_events,
    group_train_test_split,
    predict_logistic,
)
from macsentinel.visuals import bar_chart, to_png_bytes


ROOT = Path(__file__).resolve().parents[1]


class MacSentinelCoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.events = generate_macos_events()
        cls.sessions = aggregate_sessions(cls.events)

    def test_generator_is_deterministic_and_safe(self):
        repeated = generate_macos_events()
        self.assertTrue(self.events.equals(repeated))
        self.assertTrue(self.events.event_id.is_unique)
        network_targets = self.events.loc[self.events.event_type.eq("network_connect"), "target"].astype(str)
        self.assertTrue(network_targets.str.endswith(".example").all())
        forbidden = {"file_contents", "clipboard_contents", "message_body", "password", "secret"}
        self.assertTrue(forbidden.isdisjoint(self.events.columns))

    def test_sessions_have_expected_grain(self):
        self.assertEqual(len(self.sessions), self.events.session_id.nunique())
        self.assertTrue(self.sessions.session_id.is_unique)
        self.assertTrue(self.sessions.rule_risk.between(0, 100).all())

    def test_host_split_prevents_entity_leakage(self):
        train_index, test_index = group_train_test_split(self.sessions)
        train_hosts = set(self.sessions.iloc[train_index].host_id)
        test_hosts = set(self.sessions.iloc[test_index].host_id)
        self.assertTrue(train_hosts.isdisjoint(test_hosts))

    def test_model_beats_prevalence_on_unseen_hosts(self):
        train_index, test_index = group_train_test_split(self.sessions)
        features = self.sessions[FEATURE_COLUMNS].to_numpy()
        labels = self.sessions.label.to_numpy()
        model = fit_logistic(features[train_index], labels[train_index], FEATURE_COLUMNS)
        scores = predict_logistic(model, features[test_index])
        metrics = evaluate_scores(labels[test_index], scores)
        self.assertGreater(metrics["average_precision"], labels[test_index].mean() + 0.30)
        self.assertGreater(metrics["recall"], 0.70)

    def test_mimicry_reduces_recall(self):
        train_index, test_index = group_train_test_split(self.sessions)
        features = self.sessions[FEATURE_COLUMNS].to_numpy()
        labels = self.sessions.label.to_numpy()
        model = fit_logistic(features[train_index], labels[train_index], FEATURE_COLUMNS)
        baseline = evaluate_scores(labels[test_index], predict_logistic(model, features[test_index]))
        mimicry = aggregate_sessions(apply_mimicry_attack(self.events)).set_index("session_id").loc[
            self.sessions.iloc[test_index].session_id
        ]
        stressed = evaluate_scores(mimicry.label.to_numpy(), predict_logistic(model, mimicry[FEATURE_COLUMNS].to_numpy()))
        self.assertLess(stressed["recall"], baseline["recall"] - 0.40)

    def test_visual_and_app_source_are_valid(self):
        image = bar_chart(["one", "two"], [1, 2], "Test chart", "Synthetic values")
        self.assertEqual(image.size, (1200, 700))
        self.assertTrue(to_png_bytes(image).startswith(b"\x89PNG"))
        ast.parse((ROOT / "app.py").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
