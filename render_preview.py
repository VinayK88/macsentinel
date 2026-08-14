"""Render a static dashboard preview for the repository README."""

from __future__ import annotations

from pathlib import Path

from macsentinel.core import FEATURE_COLUMNS, aggregate_sessions, fit_logistic, generate_macos_events, predict_logistic
from macsentinel.visuals import bar_chart, dashboard_preview, histogram


ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT / "assets" / "macsentinel-dashboard.png"


def main() -> None:
    events = generate_macos_events()
    sessions = aggregate_sessions(events)
    model = fit_logistic(sessions[FEATURE_COLUMNS].to_numpy(), sessions.label.to_numpy(), FEATURE_COLUMNS)
    sessions["score"] = predict_logistic(model, sessions[FEATURE_COLUMNS].to_numpy())
    score_chart = histogram(
        {"benign": sessions.loc[sessions.label.eq(0), "score"], "attack": sessions.loc[sessions.label.eq(1), "score"]},
        "Detection-score distribution",
        "Synthetic benchmark sessions",
    )
    scenarios = sessions.groupby("scenario").score.mean().sort_values()
    scenario_chart = bar_chart(
        scenarios.index,
        scenarios.values,
        "Mean score by scenario",
        "Synthetic session-level detector output",
    )
    preview = dashboard_preview(
        {
            "SESSIONS": f"{len(sessions):,}",
            "EVENTS": f"{len(events):,}",
            "ATTACK STORIES": "6",
            "HOSTS": f"{events.host_id.nunique()}",
        },
        [score_chart, scenario_chart],
    )
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    preview.save(OUTPUT, format="PNG", optimize=True)
    print(f"rendered {OUTPUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
