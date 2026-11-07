"""Smoke tests for the interactive Streamlit prototype."""

from pathlib import Path

from streamlit.testing.v1 import AppTest


def test_demo_scenario_only_creates_pending_simulations():
    app_path = Path(__file__).resolve().parents[1] / "streamlit_app.py"
    app = AppTest.from_file(str(app_path)).run()

    assert not app.exception
    assert len(app.session_state["orchestrator"].list_actions()) == 0

    demo_button = next(button for button in app.button if button.label == "Load demo scenario")
    demo_button.click().run()

    actions = app.session_state["orchestrator"].list_actions()
    assert len(actions) == 3
    assert all(action.status.value == "pending_human_approval" for action in actions)
    assert len(app.session_state["orchestrator"].audit.list_events()) == 9
    assert not app.exception


def test_guided_account_compromise_exercise_creates_one_pending_simulation():
    app_path = Path(__file__).resolve().parents[1] / "streamlit_app.py"
    app = AppTest.from_file(str(app_path)).run()

    exercise_button = next(
        button for button in app.button if button.label == "Start account compromise exercise"
    )
    exercise_button.click().run()

    actions = app.session_state["orchestrator"].list_actions()
    assert len(actions) == 1
    assert actions[0].playbook.value == "session_revocation"
    assert actions[0].target == "lab-user-14"
    assert actions[0].status.value == "pending_human_approval"
    assert "Synthetic identity alert" in actions[0].rationale
    assert len(app.session_state["orchestrator"].audit.list_events()) == 3
    assert not app.exception


def test_threat_checker_analyzes_url_without_network_lookup():
    app_path = Path(__file__).resolve().parents[1] / "streamlit_app.py"
    app = AppTest.from_file(str(app_path)).run()

    content_input = next(
        area for area in app.text_area if area.label == "Paste content to inspect"
    )
    content_input.input("https://bit.ly/example").run()
    analyze_button = next(button for button in app.button if button.label == "Analyze locally")
    analyze_button.click().run()

    report = app.session_state["inspection_report"]
    assert report.kind == "URL or text"
    assert report.risk == "Medium"
    assert report.urls[0].submitted == "https://bit.ly/example"
    assert not app.exception
