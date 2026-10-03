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
