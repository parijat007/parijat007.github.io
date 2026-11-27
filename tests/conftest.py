import pytest


@pytest.fixture(autouse=True)
def _private_state_dir(tmp_path, monkeypatch):
    """Model-call logs and quota notes go to a temporary folder, never the developer's ~/.watchfloor."""
    monkeypatch.setenv("WF_STATE_DIR", str(tmp_path / "wf-state"))
