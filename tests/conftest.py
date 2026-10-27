"""Keep default receipt-consumption state inside each test's temporary directory."""

import pytest


@pytest.fixture(autouse=True)
def isolated_replay_state(tmp_path, monkeypatch):
    monkeypatch.setenv("GOVERNED_AGENT_REPLAY_STORE_PATH", str(tmp_path / "receipt_replay.sqlite3"))
