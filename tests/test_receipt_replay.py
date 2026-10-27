"""A signed execution receipt authorizes at most one dispatch, including after failure."""

import base64
from concurrent.futures import ThreadPoolExecutor
import json
import subprocess
import sys
import threading

from cryptography.hazmat.primitives import serialization
import pytest

from governed_agent.capability.crypto import generate_keypair, seal
from governed_agent.hermes import ExecutionDeniedError, GovernedToolBoundary
from governed_agent.hermes import boundary as boundary_module


class TestIssuer:
    """Expose test key fields without allowing pytest to print private material."""

    __test__ = False

    def __init__(self, key):
        self._key = key

    def __getattr__(self, name):
        return getattr(self._key, name)

    def __repr__(self):
        return "<test issuer; private key redacted>"


@pytest.fixture
def capability():
    key = TestIssuer(generate_keypair(key_size=2048, key_id="test-replay-issuer"))
    receipt = seal({"action": "record", "value": "approved"}, {"task_id": "REPLAY"}, key)
    return key, receipt


def make_boundary(key, func, **kwargs):
    boundary = GovernedToolBoundary(
        key.public_key_pem, allowed_actions={"record"}, task_id="REPLAY", **kwargs
    )
    boundary.register_tool("record", func)
    return boundary


def invoke(boundary, receipt, **kwargs):
    return boundary.invoke_tool(
        "record", kwargs.get("args", {"value": "approved"}), receipt.receipt_bytes,
        kwargs.get("signature", receipt.signature),
    )


def test_receipt_is_consumed_by_same_boundary(capability):
    key, receipt = capability
    calls = []
    boundary = make_boundary(key, lambda value: calls.append(value))
    invoke(boundary, receipt)
    with pytest.raises(ExecutionDeniedError, match="already consumed"):
        invoke(boundary, receipt)
    assert calls == ["approved"]


def test_receipt_stays_consumed_across_instances_and_reopening(capability):
    key, receipt = capability
    calls = []
    first = make_boundary(key, lambda value: calls.append(value))
    second = make_boundary(key, lambda value: calls.append(value))
    invoke(first, receipt)
    with pytest.raises(ExecutionDeniedError, match="already consumed"):
        invoke(second, receipt)
    del first, second
    with pytest.raises(ExecutionDeniedError, match="already consumed"):
        invoke(make_boundary(key, lambda value: calls.append(value)), receipt)
    assert calls == ["approved"]


def test_concurrent_threads_dispatch_receipt_only_once(capability):
    key, receipt = capability
    calls = []
    gate = threading.Barrier(8)

    def attempt(_):
        boundary = make_boundary(key, lambda value: calls.append(value))
        gate.wait(timeout=10)
        try:
            invoke(boundary, receipt)
        except ExecutionDeniedError:
            return "denied"
        return "dispatched"

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(attempt, range(8)))
    assert results.count("dispatched") == 1
    assert results.count("denied") == 7
    assert calls == ["approved"]


PROCESS_ATTEMPT = """
import base64, json, os, sys
from pathlib import Path
from governed_agent.hermes import GovernedToolBoundary, ExecutionDeniedError
data = json.loads(sys.stdin.read())
boundary = GovernedToolBoundary(data['public_key'], allowed_actions={'record'}, task_id='REPLAY')
def record(value):
    with Path(data['effects']).open('a', encoding='utf-8') as stream:
        stream.write(value + '\\n')
    if data['crash']:
        os._exit(17)
boundary.register_tool('record', record)
try:
    boundary.invoke_tool('record', {'value': 'approved'},
                         base64.b64decode(data['receipt']), base64.b64decode(data['signature']))
except ExecutionDeniedError:
    print('denied')
else:
    print('dispatched')
"""


def process_attempt(key, receipt, effects, crash=False):
    # Only public verification material crosses the process boundary.
    payload = {
        "public_key": key.public_key_pem,
        "receipt": base64.b64encode(receipt.receipt_bytes).decode("ascii"),
        "signature": base64.b64encode(receipt.signature).decode("ascii"),
        "effects": str(effects), "crash": crash,
    }
    return subprocess.run(
        [sys.executable, "-c", PROCESS_ATTEMPT], input=json.dumps(payload),
        text=True, capture_output=True, timeout=30, check=False,
    )


def test_separate_processes_share_atomic_consumption_and_restart_state(capability, tmp_path):
    key, receipt = capability
    effects = tmp_path / "effects.txt"
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: process_attempt(key, receipt, effects), range(2)))
    assert all(result.returncode == 0 for result in results)
    assert sorted(result.stdout.strip() for result in results) == ["denied", "dispatched"]
    restarted = process_attempt(key, receipt, effects)
    assert restarted.returncode == 0
    assert restarted.stdout.strip() == "denied"
    assert effects.read_text(encoding="utf-8").splitlines() == ["approved"]


def test_process_crash_after_consumption_does_not_refund_receipt(capability, tmp_path):
    key, receipt = capability
    effects = tmp_path / "effects.txt"
    crashed = process_attempt(key, receipt, effects, crash=True)
    assert crashed.returncode == 17
    restarted = process_attempt(key, receipt, effects)
    assert restarted.returncode == 0
    assert restarted.stdout.strip() == "denied"
    assert effects.read_text(encoding="utf-8").splitlines() == ["approved"]


def test_tool_exception_does_not_refund_receipt(capability):
    key, receipt = capability
    calls = []

    def failing_tool(value):
        calls.append(value)
        raise RuntimeError("tool failure")

    boundary = make_boundary(key, failing_tool)
    with pytest.raises(RuntimeError, match="tool failure"):
        invoke(boundary, receipt)
    with pytest.raises(ExecutionDeniedError, match="already consumed"):
        invoke(boundary, receipt)
    assert calls == ["approved"]


@pytest.mark.parametrize("invalid", ["signature", "request", "context"])
def test_rejected_attempt_does_not_consume_receipt(capability, invalid):
    key, receipt = capability
    calls = []
    boundary = make_boundary(key, lambda value: calls.append(value))
    changes = {}
    if invalid == "signature":
        changes["signature"] = bytes(len(receipt.signature))
    elif invalid == "request":
        changes["args"] = {"value": "unapproved"}
    else:
        boundary.task_id = "WRONG"
    with pytest.raises(ExecutionDeniedError):
        invoke(boundary, receipt, **changes)
    assert calls == []
    boundary.task_id = "REPLAY"
    invoke(boundary, receipt)
    assert calls == ["approved"]


def test_equivalent_pem_does_not_create_another_issuer_namespace(capability):
    key, receipt = capability
    calls = []
    invoke(make_boundary(key, lambda value: calls.append(value)), receipt)
    public_key = serialization.load_pem_public_key(key.public_key_pem.encode("ascii"))
    alternate_pem = public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.PKCS1
    ).decode("ascii")
    boundary = GovernedToolBoundary(alternate_pem, allowed_actions={"record"}, task_id="REPLAY")
    boundary.register_tool("record", lambda value: calls.append(value))
    with pytest.raises(ExecutionDeniedError, match="already consumed"):
        invoke(boundary, receipt)
    assert calls == ["approved"]


def test_replay_identity_uses_the_key_that_verified_the_receipt(capability, monkeypatch):
    key, receipt = capability
    other_key = TestIssuer(generate_keypair(key_size=2048))
    calls = []
    boundary = make_boundary(key, lambda value: calls.append(value))
    original_verify = boundary_module.verify

    def verify_then_change_configuration(**kwargs):
        verdict = original_verify(**kwargs)
        boundary.custodian_public_pem = other_key.public_key_pem
        return verdict

    with monkeypatch.context() as patcher:
        patcher.setattr(boundary_module, "verify", verify_then_change_configuration)
        invoke(boundary, receipt)
    boundary.custodian_public_pem = key.public_key_pem
    with pytest.raises(ExecutionDeniedError, match="already consumed"):
        invoke(boundary, receipt)
    assert calls == ["approved"]


@pytest.mark.parametrize("failure", ["corrupt", "blocked_parent"])
def test_storage_failure_denies_dispatch(capability, monkeypatch, tmp_path, failure):
    key, receipt = capability
    calls = []
    path = tmp_path / "unusable.sqlite3"
    if failure == "corrupt":
        path.write_bytes(b"not a SQLite database")
    else:
        parent_file = tmp_path / "parent-is-file"
        parent_file.write_text("blocked", encoding="utf-8")
        path = parent_file / "replay.sqlite3"
    monkeypatch.setenv("GOVERNED_AGENT_REPLAY_STORE_PATH", str(path))
    boundary = make_boundary(key, lambda value: calls.append(value))
    with pytest.raises(ExecutionDeniedError, match="Replay protection unavailable"):
        invoke(boundary, receipt)
    assert calls == []


def test_explicit_path_shares_replay_state_despite_environment_change(capability, tmp_path, monkeypatch):
    key, receipt = capability
    calls = []
    path = tmp_path / "explicit.sqlite3"
    invoke(make_boundary(key, lambda value: calls.append(value), replay_store_path=path), receipt)
    monkeypatch.setenv("GOVERNED_AGENT_REPLAY_STORE_PATH", str(tmp_path / "other.sqlite3"))
    with pytest.raises(ExecutionDeniedError, match="already consumed"):
        invoke(make_boundary(key, lambda value: calls.append(value), replay_store_path=path), receipt)
    assert calls == ["approved"]
