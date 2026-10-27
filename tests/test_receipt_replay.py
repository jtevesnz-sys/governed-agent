"""A signed execution receipt authorizes at most one dispatch, including after failure."""

import base64
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import subprocess
import sys
import threading

from cryptography.hazmat.primitives import serialization
import pytest

from governed_agent.capability.crypto import generate_keypair, seal
from governed_agent.hermes import ExecutionDeniedError, GovernedToolBoundary
from governed_agent.hermes import boundary as boundary_module
from governed_agent.hermes.replay import ReceiptReplayStore, ReplayStoreError


class TestIssuer:
    """Expose test key fields without allowing pytest to print private material."""

    __test__ = False

    def __init__(self, key):
        """Retain test key material behind a wrapper with a deliberately redacted representation."""
        self._key = key

    def __getattr__(self, name):
        """Expose key fields needed by real signing and verification without changing their values."""
        return getattr(self._key, name)

    def __repr__(self):
        """Keep private test material out of pytest fixture and argument diagnostics."""
        return "<test issuer; private key redacted>"


@pytest.fixture
def capability():
    """Create a signed test action and an issuer wrapper that suppresses private-key diagnostics."""
    key = TestIssuer(generate_keypair(key_size=2048, key_id="test-replay-issuer"))
    receipt = seal({"action": "record", "value": "approved"}, {"task_id": "REPLAY"}, key)
    return key, receipt


def make_boundary(key, func, **kwargs):
    """Register one test callable behind the same action policy and task binding used by its receipt."""
    boundary = GovernedToolBoundary(
        key.public_key_pem, allowed_actions={"record"}, task_id="REPLAY", **kwargs
    )
    boundary.register_tool("record", func)
    return boundary


def invoke(boundary, receipt, **kwargs):
    """Submit the approved action while permitting explicit invalid-argument or signature probes."""
    return boundary.invoke_tool(
        "record", kwargs.get("args", {"value": "approved"}), receipt.receipt_bytes,
        kwargs.get("signature", receipt.signature),
    )


def test_receipt_is_consumed_by_same_boundary(capability):
    """Repeated use of one receipt must produce exactly one tool side effect."""
    key, receipt = capability
    calls = []
    boundary = make_boundary(key, lambda value: calls.append(value))
    invoke(boundary, receipt)
    with pytest.raises(ExecutionDeniedError, match="already consumed"):
        invoke(boundary, receipt)
    assert calls == ["approved"]


def test_receipt_stays_consumed_across_instances_and_reopening(capability):
    """Receipt consumption must survive boundary replacement and reopening of the shared store."""
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
    """Release competing boundary instances together and require exactly one successful dispatch."""
    key, receipt = capability
    calls = []
    gate = threading.Barrier(8)

    def attempt(_):
        """Race one independently constructed boundary against the shared receipt after the thread barrier."""
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
    """Run a fresh verifier process using only public receipt material and an isolated side-effect file."""
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
    """Competing processes and a later restart must share one durable receipt-consumption decision."""
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
    """Abrupt exit after a side effect must not make the same receipt usable by a restarted process."""
    key, receipt = capability
    effects = tmp_path / "effects.txt"
    crashed = process_attempt(key, receipt, effects, crash=True)
    assert crashed.returncode == 17
    restarted = process_attempt(key, receipt, effects)
    assert restarted.returncode == 0
    assert restarted.stdout.strip() == "denied"
    assert effects.read_text(encoding="utf-8").splitlines() == ["approved"]


def test_tool_exception_does_not_refund_receipt(capability):
    """A tool exception after dispatch must leave the receipt consumed and prevent a second side effect."""
    key, receipt = capability
    calls = []

    def failing_tool(value):
        """Record the attempted side effect before raising to test that dispatch is never refunded."""
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
    """Invalid signature, request, or task binding must not burn a receipt before its valid invocation."""
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
    """Alternate PEM serialization of the same trusted key must not bypass prior receipt consumption."""
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
    """A key-setting change after verification must not move consumption into another issuer namespace."""
    key, receipt = capability
    other_key = TestIssuer(generate_keypair(key_size=2048))
    calls = []
    boundary = make_boundary(key, lambda value: calls.append(value))
    original_verify = boundary_module.verify

    def verify_then_change_configuration(**kwargs):
        """Change the boundary key setting only after the original key has verified the receipt."""
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
    """Corrupt or inaccessible replay storage must prevent tool side effects."""
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
    """An explicit database path must preserve consumption despite changes to the environment default."""
    key, receipt = capability
    calls = []
    path = tmp_path / "explicit.sqlite3"
    invoke(make_boundary(key, lambda value: calls.append(value), replay_store_path=path), receipt)
    monkeypatch.setenv("GOVERNED_AGENT_REPLAY_STORE_PATH", str(tmp_path / "other.sqlite3"))
    with pytest.raises(ExecutionDeniedError, match="already consumed"):
        invoke(make_boundary(key, lambda value: calls.append(value), replay_store_path=path), receipt)
    assert calls == ["approved"]


@pytest.mark.parametrize("configuration", ["explicit", "environment"])
def test_relative_store_stays_bound_when_tool_changes_working_directory(capability, tmp_path, monkeypatch, configuration):
    """A tool-induced cwd change must not redirect later consumption into a fresh database."""
    key, receipt = capability
    initial = tmp_path / "initial"
    changed = tmp_path / "changed"
    initial.mkdir()
    changed.mkdir()
    monkeypatch.chdir(initial)
    kwargs = {}
    if configuration == "explicit":
        kwargs["replay_store_path"] = "receipt-store.sqlite3"
    else:
        monkeypatch.setenv("GOVERNED_AGENT_REPLAY_STORE_PATH", "receipt-store.sqlite3")
    calls = []

    def record_and_change_directory(value):
        """Change cwd during the authorized side effect to probe replay-store path stability."""
        calls.append(value)
        monkeypatch.chdir(changed)

    boundary = make_boundary(key, record_and_change_directory, **kwargs)
    invoke(boundary, receipt)
    with pytest.raises(ExecutionDeniedError, match="already consumed"):
        invoke(boundary, receipt)
    assert calls == ["approved"]
    assert (initial / "receipt-store.sqlite3").is_file()
    assert not (changed / "receipt-store.sqlite3").exists()


@pytest.mark.parametrize("configuration", ["explicit", "environment"])
@pytest.mark.parametrize("home_error", [RuntimeError, KeyError])
def test_configured_store_works_without_home_directory(
    capability, tmp_path, monkeypatch, configuration, home_error
):
    """Explicit and environment paths must permit one dispatch without any usable home lookup."""
    key, receipt = capability
    path = tmp_path / "configured" / "replay.sqlite3"
    calls = []

    def unavailable_home():
        """Raise the selected home-resolution failure without touching actual home-directory state."""
        raise home_error("home directory unavailable")

    kwargs = {}
    if configuration == "explicit":
        kwargs["replay_store_path"] = path
    else:
        monkeypatch.setenv("GOVERNED_AGENT_REPLAY_STORE_PATH", str(path))
    with monkeypatch.context() as patcher:
        patcher.setattr(Path, "home", unavailable_home)
        boundary = make_boundary(key, lambda value: calls.append(value), **kwargs)
        invoke(boundary, receipt)
        with pytest.raises(ExecutionDeniedError, match="already consumed"):
            invoke(boundary, receipt)
    assert calls == ["approved"]
    assert path.is_file()


def test_empty_environment_store_uses_home_directory(capability, tmp_path, monkeypatch):
    """An empty override must persist consumption in the isolated home fallback rather than the working directory."""
    key, receipt = capability
    calls = []
    home = tmp_path / "test-home"
    monkeypatch.setenv("GOVERNED_AGENT_REPLAY_STORE_PATH", "")
    monkeypatch.setattr(Path, "home", lambda: home)
    boundary = make_boundary(key, lambda value: calls.append(value))
    invoke(boundary, receipt)
    with pytest.raises(ExecutionDeniedError, match="already consumed"):
        invoke(boundary, receipt)
    assert calls == ["approved"]
    assert (home / ".governed_agent" / "receipt_replay.sqlite3").is_file()


@pytest.mark.parametrize("home_error", [RuntimeError, KeyError])
def test_unconfigured_store_reports_controlled_error_when_home_unavailable(monkeypatch, home_error):
    """Home lookup failures without an override must become controlled replay configuration errors."""
    def unavailable_home():
        """Raise the selected home-resolution failure without touching actual home-directory state."""
        raise home_error("home directory unavailable")

    monkeypatch.delenv("GOVERNED_AGENT_REPLAY_STORE_PATH", raising=False)
    with monkeypatch.context() as patcher:
        patcher.setattr(Path, "home", unavailable_home)
        with pytest.raises(ReplayStoreError, match="Replay storage path unavailable"):
            ReceiptReplayStore()
