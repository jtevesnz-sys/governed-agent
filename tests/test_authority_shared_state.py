"""Shared-directory authority regressions, using only isolated test state."""

from concurrent.futures import ThreadPoolExecutor
import builtins
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

from governed_agent.capability.antirollback import FileBackedAuthority


KEY = b"shared-authority-test-only-key"


@pytest.mark.parametrize("configuration", ["explicit", "environment"])
def test_relative_authority_stays_bound_after_working_directory_change(tmp_path, monkeypatch, configuration):
    """Changing cwd must not switch an existing authority to a separate directory with older history."""
    initial = tmp_path / "initial"
    changed = tmp_path / "changed"
    initial.mkdir()
    changed.mkdir()
    monkeypatch.chdir(initial)
    if configuration == "explicit":
        authority = FileBackedAuthority("state", authority_key=KEY)
    else:
        monkeypatch.setenv("GOVERNED_AGENT_ANTIROLLBACK_DIR", "state")
        authority = FileBackedAuthority(authority_key=KEY)
    authority.create_pin("chain", "current", 2)
    alternate = FileBackedAuthority(changed / "state", authority_key=KEY)
    alternate.create_pin("chain", "older-separate-store", 1)
    monkeypatch.chdir(changed)
    assert authority.get_current_pin("chain").sequence == 2
    authority.create_pin("chain", "next", 3)
    assert FileBackedAuthority(initial / "state", authority_key=KEY).get_current_pin("chain").sequence == 3
    assert alternate.get_current_pin("chain").sequence == 1


def test_stale_writer_cannot_replace_newer_pin(tmp_path):
    """A writer created before a newer pin must reload and reject its attempted rollback."""
    first = FileBackedAuthority(tmp_path, authority_key=KEY)
    stale = FileBackedAuthority(tmp_path, authority_key=KEY)
    first.create_pin("chain", "newer", 2)
    with pytest.raises(ValueError, match="Rollback detected"):
        stale.create_pin("chain", "older", 1)
    assert FileBackedAuthority(tmp_path, authority_key=KEY).get_current_pin("chain").sequence == 2


def test_stale_writers_preserve_other_chains_and_readers_refresh(tmp_path):
    """Independent instances must preserve other chains and expose newly committed history on reads."""
    first = FileBackedAuthority(tmp_path, authority_key=KEY)
    second = FileBackedAuthority(tmp_path, authority_key=KEY)
    first.create_pin("alpha", "a", 1)
    second.create_pin("beta", "b", 1)
    first.create_pin("alpha", "a2", 2)
    assert second.get_current_pin("alpha").sequence == 2
    assert [pin.sequence for pin in second.get_all_pins("alpha")] == [1, 2]
    assert first.get_chain_status("beta")["pin_count"] == 1
    assert second.get_chain_status("alpha")["counter"] == 3


def test_threaded_instances_do_not_lose_updates(tmp_path):
    """Simultaneous writers must retain every distinct chain and advance one shared counter."""
    authorities = [FileBackedAuthority(tmp_path, authority_key=KEY) for _ in range(8)]
    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(lambda pair: pair[1].create_pin(str(pair[0]), "h", 1), enumerate(authorities)))
    reloaded = FileBackedAuthority(tmp_path, authority_key=KEY)
    assert reloaded.get_chain_status("0")["counter"] == 8
    assert all(reloaded.get_current_pin(str(i)) is not None for i in range(8))


_CHILD = r'''
import os, pathlib, sys, time
from governed_agent.capability.antirollback import FileBackedAuthority
root, worker, mode = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3]
def wait_for(name):
    deadline = time.monotonic() + 15
    while not (root / name).exists():
        if time.monotonic() > deadline: raise RuntimeError("barrier timeout")
        time.sleep(0.01)
if mode == "initialize":
    original_random = os.urandom
    def delayed_random(size):
        value = original_random(size)
        time.sleep(0.1)
        return value
    os.urandom = delayed_random
    (root / ("ready" + worker)).touch()
    wait_for("release")
    authority = FileBackedAuthority(root / "state")
else:
    authority = FileBackedAuthority(root / "state", authority_key=b"shared-authority-test-only-key")
(root / ("loaded" + worker)).touch()
wait_for("write")
chain = "chain" if mode == "same" else "chain" + worker
try:
    authority.create_pin(chain, "hash" + worker, 1)
    print("accepted")
except ValueError as exc:
    if "Rollback detected" not in str(exc): raise
    print("rollback")
'''


def _wait_for_files(root, names, children):
    """Wait for worker barriers with bounded time and detect children that exit before synchronization."""
    deadline = time.monotonic() + 20
    while not all((root / name).exists() for name in names):
        assert all(child.poll() is None for child in children), "worker exited before barrier"
        assert time.monotonic() < deadline, "worker barrier timed out"
        time.sleep(0.01)


@pytest.mark.parametrize("mode", ["same", "different", "initialize"])
def test_subprocess_writers_and_initializers_share_state(tmp_path, mode, monkeypatch):
    """Synchronize processes to expose lost writes, duplicate sequences, or competing initial authority keys."""
    monkeypatch.delenv("GOVERNED_AGENT_AUTHORITY_KEY", raising=False)
    children = [subprocess.Popen(
        [sys.executable, "-c", _CHILD, str(tmp_path), str(worker), mode],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    ) for worker in range(2)]
    try:
        if mode == "initialize":
            _wait_for_files(tmp_path, ["ready0", "ready1"], children)
            (tmp_path / "release").touch()
        _wait_for_files(tmp_path, ["loaded0", "loaded1"], children)
        (tmp_path / "write").touch()
        results = [child.communicate(timeout=20) for child in children]
        assert [child.returncode for child in children] == [0, 0], results
        outcomes = sorted(stdout.strip() for stdout, _ in results)
        expected = ["accepted", "rollback"] if mode == "same" else ["accepted", "accepted"]
        assert outcomes == expected
        key = None if mode == "initialize" else KEY
        authority = FileBackedAuthority(tmp_path / "state", authority_key=key)
        assert authority.get_chain_status("chain")["counter"] == (1 if mode == "same" else 2)
        if mode != "same":
            assert authority.get_current_pin("chain0") is not None
            assert authority.get_current_pin("chain1") is not None
    finally:
        for child in children:
            if child.poll() is None:
                child.kill()
            child.communicate()


@pytest.mark.parametrize("filename,content", [
    ("counter.txt", "invalid"), ("counter.txt", "-1"),
    ("pins.json", "{"), ("pins.json", "[]"),
    ("pins.json", '{"chain": null}'),
    ("pins.json", '{"chain": [{}]}'),
])
def test_existing_instances_fail_closed_on_corrupted_disk(tmp_path, filename, content):
    """Corrupted persisted records must block cached reads and writes without repairing or replacing evidence."""
    authority = FileBackedAuthority(tmp_path, authority_key=KEY)
    authority.create_pin("chain", "a", 1)
    (tmp_path / filename).write_text(content, encoding="utf-8")
    before = {name: (tmp_path / name).read_bytes() for name in ("pins.json", "counter.txt")}
    for operation in (
        lambda: authority.get_current_pin("chain"),
        lambda: authority.get_all_pins("chain"),
        lambda: authority.get_chain_status("chain"),
        lambda: authority.create_pin("chain", "b", 2),
    ):
        with pytest.raises(ValueError, match="integrity error"):
            operation()
    assert {name: (tmp_path / name).read_bytes() for name in before} == before


def test_refresh_does_not_retain_removed_chains_or_duplicate_history(tmp_path):
    """A coherent disk refresh must replace cached history rather than retain removed or duplicate entries."""
    authority = FileBackedAuthority(tmp_path, authority_key=KEY)
    authority.create_pin("alpha", "a", 1)
    authority.create_pin("beta", "b", 1)
    data = json.loads((tmp_path / "pins.json").read_text(encoding="utf-8"))
    del data["alpha"]
    (tmp_path / "pins.json").write_text(json.dumps(data), encoding="utf-8")
    (tmp_path / "counter.txt").write_text("1", encoding="utf-8")
    # A coherent full snapshot replay still requires an external anchor to detect.
    assert authority.get_current_pin("alpha") is None
    assert len(authority.get_all_pins("beta")) == 1
    assert len(authority.get_all_pins("beta")) == 1


def test_partial_save_failure_blocks_following_operations(tmp_path, monkeypatch):
    """A counter replacement failure after a pin write must leave detectable inconsistency on later operations."""
    authority = FileBackedAuthority(tmp_path, authority_key=KEY)
    authority.create_pin("chain", "a", 1)
    original_replace = os.replace

    def refuse_counter_replace(source, destination):
        """Fail only the counter replacement to simulate interruption between the two persisted files."""
        if Path(destination).name == "counter.txt":
            raise OSError("simulated counter write failure")
        return original_replace(source, destination)

    with monkeypatch.context() as patcher:
        patcher.setattr(os, "replace", refuse_counter_replace)
        with pytest.raises(OSError, match="simulated"):
            authority.create_pin("chain", "b", 2)
    with pytest.raises(ValueError, match="integrity error"):
        authority.create_pin("chain", "c", 2)
    with pytest.raises(ValueError, match="integrity error"):
        FileBackedAuthority(tmp_path, authority_key=KEY)


def test_existing_instance_rejects_missing_state_files(tmp_path):
    """An active authority must reject deleted history instead of silently restarting its counter."""
    authority = FileBackedAuthority(tmp_path, authority_key=KEY)
    authority.create_pin("chain", "a", 1)
    (tmp_path / "pins.json").unlink()
    (tmp_path / "counter.txt").unlink()
    with pytest.raises(ValueError, match="integrity error"):
        authority.create_pin("chain", "b", 2)


def test_existing_instance_fails_closed_on_state_read_error(tmp_path, monkeypatch):
    """Unreadable shared history must block operations while preserving the last intact disk state."""
    authority = FileBackedAuthority(tmp_path, authority_key=KEY)
    authority.create_pin("chain", "a", 1)
    original_open = builtins.open

    def refuse_pins_read(file, mode="r", *args, **kwargs):
        """Deny history reads while leaving other file operations available for integrity checks."""
        if Path(file).name == "pins.json" and mode == "r":
            raise PermissionError("simulated inaccessible state")
        return original_open(file, mode, *args, **kwargs)

    with monkeypatch.context() as patcher:
        patcher.setattr(builtins, "open", refuse_pins_read)
        with pytest.raises(ValueError, match="integrity error"):
            authority.get_current_pin("chain")
        with pytest.raises(ValueError, match="integrity error"):
            authority.create_pin("chain", "b", 2)
    assert FileBackedAuthority(tmp_path, authority_key=KEY).get_current_pin("chain").sequence == 1


@pytest.mark.parametrize("chain_id,checkpoint_hash,sequence", [
    ("chain", "hash", True), ("chain", "hash", False),
    ("chain", "hash", 0), ("chain", "hash", -1),
    ("chain", "hash", 1.5), ("chain", "hash", "1"),
    ("chain", "hash", None),
    (1, "hash", 1), (None, "hash", 1), ([], "hash", 1),
    ("chain", 1, 1), ("chain", None, 1), ("chain", [], 1),
])
def test_invalid_new_pins_cannot_poison_persisted_state(
    tmp_path, chain_id, checkpoint_hash, sequence
):
    """Invalid pin fields must leave disk bytes and counters unchanged and allow a later valid append."""
    authority = FileBackedAuthority(tmp_path, authority_key=KEY)
    authority.create_pin("existing", "first", 1)
    before = {name: (tmp_path / name).read_bytes() for name in ("pins.json", "counter.txt")}
    with pytest.raises(ValueError):
        authority.create_pin(chain_id, checkpoint_hash, sequence)
    assert {name: (tmp_path / name).read_bytes() for name in before} == before
    assert authority.get_chain_status("existing")["counter"] == 1
    assert authority.get_current_pin("existing").sequence == 1
    authority.create_pin("chain", "valid", 1)
    reloaded = FileBackedAuthority(tmp_path, authority_key=KEY)
    assert reloaded.get_current_pin("chain").sequence == 1
    assert reloaded.get_chain_status("existing")["counter"] == 2


@pytest.mark.parametrize("previously_used", [False, True])
def test_key_without_history_requires_explicit_recovery_without_reset(
    tmp_path, monkeypatch, previously_used
):
    """A retained key without matching history must require explicit recovery and never create replacement history."""
    monkeypatch.delenv("GOVERNED_AGENT_AUTHORITY_KEY", raising=False)
    key_file = tmp_path / "authority.key"
    if previously_used:
        authority = FileBackedAuthority(tmp_path)
        authority.create_pin("chain", "first", 1)
        (tmp_path / "pins.json").unlink()
        (tmp_path / "counter.txt").unlink()
    else:
        # The original constructor legitimately left this legacy layout before
        # the first pin, but it is indistinguishable from deleted used history.
        key_file.write_bytes(KEY)
    previous_key = key_file.read_bytes()
    with pytest.raises(ValueError, match="integrity error") as caught:
        FileBackedAuthority(tmp_path)
    message = str(caught.value)
    assert "restore the matching pins.json and counter.txt" in message
    assert "owner-approved new authority in a separate directory" in message
    if previously_used:
        with pytest.raises(ValueError, match="integrity error"):
            authority.create_pin("chain", "second", 2)
    assert key_file.read_bytes() == previous_key
    assert not (tmp_path / "pins.json").exists()
    assert not (tmp_path / "counter.txt").exists()


def test_configured_authority_directory_does_not_require_home(tmp_path, monkeypatch):
    """An explicit environment directory must support pin creation when home lookup raises."""
    configured = tmp_path / "configured"
    monkeypatch.setenv("GOVERNED_AGENT_ANTIROLLBACK_DIR", str(configured))

    def unavailable_home():
        """Simulate a host without a resolvable home directory without consulting real user state."""
        raise RuntimeError("no home directory")

    monkeypatch.setattr(Path, "home", unavailable_home)
    authority = FileBackedAuthority(authority_key=KEY)
    authority.create_pin("chain", "first", 1)
    assert authority.storage_path == configured.resolve()
    assert (configured / "pins.json").exists()


@pytest.mark.parametrize("configured", [None, ""])
def test_unconfigured_authority_directory_uses_mock_home(tmp_path, monkeypatch, configured):
    """Unset and empty directory overrides must use the isolated home fallback and persist usable pins."""
    monkeypatch.chdir(tmp_path)
    if configured is None:
        monkeypatch.delenv("GOVERNED_AGENT_ANTIROLLBACK_DIR", raising=False)
    else:
        monkeypatch.setenv("GOVERNED_AGENT_ANTIROLLBACK_DIR", configured)
    home = tmp_path / "test-home"
    monkeypatch.setattr(Path, "home", lambda: home)
    authority = FileBackedAuthority(authority_key=KEY)
    assert authority.storage_path == (home / ".governed_agent" / "antirollback").resolve()
    authority.create_pin("chain", "first", 1)
    assert authority.get_current_pin("chain").sequence == 1


def test_unavailable_home_has_controlled_authority_path_error(tmp_path, monkeypatch):
    """Missing home configuration must produce an actionable error before creating authority files."""
    monkeypatch.delenv("GOVERNED_AGENT_ANTIROLLBACK_DIR", raising=False)
    monkeypatch.chdir(tmp_path)

    def unavailable_home():
        """Simulate a host without a resolvable home directory without consulting real user state."""
        raise RuntimeError("no home directory")

    monkeypatch.setattr(Path, "home", unavailable_home)
    with pytest.raises(ValueError, match="GOVERNED_AGENT_ANTIROLLBACK_DIR"):
        FileBackedAuthority(authority_key=KEY)
    assert list(tmp_path.iterdir()) == []
