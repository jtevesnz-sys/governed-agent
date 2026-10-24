"""Regressions for execution-boundary, state, audit, and handoff bypasses."""

import hashlib
import io
import json
import sys

import pytest

from governed_agent.audit.watchtower import WatchTower
from governed_agent.capability.antirollback import FileBackedAuthority
from governed_agent.capability.crypto import generate_keypair, seal
from governed_agent.hermes import ExecutionDeniedError, GovernedToolBoundary
from governed_agent.planning.blink import create_handoff, render_brief, run_mcp_server, validate


@pytest.mark.parametrize(
    "signed_request,invoked_args",
    [
        ({"action": "read_file", "path": "approved.txt"}, {"path": "outside.txt"}),
        ({"action": "read_file", "path": "approved.txt", "options": {"mode": "read"}},
         {"path": "approved.txt", "options": {"mode": "write"}}),
        ({"action": "read_file", "path": "approved.txt"},
         {"path": "approved.txt", "options": {"mode": "write"}}),
        ({"action": "read_file", "path": "approved.txt", "options": {"enabled": 1}},
         {"path": "approved.txt", "options": {"enabled": True}}),
        ({"path": "approved.txt"}, {"path": "approved.txt"}),
    ],
)
def test_boundary_rejects_unsigned_or_changed_invocation(signed_request, invoked_args):
    key = generate_keypair(key_size=2048)
    boundary = GovernedToolBoundary(key.public_key_pem, allowed_actions={"read_file"})
    invoked = []
    boundary.register_tool("read_file", lambda **kwargs: invoked.append(kwargs))
    receipt = seal(signed_request, {}, key)

    with pytest.raises(ExecutionDeniedError):
        boundary.invoke_tool("read_file", invoked_args, receipt.receipt_bytes, receipt.signature)
    assert invoked == []


def test_boundary_accepts_exact_nested_invocation():
    key = generate_keypair(key_size=2048)
    boundary = GovernedToolBoundary(key.public_key_pem, allowed_actions={"read_file"})
    boundary.register_tool("read_file", lambda **kwargs: kwargs)
    args = {"path": "approved.txt", "options": {"mode": "read"}}
    receipt = seal({"action": "read_file", **args}, {}, key)
    assert boundary.invoke_tool("read_file", args, receipt.receipt_bytes, receipt.signature) == args


def test_boundary_dispatches_validated_snapshot_not_mutable_args(monkeypatch):
    key = generate_keypair(key_size=2048)
    boundary = GovernedToolBoundary(key.public_key_pem, allowed_actions={"read_file"})
    boundary.register_tool("read_file", lambda **kwargs: kwargs["path"])
    receipt = seal({"action": "read_file", "path": "approved.txt"}, {}, key)
    args = {"path": "approved.txt"}
    original_dumps = json.dumps
    mutations = []

    def mutate_after_serialization(value, **kwargs):
        serialized = original_dumps(value, **kwargs)
        if not mutations and isinstance(value, dict) and value.get("path") == "approved.txt":
            args["path"] = "outside.txt"
            mutations.append(True)
        return serialized

    with monkeypatch.context() as patcher:
        patcher.setattr(json, "dumps", mutate_after_serialization)
        dispatched = boundary.invoke_tool("read_file", args, receipt.receipt_bytes, receipt.signature)
    assert mutations == [True]
    assert args["path"] == "outside.txt"
    assert dispatched == "approved.txt"


@pytest.mark.parametrize("legacy_counter", [False, True])
def test_file_authority_rejects_public_legacy_signature(tmp_path, legacy_counter):
    key = b"private-test-authority-key-32bytes!"
    auth = FileBackedAuthority(tmp_path, authority_key=key)
    pin = auth.create_pin("chain", "real", 1)
    pins_file = tmp_path / "pins.json"
    data = json.loads(pins_file.read_text(encoding="utf-8"))
    forged = data["chain"][0]
    forged["checkpoint_hash"] = "forged"
    suffix = "1" if legacy_counter else pin.pin_id
    signed = f"chain|forged|1|{pin.timestamp_utc}|{suffix}".encode("utf-8")
    forged["authority_signature"] = hashlib.sha256(
        b"governed-agent-authority-secret" + signed
    ).hexdigest()
    pins_file.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ValueError, match="integrity error"):
        FileBackedAuthority(tmp_path, authority_key=key)


def test_file_authority_rejects_truncated_signed_prefix(tmp_path):
    key = b"private-test-authority-key-32bytes!"
    authority = FileBackedAuthority(tmp_path, authority_key=key)
    authority.create_pin("chain", "first", 1)
    pins_file = tmp_path / "pins.json"
    earlier_pins = pins_file.read_bytes()
    authority.create_pin("chain", "second", 2)
    pins_file.write_bytes(earlier_pins)  # Counter still records two pins.
    with pytest.raises(ValueError, match="integrity error"):
        FileBackedAuthority(tmp_path, authority_key=key)


def test_file_authority_rejects_corrupt_or_missing_counter(tmp_path):
    key = b"private-test-authority-key-32bytes!"
    authority = FileBackedAuthority(tmp_path, authority_key=key)
    authority.create_pin("chain", "first", 1)
    counter_file = tmp_path / "counter.txt"
    counter_file.write_text("not a count", encoding="utf-8")
    with pytest.raises(ValueError, match="integrity error"):
        FileBackedAuthority(tmp_path, authority_key=key)
    counter_file.unlink()
    with pytest.raises(ValueError, match="integrity error"):
        FileBackedAuthority(tmp_path, authority_key=key)


def test_file_authority_rejects_cross_chain_pin_relocation(tmp_path):
    key = b"private-test-authority-key-32bytes!"
    authority = FileBackedAuthority(tmp_path, authority_key=key)
    authority.create_pin("chain", "first", 1)
    pins_file = tmp_path / "pins.json"
    data = json.loads(pins_file.read_text(encoding="utf-8"))
    pins_file.write_text(json.dumps({"other-chain": data["chain"]}), encoding="utf-8")
    with pytest.raises(ValueError, match="integrity error"):
        FileBackedAuthority(tmp_path, authority_key=key)


def test_file_authority_rejects_empty_or_unreadable_key(tmp_path, monkeypatch):
    with pytest.raises(ValueError, match="nonempty bytes"):
        FileBackedAuthority(tmp_path, authority_key=b"")

    key_file = tmp_path / "authority.key"
    key_file.write_bytes(b"test-only-private-key")
    original_read = type(key_file).read_bytes

    def refuse_key_read(path):
        if path == key_file:
            raise PermissionError("unreadable authority key")
        return original_read(path)

    with monkeypatch.context() as patcher:
        patcher.setattr(type(key_file), "read_bytes", refuse_key_read)
        with pytest.raises(PermissionError, match="unreadable"):
            FileBackedAuthority(tmp_path)


def test_file_authority_does_not_replace_lost_key(tmp_path):
    authority = FileBackedAuthority(tmp_path)
    authority.create_pin("chain", "first", 1)
    key_file = tmp_path / "authority.key"
    key_file.unlink()
    with pytest.raises(ValueError, match="missing authority key"):
        FileBackedAuthority(tmp_path)
    assert not key_file.exists()


@pytest.mark.parametrize("missing_root", [None, "missing", "file"])
def test_watchtower_never_passes_without_existing_root(tmp_path, missing_root):
    files = [{"relative_path": "absent.txt", "lane_id": "LANE", "sha256": "a" * 64}]
    normalized = json.dumps(files, sort_keys=True, separators=(",", ":")).encode("utf-8")
    manifest = {
        "format": "governed.manifest.v1",
        "format_version": "1.0",
        "convergence_id": "CONV",
        "complete_set_sha256": hashlib.sha256(normalized).hexdigest(),
        "lane_records": [{"lane_id": "LANE"}],
        "files": files,
    }
    root = None if missing_root is None else tmp_path / missing_root
    if missing_root == "file":
        assert root is not None
        root.write_text("not a directory", encoding="utf-8")
    result = WatchTower(root_dir=root).verify(manifest)
    assert result["verdict"] != "PASS"
    assert any(c["name"] == "hash_agreement" and c["status"] == "FAIL" for c in result["checks"])


def test_watchtower_rejects_empty_artifact_set(tmp_path):
    manifest = {
        "format": "governed.manifest.v1",
        "format_version": "1.0",
        "convergence_id": "EMPTY",
        "complete_set_sha256": hashlib.sha256(b"[]").hexdigest(),
        "lane_records": [],
        "files": [],
    }
    result = WatchTower(root_dir=tmp_path).verify(manifest)
    assert result["verdict"] != "PASS"
    assert any(c["name"] == "hash_agreement" and c["status"] == "FAIL" for c in result["checks"])


def test_watchtower_rejects_placeholder_complete_set(tmp_path):
    artifact = tmp_path / "real.txt"
    artifact.write_bytes(b"real bytes")
    manifest = {
        "format": "governed.manifest.v1", "format_version": "1.0",
        "convergence_id": "REAL", "complete_set_sha256": "0" * 64,
        "lane_records": [{"lane_id": "LANE"}],
        "files": [{"relative_path": "real.txt", "lane_id": "LANE",
                   "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest()}],
    }
    result = WatchTower(root_dir=tmp_path).verify(manifest)
    assert result["verdict"] != "PASS"
    assert any(c["name"] == "complete_set_sha256" and c["status"] == "FAIL" for c in result["checks"])


@pytest.mark.parametrize("declared_size", [999, "3", True, -1])
def test_watchtower_rejects_false_artifact_size(tmp_path, declared_size):
    artifact = tmp_path / "real.txt"
    artifact.write_bytes(b"abc")
    files = [{"relative_path": "real.txt", "lane_id": "LANE",
              "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
              "size_bytes": declared_size}]
    digest = hashlib.sha256(json.dumps(files, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    manifest = {
        "format": "governed.manifest.v1", "format_version": "1.0",
        "convergence_id": "REAL", "complete_set_sha256": digest,
        "lane_records": [{"lane_id": "LANE"}], "files": files,
    }
    result = WatchTower(root_dir=tmp_path).verify(manifest)
    assert result["verdict"] != "PASS"
    assert any(c["name"] == "hash_agreement" and c["status"] == "FAIL" for c in result["checks"])


PACKET = {
    "task_id": "TASK-REGRESSION",
    "objective": "Read an approved file",
    "allowed_actions": ["read"],
    "prohibited_actions": ["activate", "deploy", "publish", "send", "overwrite"],
    "acceptance_criteria": ["Return the file contents"],
    "executor": "reviewer",
}


@pytest.mark.parametrize("use_cached_result", [False, True])
def test_handoff_revalidates_actual_packet(use_cached_result):
    valid = validate(PACKET)
    invalid = {**PACKET, "allowed_actions": ["deploy"]}
    result = valid if use_cached_result else {"blink_result": "PASS"}
    with pytest.raises(ValueError, match="failed validation"):
        create_handoff(invalid, result)
    with pytest.raises(ValueError, match="failed validation"):
        render_brief(invalid, result)


def test_disabled_blink_cannot_create_handoff(monkeypatch):
    monkeypatch.setenv("GOVERNED_AGENT_BLINK_ENABLED", "false")
    with pytest.raises(ValueError, match="validation"):
        create_handoff(PACKET, {"blink_result": "PASS"})


def test_mcp_handoff_rejects_forged_validation(monkeypatch):
    invalid = {**PACKET, "allowed_actions": ["deploy"]}
    request = {
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {"name": "create_handoff_packet", "arguments": {
            "packet": invalid, "validation": {"blink_result": "PASS"}}},
    }
    output_stream = io.StringIO()
    with monkeypatch.context() as patcher:
        patcher.setattr(sys, "stdin", io.StringIO(json.dumps(request) + "\n"))
        patcher.setattr(sys, "stdout", output_stream)
        run_mcp_server()
    output = output_stream.getvalue()
    messages = [json.loads(line) for line in output.splitlines()]
    assert len(messages) == 1
    assert messages[0]["result"]["isError"] is True


def test_mcp_handoff_accepts_valid_packet_without_cached_validation(monkeypatch):
    request = {
        "jsonrpc": "2.0", "id": 8, "method": "tools/call",
        "params": {"name": "create_handoff_packet", "arguments": {"packet": PACKET}},
    }
    output_stream = io.StringIO()
    with monkeypatch.context() as patcher:
        patcher.setattr(sys, "stdin", io.StringIO(json.dumps(request) + "\n"))
        patcher.setattr(sys, "stdout", output_stream)
        run_mcp_server()
    response = json.loads(output_stream.getvalue())
    handoff = json.loads(response["result"]["content"][0]["text"])
    assert handoff["execution_authority"] is False
    assert handoff["task"]["task_id"] == PACKET["task_id"]
