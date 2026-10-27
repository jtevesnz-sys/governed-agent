"""Verification boundaries reject malformed input and type-confused context."""

import copy
import errno
import hashlib
import json
import os
from pathlib import Path
import sys

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from governed_agent.audit.watchtower import WatchTower
from governed_agent.capability.crypto import generate_keypair, seal, verify


@pytest.fixture(scope="module")
def keypair():
    """Provide one ephemeral signing identity for malformed-receipt regression cases."""
    return generate_keypair()


def sign_raw(raw, keypair):
    """Sign exact malformed JSON bytes so rejection cannot be attributed to an invalid signature."""
    private = serialization.load_pem_private_key(keypair.private_key_pem.encode(), password=None)
    return private.sign(raw, padding.PKCS1v15(), hashes.SHA256())


@pytest.mark.parametrize("receipt", [None, True, 1, "receipt", [], [1]])
def test_nonobject_receipt_holds(receipt, keypair):
    """Even correctly signed JSON scalars and arrays must be rejected as receipt envelopes."""
    raw = json.dumps(receipt).encode()
    assert verify(raw, sign_raw(raw, keypair), {}, keypair).status == "HOLD"


@pytest.mark.parametrize("receipt", [None, True, [], {}])
def test_nonbytes_receipt_holds(receipt, keypair):
    """Unsupported receipt buffers must return HOLD rather than escape with a parsing exception."""
    assert verify(receipt, b"", {}, keypair).status == "HOLD"


@pytest.mark.parametrize("field,value", [
    ("request", None), ("request", []), ("request", True),
    ("trusted_context", None), ("trusted_context", []), ("trusted_context", True),
])
def test_receipt_nested_nonobjects_hold(field, value, keypair):
    """Signed request and context fields must be objects before their members are accessed."""
    receipt = {"request": {"action": "read"}, "trusted_context": {}}
    receipt[field] = value
    raw = json.dumps(receipt).encode()
    assert verify(raw, sign_raw(raw, keypair), {}, keypair).status == "HOLD"


@pytest.mark.parametrize("action", [[], ["read"], {}, True, 1, None])
def test_nonstring_receipt_action_holds(action, keypair):
    """Nonstring action values must fail policy checks without triggering hashability errors."""
    sealed = seal({"action": action}, {}, keypair)
    assert verify(sealed.receipt_bytes, sealed.signature, {}, keypair, allowed_actions={"read"}).status == "HOLD"


@pytest.mark.parametrize("signed,expected", [
    ({"value": True}, {"value": 1}),
    ({"value": 1}, {"value": True}),
    ({"value": 1}, {"value": 1.0}),
    ({"value": 1.0}, {"value": 1}),
    ({"value": [True]}, {"value": [1]}),
    ({"value": [{"enabled": 1}]}, {"value": [{"enabled": True}]}),
    ({"value": {"nested": [1.0]}}, {"value": {"nested": [1]}}),
])
def test_signed_context_type_confusion_holds(signed, expected, keypair):
    """JSON-distinct booleans, integers, and floats must not satisfy context binding through Python equality."""
    sealed = seal({"action": "read"}, signed, keypair)
    assert verify(sealed.receipt_bytes, sealed.signature, expected, keypair).status == "HOLD"


class EqualToAnything:
    def __eq__(self, other):
        """Emulate an attacker-controlled object that compares equal to every trusted context value."""
        return True


class JsonIntSubclass(int):
    pass


@pytest.mark.parametrize("expected", [
    None, [], True, {"value": (1,)}, {"value": {1}}, {1: "value"},
    {"value": float("nan")}, {"value": float("inf")},
    {"value": EqualToAnything()}, {"value": JsonIntSubclass(1)},
])
def test_nonjson_expected_context_holds(expected, keypair):
    """Custom equality, subclasses, and non-JSON values must not supply trusted context."""
    sealed = seal({"action": "read"}, {"value": 1}, keypair)
    assert verify(sealed.receipt_bytes, sealed.signature, expected, keypair).status == "HOLD"


def test_recursive_expected_context_holds(keypair):
    """A cyclic expected context must produce HOLD instead of uncontrolled recursion."""
    expected = {}
    expected["self"] = expected
    sealed = seal({"action": "read"}, {}, keypair)
    assert verify(sealed.receipt_bytes, sealed.signature, expected, keypair).status == "HOLD"


@pytest.mark.parametrize("context", [
    {}, {"a": True, "b": 1, "c": 1.0, "d": None},
    {"a": [{"enabled": False, "value": 0.0}], "b": "text"},
])
def test_same_json_context_accepts_regardless_of_key_order(context, keypair):
    """Equivalent native JSON context must remain acceptable when dictionary order changes."""
    sealed = seal({"action": "read"}, context, keypair)
    expected = dict(reversed(list(context.items())))
    assert verify(sealed.receipt_bytes, sealed.signature, expected, keypair).status == "ACCEPT"


@pytest.mark.parametrize("raw", [
    b'{"request":{},"trusted_context":{},"trusted_context":{}}',
    b'{"request":{},"trusted_context":{"v":1,"v":1}}',
    b'{"request":{},"trusted_context":{"v":NaN}}',
])
def test_ambiguous_or_nonjson_signed_receipt_holds(raw, keypair):
    """Valid signatures must not authorize duplicate JSON keys or nonfinite JSON values."""
    expected = {"v": float("nan")} if b"NaN" in raw else ({"v": 1} if b'"v"' in raw else {})
    assert verify(raw, sign_raw(raw, keypair), expected, keypair).status == "HOLD"


@pytest.fixture
def valid_manifest(tmp_path):
    """Create a real isolated artifact with matching per-file and complete-set digests."""
    (tmp_path / "artifact.txt").write_bytes(b"artifact")
    files = [{"relative_path": "artifact.txt", "lane_id": "A", "sha256": hashlib.sha256(b"artifact").hexdigest()}]
    canonical = json.dumps(files, sort_keys=True, separators=(",", ":")).encode()
    return {
        "format": "governed.manifest.v1", "format_version": "1.0", "convergence_id": "C1",
        "complete_set_sha256": hashlib.sha256(canonical).hexdigest(),
        "files": files, "lane_records": [{"lane_id": "A"}],
    }


def assert_controlled_failure(result):
    """Require a nonpassing verdict accompanied by an explicit failed audit check."""
    assert result["verdict"] in {"HOLD", "REVISE"}
    assert any(check["status"] == "FAIL" for check in result["checks"])


@pytest.mark.parametrize("manifest", [None, True, 1, [], [1]])
def test_watchtower_nonobject_manifest_holds(manifest, tmp_path):
    """Scalar and array manifest inputs must fail structurally before downstream field access."""
    assert_controlled_failure(WatchTower(tmp_path).verify(manifest))


@pytest.mark.parametrize("field,value", [
    ("format", []), ("format_version", None), ("convergence_id", True),
    ("files", None), ("files", {}), ("files", [1]), ("files", [None]),
    ("files", [{"relative_path": []}]), ("files", [{"relative_path": True}]),
    ("files", [{"relative_path": "artifact.txt", "sha256": []}]),
    ("files", [{"relative_path": "artifact.txt", "lane_id": []}]),
    ("lane_records", None), ("lane_records", {}), ("lane_records", [None]),
    ("lane_records", [1]), ("lane_records", [{"lane_id": []}]),
])
def test_watchtower_malformed_manifest_fields_hold(field, value, valid_manifest, tmp_path):
    """Wrong manifest member shapes must yield failed checks rather than parser or container exceptions."""
    manifest = copy.deepcopy(valid_manifest)
    manifest[field] = value
    assert_controlled_failure(WatchTower(tmp_path).verify(manifest))


@pytest.mark.parametrize("dep_graph", [
    [], True, 1, {"nodes": None}, {"nodes": {}}, {"nodes": [None]},
    {"nodes": [1]}, {"nodes": [{"node_type": "LANE"}]},
    {"nodes": [{"node_type": "LANE", "lane_id": []}]},
    {"nodes": [{"node_type": []}]},
])
def test_watchtower_malformed_dependency_graph_holds(dep_graph, valid_manifest, tmp_path):
    """Malformed dependency nodes must not crash lane-presence checks or yield audit success."""
    assert_controlled_failure(WatchTower(tmp_path).verify(valid_manifest, dep_graph))


@pytest.mark.parametrize("contracts", [
    {}, True, 1, [None], [1], [{"lane_id": []}],
    [{"independence_group": "group"}], [{"lane_id": "A", "independence_group": []}],
])
def test_watchtower_malformed_lane_contracts_hold(contracts, valid_manifest, tmp_path):
    """Invalid contract collections and lane identifiers must produce controlled independence failures."""
    assert_controlled_failure(WatchTower(tmp_path).verify(valid_manifest, lane_contracts=contracts))


@pytest.mark.parametrize("raw", ["{", "null", "[]", "true", "1", '{"files":[]} trailing'])
def test_watchtower_malformed_manifest_path_holds(raw, tmp_path):
    """Malformed or nonobject JSON read from a manifest file must produce a nonpassing verdict."""
    path = tmp_path / "manifest.json"
    path.write_text(raw, encoding="utf-8")
    assert_controlled_failure(WatchTower(tmp_path).verify(path))


def test_watchtower_valid_manifest_accepts(valid_manifest, tmp_path):
    """A valid artifact and matching dependency lane must retain a passing audit verdict."""
    result = WatchTower(tmp_path).verify(valid_manifest, {"nodes": [{"node_type": "LANE", "lane_id": "A"}]})
    assert result["verdict"] == "PASS"


@pytest.mark.parametrize("relative_path", ["bad\x00path", "x" * 300, "bad<name"])
def test_watchtower_malformed_artifact_names_fail_closed(relative_path, valid_manifest, tmp_path):
    """Malformed artifact names must fail even when their manifest complete-set digest is coherent."""
    valid_manifest["files"][0]["relative_path"] = relative_path
    canonical = json.dumps(valid_manifest["files"], sort_keys=True, separators=(",", ":")).encode()
    valid_manifest["complete_set_sha256"] = hashlib.sha256(canonical).hexdigest()
    assert_controlled_failure(WatchTower(tmp_path).verify(valid_manifest))


@pytest.mark.parametrize("operation", ["resolve", "is_file"])
@pytest.mark.parametrize("error", [ValueError("invalid path"), OSError(errno.EINVAL, "invalid name"), OSError(errno.ENAMETOOLONG, "long name")])
def test_watchtower_known_malformed_path_errors_fail_closed(operation, error, valid_manifest, tmp_path, monkeypatch):
    """Known name-validation errors during resolution or file checks must become failed audit checks."""
    original = getattr(Path, operation)

    def malformed_path(path, *args, **kwargs):
        """Inject a known malformed-name error only for the audited artifact path."""
        if path.name == "artifact.txt":
            raise error
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, operation, malformed_path)
    assert_controlled_failure(WatchTower(tmp_path).verify(valid_manifest))


def test_watchtower_unexpected_io_errors_remain_visible(valid_manifest, tmp_path, monkeypatch):
    """An unrelated permission failure must remain visible rather than being mislabeled as malformed input."""
    original = Path.resolve

    def inaccessible_path(path, *args, **kwargs):
        """Inject an unrelated permission failure only when resolving the audited artifact."""
        if path.name == "artifact.txt":
            raise PermissionError("unexpected access failure")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", inaccessible_path)
    with pytest.raises(PermissionError):
        WatchTower(tmp_path).verify(valid_manifest)


def test_watchtower_manifest_json_integer_limit_holds(tmp_path):
    """A real JSON integer-conversion limit must produce a manifest-validation HOLD."""
    get_limit = getattr(sys, "get_int_max_str_digits", None)
    if get_limit is None or get_limit() == 0:
        pytest.skip("Runtime has no active integer digit limit")
    path = tmp_path / "manifest.json"
    path.write_text('{"count":' + "9" * (get_limit() + 1) + "}", encoding="utf-8")
    result = WatchTower(tmp_path).verify(path)
    assert result["verdict"] == "HOLD"
    assert any(check["name"] == "manifest_validation" and check["status"] == "FAIL" for check in result["checks"])


def test_watchtower_manifest_json_plain_value_error_holds(tmp_path, monkeypatch):
    """A generic JSON decoder ValueError must be contained as a manifest-validation failure."""
    path = tmp_path / "manifest.json"
    path.write_text("{}", encoding="utf-8")

    def rejected_json(stream):
        """Simulate the decoder refusing a value while leaving filesystem access unchanged."""
        raise ValueError("JSON integer exceeds runtime conversion limit")

    monkeypatch.setattr(json, "load", rejected_json)
    result = WatchTower(tmp_path).verify(path)
    assert result["verdict"] == "HOLD"
    assert any(check["name"] == "manifest_validation" and check["status"] == "FAIL" for check in result["checks"])


@pytest.mark.parametrize("error", [RuntimeError("Symlink loop"), OSError(errno.ELOOP, "Symlink loop")])
def test_watchtower_resolution_loop_errors_fail_closed(error, valid_manifest, tmp_path, monkeypatch):
    """Platform-specific symlink-loop exceptions must become failed hash checks."""
    original = Path.resolve

    def looping_path(path, *args, **kwargs):
        """Inject the selected platform loop error while preserving resolution of other paths."""
        if path.name == "artifact.txt":
            raise error
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", looping_path)
    result = WatchTower(tmp_path).verify(valid_manifest)
    assert_controlled_failure(result)
    assert any(check["name"] == "hash_agreement" and check["status"] == "FAIL" for check in result["checks"])


def test_watchtower_real_artifact_symlink_loop_fails_closed(valid_manifest, tmp_path):
    """An actual self-referencing artifact symlink must fail hashing when the host permits symlink creation."""
    loop = tmp_path / "loop"
    try:
        loop.symlink_to("loop")
    except OSError as exc:
        if os.name == "nt" and getattr(exc, "winerror", None) == 1314:
            pytest.skip("Windows account lacks symbolic link privilege")
        raise
    valid_manifest["files"][0]["relative_path"] = "loop"
    canonical = json.dumps(valid_manifest["files"], sort_keys=True, separators=(",", ":")).encode()
    valid_manifest["complete_set_sha256"] = hashlib.sha256(canonical).hexdigest()
    result = WatchTower(tmp_path).verify(valid_manifest)
    assert_controlled_failure(result)
    assert any(check["name"] == "hash_agreement" and check["status"] == "FAIL" for check in result["checks"])
