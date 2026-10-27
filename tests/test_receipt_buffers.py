"""Verification and dispatch must use the same immutable signed byte buffer."""
import json

import pytest

from governed_agent.capability.crypto import generate_keypair, seal, verify
from governed_agent.hermes import ExecutionDeniedError, GovernedToolBoundary
from governed_agent.hermes import boundary as boundary_module


class MisleadingReceipt(bytes):
    def decode(self, *args, **kwargs):
        data = json.loads(bytes(self).decode(*args, **kwargs))
        data["request"]["value"] = "UNSIGNED"
        data["trusted_context"] = {"owner": True}
        return json.dumps(data)


def test_crypto_parses_the_buffer_that_was_signed_not_overridden_decode():
    key = generate_keypair(key_size=2048)
    receipt = seal({"action": "write", "value": "SIGNED"}, {"owner": 1}, key)
    verdict = verify(MisleadingReceipt(receipt.receipt_bytes), receipt.signature, {"owner": True}, key)
    assert verdict.status == "HOLD"


def test_boundary_does_not_dispatch_unsigned_bytes_subclass_payload():
    key = generate_keypair(key_size=2048)
    receipt = seal({"action": "write", "value": "SIGNED"}, {}, key)
    invoked = []

    class ChangedRequest(bytes):
        def decode(self, *args, **kwargs):
            data = json.loads(bytes(self).decode(*args, **kwargs))
            data["request"]["value"] = "UNSIGNED"
            return json.dumps(data)

    boundary = GovernedToolBoundary(key.public_key_pem)
    boundary.register_tool("write", lambda value: invoked.append(value))
    with pytest.raises(ExecutionDeniedError):
        boundary.invoke_tool("write", {"value": "UNSIGNED"}, ChangedRequest(receipt.receipt_bytes), receipt.signature)
    assert invoked == []


def test_boundary_keeps_mutable_receipt_snapshot_after_verification(monkeypatch):
    key = generate_keypair(key_size=2048)
    receipt = seal({"action": "write", "value": "SIGNED"}, {}, key)
    buffer = bytearray(receipt.receipt_bytes)
    changed = json.loads(bytes(buffer))
    changed["request"]["value"] = "UNSIGNED"
    real_verify = boundary_module.verify

    def change_after_verified(*args, **kwargs):
        verdict = real_verify(*args, **kwargs)
        assert verdict.status == "ACCEPT"
        buffer[:] = json.dumps(changed).encode()
        return verdict

    monkeypatch.setattr(boundary_module, "verify", change_after_verified)
    invoked = []
    boundary = GovernedToolBoundary(key.public_key_pem)
    boundary.register_tool("write", lambda value: invoked.append(value))
    with pytest.raises(ExecutionDeniedError):
        boundary.invoke_tool("write", {"value": "UNSIGNED"}, buffer, receipt.signature)
    assert invoked == []


def test_bytes_subclass_still_accepts_its_actual_signed_request():
    key = generate_keypair(key_size=2048)
    receipt = seal({"action": "write", "value": "SIGNED"}, {"owner": 1}, key)
    verdict = verify(MisleadingReceipt(receipt.receipt_bytes), receipt.signature, {"owner": 1}, key)
    assert verdict.status == "ACCEPT"


def test_boundary_freezes_native_buffer_without_custom_bytes_conversion():
    key = generate_keypair(key_size=2048)
    receipt = seal({"action": "write", "value": "SIGNED"}, {}, key)

    class ChangedConversion(bytes):
        def __bytes__(self):
            return b'{"request":{"action":"write","value":"UNSIGNED"}}'

    boundary = GovernedToolBoundary(key.public_key_pem)
    boundary.register_tool("write", lambda value: value)
    assert boundary.invoke_tool("write", {"value": "SIGNED"}, ChangedConversion(receipt.receipt_bytes), receipt.signature) == "SIGNED"
