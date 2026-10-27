"""Verification and dispatch must use the same immutable signed byte buffer."""
import json

import pytest

from governed_agent.capability.crypto import generate_keypair, seal, verify
from governed_agent.hermes import ExecutionDeniedError, GovernedToolBoundary
from governed_agent.hermes import boundary as boundary_module


class MisleadingReceipt(bytes):
    def decode(self, *args, **kwargs):
        """Expose unsigned decoded fields while retaining the authentic underlying byte buffer."""
        data = json.loads(bytes(self).decode(*args, **kwargs))
        data["request"]["value"] = "UNSIGNED"
        data["trusted_context"] = {"owner": True}
        return json.dumps(data)


def test_crypto_parses_the_buffer_that_was_signed_not_overridden_decode():
    """A forged decode override must not replace signed context with a Python-equal boolean value."""
    key = generate_keypair(key_size=2048)
    receipt = seal({"action": "write", "value": "SIGNED"}, {"owner": 1}, key)
    verdict = verify(MisleadingReceipt(receipt.receipt_bytes), receipt.signature, {"owner": True}, key)
    assert verdict.status == "HOLD"


def test_boundary_does_not_dispatch_unsigned_bytes_subclass_payload():
    """A receipt subclass must not substitute an unsigned tool argument during JSON decoding."""
    key = generate_keypair(key_size=2048)
    receipt = seal({"action": "write", "value": "SIGNED"}, {}, key)
    invoked = []

    class ChangedRequest(bytes):
        def decode(self, *args, **kwargs):
            """Expose unsigned decoded fields while retaining the authentic underlying byte buffer."""
            data = json.loads(bytes(self).decode(*args, **kwargs))
            data["request"]["value"] = "UNSIGNED"
            return json.dumps(data)

    boundary = GovernedToolBoundary(key.public_key_pem)
    boundary.register_tool("write", lambda value: invoked.append(value))
    with pytest.raises(ExecutionDeniedError):
        boundary.invoke_tool("write", {"value": "UNSIGNED"}, ChangedRequest(receipt.receipt_bytes), receipt.signature)
    assert invoked == []


def test_boundary_keeps_mutable_receipt_snapshot_after_verification(monkeypatch):
    """Mutating the caller buffer immediately after verification must not authorize changed invocation arguments."""
    key = generate_keypair(key_size=2048)
    receipt = seal({"action": "write", "value": "SIGNED"}, {}, key)
    buffer = bytearray(receipt.receipt_bytes)
    changed = json.loads(bytes(buffer))
    changed["request"]["value"] = "UNSIGNED"
    real_verify = boundary_module.verify

    def change_after_verified(*args, **kwargs):
        """Replace the caller buffer after real signature acceptance to expose a verification-to-dispatch race."""
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
    """A misleading decode override must not prevent acceptance of the actual signed byte content."""
    key = generate_keypair(key_size=2048)
    receipt = seal({"action": "write", "value": "SIGNED"}, {"owner": 1}, key)
    verdict = verify(MisleadingReceipt(receipt.receipt_bytes), receipt.signature, {"owner": 1}, key)
    assert verdict.status == "ACCEPT"


def test_boundary_freezes_native_buffer_without_custom_bytes_conversion():
    """Snapshotting must copy the native buffer rather than invoke an attacker-controlled bytes conversion."""
    key = generate_keypair(key_size=2048)
    receipt = seal({"action": "write", "value": "SIGNED"}, {}, key)

    class ChangedConversion(bytes):
        def __bytes__(self):
            """Offer unsigned conversion output to expose snapshot implementations that trust custom conversion hooks."""
            return b'{"request":{"action":"write","value":"UNSIGNED"}}'

    boundary = GovernedToolBoundary(key.public_key_pem)
    boundary.register_tool("write", lambda value: value)
    assert boundary.invoke_tool("write", {"value": "SIGNED"}, ChangedConversion(receipt.receipt_bytes), receipt.signature) == "SIGNED"
