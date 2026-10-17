"""Tests for Hermes tool execution boundary governance adapter."""

import pytest
from governed_agent.capability.crypto import generate_keypair, seal
from governed_agent.hermes import GovernedToolBoundary, ExecutionDeniedError


def test_governed_tool_boundary_accepts_valid_receipt():
    custodian_key = generate_keypair(key_size=2048, key_id="custodian-01")
    boundary = GovernedToolBoundary(
        custodian_public_pem=custodian_key.public_key_pem,
        allowed_actions={"read_file", "search_files"},
        task_id="TASK-HERMES-01",
    )

    # Register sample tool
    boundary.register_tool("read_file", lambda path: f"content of {path}")

    # Generate valid sealed receipt
    receipt = seal(
        request={"action": "read_file", "path": "docs/readme.md"},
        trusted_context={"task_id": "TASK-HERMES-01"},
        keypair=custodian_key,
    )

    result = boundary.invoke_tool(
        tool_name="read_file",
        args={"path": "docs/readme.md"},
        receipt_bytes=receipt.receipt_bytes,
        signature=receipt.signature,
    )

    assert result == "content of docs/readme.md"


def test_governed_tool_boundary_blocks_unauthorized_action():
    custodian_key = generate_keypair(key_size=2048, key_id="custodian-01")
    boundary = GovernedToolBoundary(
        custodian_public_pem=custodian_key.public_key_pem,
        allowed_actions={"read_file"},
        task_id="TASK-HERMES-01",
    )

    boundary.register_tool("write_file", lambda path, content: "written")

    # Receipt authorizes write_file, but boundary policy prohibits it
    receipt = seal(
        request={"action": "write_file", "path": "secret.txt"},
        trusted_context={"task_id": "TASK-HERMES-01"},
        keypair=custodian_key,
    )

    with pytest.raises(ExecutionDeniedError, match="not in allowed_actions"):
        boundary.invoke_tool(
            tool_name="write_file",
            args={"path": "secret.txt", "content": "bad"},
            receipt_bytes=receipt.receipt_bytes,
            signature=receipt.signature,
        )


def test_governed_tool_boundary_blocks_tampered_signature():
    custodian_key = generate_keypair(key_size=2048, key_id="custodian-01")
    boundary = GovernedToolBoundary(
        custodian_public_pem=custodian_key.public_key_pem,
        allowed_actions={"read_file"},
        task_id="TASK-HERMES-01",
    )

    boundary.register_tool("read_file", lambda path: "ok")

    receipt = seal(
        request={"action": "read_file", "path": "test.txt"},
        trusted_context={"task_id": "TASK-HERMES-01"},
        keypair=custodian_key,
    )

    tampered_sig = b"0" * len(receipt.signature)

    with pytest.raises(ExecutionDeniedError, match="Capability verification failed"):
        boundary.invoke_tool(
            tool_name="read_file",
            args={"path": "test.txt"},
            receipt_bytes=receipt.receipt_bytes,
            signature=tampered_sig,
        )


def test_governed_tool_boundary_blocks_context_mismatch():
    custodian_key = generate_keypair(key_size=2048, key_id="custodian-01")
    boundary = GovernedToolBoundary(
        custodian_public_pem=custodian_key.public_key_pem,
        allowed_actions={"read_file"},
        task_id="TASK-HERMES-01",
    )

    boundary.register_tool("read_file", lambda path: "ok")

    # Receipt sealed for a different task context
    receipt = seal(
        request={"action": "read_file", "path": "test.txt"},
        trusted_context={"task_id": "TASK-ROGUE-99"},
        keypair=custodian_key,
    )

    with pytest.raises(ExecutionDeniedError, match="Capability verification failed"):
        boundary.invoke_tool(
            tool_name="read_file",
            args={"path": "test.txt"},
            receipt_bytes=receipt.receipt_bytes,
            signature=receipt.signature,
        )
