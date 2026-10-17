"""Tests for planning layer (BLINK scope validation and handoff briefs)."""

import pytest

from governed_agent.planning.blink import (
    create_handoff,
    render_brief,
    validate,
)

VALID_PACKET = {
    "task_id": "TEST-BLINK-001",
    "objective": "Validate a bounded planning packet",
    "focus_point": "Packet scope only",
    "allowed_paths": ["/workspace/build/output"],
    "allowed_actions": ["read", "propose"],
    "prohibited_actions": ["activate", "deploy", "publish", "send", "overwrite"],
    "acceptance_criteria": ["Return a deterministic validation result"],
    "evidence_refs": ["fixture"],
    "executor": "procc",
}


def test_valid_packet_passes_without_execution_authority():
    result = validate(VALID_PACKET)
    assert result["blink_result"] == "PASS"
    assert result["execution_authority"] is False
    assert result["not_authorization"] is True
    assert result["failures"] == []


def test_missing_required_prohibition_fails():
    tampered = dict(VALID_PACKET)
    tampered["prohibited_actions"] = ["activate", "deploy", "publish"]  # missing 'send', 'overwrite'
    result = validate(tampered)
    assert result["blink_result"] == "FAIL"
    assert any("prohibited_actions must explicitly include" in f for f in result["failures"])


def test_risky_action_fails():
    tampered = dict(VALID_PACKET)
    tampered["allowed_actions"] = ["read", "deploy"]
    result = validate(tampered)
    assert result["blink_result"] == "FAIL"
    assert any("high-risk actions" in f for f in result["failures"])


def test_handoff_requires_named_executor():
    tampered = dict(VALID_PACKET)
    tampered.pop("executor")
    result = validate(tampered)
    with pytest.raises(ValueError, match="executor is required"):
        create_handoff(tampered, result)


def test_handoff_is_deterministic_and_never_dispatches():
    res1 = validate(VALID_PACKET)
    handoff1 = create_handoff(VALID_PACKET, res1)

    res2 = validate(VALID_PACKET)
    handoff2 = create_handoff(VALID_PACKET, res2)

    assert handoff1["packet_sha256"] == handoff2["packet_sha256"]
    assert handoff1["execution_authority"] is False
    assert handoff1["dispatch_performed"] is False
    assert handoff1["authorization_required_before_execution"] is True


def test_reasoning_brief_is_deterministic_and_non_executing():
    res = validate(VALID_PACKET)
    brief = render_brief(VALID_PACKET, res)
    assert "READ + PROPOSE ONLY" in brief
    assert "No execution authority is granted" in brief
    assert VALID_PACKET["objective"] in brief
