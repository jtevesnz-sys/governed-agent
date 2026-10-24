#!/usr/bin/env python3
"""
Governed Agent — Task Packet Scope Validation (BLINK Planning Core)
Validates bounded task packets, enforces prohibition boundaries,
and renders deterministic reasoning briefs.

Guarantees:
- Plan != Authority (execution_authority is always False).
- Tamper-evident handoffs bound by SHA-256.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from typing import Any, Dict, List, Optional, Set

ALLOWED_ACTIONS: Set[str] = {"read", "propose", "create-candidate", "verify", "classify"}
HIGH_RISK_ACTIONS: Set[str] = {
    "activate",
    "deploy",
    "publish",
    "send",
    "overwrite",
    "delete",
    "credential",
    "network",
    "listener",
    "schedule",
    "install",
}
REQUIRED_PROHIBITIONS: Set[str] = {"activate", "deploy", "publish", "send", "overwrite"}


def enabled() -> bool:
    """Return whether BLINK validation is enabled."""
    return os.environ.get("GOVERNED_AGENT_BLINK_ENABLED", "true").lower() == "true"


def validate(packet: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate a bounded task packet.

    Checks:
    - BLINK enabled check (respects GOVERNED_AGENT_BLINK_ENABLED).
    - task_id, objective, and acceptance_criteria presence.
    - allowed_actions within safe bounded set.
    - No high-risk actions in allowed_actions.
    - Required prohibitions explicitly present.
    - No intersection between allowed and prohibited actions.
    """
    failures: List[str] = []
    warnings: List[str] = []

    task_id = packet.get("task_id", "")
    objective = packet.get("objective", "")

    if not enabled():
        warnings.append("BLINK validation is disabled via GOVERNED_AGENT_BLINK_ENABLED=false")
        return {
            "task_id": task_id,
            "objective": objective,
            "blink_result": "FAIL",
            "failures": ["BLINK validation is disabled"],
            "warnings": warnings,
            "execution_authority": False,
            "not_authorization": True,
        }
    allowed = set(packet.get("allowed_actions", []))
    prohibited = set(packet.get("prohibited_actions", []))
    criteria = packet.get("acceptance_criteria", [])
    paths = packet.get("allowed_paths", [])

    if not task_id:
        failures.append("task_id is required")
    if not objective:
        failures.append("objective is required")
    if not criteria:
        failures.append("at least one acceptance_criterion is required")

    unknown = sorted(allowed - ALLOWED_ACTIONS)
    if unknown:
        failures.append("allowed_actions exceeds the bounded planning surface: " + ", ".join(unknown))

    risky_allowed = sorted(allowed & HIGH_RISK_ACTIONS)
    if risky_allowed:
        failures.append("high-risk actions cannot be allowed by planning layer: " + ", ".join(risky_allowed))

    missing = sorted(REQUIRED_PROHIBITIONS - prohibited)
    if missing:
        failures.append("prohibited_actions must explicitly include: " + ", ".join(missing))

    overlap = sorted(allowed & prohibited)
    if overlap:
        failures.append("actions cannot be both allowed and prohibited: " + ", ".join(overlap))

    if not packet.get("focus_point"):
        warnings.append("focus_point is absent; reasoning may be broader than necessary")
    if not paths:
        warnings.append("allowed_paths is empty; packet is reasoning-only or needs a path boundary")
    if not packet.get("evidence_refs"):
        warnings.append("evidence_refs is empty; return UNKNOWN rather than infer missing context")

    return {
        "task_id": task_id,
        "blink_result": "PASS" if not failures else "FAIL",
        "failures": failures,
        "warnings": warnings,
        "execution_authority": False,
        "not_authorization": True,
        "required_next_controls": [
            "Use supplied evidence only; identify gaps explicitly.",
            "Keep model work read-and-propose only.",
            "An executor must independently verify any proposed change.",
        ],
    }


def render_brief(packet: Dict[str, Any], result: Optional[Dict[str, Any]] = None) -> str:
    """Render a deterministic reasoning brief from a valid task packet."""
    # A caller-provided result is not proof for this packet; check it afresh.
    if not enabled() or validate(packet)["blink_result"] != "PASS":
        raise ValueError("Task packet failed validation")

    lines = [
        "SCOPE CHECK",
        f"Task ID: {packet['task_id']}",
        f"Task: {packet['objective']}",
        "Scope: READ + PROPOSE ONLY. No execution authority is granted.",
        f"Allowed actions: {', '.join(packet['allowed_actions'])}",
        f"Prohibited actions: {', '.join(packet['prohibited_actions'])}",
        f"Allowed paths: {', '.join(packet.get('allowed_paths', [])) or 'none supplied'}",
        "",
        "FOCUS",
        f"Focus point: {packet.get('focus_point') or 'Use the smallest evidence-backed focus required by the objective.'}",
        "",
        "DECISION-QUALITY PROCESS",
        "1. Inspect supplied evidence before proposing anything.",
        "2. Separate direct evidence, inference, and unknowns.",
        "3. Trace the minimal root cause or decision path.",
        "4. Propose only bounded changes within the declared scope.",
        "",
        "QUALITY CHECK",
        "Check completeness, accuracy, internal consistency, unsupported claims, and scope drift.",
        "Return evidence status and disposition; do not claim execution or test success.",
        "",
        "Acceptance criteria:",
        *[f"- {item}" for item in packet["acceptance_criteria"]],
    ]
    return "\n".join(lines)


def create_handoff(packet: Dict[str, Any], result: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Create a deterministic, hash-bound handoff packet for a named executor."""
    # Never trust a cached or caller-authored PASS; disabled validation cannot mint a handoff.
    if not enabled() or validate(packet)["blink_result"] != "PASS":
        raise ValueError("Task packet failed validation")

    executor = str(packet.get("executor", "")).strip()
    if not executor:
        raise ValueError("executor is required for a handoff packet")

    canonical_input = {
        "task_id": packet["task_id"],
        "objective": packet["objective"],
        "focus_point": packet.get("focus_point", ""),
        "allowed_paths": packet.get("allowed_paths", []),
        "allowed_actions": packet["allowed_actions"],
        "prohibited_actions": packet["prohibited_actions"],
        "acceptance_criteria": packet["acceptance_criteria"],
        "evidence_refs": packet.get("evidence_refs", []),
        "executor": executor,
    }
    canonical_bytes = json.dumps(canonical_input, sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest = hashlib.sha256(canonical_bytes).hexdigest()

    return {
        "schema_version": "governed.handoff.v1",
        "handoff_id": f"handoff_{packet['task_id']}_{digest[:12]}",
        "correlation_id": f"corr_{digest[:16]}",
        "packet_sha256": digest,
        "executor": executor,
        "task": canonical_input,
        "reasoning_brief": render_brief(packet, result),
        "execution_authority": False,
        "dispatch_performed": False,
        "authorization_required_before_execution": True,
        "required_executor_return": [
            "STATUS=COMPLETE|BLOCKED|ESCALATE",
            "FILES_CHANGED=exact paths or none",
            "COMMANDS_RUN=sanitised commands or none",
            "TEST_RESULTS=actual output or NOT_RUN",
            "EVIDENCE=hashes, receipts, or references",
        ],
    }


def run_mcp_server() -> None:
    """Run an stdio JSON-RPC MCP server for tool integration."""
    for line in sys.stdin:
        try:
            request = json.loads(line)
            if "id" not in request:
                continue

            method = request.get("method")
            if method == "initialize":
                resp = {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "governed-agent-planning", "version": "0.1.2"},
                }
            elif method == "tools/list":
                resp = {
                    "tools": [
                        {
                            "name": "validate_task_packet",
                            "description": "Validate a bounded task packet against BLINK safety constraints.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "packet": {
                                        "type": "object",
                                        "description": "Task packet containing task_id, objective, allowed_actions, prohibited_actions, acceptance_criteria.",
                                    }
                                },
                                "required": ["packet"],
                            },
                        },
                        {
                            "name": "create_handoff_packet",
                            "description": "Create a deterministic SHA-256 hash-bound handoff after revalidating the packet.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "packet": {"type": "object"},
                                    "validation": {"type": "object", "description": "Optional legacy result; ignored and revalidated."},
                                },
                                "required": ["packet"],
                            },
                        },
                    ]
                }
            elif method == "tools/call":
                params = request.get("params", {})
                tool_name = params.get("name")
                tool_args = params.get("arguments", {})
                if tool_name == "validate_task_packet":
                    pkt = tool_args.get("packet", {})
                    v_res = validate(pkt)
                    resp = {"content": [{"type": "text", "text": json.dumps(v_res)}]}
                elif tool_name == "create_handoff_packet":
                    pkt = tool_args.get("packet", {})
                    try:
                        h_res = create_handoff(pkt)
                        resp = {"content": [{"type": "text", "text": json.dumps(h_res)}]}
                    except (ValueError, TypeError, KeyError) as exc:
                        resp = {"isError": True, "content": [{"type": "text", "text": str(exc)}]}
                else:
                    resp = {"isError": True, "content": [{"type": "text", "text": f"Unknown tool: {tool_name}"}]}
            else:
                resp = {}

            message = {"jsonrpc": "2.0", "id": request["id"], "result": resp}
            print(json.dumps(message), flush=True)
        except Exception:
            continue


if __name__ == "__main__":
    run_mcp_server()
