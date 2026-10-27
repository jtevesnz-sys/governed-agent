"""
Governed Agent — Hermes Execution Boundary Adapter
Provides cryptographic capability enforcement for Hermes and tool dispatch runtimes.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Set, Union
from ..capability.crypto import compute_fingerprint_sha256, verify, VerifyResult
from .replay import ReceiptReplayStore, ReplayStoreError


class ExecutionDeniedError(Exception):
    """Raised when an action execution is denied by governance boundary."""
    pass


class GovernedToolBoundary:
    """
    Enforces capability receipts, context binding, and allowed actions
    at the tool execution boundary before invoking tools.
    """

    def __init__(
        self,
        custodian_public_pem: str,
        allowed_actions: Optional[Set[str]] = None,
        task_id: str = "",
        max_age_seconds: int = 300,
        replay_store_path: Optional[Union[str, Path]] = None,
    ):
        self.custodian_public_pem = custodian_public_pem
        self.allowed_actions = allowed_actions or set()
        self.task_id = task_id
        self.max_age_seconds = max_age_seconds
        self._tools: Dict[str, Callable[..., Any]] = {}
        self._replay_store = ReceiptReplayStore(replay_store_path)

    def register_tool(self, name: str, func: Callable[..., Any]) -> None:
        """Register a tool callable under this governed boundary."""
        self._tools[name] = func

    def invoke_tool(
        self,
        tool_name: str,
        args: Dict[str, Any],
        receipt_bytes: bytes,
        signature: bytes,
    ) -> Any:
        """
        Verify capability receipt and invoke the tool if accepted.
        Raises ExecutionDeniedError if verification fails or action prohibited.
        """
        # Freeze before verification. The signature, parsed request and replay
        # identity must all refer to one native immutable buffer, including when
        # callers supply a bytearray or a bytes subclass with an overridden decode.
        if isinstance(receipt_bytes, (bytes, bytearray)):
            receipt_bytes = memoryview(receipt_bytes).tobytes()
        if tool_name not in self._tools:
            raise ExecutionDeniedError(f"Tool '{tool_name}' is not registered")

        if self.allowed_actions and tool_name not in self.allowed_actions:
            raise ExecutionDeniedError(f"Action '{tool_name}' is not in allowed_actions")

        expected_context: Dict[str, Any] = {}
        if self.task_id:
            expected_context["task_id"] = self.task_id

        custodian_public_pem = self.custodian_public_pem
        # Verify receipt with cryptographic authority
        verdict: VerifyResult = verify(
            receipt_bytes=receipt_bytes,
            signature=signature,
            trusted_expected_context=expected_context,
            key=custodian_public_pem,
            max_age_seconds=self.max_age_seconds,
            allowed_actions=self.allowed_actions if self.allowed_actions else None,
        )

        if verdict.status != "ACCEPT":
            raise ExecutionDeniedError(f"Capability verification failed: {verdict.reason}")

        # The signed request schema is {"action": tool_name, **tool_kwargs}.
        # Compare JSON representations, not Python equality (True == 1), before dispatch.
        try:
            receipt_data = json.loads(receipt_bytes.decode("utf-8"))
            request = receipt_data["request"]
            if not isinstance(request, dict) or not isinstance(args, dict) or "action" in args:
                raise ExecutionDeniedError("Invalid signed tool request or invocation arguments")
            canonical = lambda value: json.dumps(
                value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
            )
            # Freeze the entire JSON argument tree and dispatch only this validated copy.
            args_snapshot = json.loads(canonical(args))
            expected = {"action": tool_name, **args_snapshot}
            if canonical(request) != canonical(expected):
                raise ExecutionDeniedError("Invocation does not match signed request")
        except (KeyError, TypeError, ValueError, UnicodeDecodeError) as exc:
            raise ExecutionDeniedError("Malformed signed tool request or invocation arguments") from exc

        # Bind identity to the trusted key's normalized public material, never to
        # receipt metadata or signature encoding. Only validated requests consume.
        issuer_fingerprint = compute_fingerprint_sha256(custodian_public_pem)
        receipt_digest = hashlib.sha256(receipt_bytes).hexdigest()
        try:
            consumed = self._replay_store.consume(issuer_fingerprint, receipt_digest)
        except ReplayStoreError as exc:
            raise ExecutionDeniedError("Replay protection unavailable") from exc
        if not consumed:
            raise ExecutionDeniedError("Capability receipt already consumed")

        return self._tools[tool_name](**args_snapshot)
