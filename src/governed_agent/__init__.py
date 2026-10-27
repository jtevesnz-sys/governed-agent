"""Governed Agent — capability sealing, scope-bounded planning, independent audit, and runtime tool boundaries."""

from .capability import (
    KeyPair,
    SealResult,
    VerifyResult,
    generate_keypair,
    seal,
    verify,
    quick_seal,
    quick_verify,
    FileKeyStore,
    create_keystore,
    Pin,
    Checkpoint,
    FileBackedAuthority,
    InMemoryAuthority,
    create_antirollback_authority,
    create_checkpoint,
)
from .planning import (
    validate,
    render_brief,
    create_handoff,
    ALLOWED_ACTIONS,
    HIGH_RISK_ACTIONS,
    REQUIRED_PROHIBITIONS,
    enabled,
)
from .audit import (
    WatchTower,
    WatchTowerVerdict,
)
from .hermes import GovernedToolBoundary, ExecutionDeniedError

__version__ = "0.1.4"
__author__ = "jtevesnz-sys"
__license__ = "MIT"

__all__ = [
    # Capability Layer
    "KeyPair",
    "SealResult",
    "VerifyResult",
    "generate_keypair",
    "seal",
    "verify",
    "quick_seal",
    "quick_verify",
    "FileKeyStore",
    "create_keystore",
    "Pin",
    "Checkpoint",
    "FileBackedAuthority",
    "InMemoryAuthority",
    "create_antirollback_authority",
    "create_checkpoint",
    # Planning Layer
    "validate",
    "render_brief",
    "create_handoff",
    "ALLOWED_ACTIONS",
    "HIGH_RISK_ACTIONS",
    "REQUIRED_PROHIBITIONS",
    "enabled",
    # Audit Layer
    "WatchTower",
    "WatchTowerVerdict",
    # Hermes Tool Boundary
    "GovernedToolBoundary",
    "ExecutionDeniedError",
]
