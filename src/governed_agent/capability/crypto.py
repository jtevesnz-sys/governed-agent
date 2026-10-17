#!/usr/bin/env python3
"""
Governed Agent — Cryptographic Capability Primitives (KCAP Core)
RSA Seal/Verify & Key Management with strict canonicalization.
"""

from __future__ import annotations

import base64
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

CRYPTOGRAPHY_AVAILABLE = True


class KeySize(Enum):
    """Supported RSA key sizes."""

    BITS_2048 = 2048
    BITS_3072 = 3072
    BITS_4096 = 4096
    BITS_8192 = 8192


class KeyExponent(Enum):
    """RSA public exponent."""

    EXP_65537 = 65537


@dataclass
class KeyPair:
    """RSA key pair with metadata."""

    private_key_pem: str
    public_key_pem: str
    key_size: int
    exponent: int
    fingerprint_sha256: str
    created_at: str
    key_id: str
    version: int = 1


@dataclass
class SealResult:
    """Result of capability seal operation."""

    receipt_bytes: bytes
    signature: bytes
    key_id: str
    fingerprint_sha256: str
    algorithm: str = "RSA-SHA256-PKCS1v15"
    timestamp: str = ""


@dataclass
class VerifyResult:
    """Result of capability verification operation."""

    status: str  # "ACCEPT" or "HOLD"
    reason: str = ""
    key_id: str = ""
    fingerprint_sha256: str = ""


class KeyStore:
    """Abstract interface for key storage."""

    def store_keypair(self, keypair: KeyPair) -> bool:
        raise NotImplementedError

    def load_keypair(self, key_id: str) -> Optional[KeyPair]:
        raise NotImplementedError

    def list_keypairs(self) -> List[str]:
        raise NotImplementedError

    def delete_keypair(self, key_id: str) -> bool:
        raise NotImplementedError

    def rotate_key(self, old_key_id: str, new_key_size: int = 2048) -> KeyPair:
        raise NotImplementedError


class FileKeyStore(KeyStore):
    """File-backed key store with index."""

    def __init__(self, base_path: Union[str, Path, None] = None):
        if base_path is None:
            default_dir = os.environ.get("GOVERNED_AGENT_KEYS_DIR", str(Path.home() / ".governed_agent" / "keys"))
            self.base_path = Path(default_dir)
        else:
            self.base_path = Path(base_path)

        self.base_path.mkdir(parents=True, exist_ok=True)
        self._index_file = self.base_path / "keystore_index.json"
        self._index = self._load_index()

    def _load_index(self) -> Dict[str, Any]:
        if self._index_file.exists():
            try:
                with open(self._index_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def _save_index(self) -> None:
        with open(self._index_file, "w", encoding="utf-8") as f:
            json.dump(self._index, f, indent=2)

    def store_keypair(self, keypair: KeyPair) -> bool:
        try:
            private_path = self.base_path / f"{keypair.key_id}_private.pem"
            public_path = self.base_path / f"{keypair.key_id}_public.pem"

            with open(private_path, "w", encoding="utf-8") as f:
                f.write(keypair.private_key_pem)
            with open(public_path, "w", encoding="utf-8") as f:
                f.write(keypair.public_key_pem)

            self._index[keypair.key_id] = {
                "key_id": keypair.key_id,
                "key_size": keypair.key_size,
                "exponent": keypair.exponent,
                "fingerprint_sha256": keypair.fingerprint_sha256,
                "created_at": keypair.created_at,
                "version": keypair.version,
                "private_path": str(private_path),
                "public_path": str(public_path),
            }
            self._save_index()
            return True
        except Exception:
            return False

    def load_keypair(self, key_id: str) -> Optional[KeyPair]:
        if key_id not in self._index:
            return None

        try:
            entry = self._index[key_id]
            private_path = Path(entry["private_path"])
            public_path = Path(entry["public_path"])

            with open(private_path, "r", encoding="utf-8") as f:
                private_pem = f.read()
            with open(public_path, "r", encoding="utf-8") as f:
                public_pem = f.read()

            return KeyPair(
                private_key_pem=private_pem,
                public_key_pem=public_pem,
                key_size=entry["key_size"],
                exponent=entry["exponent"],
                fingerprint_sha256=entry["fingerprint_sha256"],
                created_at=entry["created_at"],
                key_id=key_id,
                version=entry.get("version", 1),
            )
        except Exception:
            return None

    def list_keypairs(self) -> List[str]:
        return list(self._index.keys())

    def delete_keypair(self, key_id: str) -> bool:
        if key_id not in self._index:
            return False

        try:
            entry = self._index[key_id]
            private_path = Path(entry["private_path"])
            public_path = Path(entry["public_path"])

            if private_path.exists():
                private_path.unlink()
            if public_path.exists():
                public_path.unlink()

            del self._index[key_id]
            self._save_index()
            return True
        except Exception:
            return False

    def rotate_key(self, old_key_id: str, new_key_size: int = 2048) -> KeyPair:
        old_keypair = self.load_keypair(old_key_id)
        if not old_keypair:
            raise ValueError(f"Key not found: {old_key_id}")

        timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        archive_id = f"{old_key_id}_archived_{timestamp_str}"
        old_private_path = self.base_path / f"{old_key_id}_private.pem"
        old_public_path = self.base_path / f"{old_key_id}_public.pem"

        if old_private_path.exists():
            old_private_path.rename(self.base_path / f"{archive_id}_private.pem")
        if old_public_path.exists():
            old_public_path.rename(self.base_path / f"{archive_id}_public.pem")

        new_keypair = generate_keypair(key_size=new_key_size, key_id=old_key_id)
        self.store_keypair(new_keypair)
        return new_keypair


def compute_sha256(data: bytes) -> str:
    """Compute SHA256 hash, returning uppercase hex."""
    return hashlib.sha256(data).hexdigest().upper()


def compute_fingerprint_sha256(public_key_pem: str) -> str:
    """Compute SHA256 fingerprint of DER-SPKI."""
    if CRYPTOGRAPHY_AVAILABLE:
        public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return compute_sha256(der)
    return compute_sha256(public_key_pem.encode("utf-8"))  # pragma: no cover


def generate_keypair(key_size: int = 2048, key_id: Optional[str] = None, exponent: int = 65537) -> KeyPair:
    """Generate an RSA key pair."""
    if not CRYPTOGRAPHY_AVAILABLE:
        raise RuntimeError("The 'cryptography' library is required for keypair generation.")

    private_key = rsa.generate_private_key(public_exponent=exponent, key_size=key_size)
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    fingerprint = compute_fingerprint_sha256(public_pem)
    key_id = key_id or f"kcap-key-{hashlib.sha256(public_pem.encode('utf-8')).hexdigest()[:16]}"
    now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    return KeyPair(
        private_key_pem=private_pem,
        public_key_pem=public_pem,
        key_size=key_size,
        exponent=exponent,
        fingerprint_sha256=fingerprint,
        created_at=now_iso,
        key_id=key_id,
    )


def canonicalize_json(data: Dict[str, Any]) -> bytes:
    """Canonicalize JSON: ASCII sorted compact representation."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def compute_canonical_hash(data: Dict[str, Any]) -> str:
    """Compute SHA256 hex digest of canonicalized JSON."""
    return compute_sha256(canonicalize_json(data))


def seal(request: Dict[str, Any], trusted_context: Dict[str, Any], keypair: KeyPair) -> SealResult:
    """
    Seal an action request with trusted context into an unforgeable receipt.
    seal(request, trusted_context, keypair) -> SealResult(receipt_bytes, signature)
    """
    now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    receipt: Dict[str, Any] = {
        "request": request,
        "trusted_context": trusted_context,
        "timestamp": now_iso,
        "key_id": keypair.key_id,
    }

    for key, value in request.items():
        if key not in receipt:
            receipt[key] = value

    receipt_bytes = canonicalize_json(receipt)

    if not CRYPTOGRAPHY_AVAILABLE:
        raise RuntimeError("The 'cryptography' library is required to seal capabilities.")

    loaded_key = serialization.load_pem_private_key(keypair.private_key_pem.encode("utf-8"), password=None)
    if not isinstance(loaded_key, RSAPrivateKey):
        raise TypeError("Expected RSAPrivateKey")
    signature = loaded_key.sign(receipt_bytes, padding.PKCS1v15(), hashes.SHA256())

    return SealResult(
        receipt_bytes=receipt_bytes,
        signature=signature,
        key_id=keypair.key_id,
        fingerprint_sha256=keypair.fingerprint_sha256,
        timestamp=now_iso,
    )


def verify(
    receipt_bytes: bytes,
    signature: bytes,
    trusted_expected_context: Dict[str, Any],
    keypair: KeyPair,
) -> VerifyResult:
    """
    Verify a capability receipt and signature against expected context.
    verify(...) -> VerifyResult(status='ACCEPT' | 'HOLD')
    """
    try:
        receipt = json.loads(receipt_bytes.decode("utf-8"))
    except Exception:
        return VerifyResult(status="HOLD", reason="Invalid receipt JSON")

    if receipt.get("trusted_context") != trusted_expected_context:
        return VerifyResult(
            status="HOLD",
            reason="Trusted context mismatch",
            key_id=keypair.key_id,
            fingerprint_sha256=keypair.fingerprint_sha256,
        )

    if not CRYPTOGRAPHY_AVAILABLE:
        return VerifyResult(status="HOLD", reason="Cryptography library unavailable")

    try:
        loaded_pub = serialization.load_pem_public_key(keypair.public_key_pem.encode("utf-8"))
        if not isinstance(loaded_pub, RSAPublicKey):
            return VerifyResult(status="HOLD", reason="Expected RSAPublicKey")
        loaded_pub.verify(signature, receipt_bytes, padding.PKCS1v15(), hashes.SHA256())
    except Exception as exc:
        return VerifyResult(
            status="HOLD",
            reason=f"Signature verification failed: {exc}",
            key_id=keypair.key_id,
            fingerprint_sha256=keypair.fingerprint_sha256,
        )

    return VerifyResult(
        status="ACCEPT",
        key_id=keypair.key_id,
        fingerprint_sha256=keypair.fingerprint_sha256,
    )


def create_keystore(base_path: Union[str, Path, None] = None) -> FileKeyStore:
    """Create a file-backed keystore."""
    return FileKeyStore(base_path)


def quick_seal(
    request: Dict[str, Any],
    trusted_context: Dict[str, Any],
    keystore: FileKeyStore,
    key_id: str,
) -> Optional[SealResult]:
    """Quick seal using a keystore."""
    keypair = keystore.load_keypair(key_id)
    if not keypair:
        return None
    return seal(request, trusted_context, keypair)


def quick_verify(
    receipt_bytes: bytes,
    signature: bytes,
    trusted_expected_context: Dict[str, Any],
    keystore: FileKeyStore,
    key_id: str,
) -> Optional[VerifyResult]:
    """Quick verify using a keystore."""
    keypair = keystore.load_keypair(key_id)
    if not keypair:
        return None
    return verify(receipt_bytes, signature, trusted_expected_context, keypair)
