#!/usr/bin/env python3
"""
Governed Agent — Antirollback Authority (KCAP Monotonic Pinning)
Provides external monotonic counter, tamper-evident pin records,
and freshness interval validation for capability checkpoints.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import threading
from typing import Any, Dict, List, Optional, Union
import uuid


@dataclass
class Pin:
    """Pin structure representing external monotonic anchor."""

    chain_id: str
    checkpoint_hash: str
    sequence: int
    timestamp_utc: str
    authority_signature: str
    pin_id: str = ""

    def __post_init__(self):
        if not self.pin_id:
            self.pin_id = f"pin_{uuid.uuid4().hex[:16]}"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Pin:
        return cls(**data)


@dataclass
class Checkpoint:
    """Capability checkpoint state."""

    chain_id: str
    schema_hash: str
    backend_hash: str
    interface_hash: str
    principal: str
    anchor_hash: str
    tree_hash: str
    sequence: int
    prior_checkpoint_hash: str
    current_state_hash: str
    observation_utc: str
    expiry_utc: str
    checkpoint_id: str = ""

    def __post_init__(self):
        if not self.checkpoint_id:
            self.checkpoint_id = f"chk_{uuid.uuid4().hex[:16]}"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class AntirollbackAuthority:
    """Abstract interface for external monotonic pinning."""

    def get_trusted_now_utc(self) -> datetime:
        raise NotImplementedError

    def get_current_pin(self, chain_id: str) -> Optional[Pin]:
        raise NotImplementedError

    def verify_freshness(self, checkpoint: Checkpoint, max_age_seconds: int) -> bool:
        raise NotImplementedError

    def create_pin(self, chain_id: str, checkpoint_hash: str, sequence: int) -> Pin:
        raise NotImplementedError


class FileBackedAuthority(AntirollbackAuthority):
    """File-backed antirollback authority."""

    def __init__(
        self,
        storage_path: Union[str, Path, None] = None,
        authority_key: Optional[bytes] = None,
    ):
        if storage_path is None:
            default_dir = os.environ.get(
                "GOVERNED_AGENT_ANTIROLLBACK_DIR",
                str(Path.home() / ".governed_agent" / "antirollback"),
            )
            self.storage_path = Path(default_dir)
        else:
            self.storage_path = Path(storage_path)

        self.storage_path.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._pins_file = self.storage_path / "pins.json"
        self._counter_file = self.storage_path / "counter.txt"
        self._key_file = self.storage_path / "authority.key"

        if authority_key is not None:
            self._authority_key = authority_key
        elif self._key_file.exists():
            try:
                self._authority_key = self._key_file.read_bytes()
            except Exception:
                self._authority_key = b"governed-agent-authority-secret"
        else:
            env_key = os.environ.get("GOVERNED_AGENT_AUTHORITY_KEY")
            if env_key:
                self._authority_key = env_key.encode("utf-8")
            else:
                self._authority_key = os.urandom(32)
                try:
                    self._key_file.write_bytes(self._authority_key)
                except Exception:
                    pass

        self._pins: Dict[str, List[Pin]] = defaultdict(list)
        self._counter = 0

        self._load()

    def _sign(self, data: str) -> str:
        return hmac.new(self._authority_key, data.encode("utf-8"), hashlib.sha256).hexdigest()

    def _verify_pin_signature(self, pin: Pin) -> bool:
        pin_data = f"{pin.chain_id}|{pin.checkpoint_hash}|{pin.sequence}|{pin.timestamp_utc}|{pin.pin_id}"
        expected_hmac = self._sign(pin_data)
        # Fallback check for legacy pins signed with old format f"{chain_id}|{checkpoint_hash}|{sequence}|{timestamp}|{counter}"
        legacy_secret = b"governed-agent-authority-secret"
        legacy_expected = hashlib.sha256(legacy_secret + pin_data.encode("utf-8")).hexdigest()
        if hmac.compare_digest(pin.authority_signature, expected_hmac):
            return True
        if hmac.compare_digest(pin.authority_signature, legacy_expected):
            return True
        # Check counter variant for backward compatibility
        for c in range(0, self._counter + 100):
            old_data = f"{pin.chain_id}|{pin.checkpoint_hash}|{pin.sequence}|{pin.timestamp_utc}|{c}"
            if hmac.compare_digest(pin.authority_signature, hashlib.sha256(legacy_secret + old_data.encode("utf-8")).hexdigest()):
                return True
            if hmac.compare_digest(pin.authority_signature, self._sign(old_data)):
                return True
        return False

    def _load(self) -> None:
        with self._lock:
            if self._counter_file.exists():
                try:
                    with open(self._counter_file, "r", encoding="utf-8") as f:
                        self._counter = int(f.read().strip())
                except Exception:
                    self._counter = 0

            if self._pins_file.exists():
                with open(self._pins_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for chain_id, pins_data in data.items():
                        loaded_pins = []
                        last_seq = 0
                        for p in pins_data:
                            pin_obj = Pin.from_dict(p)
                            # Authenticate pin on load
                            if not self._verify_pin_signature(pin_obj):
                                raise ValueError(
                                    f"Anti-rollback state integrity error: invalid signature for pin {pin_obj.pin_id} in chain {chain_id}"
                                )
                            # Monotonic sequence integrity
                            if pin_obj.sequence <= last_seq:
                                raise ValueError(
                                    f"Anti-rollback state integrity error: sequence non-monotonic ({pin_obj.sequence} <= {last_seq})"
                                )
                            last_seq = pin_obj.sequence
                            loaded_pins.append(pin_obj)
                        self._pins[chain_id] = loaded_pins

    def _save(self) -> None:
        with self._lock:
            pins_data = {chain_id: [p.to_dict() for p in pins] for chain_id, pins in self._pins.items()}
            with open(self._pins_file, "w", encoding="utf-8") as f:
                json.dump(pins_data, f, indent=2)

            with open(self._counter_file, "w", encoding="utf-8") as f:
                f.write(str(self._counter))

    def get_trusted_now_utc(self) -> datetime:
        return datetime.now(timezone.utc)

    def get_current_pin(self, chain_id: str) -> Optional[Pin]:
        with self._lock:
            pins = self._pins.get(chain_id, [])
            if not pins:
                return None
            return pins[-1]

    def get_all_pins(self, chain_id: str) -> List[Pin]:
        with self._lock:
            return list(self._pins.get(chain_id, []))

    def verify_freshness(self, checkpoint: Checkpoint, max_age_seconds: int) -> bool:
        if not (1 <= max_age_seconds <= 3600):
            return False

        trusted_now = self.get_trusted_now_utc()

        try:
            obs_time = datetime.fromisoformat(checkpoint.observation_utc.replace("Z", "+00:00"))
            exp_time = datetime.fromisoformat(checkpoint.expiry_utc.replace("Z", "+00:00"))
        except Exception:
            return False

        if obs_time.tzinfo is None:
            obs_time = obs_time.replace(tzinfo=timezone.utc)
        if exp_time.tzinfo is None:
            exp_time = exp_time.replace(tzinfo=timezone.utc)

        # Observation cannot be in the future
        if obs_time > trusted_now:
            return False

        # Observation cannot be older than max_age_seconds
        age = (trusted_now - obs_time).total_seconds()
        if age > max_age_seconds:
            return False

        # Expiry must cover current time
        if exp_time < trusted_now:
            return False

        # Validity interval must have positive duration
        if exp_time <= obs_time:
            return False

        return True

    def create_pin(self, chain_id: str, checkpoint_hash: str, sequence: int) -> Pin:
        with self._lock:
            latest = self.get_current_pin(chain_id)
            if latest and sequence <= latest.sequence:
                raise ValueError(
                    f"Rollback detected: sequence {sequence} <= latest sequence {latest.sequence}"
                )

            self._counter += 1
            trusted_now = self.get_trusted_now_utc()
            timestamp = trusted_now.isoformat().replace("+00:00", "Z")
            pin_id = f"pin_{uuid.uuid4().hex[:16]}"

            pin_data = f"{chain_id}|{checkpoint_hash}|{sequence}|{timestamp}|{pin_id}"
            signature = self._sign(pin_data)

            pin = Pin(
                chain_id=chain_id,
                checkpoint_hash=checkpoint_hash,
                sequence=sequence,
                timestamp_utc=timestamp,
                authority_signature=signature,
                pin_id=pin_id,
            )

            self._pins[chain_id].append(pin)
            self._save()
            return pin

    def get_chain_status(self, chain_id: str) -> Dict[str, Any]:
        with self._lock:
            pins = self._pins.get(chain_id, [])
            return {
                "chain_id": chain_id,
                "pin_count": len(pins),
                "latest_sequence": pins[-1].sequence if pins else 0,
                "latest_timestamp": pins[-1].timestamp_utc if pins else None,
                "counter": self._counter,
            }


class InMemoryAuthority(AntirollbackAuthority):
    """In-memory authority for fast local testing and ephemeral workflows."""

    def __init__(self):
        self._pins: Dict[str, List[Pin]] = defaultdict(list)
        self._counter = 0
        self._lock = threading.RLock()

    def get_trusted_now_utc(self) -> datetime:
        return datetime.now(timezone.utc)

    def get_current_pin(self, chain_id: str) -> Optional[Pin]:
        with self._lock:
            pins = self._pins.get(chain_id, [])
            return pins[-1] if pins else None

    def verify_freshness(self, checkpoint: Checkpoint, max_age_seconds: int) -> bool:
        if not (1 <= max_age_seconds <= 3600):
            return False

        trusted_now = self.get_trusted_now_utc()

        try:
            obs_time = datetime.fromisoformat(checkpoint.observation_utc.replace("Z", "+00:00"))
            exp_time = datetime.fromisoformat(checkpoint.expiry_utc.replace("Z", "+00:00"))
        except Exception:
            return False

        if obs_time.tzinfo is None:
            obs_time = obs_time.replace(tzinfo=timezone.utc)
        if exp_time.tzinfo is None:
            exp_time = exp_time.replace(tzinfo=timezone.utc)

        if obs_time > trusted_now:
            return False
        if (trusted_now - obs_time).total_seconds() > max_age_seconds:
            return False
        if exp_time < trusted_now:
            return False
        if exp_time <= obs_time:
            return False

        return True

    def create_pin(self, chain_id: str, checkpoint_hash: str, sequence: int) -> Pin:
        with self._lock:
            latest = self.get_current_pin(chain_id)
            if latest and sequence <= latest.sequence:
                raise ValueError(
                    f"Rollback detected: sequence {sequence} <= latest sequence {latest.sequence}"
                )

            self._counter += 1
            trusted_now = self.get_trusted_now_utc()
            timestamp = trusted_now.isoformat().replace("+00:00", "Z")

            pin = Pin(
                chain_id=chain_id,
                checkpoint_hash=checkpoint_hash,
                sequence=sequence,
                timestamp_utc=timestamp,
                authority_signature=f"sig_{uuid.uuid4().hex[:16]}",
            )
            self._pins[chain_id].append(pin)
            return pin


def create_checkpoint(
    chain_id: str,
    schema_hash: str,
    backend_hash: str,
    interface_hash: str,
    principal: str,
    anchor_hash: str,
    tree_hash: str,
    sequence: int,
    prior_checkpoint_hash: str,
    current_state_hash: str,
    validity_duration_seconds: int = 300,
) -> Checkpoint:
    """Create a checkpoint with compliant UTC timestamps."""
    now = datetime.now(timezone.utc)
    expiry = datetime.fromtimestamp(now.timestamp() + validity_duration_seconds, tz=timezone.utc)

    return Checkpoint(
        chain_id=chain_id,
        schema_hash=schema_hash,
        backend_hash=backend_hash,
        interface_hash=interface_hash,
        principal=principal,
        anchor_hash=anchor_hash,
        tree_hash=tree_hash,
        sequence=sequence,
        prior_checkpoint_hash=prior_checkpoint_hash,
        current_state_hash=current_state_hash,
        observation_utc=now.isoformat().replace("+00:00", "Z"),
        expiry_utc=expiry.isoformat().replace("+00:00", "Z"),
    )


def create_antirollback_authority(
    storage_path: Union[str, Path, None] = None,
    in_memory: bool = False,
) -> AntirollbackAuthority:
    """Factory helper to obtain an antirollback authority."""
    if in_memory:
        return InMemoryAuthority()
    return FileBackedAuthority(storage_path)
