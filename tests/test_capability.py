"""Tests for capability layer (KCAP crypto primitives & antirollback)."""

import json
from pathlib import Path
import tempfile

import pytest

from governed_agent.capability.antirollback import (
    FileBackedAuthority,
    InMemoryAuthority,
    create_antirollback_authority,
    create_checkpoint,
)
from governed_agent.capability.crypto import (
    FileKeyStore,
    KeyExponent,
    KeyPair,
    KeySize,
    canonicalize_json,
    compute_canonical_hash,
    compute_fingerprint_sha256,
    compute_sha256,
    generate_keypair,
    quick_seal,
    quick_verify,
    seal,
    verify,
)


def test_keypair_generation():
    kp = generate_keypair(key_size=2048, key_id="test-key-01")
    assert kp.key_id == "test-key-01"
    assert kp.key_size == 2048
    assert kp.exponent == 65537
    assert len(kp.fingerprint_sha256) == 64
    assert "-----BEGIN RSA PRIVATE KEY-----" in kp.private_key_pem or "-----BEGIN PRIVATE KEY-----" in kp.private_key_pem
    assert "-----BEGIN PUBLIC KEY-----" in kp.public_key_pem


def test_canonicalization_deterministic():
    obj1 = {"b": 2, "a": 1, "z": {"k2": "v2", "k1": "v1"}}
    obj2 = {"z": {"k1": "v1", "k2": "v2"}, "a": 1, "b": 2}
    c1 = canonicalize_json(obj1)
    c2 = canonicalize_json(obj2)
    assert c1 == c2
    assert compute_canonical_hash(obj1) == compute_canonical_hash(obj2)


def test_seal_verify_roundtrip():
    kp = generate_keypair(key_size=2048, key_id="seal-test-key")
    request = {"action": "write_file", "path": "output.txt"}
    context = {"task_id": "T-100", "role": "builder"}

    sealed = seal(request, context, kp)
    assert sealed.key_id == kp.key_id
    assert len(sealed.signature) == 256  # 2048-bit RSA produces 256-byte signature

    # Verification with identical context must ACCEPT
    ver = verify(sealed.receipt_bytes, sealed.signature, context, kp)
    assert ver.status == "ACCEPT"
    assert ver.reason == ""

    # Verification with altered context must HOLD
    tampered_context = {"task_id": "T-100", "role": "admin"}
    ver_tampered = verify(sealed.receipt_bytes, sealed.signature, tampered_context, kp)
    assert ver_tampered.status == "HOLD"
    assert "mismatch" in ver_tampered.reason.lower()


def test_file_keystore_storage_and_rotation():
    with tempfile.TemporaryDirectory() as tmpdir:
        keystore = FileKeyStore(tmpdir)
        kp = generate_keypair(key_size=2048, key_id="stored-key")
        assert keystore.store_keypair(kp) is True

        loaded = keystore.load_keypair("stored-key")
        assert loaded is not None
        assert loaded.fingerprint_sha256 == kp.fingerprint_sha256

        rotated = keystore.rotate_key("stored-key", new_key_size=2048)
        assert rotated.key_id == "stored-key"
        assert rotated.fingerprint_sha256 != kp.fingerprint_sha256


def test_antirollback_monotonic_enforcement():
    auth = InMemoryAuthority()
    chain_id = "agent_run_1"

    # Create sequence 1
    pin1 = auth.create_pin(chain_id, "hash_001", 1)
    assert pin1.sequence == 1

    # Create sequence 2
    pin2 = auth.create_pin(chain_id, "hash_002", 2)
    assert pin2.sequence == 2

    # Attempting to reuse or decrement sequence must raise ValueError (anti-rollback)
    with pytest.raises(ValueError, match="Rollback detected"):
        auth.create_pin(chain_id, "hash_001_replay", 1)

    with pytest.raises(ValueError, match="Rollback detected"):
        auth.create_pin(chain_id, "hash_002_replay", 2)


def test_checkpoint_freshness_verification():
    auth = InMemoryAuthority()
    chk = create_checkpoint(
        chain_id="chain_chk",
        schema_hash="s1",
        backend_hash="b1",
        interface_hash="i1",
        principal="test_principal",
        anchor_hash="a1",
        tree_hash="t1",
        sequence=1,
        prior_checkpoint_hash="0" * 64,
        current_state_hash="state1",
        validity_duration_seconds=300,
    )
    assert auth.verify_freshness(chk, max_age_seconds=300) is True

    # Expired checkpoint check
    chk_expired = create_checkpoint(
        chain_id="chain_chk_exp",
        schema_hash="s1",
        backend_hash="b1",
        interface_hash="i1",
        principal="test_principal",
        anchor_hash="a1",
        tree_hash="t1",
        sequence=1,
        prior_checkpoint_hash="0" * 64,
        current_state_hash="state1",
        validity_duration_seconds=10,
    )
    # Manually backdate observation and expiry
    chk_expired.observation_utc = "2020-01-01T00:00:00Z"
    chk_expired.expiry_utc = "2020-01-01T00:05:00Z"
    assert auth.verify_freshness(chk_expired, max_age_seconds=300) is False
