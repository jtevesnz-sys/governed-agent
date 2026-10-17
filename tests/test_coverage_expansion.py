"""Comprehensive unit tests expanding coverage across capability, planning, and audit."""

import json
from pathlib import Path
import tempfile
import pytest

from governed_agent.capability.antirollback import (
    FileBackedAuthority,
    InMemoryAuthority,
    create_antirollback_authority,
    create_checkpoint,
    Pin,
)
from governed_agent.capability.crypto import (
    FileKeyStore,
    create_keystore,
    generate_keypair,
    seal,
    verify,
    quick_seal,
    quick_verify,
)
from governed_agent.planning.blink import (
    validate,
    render_brief,
    create_handoff,
    enabled,
)
from governed_agent.audit.watchtower import WatchTower, WatchTowerVerdict


def test_file_backed_authority_full_lifecycle():
    with tempfile.TemporaryDirectory() as tmpdir:
        auth = FileBackedAuthority(tmpdir)
        chain_id = "test_chain"
        assert auth.get_current_pin(chain_id) is None
        assert auth.get_all_pins(chain_id) == []

        pin1 = auth.create_pin(chain_id, "hash1", 1)
        assert pin1.sequence == 1
        assert auth.get_current_pin(chain_id).sequence == 1
        assert len(auth.get_all_pins(chain_id)) == 1

        pin2 = auth.create_pin(chain_id, "hash2", 2)
        assert pin2.sequence == 2

        # Check status
        status = auth.get_chain_status(chain_id)
        assert status["pin_count"] == 2
        assert status["latest_sequence"] == 2

        # Replay error check
        with pytest.raises(ValueError, match="Rollback detected"):
            auth.create_pin(chain_id, "hash1", 1)

        # Freshness bounds check
        chk = create_checkpoint(
            chain_id=chain_id,
            schema_hash="s",
            backend_hash="b",
            interface_hash="i",
            principal="p",
            anchor_hash="a",
            tree_hash="t",
            sequence=1,
            prior_checkpoint_hash="0" * 64,
            current_state_hash="c",
            validity_duration_seconds=300,
        )
        assert auth.verify_freshness(chk, 300) is True
        assert auth.verify_freshness(chk, 0) is False  # Out of 1..3600 bound
        assert auth.verify_freshness(chk, 5000) is False  # Out of 1..3600 bound

        # Reload authority from disk
        reloaded = FileBackedAuthority(tmpdir)
        assert reloaded.get_current_pin(chain_id).sequence == 2
        assert reloaded.get_chain_status(chain_id)["counter"] == 2


def test_factory_create_antirollback_authority():
    with tempfile.TemporaryDirectory() as tmpdir:
        auth_file = create_antirollback_authority(tmpdir, in_memory=False)
        assert isinstance(auth_file, FileBackedAuthority)
        auth_mem = create_antirollback_authority(in_memory=True)
        assert isinstance(auth_mem, InMemoryAuthority)


def test_file_keystore_crud_and_quick_helpers():
    with tempfile.TemporaryDirectory() as tmpdir:
        ks = create_keystore(tmpdir)
        kp = generate_keypair(key_size=2048, key_id="key-01")
        assert ks.store_keypair(kp) is True
        assert "key-01" in ks.list_keypairs()

        # Quick seal & verify
        req = {"action": "test"}
        ctx = {"task": "1"}
        s = quick_seal(req, ctx, ks, "key-01")
        assert s is not None
        v = quick_verify(s.receipt_bytes, s.signature, ctx, ks, "key-01")
        assert v is not None and v.status == "ACCEPT"

        # Missing key handling
        assert quick_seal(req, ctx, ks, "non-existent") is None
        assert quick_verify(s.receipt_bytes, s.signature, ctx, ks, "non-existent") is None

        # Delete keypair
        assert ks.delete_keypair("key-01") is True
        assert "key-01" not in ks.list_keypairs()
        assert ks.delete_keypair("non-existent") is False


def test_crypto_verify_failure_cases():
    kp = generate_keypair(key_size=2048, key_id="k1")
    s = seal({"a": 1}, {"ctx": "ok"}, kp)

    # Invalid JSON
    res_bad_json = verify(b"invalid-json", s.signature, {"ctx": "ok"}, kp)
    assert res_bad_json.status == "HOLD"
    assert "Invalid receipt JSON" in res_bad_json.reason

    # Bad signature
    tampered_sig = b"0" * len(s.signature)
    res_bad_sig = verify(s.receipt_bytes, tampered_sig, {"ctx": "ok"}, kp)
    assert res_bad_sig.status == "HOLD"
    assert "verification failed" in res_bad_sig.reason.lower()


def test_blink_validation_edges():
    assert enabled() is True

    # Missing task_id
    p1 = {
        "objective": "obj",
        "allowed_actions": ["read"],
        "prohibited_actions": ["activate", "deploy", "publish", "send", "overwrite"],
        "acceptance_criteria": ["crit"],
    }
    r1 = validate(p1)
    assert r1["blink_result"] == "FAIL"
    assert "task_id is required" in r1["failures"]

    # Action overlap
    p2 = {
        "task_id": "T1",
        "objective": "obj",
        "allowed_actions": ["read", "propose"],
        "prohibited_actions": ["activate", "deploy", "publish", "send", "overwrite", "read"],
        "acceptance_criteria": ["crit"],
    }
    r2 = validate(p2)
    assert r2["blink_result"] == "FAIL"
    assert any("both allowed and prohibited" in f for f in r2["failures"])


def test_blink_render_brief_and_handoff_failures():
    invalid_packet = {"task_id": ""}
    res = validate(invalid_packet)
    with pytest.raises(ValueError, match="failed validation"):
        render_brief(invalid_packet, res)
    with pytest.raises(ValueError, match="failed validation"):
        create_handoff(invalid_packet, res)


def test_watchtower_invalid_manifest_structures():
    with tempfile.TemporaryDirectory() as tmpdir:
        auditor = WatchTower(tmpdir)

        # Missing required fields
        res = auditor.verify({"format": "test"})
        assert res["verdict"] == WatchTowerVerdict.HOLD.value
        assert any(c["name"] == "manifest_validation" and c["status"] == "FAIL" for c in res["checks"])

        # Invalid file hash length
        bad_hash_manifest = {
            "format": "governed.manifest.v1",
            "format_version": "1.0",
            "convergence_id": "C1",
            "complete_set_sha256": "0" * 64,
            "lane_records": [],
            "files": [{"relative_path": "a.txt", "sha256": "short"}],
        }
        res_hash = auditor.verify(bad_hash_manifest)
        assert res_hash["verdict"] == WatchTowerVerdict.REVISE.value

        # From file path
        manifest_file = Path(tmpdir) / "manifest.json"
        manifest_file.write_text(json.dumps(bad_hash_manifest))
        res_file = auditor.verify(manifest_file)
        assert res_file["verdict"] == WatchTowerVerdict.REVISE.value
