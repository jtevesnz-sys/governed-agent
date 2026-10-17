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


def test_verify_with_public_key_pem_and_constraints():
    kp = generate_keypair(key_size=2048, key_id="key-constraints")
    req = {"action": "read_data", "target": "table_1"}
    ctx = {"session": "sess_01"}
    sealed = seal(req, ctx, kp)

    # 1. Verify using public_key_pem string only (no private key needed)
    res_pub = verify(sealed.receipt_bytes, sealed.signature, ctx, kp.public_key_pem)
    assert res_pub.status == "ACCEPT"

    # 2. Verify with allowed_actions check
    res_allowed = verify(sealed.receipt_bytes, sealed.signature, ctx, kp.public_key_pem, allowed_actions={"read_data"})
    assert res_allowed.status == "ACCEPT"

    res_disallowed = verify(sealed.receipt_bytes, sealed.signature, ctx, kp.public_key_pem, allowed_actions={"mutate_data"})
    assert res_disallowed.status == "HOLD"
    assert "not in allowed_actions" in res_disallowed.reason

    # 3. Verify freshness / expiry
    res_fresh = verify(sealed.receipt_bytes, sealed.signature, ctx, kp.public_key_pem, max_age_seconds=60)
    assert res_fresh.status == "ACCEPT"

    res_expired = verify(sealed.receipt_bytes, sealed.signature, ctx, kp.public_key_pem, max_age_seconds=0)
    assert res_expired.status == "HOLD"
    assert "Receipt expired" in res_expired.reason


def test_blink_mcp_server_tools_list_and_call():
    import io
    import sys
    from governed_agent.planning.blink import run_mcp_server

    req_init = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    req_list = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    req_call = json.dumps({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "validate_task_packet",
            "arguments": {
                "packet": {
                    "task_id": "T-MCP",
                    "objective": "test mcp",
                    "allowed_actions": ["read"],
                    "prohibited_actions": ["activate", "deploy", "publish", "send", "overwrite"],
                    "acceptance_criteria": ["test ok"],
                }
            },
        },
    })
    input_data = f"{req_init}\n{req_list}\n{req_call}\n"

    old_stdin = sys.stdin
    old_stdout = sys.stdout
    try:
        sys.stdin = io.StringIO(input_data)
        sys.stdout = io.StringIO()
        run_mcp_server()
        output = sys.stdout.getvalue()
    finally:
        sys.stdin = old_stdin
        sys.stdout = old_stdout

    lines = [json.loads(line) for line in output.strip().split("\n") if line.strip()]
    assert len(lines) == 3
    # Check tools/list has tools
    tools = lines[1]["result"]["tools"]
    assert len(tools) >= 2
    assert any(t["name"] == "validate_task_packet" for t in tools)
    # Check tools/call succeeded
    call_content = json.loads(lines[2]["result"]["content"][0]["text"])
    assert call_content["blink_result"] == "PASS"


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


def test_file_backed_authority_tamper_detected():
    with tempfile.TemporaryDirectory() as tmpdir:
        auth = FileBackedAuthority(tmpdir)
        chain_id = "test_chain"
        auth.create_pin(chain_id, "hash1", 1)

        # 1. Corrupt pins.json signature/sequence
        pins_file = Path(tmpdir) / "pins.json"
        data = json.loads(pins_file.read_text(encoding="utf-8"))
        data[chain_id][0]["sequence"] = 999  # Tampered sequence without valid signature
        pins_file.write_text(json.dumps(data), encoding="utf-8")

        with pytest.raises(ValueError, match="Anti-rollback state integrity error"):
            FileBackedAuthority(tmpdir)

        # 2. Test non-monotonic sequence in stored pins in a fresh dir
        with tempfile.TemporaryDirectory() as tmpdir2:
            auth2 = FileBackedAuthority(tmpdir2, authority_key=b"k"*32)
            p1 = auth2.create_pin("c2", "h1", 1)
            p2 = auth2.create_pin("c2", "h2", 2)
            # Swap sequence order
            pins_file = Path(tmpdir2) / "pins.json"
            data = json.loads(pins_file.read_text(encoding="utf-8"))
            data["c2"][1]["sequence"] = 0
            pins_file.write_text(json.dumps(data), encoding="utf-8")
            with pytest.raises(ValueError, match="Anti-rollback state integrity error"):
                FileBackedAuthority(tmpdir2, authority_key=b"k"*32)


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
