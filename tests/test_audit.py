"""Tests for audit layer (Watchtower independent 6-point verifier)."""

import hashlib
import json
from governed_agent.audit.watchtower import WatchTower, WatchTowerVerdict


def with_complete_set(manifest):
    """Bind a test manifest to its declared file entries."""
    entries = []
    for file in manifest["files"]:
        entry = {
            "lane_id": file.get("lane_id", ""),
            "relative_path": file.get("relative_path", "").replace("\\", "/"),
            "sha256": file.get("sha256", ""),
        }
        if "size_bytes" in file:
            entry["size_bytes"] = file["size_bytes"]
        entries.append(entry)
    entries.sort(key=lambda item: item["relative_path"])
    manifest["complete_set_sha256"] = hashlib.sha256(
        json.dumps(entries, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return manifest

SAMPLE_MANIFEST = {
    "format": "governed.manifest.v1",
    "format_version": "1.0",
    "convergence_id": "CONV-001",
    "complete_set_sha256": "0" * 64,
    "lane_records": [{"lane_id": "LANE_A"}, {"lane_id": "LANE_B"}],
    "files": [
        {"relative_path": "src/module.py", "lane_id": "LANE_A", "sha256": "a" * 64},
        {"relative_path": "docs/guide.md", "lane_id": "LANE_B", "sha256": "b" * 64},
    ],
}
with_complete_set(SAMPLE_MANIFEST)

SAMPLE_DEP_GRAPH = {
    "nodes": [
        {"lane_id": "LANE_A", "node_type": "LANE"},
        {"lane_id": "LANE_B", "node_type": "LANE"},
    ]
}


def test_watchtower_verdict_pass(tmp_path):
    # Create real files on disk
    src_file = tmp_path / "src" / "module.py"
    src_file.parent.mkdir(parents=True)
    src_file.write_text("print('hello')", encoding="utf-8")
    src_hash = hashlib.sha256(src_file.read_bytes()).hexdigest()

    doc_file = tmp_path / "docs" / "guide.md"
    doc_file.parent.mkdir(parents=True)
    doc_file.write_text("# Guide", encoding="utf-8")
    doc_hash = hashlib.sha256(doc_file.read_bytes()).hexdigest()

    manifest = {
        "format": "governed.manifest.v1",
        "format_version": "1.0",
        "convergence_id": "CONV-001",
        "complete_set_sha256": "0" * 64,
        "lane_records": [{"lane_id": "LANE_A"}, {"lane_id": "LANE_B"}],
        "files": [
            {"relative_path": "src/module.py", "lane_id": "LANE_A", "sha256": src_hash,
             "size_bytes": len(src_file.read_bytes())},
            {"relative_path": "docs/guide.md", "lane_id": "LANE_B", "sha256": doc_hash,
             "size_bytes": len(doc_file.read_bytes())},
        ],
    }

    auditor = WatchTower(root_dir=tmp_path)
    result = auditor.verify(with_complete_set(manifest), SAMPLE_DEP_GRAPH)
    assert result["verdict"] == WatchTowerVerdict.PASS.value
    assert result["prohibited_residue_found"] is False
    assert result["independence_violations"] == []


def test_watchtower_missing_file_holds(tmp_path):
    manifest = {
        "format": "governed.manifest.v1",
        "format_version": "1.0",
        "convergence_id": "CONV-001",
        "complete_set_sha256": "0" * 64,
        "lane_records": [{"lane_id": "LANE_A"}],
        "files": [
            {"relative_path": "nonexistent.py", "lane_id": "LANE_A", "sha256": "a" * 64},
        ],
    }
    dep_graph = {"nodes": [{"lane_id": "LANE_A", "node_type": "LANE"}]}
    auditor = WatchTower(root_dir=tmp_path)
    result = auditor.verify(with_complete_set(manifest), dep_graph)
    assert result["verdict"] == WatchTowerVerdict.HOLD.value
    assert any(c["name"] == "hash_agreement" and c["status"] == "FAIL" for c in result["checks"])


def test_watchtower_hash_mismatch_revises(tmp_path):
    f = tmp_path / "mod.py"
    f.write_text("actual content", encoding="utf-8")
    manifest = {
        "format": "governed.manifest.v1",
        "format_version": "1.0",
        "convergence_id": "CONV-001",
        "complete_set_sha256": "0" * 64,
        "lane_records": [{"lane_id": "LANE_A"}],
        "files": [
            {"relative_path": "mod.py", "lane_id": "LANE_A", "sha256": "f" * 64},
        ],
    }
    dep_graph = {"nodes": [{"lane_id": "LANE_A", "node_type": "LANE"}]}
    auditor = WatchTower(root_dir=tmp_path)
    result = auditor.verify(with_complete_set(manifest), dep_graph)
    assert result["verdict"] == WatchTowerVerdict.REVISE.value
    assert any("Hash mismatch" in c["details"] for c in result["checks"])


def test_watchtower_unlisted_file_holds(tmp_path):
    f1 = tmp_path / "mod.py"
    f1.write_text("mod", encoding="utf-8")
    h1 = hashlib.sha256(f1.read_bytes()).hexdigest()

    # Create unlisted file
    f2 = tmp_path / "unlisted.py"
    f2.write_text("rogue", encoding="utf-8")

    manifest = {
        "format": "governed.manifest.v1",
        "format_version": "1.0",
        "convergence_id": "CONV-001",
        "complete_set_sha256": "0" * 64,
        "lane_records": [{"lane_id": "LANE_A"}],
        "files": [
            {"relative_path": "mod.py", "lane_id": "LANE_A", "sha256": h1},
        ],
    }
    dep_graph = {"nodes": [{"lane_id": "LANE_A", "node_type": "LANE"}]}
    auditor = WatchTower(root_dir=tmp_path)
    result = auditor.verify(with_complete_set(manifest), dep_graph)
    assert result["verdict"] == WatchTowerVerdict.HOLD.value
    assert any(c["name"] == "no_unlisted_files" and c["status"] == "FAIL" for c in result["checks"])


def test_watchtower_path_traversal_holds(tmp_path):
    sub = tmp_path / "sub"
    sub.mkdir()
    manifest = {
        "format": "governed.manifest.v1",
        "format_version": "1.0",
        "convergence_id": "CONV-001",
        "complete_set_sha256": "0" * 64,
        "lane_records": [{"lane_id": "LANE_A"}],
        "files": [
            {"relative_path": "../escape.txt", "lane_id": "LANE_A", "sha256": "a" * 64},
        ],
    }
    dep_graph = {"nodes": [{"lane_id": "LANE_A", "node_type": "LANE"}]}
    auditor = WatchTower(root_dir=sub)
    result = auditor.verify(with_complete_set(manifest), dep_graph)
    assert result["verdict"] == WatchTowerVerdict.REVISE.value
    assert any("Path traversal escape" in c.get("details", "") for c in result["checks"])


def test_watchtower_complete_set_hash_mismatch_revises():
    manifest = {
        "format": "governed.manifest.v1",
        "format_version": "1.0",
        "convergence_id": "CONV-001",
        "complete_set_sha256": "1" * 64,  # Not '0'*64 and not match
        "lane_records": [{"lane_id": "LANE_A"}],
        "files": [
            {"relative_path": "a.txt", "lane_id": "LANE_A", "sha256": "a" * 64},
        ],
    }
    dep_graph = {"nodes": [{"lane_id": "LANE_A", "node_type": "LANE"}]}
    auditor = WatchTower()
    result = auditor.verify(manifest, dep_graph)
    assert result["verdict"] == WatchTowerVerdict.REVISE.value
    assert any("complete_set_sha256 mismatch" in c.get("details", "") for c in result["checks"])


def test_watchtower_missing_lane_holds():
    auditor = WatchTower()
    dep_graph_extra = {
        "nodes": [
            {"lane_id": "LANE_A", "node_type": "LANE"},
            {"lane_id": "LANE_B", "node_type": "LANE"},
            {"lane_id": "LANE_MISSING", "node_type": "LANE"},
        ]
    }
    result = auditor.verify(SAMPLE_MANIFEST, dep_graph_extra)
    assert result["verdict"] == WatchTowerVerdict.HOLD.value
    lane_check = next(c for c in result["checks"] if c["name"] == "required_lanes")
    assert lane_check["status"] == "FAIL"


def test_watchtower_residue_holds():
    auditor = WatchTower()
    tampered_manifest = dict(SAMPLE_MANIFEST)
    tampered_manifest["files"] = list(SAMPLE_MANIFEST["files"]) + [
        {"relative_path": "debug.tmp", "lane_id": "LANE_A", "sha256": "c" * 64}
    ]
    result = auditor.verify(with_complete_set(tampered_manifest), SAMPLE_DEP_GRAPH)
    assert result["verdict"] == WatchTowerVerdict.HOLD.value
    assert result["prohibited_residue_found"] is True


def test_watchtower_independence_violation_revises():
    auditor = WatchTower()
    tampered_manifest = dict(SAMPLE_MANIFEST)
    # Both lanes claiming the same file path with different hashes
    tampered_manifest["files"] = [
        {"relative_path": "shared.json", "lane_id": "LANE_A", "sha256": "1" * 64},
        {"relative_path": "shared.json", "lane_id": "LANE_B", "sha256": "2" * 64},
    ]
    lane_contracts = [
        {"lane_id": "LANE_A", "independence_group": "GRP_CORE"},
        {"lane_id": "LANE_B", "independence_group": "GRP_CORE"},
    ]
    result = auditor.verify(with_complete_set(tampered_manifest), SAMPLE_DEP_GRAPH, lane_contracts)
    assert result["verdict"] == WatchTowerVerdict.REVISE.value
    assert len(result["independence_violations"]) > 0
