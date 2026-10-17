"""Tests for audit layer (Watchtower independent 6-point verifier)."""

from governed_agent.audit.watchtower import WatchTower, WatchTowerVerdict

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

SAMPLE_DEP_GRAPH = {
    "nodes": [
        {"lane_id": "LANE_A", "node_type": "LANE"},
        {"lane_id": "LANE_B", "node_type": "LANE"},
    ]
}


def test_watchtower_verdict_pass():
    auditor = WatchTower()
    result = auditor.verify(SAMPLE_MANIFEST, SAMPLE_DEP_GRAPH)
    assert result["verdict"] == WatchTowerVerdict.PASS.value
    assert result["prohibited_residue_found"] is False
    assert result["independence_violations"] == []


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
    result = auditor.verify(tampered_manifest, SAMPLE_DEP_GRAPH)
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
    result = auditor.verify(tampered_manifest, SAMPLE_DEP_GRAPH, lane_contracts)
    assert result["verdict"] == WatchTowerVerdict.REVISE.value
    assert len(result["independence_violations"]) > 0
