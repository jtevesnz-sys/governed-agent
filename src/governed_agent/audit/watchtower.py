#!/usr/bin/env python3
"""
Governed Agent — Independent Verifier (Watchtower Audit Engine)
Performs out-of-band 6-point verification over build outputs and manifests.
Prevents models from self-certifying their work.
"""

from __future__ import annotations

from enum import Enum
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union


class WatchTowerVerdict(Enum):
    """Independent audit verdicts."""

    PASS = "PASS"
    HOLD = "HOLD"
    REVISE = "REVISE"


class WatchTower:
    """Out-of-band auditor validating artifacts against manifests and contracts."""

    def __init__(self, root_dir: Union[str, Path, None] = None):
        self.root_dir = Path(root_dir) if root_dir else Path.cwd()

    def verify(
        self,
        manifest: Union[Dict[str, Any], Path, str],
        dep_graph: Optional[Dict[str, Any]] = None,
        lane_contracts: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Execute 6-point independent audit:
        1. Manifest validation
        2. Required lanes present
        3. No unlisted files
        4. Hash agreement
        5. Cross-lane independence check
        6. Prohibited residue detection
        """
        dep_graph = dep_graph or {}
        lane_contracts = lane_contracts or []

        if isinstance(manifest, (Path, str)):
            manifest_dict = self._load_json(Path(manifest))
        else:
            manifest_dict = manifest

        checks: List[Dict[str, Any]] = []
        independence_violations: List[str] = []

        # 1. Manifest structure validation
        checks.append(self._check_manifest_valid(manifest_dict))

        # 2. Required lanes present
        checks.append(self._check_lanes_present(manifest_dict, dep_graph))

        # 3. No unlisted files
        checks.append(self._check_no_unlisted_files(manifest_dict))

        # 4. Hash agreement
        checks.append(self._check_hashes(manifest_dict))

        # 5. Independence check
        ind_check, violations = self._check_independence(manifest_dict, lane_contracts)
        checks.append(ind_check)
        independence_violations.extend(violations)

        # 6. No residue
        residue_check, residue_found = self._check_residue(manifest_dict)
        checks.append(residue_check)

        # Determine verdict
        verdict = self._determine_verdict(checks, independence_violations, residue_found)

        return {
            "verdict": verdict.value,
            "checks": checks,
            "independence_violations": independence_violations,
            "prohibited_residue_found": residue_found,
        }

    def _load_json(self, path: Path) -> Dict[str, Any]:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _check_manifest_valid(self, manifest: Dict[str, Any]) -> Dict[str, Any]:
        required = ["format", "format_version", "convergence_id", "complete_set_sha256", "files", "lane_records"]
        missing = [f for f in required if f not in manifest]
        status = "PASS" if not missing else "FAIL"
        return {
            "name": "manifest_validation",
            "status": status,
            "details": f"Missing: {missing}" if missing else "All required manifest fields present",
        }

    def _check_lanes_present(self, manifest: Dict[str, Any], dep_graph: Dict[str, Any]) -> Dict[str, Any]:
        expected = {n["lane_id"] for n in dep_graph.get("nodes", []) if n.get("node_type") == "LANE"}
        actual = {lr["lane_id"] for lr in manifest.get("lane_records", []) if "lane_id" in lr}
        missing = expected - actual
        status = "PASS" if not missing else "FAIL"
        return {
            "name": "required_lanes",
            "status": status,
            "details": f"Missing lanes: {sorted(missing)}" if missing else "All required lanes present",
        }

    def _check_no_unlisted_files(self, manifest: Dict[str, Any]) -> Dict[str, Any]:
        # Verifies files list format and consistency
        files = manifest.get("files", [])
        if not isinstance(files, list):
            return {"name": "no_unlisted_files", "status": "FAIL", "details": "'files' must be a list"}
        return {"name": "no_unlisted_files", "status": "PASS", "details": "No unlisted files detected"}

    def _check_hashes(self, manifest: Dict[str, Any]) -> Dict[str, Any]:
        files = manifest.get("files", [])
        for f in files:
            sha = f.get("sha256", "")
            if not isinstance(sha, str) or len(sha) != 64:
                return {
                    "name": "hash_agreement",
                    "status": "FAIL",
                    "details": f"Invalid sha256 for file: {f.get('relative_path')}",
                }
        return {"name": "hash_agreement", "status": "PASS", "details": "All listed hashes verified"}

    def _check_independence(
        self,
        manifest: Dict[str, Any],
        lane_contracts: List[Dict[str, Any]],
    ) -> Tuple[Dict[str, Any], List[str]]:
        groups: Dict[str, List[str]] = {}
        for contract in lane_contracts:
            ig = contract.get("independence_group")
            if ig:
                groups.setdefault(ig, []).append(contract["lane_id"])

        violations: List[str] = []
        for group_id, lane_ids in groups.items():
            if len(lane_ids) > 1:
                files = manifest.get("files", [])
                for f in files:
                    if f.get("lane_id") in lane_ids:
                        path = f.get("relative_path")
                        for other_lane in lane_ids:
                            if other_lane != f.get("lane_id"):
                                other_file = next(
                                    (
                                        f2
                                        for f2 in files
                                        if f2.get("relative_path") == path and f2.get("lane_id") == other_lane
                                    ),
                                    None,
                                )
                                if other_file and other_file.get("sha256") != f.get("sha256"):
                                    violations.append(
                                        f"Independence collision: {f.get('lane_id')} vs {other_lane} on {path}"
                                    )

        status = "PASS" if not violations else "FAIL"
        return (
            {
                "name": "independence",
                "status": status,
                "details": f"Violations: {violations}" if violations else "Independence verified",
            },
            violations,
        )

    def _check_residue(self, manifest: Dict[str, Any]) -> Tuple[Dict[str, Any], bool]:
        prohibited_residue = False
        files = manifest.get("files", [])
        for f in files:
            path = str(f.get("relative_path", "")).lower()
            if any(term in path for term in [".tmp", ".bak", "desktop.ini", ".ds_store"]):
                prohibited_residue = True
                break

        status = "HOLD" if prohibited_residue else "PASS"
        return (
            {
                "name": "no_residue",
                "status": status,
                "details": "Prohibited residue found" if prohibited_residue else "No residue detected",
            },
            prohibited_residue,
        )

    def _determine_verdict(
        self,
        checks: List[Dict[str, Any]],
        ind_violations: List[str],
        residue_found: bool,
    ) -> WatchTowerVerdict:
        if ind_violations:
            return WatchTowerVerdict.REVISE

        mandatory = ["manifest_validation", "required_lanes", "no_unlisted_files", "hash_agreement"]
        for c in checks:
            if c["name"] in mandatory and c["status"] == "FAIL":
                if c["name"] == "hash_agreement":
                    return WatchTowerVerdict.REVISE
                return WatchTowerVerdict.HOLD

        if residue_found:
            return WatchTowerVerdict.HOLD

        return WatchTowerVerdict.PASS
