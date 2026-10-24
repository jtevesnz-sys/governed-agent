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
        self.root_dir = Path(root_dir) if root_dir else None

    def verify(
        self,
        manifest: Union[Dict[str, Any], Path, str],
        dep_graph: Optional[Dict[str, Any]] = None,
        lane_contracts: Optional[List[Dict[str, Any]]] = None,
        root_dir: Union[str, Path, None] = None,
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
        effective_root = Path(root_dir) if root_dir else self.root_dir

        if isinstance(manifest, (Path, str)):
            manifest_path = Path(manifest)
            manifest_dict = self._load_json(manifest_path)
            if effective_root is None:
                effective_root = manifest_path.parent
        else:
            manifest_dict = manifest

        checks: List[Dict[str, Any]] = []
        independence_violations: List[str] = []

        # 1. Manifest structure validation
        checks.append(self._check_manifest_valid(manifest_dict))

        # Complete set hash check if present and valid
        checks.append(self._check_complete_set_hash(manifest_dict))

        # 2. Required lanes present
        checks.append(self._check_lanes_present(manifest_dict, dep_graph))

        # 3. No unlisted files
        checks.append(self._check_no_unlisted_files(manifest_dict, effective_root))

        # 4. Hash agreement
        checks.append(self._check_hashes(manifest_dict, effective_root))

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

    def _check_complete_set_hash(self, manifest: Dict[str, Any]) -> Dict[str, Any]:
        complete_set_sha = manifest.get("complete_set_sha256")
        if not complete_set_sha or not isinstance(complete_set_sha, str) or len(complete_set_sha) != 64:
            return {
                "name": "complete_set_sha256",
                "status": "FAIL",
                "details": "Invalid complete_set_sha256 in manifest",
            }
        files = manifest.get("files", [])
        if not isinstance(files, list):
            return {
                "name": "complete_set_sha256",
                "status": "FAIL",
                "details": "'files' must be a list",
            }

        try:
            # Deterministic canonical serialization of file entries
            normalized = []
            for f in files:
                rel = f.get("relative_path", "").replace("\\", "/")
                entry: Dict[str, Any] = {
                    "lane_id": f.get("lane_id", ""),
                    "relative_path": rel,
                    "sha256": f.get("sha256", ""),
                }
                if "size_bytes" in f:
                    entry["size_bytes"] = f["size_bytes"]
                normalized.append(entry)

            normalized.sort(key=lambda x: x["relative_path"])
            canonical = json.dumps(normalized, separators=(",", ":"), sort_keys=True).encode("utf-8")
            recomputed = hashlib.sha256(canonical).hexdigest()

            if recomputed.lower() != complete_set_sha.lower():
                return {
                    "name": "complete_set_sha256",
                    "status": "FAIL",
                    "details": f"complete_set_sha256 mismatch: expected {complete_set_sha}, computed {recomputed}",
                }
        except Exception as exc:
            return {
                "name": "complete_set_sha256",
                "status": "FAIL",
                "details": f"Error computing complete_set_sha256: {exc}",
            }

        return {
            "name": "complete_set_sha256",
            "status": "PASS",
            "details": "complete_set_sha256 verified",
        }

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

    def _check_no_unlisted_files(
        self,
        manifest: Dict[str, Any],
        root_dir: Optional[Path] = None,
    ) -> Dict[str, Any]:
        # Verifies files list format and detects unlisted files on disk
        files = manifest.get("files", [])
        if not isinstance(files, list):
            return {"name": "no_unlisted_files", "status": "FAIL", "details": "'files' must be a list"}

        target_root = root_dir if root_dir is not None else self.root_dir
        if target_root is None or not target_root.is_dir():
            return {"name": "no_unlisted_files", "status": "FAIL", "details": "Artifact root directory is required"}

        manifest_paths = set()
        for f in files:
            rel = f.get("relative_path")
            if rel:
                manifest_paths.add(Path(rel).as_posix())

        unlisted = []
        for p in target_root.rglob("*"):
            if p.is_file():
                rel_posix = p.relative_to(target_root).as_posix()
                # Skip ignore files / directories or manifest itself if located in root
                if rel_posix in {".git", ".gitignore", "manifest.json"}:
                    continue
                if rel_posix not in manifest_paths:
                    unlisted.append(rel_posix)

        if unlisted:
            return {
                "name": "no_unlisted_files",
                "status": "FAIL",
                "details": f"Unlisted files detected: {sorted(unlisted)}",
            }
        return {"name": "no_unlisted_files", "status": "PASS", "details": "No unlisted files detected"}

    def _check_hashes(
        self,
        manifest: Dict[str, Any],
        root_dir: Optional[Path] = None,
    ) -> Dict[str, Any]:
        files = manifest.get("files", [])
        target_root = root_dir if root_dir is not None else self.root_dir
        if target_root is None or not target_root.is_dir():
            return {"name": "hash_agreement", "status": "FAIL", "details": "Artifact root directory is required"}
        if not isinstance(files, list) or not files:
            return {"name": "hash_agreement", "status": "FAIL", "details": "At least one artifact file is required"}

        for f in files:
            sha = f.get("sha256", "")
            rel = f.get("relative_path", "")
            if not isinstance(sha, str) or len(sha) != 64:
                return {
                    "name": "hash_agreement",
                    "status": "FAIL",
                    "details": f"Invalid sha256 for file: {rel}",
                }
            if "size_bytes" in f and (type(f["size_bytes"]) is not int or f["size_bytes"] < 0):
                return {"name": "hash_agreement", "status": "FAIL", "details": f"Invalid size_bytes for file: {rel}"}

            if not target_root.is_dir():
                return {"name": "hash_agreement", "status": "FAIL", "details": "Artifact root directory is unavailable"}
            file_path = (target_root / rel).resolve()
            try:
                # Canonical containment check: prevent path traversal outside root_dir
                file_path.relative_to(target_root.resolve())
            except ValueError:
                return {
                    "name": "hash_agreement",
                    "status": "FAIL",
                    "details": f"Path traversal escape detected for file: {rel}",
                }

            if not file_path.is_file():
                return {
                    "name": "hash_agreement",
                    "status": "FAIL",
                    "details": f"Missing file on disk: {rel}",
                }

            h = hashlib.sha256()
            actual_size = 0
            with open(file_path, "rb") as fp:
                for chunk in iter(lambda: fp.read(8192), b""):
                    actual_size += len(chunk)
                    h.update(chunk)
            if "size_bytes" in f and actual_size != f["size_bytes"]:
                return {
                    "name": "hash_agreement",
                    "status": "FAIL",
                    "details": f"Size mismatch for {rel}: expected {f['size_bytes']}, got {actual_size}",
                }
            computed = h.hexdigest()
            if computed.lower() != sha.lower():
                return {
                    "name": "hash_agreement",
                    "status": "FAIL",
                    "details": f"Hash mismatch for {rel}: expected {sha}, got {computed}",
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

        mandatory = ["manifest_validation", "required_lanes", "no_unlisted_files", "hash_agreement", "complete_set_sha256"]
        for c in checks:
            if c["name"] in mandatory and c["status"] == "FAIL":
                if c["name"] in {"hash_agreement", "complete_set_sha256"}:
                    if c["name"] == "hash_agreement" and "Missing file on disk" in c.get("details", ""):
                        return WatchTowerVerdict.HOLD
                    return WatchTowerVerdict.REVISE
                return WatchTowerVerdict.HOLD

        if residue_found:
            return WatchTowerVerdict.HOLD

        return WatchTowerVerdict.PASS
