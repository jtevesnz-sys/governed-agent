# Case study: correcting stale system-check reporting

Incident: 22 October 2026, New Zealand. Prepared for review: 27 October 2026.

**Evidence status:** a retained internal repair note, a separate role-guard note and a machine-readable checker receipt were inspected. This is a documented historical case, not an independently reproduced benchmark. The private system and raw logs are not included in this repository.

## Problem and result

A system checker had been updated to inspect a newer runtime home, but two report strings still named the older release. This made the generated operational report misleading even when its underlying checks used the newer location.

The incident record attributes diagnosis to Technician R2 in a read-only Hermes session. Codex applied two exact text replacements. The retained verification record reports a successful syntax check, preserved rollback bytes and one manual checker run with exit 0 and no findings. The generated report used the newer release label and explicitly retained qualification limits.

## Division of responsibility

| Step | Recorded actor | Evidence and limit |
|---|---|---|
| Inspect bounded inputs | Technician R2 | Read-only file access; a disallowed skill-view call was blocked. |
| Identify mismatch | Technician R2 | New runtime source path versus two stale report labels. |
| Apply change | Codex | Two bounded replacements under the existing repair request; Technician's guard was not bypassed. |
| Check syntax and preserved bytes | Repair workflow | AST parse and source/stage/rollback readbacks recorded. |
| Check resulting output | Manual system checker | Exit 0 and empty findings recorded; no claim of unattended reboot, activation or external intake. |
| Read-only role verification | Technician R2 | Later guard record says ACCEPTED, exit 0, no repairs allowed and BLINK change propose-only. |

This distinction matters: the evidence supports useful agent diagnosis within a controlled repair workflow. It does not support the claim that Technician autonomously changed the system.

## Recorded artifact identity

These SHA-256 values were read from the historical receipts. The original Windows artifacts were not independently rehashed during the documentation review.

| Artifact | Recorded SHA-256 |
|---|---|
| Script before correction | `f4ca19c22a6a501050c4ab98c1a16f22c06550079e77cfcec29b9dcf465b2179` |
| Script after correction | `74012b8761a0346f3383fd9f5ebfc67cb6b4147e33afab575a205ce01775819e` |
| Manual check report, 15,956 bytes | `5e515592dd6a10f48154d56830637738a3eecee4d8ec00033c6cdf0320828af0` |

The machine receipt identifies its scope as a read-only census, with no activation or artifact intake. Hashes bind a record to artifact bytes when those bytes are available; hashes alone do not let an external reader inspect or reproduce missing source.

## Failures retained

The related role-verification record also contains a Janitor session that failed to complete its requested triage and a bounded successor that timed out and exited 1. Those results are not counted as successful repair. A permitted read or an accepted output guard does not establish live MCP transport, complete triage or general BLINK automation.

## What this demonstrates

The case illustrates bounded diagnosis, accurate attribution, a narrow change, preserved rollback evidence and a check of the resulting report. It is a modest operational improvement with a traceable evidence chain.

It does not establish general repair success rates, coding-agent parity, universal BLINK deployment, production security or independently verified system health. The next step for public reproducibility is to release an approved synthetic checker with the same stale-label fault, its expected output contract, the patch and retained success/failure outputs. That fixture has not been produced or evaluated by this documentation task.

## Internal evidence references

The reviewer inspected retained records titled `WORK_ADMIN_CENSUS_LABEL_REPAIR_20261022_2250_01.md` and `WORK_ADMIN_HERMES_MCP_BLINK_20261022_2317_01.md`, plus the matching manual census JSON receipt. These sources remain private; no public link or independent external review is claimed. Machine/account identifiers, local paths and unrelated project material have been omitted from this proposed public summary.
