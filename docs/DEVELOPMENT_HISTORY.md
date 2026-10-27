# Development history and evidence boundaries

Prepared 27 October 2026. Proposed documentation addition.

Governed Agent is the public reference implementation within Jeremy Eves's wider work on agent coordination, evidence handling, maintenance and evaluation. This page distinguishes inspectable public code from retained internal design and run records. Internal records have not been published with this repository and are not independently reproducible from this page alone.

## Timeline

| Date | Development record | What the evidence supports |
|---|---|---|
| July 2026 | Retained WORK_ADMIN recap defining coordinator, owner approval, Janitor discovery and Technician copy/hash/receipt roles | Design history. The recap explicitly records that the desired full autopilot and backup loop had not been achieved then. |
| August 2026 | Retained BLINK operating specification and coding-improvement playbook | Drift-control and coding-workflow design. Both were proposals at preparation, not installation or performance receipts. |
| September 2026 | Retained maintenance playbook covering Technician, Janitor, BLINK and verification roles | A documented maintenance operating model including gateway, MCP, provider and integration faults. Fleet adoption is a separate question. |
| 15 October 2026 | Retained Academy starter separating teacher, student and examiner; paired lesson/no-lesson comparison and unseen retest | Evaluation design. The starter records training as not run at preparation; no later measured learning result is claimed here. |
| 17 October 2026 | [Public boundary/audit implementation change](https://github.com/jtevesnz-sys/governed-agent/commit/e504374a4cdaf95dcfe6fa551bfe6d9baf226b08) | Inspectable development of the Hermes adapter, artifact checks and planning interface. Historical claims in commit messages are not current security qualification. |
| 22 October 2026 | Retained Technician diagnosis, Codex reporting correction and manual checker receipt | One bounded maintenance incident, described in the [case study](case-studies/MAINTENANCE_REPAIR_20261022.md). This was a reporting repair, with separate diagnostic and implementation roles. |
| 25 October 2026 NZDT / 24 October UTC | [v0.1.3 reference release](https://github.com/jtevesnz-sys/governed-agent/releases/tag/v0.1.3), commit `4b6d245281a0506c0462ca5835df17589aefcda4` | Scoped security fixes and explicit security limitations. [CI run 40141830292](https://github.com/jtevesnz-sys/governed-agent/actions/runs/40141830292) succeeded on Python 3.10–3.13; its Python 3.12 log records 63 tests passing and 90% statement coverage. |
| 26 October 2026 | Retained scheduled journal-cycle receipt and admin source readback; separate automatic diary continuation record | Bounded historical integration evidence. A later health snapshot reports degraded capture, so this is not a claim of continuous uptime. |

The dates describe document or run records, not a claim of worldwide invention, sole authorship or independent certification. Original source timestamps and retained execution records should accompany any stronger historical claim.

## How the components relate

| Component | Intended role | Demonstrated boundary |
|---|---|---|
| Governed Agent | Signed requests, bounded planning and artifact checking | Public Python reference implementation and CI evidence. It is not a production security gate. |
| WORK_ADMIN | Project context, decisions, handovers and evidence records | Retained designs and bounded journal-integration records; present reliability requires current evidence. |
| BLINK | Alignment, bounded decisions, coding procedures and recovery | Historical specifications, a retained read-only guard route and the narrower public planning module. |
| Maintenance team | Diagnose faults and coordinate bounded repairs | One retained diagnosis/repair/check incident; generalized autonomous repair performance is unmeasured. |
| Academy / Test Team | Improve agent instructions/workflows and evaluate results | Documented operating design; measured learning gains are not established. |
| PROCC/MATRIX | Research framing, source provenance, claim states and challenge/verification | Versioned method and supporting validator work; comparative research superiority is unmeasured. |

The broader BLINK design should not be equated with [`planning/blink.py`](https://github.com/jtevesnz-sys/governed-agent/blob/4b6d245281a0506c0462ca5835df17589aefcda4/src/governed_agent/planning/blink.py). That public module validates task packets and creates hash-bound handoffs while explicitly returning no execution authority. Universal integration of the broader capability across current agents requires a current configuration and invocation inventory.

## Qualification limits

Unit tests establish the tested behavior of the named code version. They do not establish production security, reliable autonomous operations or performance parity with commercial coding/research agents. Likewise, a retained incident or cycle receipt is historical evidence, not independent replication.

The reference release explicitly retains limits around signing-key custody, replay of full prior state, trusted manifest provenance and enforced auditor isolation. Those limits remain controlling. Academy improvement, fleet-wide BLINK use, general repair effectiveness and end-to-end Kernel execution need their own evidence.

## Contribution and next evidence

Jeremy Eves describes his contribution as defining objectives, role responsibilities, governance rules and the integration direction. The public repository supplies inspectable implementation work; the maintenance case credits Technician diagnosis and Codex edits separately. Upstream platforms, models and AI-assisted implementation should retain their own attribution. This page does not independently establish who authored every line or idea.

The next useful addition is a sanitized, reproducible repair fixture with its patch, checker and all outcomes, followed by a frozen baseline/candidate agent evaluation. Until those artifacts exist, describe the private records as retained internal evidence rather than publicly reproduced capability.
