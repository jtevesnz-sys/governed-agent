# Governed Agent

> **Reference implementation (v0.1.4), not a production security gate.** The file-backed anti-rollback authority detects partial state corruption but cannot detect replay of a complete older snapshot. Its default key is stored beside the state; anyone able to read that key and write the state can forge pins. Use separately protected key custody and an independent monotonic anchor before relying on durable rollback resistance. See the Sequence-Checked Pins section below.

> **Deterministic capability-based security, scope-bounded planning, and out-of-band audit for autonomous AI agents.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![CI](https://github.com/jtevesnz-sys/governed-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/jtevesnz-sys/governed-agent/actions/workflows/ci.yml)
[![Whitepaper](https://img.shields.io/badge/paper-WHITE__PAPER.md-orange.svg)](WHITE_PAPER.md)
[![arXiv LaTeX](https://img.shields.io/badge/arXiv-paper%2Fgoverned__agent__paper.tex-purple.svg)](paper/governed_agent_paper.tex)
[![Blog Post](https://img.shields.io/badge/blog-BLOG__POST.md-blue.svg)](BLOG_POST.md)

---

## A focused public release, backed by a larger body of work

`governed-agent` is designed as a focused Tier 1 release: roughly 1,200 lines of code covering cryptographic capability sealing, scope-bound planning validation, and independent audit primitives. Its purpose is to give developers a clear, usable foundation for governed agents.

It comes from a broader private engineering effort of roughly 20,000 lines. That work spans the systems and workflows behind our research and agent operations. We are keeping it private while making the core governance ideas available for others to inspect and build on.

The distinction is deliberate: **a focused release that shows the engineering clearly, with the broader operating system protected for continued development.**

---

## Development history and operational examples

Governed Agent is the public reference implementation within a wider body of work on project-scoped coordination, research controls, agent maintenance and evaluation. The [development history](docs/DEVELOPMENT_HISTORY.md) distinguishes public implementation evidence from retained internal designs and run records.

One [maintenance case study](docs/case-studies/MAINTENANCE_REPAIR_20261022.md) records Technician diagnosis, a bounded Codex correction and a checked system report. It illustrates the operating method while preserving the limits of a single, internally recorded incident. Comparative agent performance and production qualification remain unestablished.

---

## Technical Whitepaper

For the formal mathematical specification, threat model, cryptographic formulation, and benchmark evaluation, read the **[Technical Whitepaper (WHITE_PAPER.md)](WHITE_PAPER.md)**.

---

## The Problem: Ambient Authority & Self-Certification

Production LLM agent frameworks (LangChain, CrewAI, AutoGen, and tool-calling models) operate under **ambient authority**:
1. **Unbounded execution:** If an agent is given tool access (database writes, terminal execution, file mutations), it can execute those tools whenever the model decides to emit a tool call.
2. **Probabilistic guardrails:** Traditional safety relies on prompt instructions ("*do not delete files*") or secondary LLM filters. These are easily evaded via prompt injection or context drift.
3. **Self-certification:** The same model executing actions is asked to verify whether its execution succeeded.

**Governed Agent** replaces some prompt-only checks with deterministic checks under explicit key-custody, dispatcher, and storage assumptions:
* **Capabilities are cryptographically signed** with RSA-SHA256 tokens; the supplied file-backed pin store checks sequence consistency but is not an independent monotonic anchor.
* **Planning does not grant execution authority** (`execution_authority: False`).
* **An out-of-band auditor** checks listed artifacts against their declared hashes when given a real artifact root; the caller must establish trust in the manifest and isolation of the auditor.

---

## Architecture: The 5-Layer Governance Model

```
   ┌─────────────────────────────────────────────────────────────┐
   │                    1. CAPABILITY LAYER                      │
   │   RSA-SHA256 Capability Sealing & Monotonic Anti-Rollback   │
   │   (Tokens bound to scope, expiry, and non-decreasing pins)  │
   └──────────────────────────────┬──────────────────────────────┘
                                  │
                                  ▼
   ┌─────────────────────────────────────────────────────────────┐
   │                     2. PLANNING LAYER                       │
   │   Scope-Bounded Task Packets (Plan != Authority)            │
   │   (Allowed actions, strict prohibitions, SHA-256 handoffs)  │
   └──────────────────────────────┬──────────────────────────────┘
                                  │
                                  ▼
   ┌─────────────────────────────────────────────────────────────┐
   │                    3. GOVERNANCE LAYER                      │
   │   Domain Boundaries & Case Envelope Verification            │
   └──────────────────────────────┬──────────────────────────────┘
                                  │
                                  ▼
   ┌─────────────────────────────────────────────────────────────┐
   │                      4. INTAKE LAYER                        │
   │   Credential Sanitization, Secret Defense & Receipt Store   │
   └──────────────────────────────┬──────────────────────────────┘
                                  │
                                  ▼
   ┌─────────────────────────────────────────────────────────────┐
   │                      5. AUDIT LAYER                         │
   │   Out-of-Band Independent Verifier (Watchtower)             │
   │   (6-point audit: manifest, hashes, residue, PASS/HOLD)     │
   └─────────────────────────────────────────────────────────────┘
```

> **Tier 1 (Core)** provides reference implementations for **Layer 1 (Capability)**, **Layer 2 (Planning)**, and **Layer 5 (Audit)**.

---

## Core Primitives

### 1. Capability Sealing (`governed_agent.capability`)
Before an agent can invoke a privileged tool, it must hold an unforgeable capability token generated by an authoritative custodian.

```python
from governed_agent.capability import generate_keypair, seal, verify

# Custodian generates keypair
custodian_key = generate_keypair(key_size=2048, key_id="custodian-primary")

# Seal a capability receipt for a specific agent action and context
receipt = seal(
    request={"action": "mutate_table", "table": "orders"},
    trusted_context={"task_id": "JOB-9102", "role": "database-migration"},
    keypair=custodian_key,
)

# Tool execution boundary verifies the capability token before execution
verdict = verify(
    receipt_bytes=receipt.receipt_bytes,
    signature=receipt.signature,
    trusted_expected_context={"task_id": "JOB-9102", "role": "database-migration"},
    key=custodian_key.public_key_pem,
)

assert verdict.status == "ACCEPT"
```

`GovernedToolBoundary.invoke_tool` requires the signed request to contain exactly `{"action": tool_name, **args}`; a signature over the action alone cannot authorize different paths, payloads, or extra arguments.

The execution boundary consumes a receipt durably before calling its tool. Reusing it is denied even after an exception or process restart. All boundaries in one execution domain must share the same protected SQLite replay file: pass `replay_store_path=...`, set `GOVERNED_AGENT_REPLAY_STORE_PATH`, or use the default `~/.governed_agent/receipt_replay.sqlite3`. Preserve that history; deleting it or restoring an older copy removes replay evidence. Verification alone remains a read-only cryptographic check and does not consume execution authority. See the [v0.1.4 release notes](docs/releases/v0.1.4.md) for upgrade requirements and limits.

Configured replay and pin-authority paths bind to an absolute location when the object is constructed, so later changes to the working directory cannot select different state.

### 2. Sequence-Checked Pins (`governed_agent.capability.antirollback`)
Rejects a repeated or lower sequence relative to the latest stored state. File-backed instances reload under a shared process lock before reading or updating it; durable rollback resistance against full snapshot restoration still requires an external anchor:

```python
from governed_agent.capability import InMemoryAuthority

authority = InMemoryAuthority()
pin1 = authority.create_pin(chain_id="deploy_session", checkpoint_hash="hash_v1", sequence=1)
pin2 = authority.create_pin(chain_id="deploy_session", checkpoint_hash="hash_v2", sequence=2)

# Attempting to replay sequence 1 raises an immediate anti-rollback violation:
# ValueError: Rollback detected: sequence 1 <= latest sequence 2
```

`FileBackedAuthority` now accepts only pins authenticated with its configured private key. Legacy pins signed with the public fallback secret are rejected on load; do not automatically re-sign or trust them. Re-establish a trusted state under separately reviewed authority before migration. An unreadable or empty key fails closed; if a key is lost, existing pins cannot be authenticated by a replacement key.

**Limits:** The file-backed counter detects partial truncation or inconsistency, but a party able to restore both `pins.json` and `counter.txt` to an older valid snapshot can still roll back the state. It is not a standalone external monotonic anchor. The default `authority.key` lives beside those files: if an attacker can read that key and write the pins, they can forge authenticated state. Keep the authority key in a separately protected trust domain and use an independent monotonic store before treating this as a rollback-resistant security gate.

**Existing key without state:** A legacy, never-pinned authority may contain only `authority.key`; the same layout can result from lost history. The implementation cannot safely distinguish them and does not create empty replacement state. Restore the matching `pins.json` and `counter.txt`, or obtain owner approval to establish a new authority in a separate directory. Preserve the original key and history; recovery is an operator decision.

### 3. Scope-Bounded Planning (`governed_agent.planning`)
Ensures planning agents cannot execute actions or grant themselves authority:

```python
from governed_agent.planning import validate, create_handoff

task_packet = {
    "task_id": "TASK-501",
    "objective": "Analyze migration logs and propose indexing changes",
    "allowed_actions": ["read", "propose"],
    "prohibited_actions": ["activate", "deploy", "publish", "send", "overwrite"],
    "acceptance_criteria": ["Return index recommendations backed by query cost estimates"],
    "executor": "database_engineer",
}

validation = validate(task_packet)
assert validation["blink_result"] == "PASS"
assert validation["execution_authority"] is False  # Never grants execution authority!

# Generates deterministic, hash-bound handoff packet
handoff = create_handoff(task_packet, validation)
print(f"Handoff ID: {handoff['handoff_id']}")
print(f"Packet SHA256: {handoff['packet_sha256']}")
```

Handoff creation and reasoning-brief rendering revalidate the supplied packet; caller-provided validation results are ignored. When `GOVERNED_AGENT_BLINK_ENABLED=false`, validation returns `FAIL` and handoffs are denied rather than issuing an unchecked `PASS`.

### 4. Independent Audit (`governed_agent.audit`)
Enforces separation of duties by auditing build outputs against manifests without model involvement:

```python
from governed_agent.audit import WatchTower, WatchTowerVerdict

auditor = WatchTower(root_dir="artifacts")
audit_result = auditor.verify("manifest.json")

# Returns strict, non-negotiable verdicts: PASS, HOLD, or REVISE
if audit_result["verdict"] != WatchTowerVerdict.PASS.value:
    raise RuntimeError(f"Audit failed with status: {audit_result['verdict']}")
```

A full audit requires an existing artifact directory and at least one listed file. Without either, Watchtower returns a non-PASS verdict instead of treating metadata-only checks as filesystem verification. If a manifest declares `size_bytes`, the value must be a nonnegative integer matching the bytes actually read during hashing; a digest over a false size declaration cannot earn PASS.

---

## Comparison Matrix

| Property | LangChain / CrewAI | Anthropic MCP | NeMo Guardrails | Governed Agent |
| :--- | :--- | :--- | :--- | :--- |
| **Tool Execution Authority** | Ambient | Ambient per server | Prompt/Text filter | **Cryptographic token (RSA-SHA256)** |
| **Anti-Replay / Monotonicity** | ❌ None | ❌ None | ❌ None | **Sequence checks; durable rollback resistance requires external anchor** |
| **Tamper-Evident Handoffs** | ❌ Plain text/dict | ❌ JSON-RPC | ❌ None | **✅ SHA-256 bound task packets** |
| **Planning vs Execution Separation** | ❌ Blended | ❌ Blended | ❌ Blended | **✅ Strict (`execution_authority: False`)** |
| **Self-Certification Prevention** | ❌ Model self-eval | ❌ None | ❌ None | **✅ Out-of-band 6-point verifier** |
| **Failure Mode** | Silent fault | Silent fault | Evasion | **Fail-closed (`HOLD`)** |

---

## Installation

```bash
pip install governed-agent
```

For development and running tests:

```bash
git clone https://github.com/jtevesnz-sys/governed-agent.git
cd governed-agent
pip install -e .[test]
pytest
```

---

## Community & Contact

* **GitHub Discussions:** Ask questions, share architectures, or propose integrations in [Discussions](https://github.com/jtevesnz-sys/governed-agent/discussions).
* **Security Advisories:** Report potential vulnerabilities privately via [Security Advisories](https://github.com/jtevesnz-sys/governed-agent/security).
* **Inquiries & Pilots:** Open a discussion thread or reach out via project GitHub handles.

---

## License

MIT License. Copyright (c) 2026 jtevesnz-sys.
