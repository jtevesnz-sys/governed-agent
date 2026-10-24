# Article: Governed Agents — Cryptographic Capability Sealing for LLM Tool Access

**Author:** jtevesnz-sys  
**Repository:** [https://github.com/jtevesnz-sys/governed-agent](https://github.com/jtevesnz-sys/governed-agent)  
**Whitepaper:** [https://github.com/jtevesnz-sys/governed-agent/blob/main/WHITE_PAPER.md](https://github.com/jtevesnz-sys/governed-agent/blob/main/WHITE_PAPER.md)  

---

## The Reality of Autonomous Agent Deployments

In 2026, autonomous agent frameworks have evolved from simple single-prompt scripts into sophisticated multi-turn loops. Frameworks like LangChain, CrewAI, AutoGen, and tool-calling environments allow models to invoke terminal commands, write to databases, call external APIs, and mutate file systems.

Yet almost every production deployment relies on an architectural pattern that operating system designers abandoned over fifty years ago: **ambient authority**.

If an agent is given access to a database tool, any token emission from the LLM that matches the tool schema executes with full privileges. To prevent catastrophic mutations—such as deleting production records or overwriting critical configuration—practitioners surround the model with **probabilistic guardrails**:
1. System prompt instructions: *"You are an assistant. Do not delete files or execute destructive SQL queries."*
2. Secondary LLM classifiers (e.g., NeMo Guardrails, Llama Guard): evaluating incoming prompts and outgoing tool calls with a smaller, faster model.

Under real-world conditions, probabilistic guardrails fail. Under adversarial prompt injection, jailbreaking, or contextual reasoning drift across extended conversations, language models easily bypass semantic filters. 

Even worse, agent pipelines suffer from the **self-certification trap**: after modifying a database or deploying code, the orchestrator asks the model, *"Did this pass?"* An agent that hallucinates a successful deployment will cheerfully certify its own hallucination.

If we would never give a junior developer unchecked production database access based purely on a promise to behave, why do we build autonomous agent systems this way?

---

## Returning to First Principles: Capability-Based Security

In 1966, Jack Dennis and Earl Van Horn introduced the concept of **capability-based security**: an entity should not perform an action because of ambient identity or role; it must present an unforgeable token explicitly granting the authority to perform that exact action.

In 1975, Jerome Saltzer and Michael Schroeder formulated the principle of **separation of duties**: no critical operation should be executed without independent authorization and verification across distinct components.

**Governed Agent** is a reference implementation of scoped capability checks and out-of-band audits. It does not guarantee production security: its file-backed anti-rollback state permits a complete older-snapshot replay, and its default key is co-located with that state. Protect the key separately and use an independent monotonic anchor before treating it as a security gate.

---

## The 5-Layer Governance Architecture

Governed Agent structures agent execution across five distinct operational layers:

```
[Layer 1: Capability]   RSA-SHA256 Token Sealing & Monotonic Anti-Rollback
          │
[Layer 2: Planning]     Scope-Bounded Task Packets (execution_authority: False)
          │
[Layer 3: Governance]   Consent-Gated Domain Boundaries & Policy Envelopes
          │
[Layer 4: Intake]       Credential Sanitization, Secret Blockers & Receipt Storage
          │
[Layer 5: Audit]        Independent Out-of-Band Verifier (Watchtower)
```

The newly published Tier 1 release open-sources reference implementations for **Layer 1 (Capability)**, **Layer 2 (Planning)**, and **Layer 5 (Audit)**.

---

### 1. Capability Sealing & Monotonic Anti-Rollback (KCAP Core)

Before an agent invokes a mutating tool, it must hold a cryptographically sealed capability token. 

The custodian creates a canonical JSON payload binding:
* The exact requested action and arguments.
* The trusted context (task identifier, authorized role, and expiration window).
* An authoritative UTC timestamp.

This payload is signed using standard **RSA-SHA256 PKCS#1 v1.5**. When the agent dispatches the tool call, the tool boundary verifies the digital signature and compares the runtime context against the token. If the signature is invalid or if the context has been manipulated, the call fails closed with status `HOLD`.

#### Monotonic Anti-Rollback State
Digital signatures alone do not prevent replay attacks: a compromised agent could attempt to reuse an earlier, valid capability token.

To check local sequence ordering, Governed Agent introduces **sequence pinning**. State checkpoints are bound to increasing sequence counters ($Seq_{n+1} > Seq_n$) relative to the currently loaded state. A repeated sequence raises the following error; restoring both file-backed state files to an older valid snapshot is not detected:

```python
ValueError: Rollback detected: sequence 1 <= latest sequence 2
```

In addition, checkpoints enforce a strict UTC freshness bound (1 to 3,600 seconds) against an authoritative time anchor, preventing expired tokens from being executed.

---

### 2. Scope-Bounded Planning (BLINK Core)

In typical agent architectures, planning and execution are blended into a single loop. An agent plans a 5-step task and immediately begins firing mutating tools.

Governed Agent enforces a strict rule: **Plan != Execution Authority**.

A planning agent emits a structured task packet specifying:
* `objective`: The declared scope.
* `allowed_actions`: Strictly bounded safe actions (`read`, `propose`, `verify`, `classify`).
* `prohibited_actions`: Explicitly banning dangerous operations (`activate`, `deploy`, `publish`, `send`, `overwrite`).
* `acceptance_criteria`: Concrete metrics for completion.

The BLINK validator checks this packet and outputs:
```json
{
  "blink_result": "PASS",
  "execution_authority": false,
  "not_authorization": true
}
```

A deterministic SHA-256 handoff packet is computed from the canonical packet bytes. Downstream executors receive an immutable specification of what was planned, but cannot use that plan as execution authority.

---

### 3. Out-of-Band Independent Audit (Watchtower Core)

Models must never grade their own homework. In Governed Agent, artifact acceptance is governed by **Watchtower**, an out-of-band audit script that executes completely outside the LLM process.

Watchtower runs a strict 6-point verification over all generated files and manifests:
1. **Manifest Validation:** Checks schema completeness, convergence IDs, and declared files.
2. **Required Lanes:** Confirms all planned execution lanes emitted outputs.
3. **Unlisted File Detection:** Traverses output directories to catch unauthorized side effects or stray files.
4. **Hash Agreement:** Recomputes SHA-256 digests of all generated files against the declared manifest.
5. **Cross-Lane Independence:** Verifies that parallel, isolated agent lanes did not produce conflicting mutations on shared paths.
6. **Prohibited Residue Detection:** Flags stray temporary files (`.tmp`, `.bak`, `.env`).

Watchtower returns non-negotiable verdict enums: `PASS`, `HOLD`, or `REVISE`. A model cannot self-certify its way past a missing hash or an unauthorized temporary file.

---

## Performance: Cryptographic Safety Without Latency

Security controls in AI systems often introduce unacceptable latency. We benchmarked the cryptographic overhead of Governed Agent on standard hardware (Python 3.14):

* **RSA-2048 Keypair Generation:** ~12.4 ms
* **Capability Sealing (RSA-SHA256):** ~0.42 ms
* **Capability Verification:** ~0.08 ms
* **Earlier full unit test suite (35 tests):** **0.84 seconds**; the v0.1.3 reference release passed 63 local tests with 90% coverage.

Compared to LLM inference latencies (500 ms – 3,000 ms per turn), cryptographic capability verification consumes **less than 0.1% of the turn duration**. These historical microbenchmarks do not qualify the entire reference system as a security boundary.

---

## A Focused Release Backed by a Broader Engineering Effort

`governed-agent` is released as a focused Tier 1 package: roughly 1,350 lines of pure Python (`cryptography` + `pydantic`), 63 local unit tests measuring 90% code coverage for v0.1.3, a technical whitepaper, and an end-to-end demo.

It originates from a broader private engineering effort of roughly 20,000 lines spanning our research and agent operations at Mercenarios AI. That broader codebase includes multi-role factory lifecycles, research corpora, intake sanitization pipelines, and memory indices. We are keeping the broader operating system private for continued commercial development while making the core governance architecture available for the community to inspect, test, and adopt.

---

## Getting Started

Install the package or clone the repository:

```bash
git clone https://github.com/jtevesnz-sys/governed-agent.git
cd governed-agent
pip install -e ".[test]"
pytest -v
```

Run the end-to-end demonstration in under 0.1 seconds:

```bash
python examples/quickstart_demo.py
```

### Links
* **GitHub Repository:** [https://github.com/jtevesnz-sys/governed-agent](https://github.com/jtevesnz-sys/governed-agent)
* **Technical Whitepaper:** [https://github.com/jtevesnz-sys/governed-agent/blob/main/WHITE_PAPER.md](https://github.com/jtevesnz-sys/governed-agent/blob/main/WHITE_PAPER.md)
* **Launch & Distribution Kit:** [https://github.com/jtevesnz-sys/governed-agent/blob/main/LAUNCH_KIT.md](https://github.com/jtevesnz-sys/governed-agent/blob/main/LAUNCH_KIT.md)
