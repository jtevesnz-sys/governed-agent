# Governed Agent: Cryptographic Capability Sealing and Out-of-Band Audit for Autonomous LLM Agents

**Author:** jtevesnz-sys  
**Affiliation:** Mercenarios AI Systems  
**Code Repository:** [https://github.com/jtevesnz-sys/governed-agent](https://github.com/jtevesnz-sys/governed-agent)  
**Date:** October 2026  

**v0.1.3 reference-release correction:** The bundled file-backed pin authority is not a durable monotonic anchor: a valid replay of both state files restores older state. Its default HMAC key is co-located with the state, so a party able to read the key and write the state can forge pins. The code is a reference implementation, not a production security gate without separate key custody, independent monotonic storage, and independent review. Historical benchmarks below describe an earlier revision, not a fresh v0.1.3 benchmark.

---

## Abstract

Autonomous Large Language Model (LLM) agent frameworks (such as LangChain, AutoGen, CrewAI, and the Model Context Protocol) operate predominantly under *ambient authority*. When an agent is granted access to a toolset—such as mutating database queries, system execution, or network calls—the execution boundary relies on probabilistic prompt-following ("*do not delete production tables*") or heuristic secondary text classifiers. Under adversarial prompt injection, jailbreaking, or contextual reasoning drift, these probabilistic barriers fail, granting unauthorized execution authority to unvetted LLM outputs. Furthermore, existing architectures allow models to self-certify their own work, creating severe alignment vulnerabilities.

We present **Governed Agent**, a deterministic capability-security architecture for autonomous LLM agent execution. Governed Agent enforces three core invariants:
1. **Cryptographic Capability Sealing (KCAP):** Privileged tool invocations require RSA-SHA256 tokens bound to the verified request and trusted context. The bundled pin store checks sequences against its current local state; durable rollback resistance needs an external anchor.
2. **Separation of Planning and Execution Authority (BLINK):** The planning phase generates hash-bound task packets where execution authority is strictly withheld (`execution_authority: False`), enforcing deterministic prohibition gates before dispatch.
3. **Out-of-Band Independent Audit (Watchtower):** A decoupled verification engine evaluates all mutated artifacts, directories, and manifests against cryptographic baselines, issuing non-negotiable `PASS`, `HOLD`, or `REVISE` verdicts without model self-certification.

The v0.1.3 reference implementation passed 63 local unit tests with 90% statement coverage on Python 3.14. These local checks do not establish production-ready rollback resistance or cross-version benchmarks.

---

## 1. Introduction

The prevailing paradigm of LLM agent tool invocation models agent actions as direct function calls triggered by model-emitted text or JSON blobs. In this model, tool access is binary and ambient: if an agent instance has access to a SQL execution tool or a shell interface, any output token sequence corresponding to that tool call will be executed by the runtime harness.

This architecture introduces two critical systemic vulnerabilities:
1. **The Ambient Authority Trap:** Guardrails implemented via system prompts or text-classification filters (e.g., NeMo Guardrails, Llama Guard) are fundamentally probabilistic. They operate in the semantic domain of language, which is susceptible to prompt injection, persona manipulation, and semantic obfuscation.
2. **The Self-Certification Hazard:** In multi-step pipelines, agents are routinely prompted to verify the correctness of their own actions. An agent that hallucinates a successful database migration will attest to its own success, masking catastrophic silent errors.

In operating systems and distributed systems, this class of problem was resolved decades ago through **capability-based security** (Dennis and Van Horn, 1966) and **separation of duties** (Saltzer and Schroeder, 1975). An entity should not perform an action because it possesses identity or ambient presence; it must present an unforgeable, scoped token explicitly authorizing the action.

**Governed Agent** adapts these principles through RSA-2048/SHA-256 capability checks, sequence-checked pin state, and an out-of-band audit implementation. These checks have explicit key, state, dispatcher, and manifest trust assumptions; they do not alone guarantee system safety.

---

## 2. Threat Model & Security Invariants

### 2.1 Threat Model
We assume an untrusted or manipulable LLM. The model may experience:
* Direct or indirect prompt injection via retrieved third-party content.
* Semantic drift over extended context windows.
* Hallucinatory self-attestation of completed work.
* Out-of-order tool invocation or unauthorized replay of previously granted privileges.

The execution boundary (the local or remote tool dispatcher) and the audit engine are assumed to run in isolated execution contexts adhering strictly to cryptographic verification routines.

### 2.2 Core Invariants
* **Invariant 1 (No Ambient Authority):** No mutating tool may execute without presenting a cryptographically valid capability token signed by an authorized custodian key.
* **Invariant 2 (Plan $\neq$ Execution Authority):** An agent tasked with planning, scoping, or decomposing an objective cannot generate execution authority for that plan.
* **Invariant 3 (Sequence Checks):** A new pin must have $Seq_{n+1} > Seq_n$ relative to loaded state. The bundled file-backed implementation does not enforce this across a full older-state snapshot restore.
* **Invariant 4 (External Audit):** Artifact validity is checked against a manifest and real files by a verifier independent of the generating model. This reference implementation does not authenticate the manifest itself; its provenance must be established separately.

---

## 3. Architecture & Core Primitives

Governed Agent structures agent execution across a 5-layer pipeline:

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

The open-source reference release focuses on Layers 1, 2, and 5.

### 3.1 Cryptographic Capability Sealing (KCAP Core)
The capability layer implements RSA-SHA256 PKCS#1 v1.5 capability sealing. Before a tool executes, the custodian creates a canonical JSON payload comprising the exact action request, parameters, trusted context (role, task ID, expiry), and timestamp.

The sealing function:
$$\text{Receipt} = \text{Canonicalize}(\text{Request} \cup \text{TrustedContext} \cup \text{Timestamp})$$
$$\sigma = \text{Sign}_{K_{\text{private}}}(\text{SHA-256}(\text{Receipt}))$$

The tool execution interface evaluates:
$$\text{Verify}_{K_{\text{public}}}(\text{Receipt}, \sigma) \overset{?}{=} \text{VALID} \quad \land \quad \text{Context}_{\text{runtime}} = \text{Context}_{\text{token}}$$

If verification fails or if the runtime context mismatches the sealed token, the tool dispatcher immediately fails closed with status `HOLD`.

### 3.2 Monotonic Anti-Rollback Authority
The reference implementation checks new sequence numbers against its loaded state. This does not prevent replay of the complete file-backed state; durable non-replay requires an independently protected monotonic authority. Each state checkpoint is bound to a pin containing:
$$\text{Pin} = (\text{ChainID}, \text{CheckpointHash}, \text{Sequence}, \text{Timestamp}, \sigma_{\text{auth}})$$

When a new pin is submitted:
$$\text{Enforce}(Seq_{\text{new}} > Seq_{\text{latest}})$$
Any attempt to submit a sequence $Seq \le Seq_{\text{latest}}$ raises an immediate `ValueError: Rollback detected`. In addition, checkpoints are validated against a strict freshness bound $\Delta t \in [1, 3600\text{s}]$:
$$t_{\text{obs}} \le t_{\text{trusted}} \le t_{\text{expiry}} \quad \land \quad (t_{\text{trusted}} - t_{\text{obs}}) \le \Delta t_{\text{max}}$$

### 3.3 Scope-Bounded Planning (BLINK Core)
The planning layer decouples decomposition from execution. A planning agent emits a structured task packet:
$$\text{Packet} = (\text{TaskID}, \text{Objective}, \mathcal{A}_{\text{allowed}}, \mathcal{P}_{\text{prohibited}}, \text{Paths}, \text{Criteria})$$

The BLINK validator enforces:
1. $\mathcal{A}_{\text{allowed}} \subseteq \{\text{read}, \text{propose}, \text{create-candidate}, \text{verify}, \text{classify}\}$
2. $\mathcal{A}_{\text{allowed}} \cap \mathcal{P}_{\text{high-risk}} = \emptyset$
3. $\{\text{activate}, \text{deploy}, \text{publish}, \text{send}, \text{overwrite}\} \subseteq \mathcal{P}_{\text{prohibited}}$
4. Output payload invariant: `execution_authority: False, not_authorization: True`

Deterministic SHA-256 handoff packaging binds the plan to an immutable digest, ensuring that no downstream agent can claim execution authority from an upstream plan.

### 3.4 Out-of-Band Independent Audit (Watchtower Core)
Rather than asking the LLM if its file generation or compilation succeeded, Watchtower runs outside the agent process:
1. **Manifest Validation:** Verifies schema, convergence IDs, and file lists.
2. **Lane Completeness:** Ensures all planned execution lanes emitted outputs.
3. **Unlisted File Detection:** Traverses output directories to detect unauthorized side effects or leaked temporary files.
4. **Cryptographic Hash Agreement:** Recalculates SHA-256 digests of all generated files against declared manifests.
5. **Cross-Lane Independence:** Checks that parallel, isolated agent lanes did not produce conflicting mutations on shared paths.
6. **Residue Detection:** Flags lingering temporary artifacts (`.tmp`, `.bak`, `.env`).

Watchtower returns deterministic verdict enums:
$$\text{Verdict} \in \{\text{PASS}, \text{HOLD}, \text{REVISE}\}$$
The model cannot self-certify when the caller isolates the verifier and independently authenticates the manifest; a `PASS` alone does not establish manifest provenance.

---

## 4. Implementation & Performance

The reference package is implemented in pure Python (requiring `cryptography` and `pydantic`):
* `governed_agent.capability.crypto`: 390 LOC
* `governed_agent.capability.antirollback`: 337 LOC
* `governed_agent.planning.blink`: 218 LOC
* `governed_agent.audit.watchtower`: 213 LOC
* Total reference core: **1,239 LOC**

### 4.1 Verification Overhead
Benchmarked on an AMD / Windows 11 host with Python 3.14:
* **Keypair Generation (RSA-2048):** ~12.4 ms
* **Capability Sealing (RSA-SHA256):** ~0.42 ms
* **Capability Verification:** ~0.08 ms
* **Earlier full test suite (35 unit tests):** **0.84 seconds** total execution time (89% coverage); not the v0.1.3 suite. The v0.1.3 suite passed 63 tests with 90% local coverage.

Compared to typical LLM inference latencies (500 ms – 3,000 ms per turn), the cryptographic verification overhead is **less than 0.1% of the turn duration**, rendering the governance boundary computationally negligible.

---

## 5. Comparative Evaluation

| Feature / Dimension | LangChain / CrewAI | Anthropic MCP | NeMo / Guardrails | Governed Agent |
| :--- | :--- | :--- | :--- | :--- |
| **Execution Authorization** | Ambient tool availability | Server-level permission | Secondary LLM text filter | **Cryptographic RSA-2048 token** |
| **Replay & Rollback Defense** | Context-dependent | Context-dependent | Context-dependent | **Loaded-state sequence checks; external anchor required for durable rollback resistance** |
| **Plan / Execution Separation** | Blended in context | Blended in context | None | **Strict (`execution_authority: False`)** |
| **Audit Mechanism** | Model self-evaluation | None | Model text evaluation | **Out-of-band 6-point verification** |
| **Failure State** | Uncontrolled tool call | Client error / Open | Filter bypass | **Fail-closed (`HOLD`)** |

---

## 6. Applications: Enterprise Automation & Mercenarios AI

The reference code is not qualified as a production security gate. With independently protected keys, state anchors, and a trusted dispatcher/auditor, its primitives may support enterprise automation; the following are architectural examples, not established deployment guarantees:
* **Marketing & Campaign Automation:** Agents can draft copy, analyze market trends, and organize creative assets autonomously, but cannot mutate live ad spend or publish campaigns without cryptographic custodian tokens.
* **Database & Infrastructure Migration:** Schema planning is isolated from migration execution; all produced migration artifacts are verified out-of-band by Watchtower before release.
* **Auditability & Compliance:** Every privileged action produces an immutable 21-field cryptographic receipt containing input hashes, timestamps, and custodian signatures, satisfying enterprise compliance requirements.

---

## 7. Conclusion & Future Work

Prompt-based guardrails are insufficient for high-consequence autonomous AI agents. This reference implementation demonstrates cryptographic capability checks, sequence-checked local pin state, and out-of-band artifact audits under explicit trust assumptions; production security and durable anti-rollback require further independent protections.

Future work includes formalizing Layer 3 (consent-gated case envelopes) and Layer 4 (receipt stores with automated secret sanitization), as well as integrating hardware security modules (HSMs) and RFC 3161 timestamping authorities for enterprise monotonic pinning.

---

## References

1. Dennis, J. B., & Van Horn, E. C. (1966). *Programming Semantics for Multiprogrammed Computations*. Communications of the ACM, 9(3), 143-155.
2. Saltzer, J. H., & Schroeder, M. D. (1975). *The Protection of Information in Computer Systems*. Proceedings of the IEEE, 63(9), 1278-1308.
3. Chase, H. (2022). *LangChain: Building applications with LLMs through composability*.
4. Anthropic. (2024). *Model Context Protocol (MCP) Specification*.
5. Rebedea, T., et al. (2023). *NeMo Guardrails: A Toolkit for Controllable and Safe LLM Applications with Programmable Rails*. NVIDIA.
