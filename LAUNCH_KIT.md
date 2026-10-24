# Governed Agent: Launch Announcement & Social Distribution Kit

This kit contains draft technical posts for Governed Agent. For v0.1.3, describe it only as a reference implementation: file-backed state can be rolled back by restoring a complete older snapshot, the default key is co-located with that state, and Watchtower does not authenticate manifest provenance. Performance figures below come from an earlier revision and have not been rerun for v0.1.3. Review each post before publishing; this kit is not a publication receipt.

---

## 1. Hacker News ("Show HN")

**Title:** Show HN: Governed Agent – Cryptographic Capability Sealing and Out-of-Band Audit for LLMs

**Link:** https://github.com/jtevesnz-sys/governed-agent

**Text Body:**

Hey HN,

Most autonomous agent setups (LangChain, CrewAI, AutoGen, and tool-calling models) operate under ambient authority: if an agent is granted a tool (database writes, terminal execution, API mutations), it can call it whenever the model emits that tool call.

Safety guardrails today are predominantly probabilistic: system prompts ("please don't delete files") or secondary LLMs checking outputs (NeMo, Llama Guard). If prompt injection or context drift occurs, the probabilistic filter fails and the agent executes the tool anyway. Even worse, agents are frequently prompted to verify their own outputs ("did this pass?"), letting models grade their own homework.

We built and open-sourced **Governed Agent** to replace prompt-based safety with classical capability-based security (Dennis & Van Horn, 1966) and separation of duties:

1. **Cryptographic Capability Sealing (KCAP):** Mutating tools cannot execute without an RSA-2048 / SHA-256 digital capability token signed by a custodian key. Tokens are bound to exact task IDs, execution contexts, and expiry.
2. **Sequence-Checked Pins:** The bundled file-backed authority checks against loaded state. It does not contain an external monotonic anchor, so full valid snapshot replay is possible; keep the key separately and add an independent anchor before production security-gate use.
3. **Plan != Authority (BLINK):** The planning layer generates hash-bound task packets where execution authority is strictly withheld (`execution_authority: False`). A model that decomposes a task cannot grant itself authority to execute it.
4. **Out-of-Band Audit (Watchtower):** An independently deployed verifier checks generated files against a caller-supplied manifest (structure, lanes, hashes, collisions, and residue). The caller must authenticate manifest provenance separately.

The core reference package is ~1,240 lines of pure Python (`cryptography` + `pydantic`). Verification overhead is <0.5ms per turn—negligible compared to LLM latency.

It is designed as a focused Tier 1 release: roughly 1,200 lines covering capability sealing, scope-bound planning, and independent audit. It comes from a broader private engineering effort of roughly 20,000 lines spanning our research and agent operations. We are keeping the broader operating system private for continued development while making the core governance architecture available to inspect and build on.

Repo: https://github.com/jtevesnz-sys/governed-agent  
Whitepaper / Architecture: https://github.com/jtevesnz-sys/governed-agent/blob/main/WHITE_PAPER.md

Feedback, critique, and issues on the capability token schema are welcome.

---

## 2. X / Twitter (Technical Thread)

**Tweet 1 (Hook):**
Prompt-based agent guardrails are fundamentally broken. 

Telling an LLM "do not delete tables" or using a second LLM to filter text fails under prompt injection and context drift.

Today we're open-sourcing Governed Agent: cryptographic capability tokens for autonomous AI agents. 🧵👇
https://github.com/jtevesnz-sys/governed-agent

**Tweet 2 (The Core Problem):**
Current agent frameworks run on ambient authority. If an agent has a tool, it can invoke it at will. And models routinely self-certify their own work.

If you wouldn't give a junior dev raw database admin rights based on "promising to behave", why do we give it to an LLM?

**Tweet 3 (The Solution: KCAP):**
Governed Agent brings 1960s operating system capability security to LLMs:

🔑 **Cryptographic Sealing:** Tools require RSA-SHA256 capability tokens bound to exact task contexts.
🔒 **Sequence Checks:** Pins increase against loaded state ($Seq_{n+1} > Seq_n$); full older-state replay requires an external anchor to detect.

**Tweet 4 (Separation of Duties):**
⚡ **Plan != Authority:** Planning agents output structured task packets with `execution_authority: False`. Planning work does not authorize executing it.
🛡️ **Out-of-Band Audit (Watchtower):** Manifests and file diffs are audited outside the LLM loop. No model self-certification.

**Tweet 5 (Open Source & Fast):**
Pure Python, zero bloat (~1,350 LOC), 63 local unit tests (90% coverage) in v0.1.3, <0.5ms verification overhead per turn.

Star the repo and read the whitepaper:
GitHub: https://github.com/jtevesnz-sys/governed-agent
Paper: https://github.com/jtevesnz-sys/governed-agent/blob/main/WHITE_PAPER.md

---

## 3. LinkedIn (Enterprise & Architecture Positioning)

**Heading:** Why Enterprise AI Automation Needs Cryptographic Governance, Not Just Prompt Guardrails

Every enterprise deploying autonomous AI agents is wrestling with the same critical question: *How do we guarantee an autonomous agent cannot execute unauthorized actions if prompt-injected or drifting?*

Prompt-based guardrails ("please do not delete customer records") and secondary LLM text filters are probabilistic. In production systems with access to databases, APIs, or infrastructure, probabilistic controls are a compliance liability.

At Mercenarios AI, we have open-sourced **Governed Agent**—an architectural framework that replaces prompt-based compliance with deterministic, capability-based security:

🔹 **Cryptographic Capability Tokens:** Tools cannot execute without RSA-SHA256 signed tokens bound to specific task envelopes and expiry windows.
🔹 **Loaded-State Sequence Checks:** File-backed counters detect partial state inconsistency, not whole-snapshot rollback. Production use requires independent monotonic storage and key custody.
🔹 **Separation of Planning and Authority:** Decomposing a workflow generates immutable task packets where execution authority is strictly withheld (`execution_authority: False`).
🔹 **Out-of-Band Auditing:** When deployed independently of the generating model, Watchtower checks artifacts against a caller-supplied manifest; the caller must authenticate the manifest separately.

The reference implementation is live on GitHub:
👉 Repository: https://github.com/jtevesnz-sys/governed-agent
👉 Technical Whitepaper: https://github.com/jtevesnz-sys/governed-agent/blob/main/WHITE_PAPER.md

If you are designing high-reliability agent workflows for enterprise automation, we'd welcome your thoughts on capability-based agent control.

#ArtificialIntelligence #AgenticAI #Cybersecurity #SoftwareArchitecture #EnterpriseAI #Python
