# Ecosystem Submissions & Directory Registry Kit

This guide contains pre-formatted submission snippets, links, and text for listing `governed-agent` in the leading AI agent directories, curated awesome-lists, and developer catalogs.

---

## 1. Curated "Awesome" Repositories (GitHub PRs)

### A. `awesome-ai-agents` / `awesome-llm-agents`
* **Target Repositories:**
  * `e2b-dev/awesome-ai-agents`
  * `hyperspaceorg/awesome-llm-agents`
  * `ashishpatel26/Awesome-AI-Agents`
* **Target Category:** `Security & Governance` or `Agent Frameworks / Infrastructure`
* **Markdown Snippet to Insert:**
  ```markdown
  - [Governed Agent](https://github.com/jtevesnz-sys/governed-agent) - Cryptographic capability sealing (RSA-SHA256), scope-bounded planning, and out-of-band audit for autonomous LLM agent execution.
  ```

### B. `awesome-mcp` (Model Context Protocol Ecosystem)
* **Target Repository:** `punkpeye/awesome-mcp-servers` or `wong2/awesome-mcp-servers`
* **Target Category:** `Security / Governance / Utilities`
* **Markdown Snippet to Insert:**
  ```markdown
  - [Governed Agent](https://github.com/jtevesnz-sys/governed-agent) - Capability-based security and out-of-band audit verifier for MCP tool execution boundaries.
  ```

---

## 2. Agent Catalog & Tool Platforms

### A. AgentSkills.io / Tool Registry
* **Project Name:** Governed Agent
* **Short Description:** Cryptographic capability tokens, monotonic anti-rollback state, and independent audit verifier for autonomous LLM tool calling.
* **Tags / Topics:** `agent-security`, `capability-security`, `mcp`, `python`, `audit`, `llm-governance`
* **Repository URL:** `https://github.com/jtevesnz-sys/governed-agent`
* **Documentation URL:** `https://github.com/jtevesnz-sys/governed-agent/blob/main/WHITE_PAPER.md`

### B. PyPI (Python Package Index)
* **Package Name:** `governed-agent`
* **Current Version:** `0.1.0`
* **Distribution Files Ready:**
  * `dist/governed_agent-0.1.0-py3-none-any.whl`
  * `dist/governed_agent-0.1.0.tar.gz`
* **Upload Command:**
  ```bash
  twine upload dist/*
  ```
  *(Requires your PyPI API token `__token__`)*

---

## 3. Academic & Technical Preprint Submissions

### A. arXiv (Computer Science — Artificial Intelligence / Cryptography and Security)
* **Category:** `cs.AI` (Artificial Intelligence) or `cs.CR` (Cryptography and Security)
* **Title:** Governed Agent: Cryptographic Capability Sealing and Out-of-Band Audit for Autonomous LLM Agents
* **Author:** `jtevesnz-sys`
* **Source LaTeX File:** `paper/governed_agent_paper.tex` (Standard article class, UTF-8, fully self-contained without external dependencies)
* **Abstract:**
  > Autonomous Large Language Model (LLM) agent architectures operate predominantly under ambient authority. When tools are exposed to an agent runtime, tool invocation decisions depend upon probabilistic system prompts or secondary text classification guardrails. Under adversarial prompt injection, jailbreaking, or semantic drift, these linguistic boundaries fail, permitting unauthorized mutations. Furthermore, prevailing designs encourage models to evaluate the validity of their own output, introducing acute self-certification hazards. We present Governed Agent, a deterministic security architecture for LLM agent tool dispatch based on classical capability-based operating systems. Governed Agent enforces three architectural invariants: (1) Cryptographic Capability Sealing (KCAP), requiring unforgeable RSA-SHA256 tokens and monotonic anti-rollback sequence anchors before tool invocation; (2) Separation of Planning and Execution Authority (BLINK), enforcing that multi-turn decomposition yields strictly unprivileged task packets; and (3) Out-of-Band Independent Audit (Watchtower), decoupling verification from the generating model through external multi-point manifest inspections emitting non-negotiable PASS, HOLD, or REVISE verdicts. Benchmarks demonstrate that full capability verification introduces sub-millisecond overhead (<0.5 ms per turn), proving that mathematical security primitives can enforce hard operational boundaries on autonomous models without sacrificing runtime performance.
