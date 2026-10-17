# Contributing to Governed Agent

Thank you for your interest in contributing to Governed Agent! We welcome contributions that maintain the mathematical rigor, determinism, and minimal overhead of the core primitives.

---

## Architectural Principles

Before submitting a Pull Request, please ensure your changes adhere to our core invariants:

1. **Deterministic Security:** Security boundaries must not rely on prompt phrasing, heuristic text filters, or probabilistic model checks.
2. **Minimal Dependencies:** The core package relies solely on `cryptography` and `pydantic`. Avoid adding heavy third-party dependencies to the core runtime.
3. **Plan != Execution Authority:** Planning and task decomposition must never grant or imply execution authority.
4. **Out-of-Band Audit:** Work outputs must be verifiable by independent scripts or external inspectors without model self-certification.

---

## Development Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/jtevesnz-sys/governed-agent.git
   cd governed-agent
   ```

2. **Create and activate a virtual environment:**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install editable package with test dependencies:**
   ```bash
   pip install -e ".[test]"
   ```

4. **Run test suite:**
   ```bash
   pytest -v --tb=short
   ```

---

## Pull Request Guidelines

* All new primitives or modifications must include unit tests with clear assertions.
* Maintain clean error-handling: unexpected or invalid capabilities must **fail closed** (`HOLD` status or specific exceptions).
* Do not commit environment files, private credentials, or internal file paths.
* Keep pull requests small and focused on a single architectural improvement.
