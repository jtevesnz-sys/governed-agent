## Pull Request Checklist

Before submitting this pull request, please verify:

- [ ] My code adheres to the project's architectural invariants:
  - [ ] **Deterministic Security:** Does not rely on prompt phrasing or probabilistic text classifiers.
  - [ ] **Plan != Authority:** Planning logic does not grant execution authority (`execution_authority: False`).
  - [ ] **Minimal Dependencies:** Does not introduce heavy third-party runtime dependencies beyond `cryptography` and `pydantic`.
- [ ] I have added unit tests for new functionality in `tests/`.
- [ ] All unit tests pass locally (`pytest -v`).
- [ ] No internal credentials, secrets, or local file system paths are included.
- [ ] Relevant documentation or examples have been updated.

---

### Description
<!-- Provide a brief description of the changes introduced by this PR -->

### Related Issues
<!-- Link to any related issues (e.g. fixes #12) -->
