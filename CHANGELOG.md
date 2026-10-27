# Changes

## 0.1.4 — release candidate, pending owner approval

Review baseline: v0.1.3, commit `4b6d245281a0506c0462ca5835df17589aefcda4`.

- Consume each verified, exactly bound tool receipt atomically in a shared SQLite store before dispatch. The record survives tool exceptions and process death; unavailable replay storage denies execution. Receipt identity combines the trusted public key's DER fingerprint and the exact signed bytes. No automatic refund or history cleanup is provided.
- Resolve configured replay and pin-authority storage paths once at construction. A tool changing the working directory cannot redirect a relative path into fresh replay history or another authority's older state.
- Freeze the native receipt buffer before parsing, signature verification, request matching and replay hashing. Mutable buffers and overridden bytes methods cannot replace the signed request between those steps.
- Serialize file-backed authority initialization, reads and writes with a shared Windows/POSIX lock, and reload the latest state before acting. Stale writers cannot overwrite newer sequences or another chain's progress. Invalid pin inputs are rejected before state changes.
- Return controlled verification failures for malformed receipts, manifest structures and known malformed artifact paths. Compare JSON context recursively with exact scalar types: `true`, `1` and `1.0` are distinct. Duplicate receipt keys and non-finite context values are rejected.
- Treat oversized JSON integers and artifact resolution loops as controlled audit failures. Honor configured state paths without requiring a home directory; empty environment settings use the documented fallback. A key-only authority store remains blocked until its matching history is restored or an owner approves a separate new authority, preserving the existing key and state.
- Add the prepared development history, maintenance case study and README links. Their retained internal evidence and public verification limits remain distinct.
- Add Windows Python 3.12 to CI alongside Linux Python 3.10–3.13.
- Align package metadata and reported package/server versions at 0.1.4, and include release documentation and the test-isolation fixture in the source distribution.

Local verification: 234 tests passed on Windows, Python 3.12; 92% statement coverage. One real symlink-loop fixture was skipped because this Windows account lacks symlink creation privileges; portable injected-loop regressions passed and Linux CI exercises the real loop. Regression failures were observed before the corresponding corrections. These checks and a bounded separate-context code review do not constitute a comprehensive security audit or production qualification.

Replay protection requires a retained shared database on storage supporting SQLite locking and durable commits. The pin lock coordinates cooperating processes; it does not stop an external writer bypassing that lock. Pin and counter replacements are individually atomic, with interrupted inconsistent pairs rejected, rather than a two-file crash transaction. Full snapshot replay, signing-key custody, trusted manifests and auditor isolation retain the reference implementation's existing limits.

The package metadata, imported package version and planning-server version are aligned at 0.1.4. The proposed tag is `v0.1.4`; no tag or release is created by this preparation. See [release notes and upgrade requirements](docs/releases/v0.1.4.md).
