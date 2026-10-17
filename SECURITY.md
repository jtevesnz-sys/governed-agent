# Security Policy

## Reporting a Vulnerability

Security and cryptographic integrity are foundational to Governed Agent. If you discover a security vulnerability, capability bypass, or flaw in the verification routines, please report it responsibly.

### How to Report
Please report security issues privately via GitHub Security Advisories:
* Navigate to the repository's **Security** tab: [https://github.com/jtevesnz-sys/governed-agent/security](https://github.com/jtevesnz-sys/governed-agent/security)
* Click **"Report a vulnerability"** to open a private advisory.

Please do not open a public issue for an unpatched security vulnerability.

### Supported Versions
Only the latest release (`v0.1.x`) receives active security patches.

### Scope
In-scope security topics:
* Canonical JSON serialization bypasses leading to signature forgery.
* Monotonic sequence counter manipulation or replay vulnerabilities.
* Context tampering in capability token verification.
* Path traversal or residue leakage in out-of-band audit routines.
