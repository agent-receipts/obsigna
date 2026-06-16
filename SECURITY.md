# Security Policy

## Supported Versions

Security fixes are applied to the latest release of each component. We do not backport fixes to older versions.

## Reporting a Vulnerability

**Do not report security vulnerabilities through public GitHub issues.**

Instead, please use GitHub's **Report a vulnerability** feature on this repository:
[Report a vulnerability](https://github.com/agent-receipts/obsigna/security/advisories/new)

Include as much detail as possible: description, steps to reproduce, impact assessment, and any suggested fix.

## Scope

This policy covers the protocol specification, all SDK implementations (Go, TypeScript, Python), and the MCP proxy. Security reports for this project include:

- Cryptographic weaknesses in receipt signing or verification
- Hash chain integrity bypasses
- Key material leakage (private keys exposed via logs, tests, or store)
- MCP proxy security (policy bypass, data leakage, redaction failures)
- Injection attacks through tool parameters or taxonomy config

## Disclosure Policy

- Reports are triaged within 48 hours
- Fixes are coordinated with the reporter before public disclosure
- Reporters are credited in release notes unless they prefer anonymity
