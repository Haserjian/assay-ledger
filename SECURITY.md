# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in the Assay Public Ledger, please report it responsibly.

**Do not open a public issue.**

Email: [security@assay-ledger] or open a private security advisory on this repository.

We will acknowledge within 48 hours and aim to resolve critical issues within 7 days.

## Scope

- Workflow injection (command injection via workflow inputs)
- XSS or content injection in the GitHub Pages site
- Append-only invariant bypass (modifying or deleting existing ledger entries)
- Schema validation bypass (malformed entries passing validation)

## Out of Scope

- The ledger records attestation *pointers*, not evidence. A valid ledger entry does not guarantee the underlying evidence was honestly created.
- Denial of service via high-volume workflow_dispatch (rate-limited by GitHub)
