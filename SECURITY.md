# Security policy

## Supported version

This repository is an early proof of concept. Security fixes are applied to the current
`main` branch.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting feature rather than opening a public
issue. Include the affected file or endpoint, reproduction steps, expected impact, and
any suggested mitigation. Do not include working credentials or private customer data.

## Security boundaries

The project is designed around these invariants:

- Tools are read-only and use fixed upstream API hosts.
- A model cannot execute a shell command or arbitrary HTTP request.
- Only one normalized public domain from the current message can reach a connector.
- URLs, IP addresses, CVEs, hashes, email addresses, and internal domains are rejected.
- Keys are not included in prompts, tool results, or normal logs.
- File upload and active scanning are not implemented.
- Every run selects one connector from a fixed domain-only plan.

If a contribution changes one of these boundaries, it should include a focused threat
analysis and tests for the new behavior.
