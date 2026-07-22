# Domain Research Agent

[![tests](https://github.com/sdontogan/security-research-agent-poc/actions/workflows/test.yml/badge.svg)](https://github.com/sdontogan/security-research-agent-poc/actions/workflows/test.yml)
[![live web POC](https://img.shields.io/badge/live_web_POC-beyond--features.com-176b67)](https://beyond-features.com/projects/ai-security-research-agent-poc/#live-demo)

This public repository is the source of truth for the Python and Streamlit research
workbench. The portfolio also includes a smaller
[Cloudflare web adaptation](https://beyond-features.com/projects/ai-security-research-agent-poc/#live-demo)
that preserves the same read-only boundaries for a browser-based demonstration.

I built this small project to explore a narrow question: how can an agent explain
domain-reputation data without being given broad access to a machine or network?

The result is a local, read-only workbench for one public domain at a time. It validates
the domain in code, retrieves an existing VirusTotal domain report, applies a transparent
priority rule, and explains what the evidence does—and does not—show.

This is intentionally a proof of concept. It is not a scanner, a penetration-testing
system, or a production risk engine.

## Repository and web demo

Changes to the local Python agent appear in this repository after they are committed and
pushed to `main`. The portfolio links here for the latest source. The web POC is not a
direct import of the Streamlit application: it runs on Astro and Cloudflare Pages
Functions, so changes that affect shared behavior should be deliberately ported and
tested in both runtimes.

## What works

- A local Streamlit chat interface focused only on public domains
- VirusTotal and optional OpenAI keys from the sidebar or a `.env` file
- Existing VirusTotal domain-report lookups without submitting content for scanning
- Optional OpenAI interpretation after deterministic validation and scoring
- A deterministic report when no OpenAI key is configured
- An offline `example.com` fixture that requires no keys
- A visible evidence and tool trace for each lookup

URLs, IP addresses, CVE identifiers, hashes, email addresses, internal domains, and
multiple-domain requests are rejected before any connector or model call.

## Run it locally

Python 3.11 or newer is required.

```bash
cd security-research-agent-poc
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
streamlit run app.py
```

Open the address printed by Streamlit, normally `http://127.0.0.1:8501`. The checked-in
configuration binds the app to the local loopback interface; this POC is not intended to
be exposed directly to a network.

For a no-key walkthrough, turn on **Offline demo mode** and enter:

```text
Check example.com
```

The fixture is deliberately limited to `example.com` so synthetic evidence cannot be
attached to an arbitrary domain.

## Connections

Keys entered in the sidebar remain in server-process memory for the current local app
session and are not written to disk. For regular local use, copy `.env.example` to `.env`.

| Variable | Required | Purpose |
| --- | --- | --- |
| `VIRUSTOTAL_API_KEY` | For live lookups | Retrieves an existing domain report |
| `OPENAI_API_KEY` | No | Adds a short interpretation after the lookup |
| `OPENAI_MODEL` | No | Selects the model; defaults to `gpt-5-mini` |

Without a VirusTotal key, live lookups return an unavailable result rather than making an
unsupported claim. Offline demo mode remains available without any keys.

When OpenAI is enabled, only the normalized domain and bounded evidence for the current
request are sent to OpenAI with Responses application-state storage disabled
(`store=False`). OpenAI API traffic remains subject to its
[data controls and abuse-monitoring policy](https://developers.openai.com/api/docs/guides/your-data#default-usage-policies-by-endpoint).
VirusTotal receives the normalized public domain. Chat history and API keys are not sent
to either service.

## How a request moves through the app

```text
chat message
    -> reject non-domain and mixed input shapes
    -> normalize exactly one public domain
    -> retrieve its existing VirusTotal domain report
    -> bound and normalize the evidence
    -> apply a transparent priority rule
    -> optionally ask OpenAI for a short interpretation
    -> display the deterministic assessment and evidence trace
```

The model cannot select another endpoint, execute a command, fetch an arbitrary URL, or
change an external system.

## Data source

- [VirusTotal API v3](https://docs.virustotal.com/reference/overview)

The connector uses only the VirusTotal `/domains/{domain}` report endpoint. It does not
upload files or submit URLs for scanning.

## Adding another domain source

Each integration is a small adapter in `security_research_agent/tools/` that accepts a
validated domain and returns a `ToolEvidence` record. To add another domain-reputation
source:

1. Use one fixed HTTPS API host and a read-only report endpoint.
2. Validate the normalized domain again inside the adapter.
3. Bound and normalize every upstream field.
4. Register the adapter explicitly in `security_research_agent/tools/__init__.py`.
5. Add fixture, malformed-response, no-key, and unsupported-input tests.

Support for active scanners or other indicator types is deliberately outside this POC's
scope.

## Demonstration priority rules

Five or more malicious VirusTotal detections are **high** priority. One or more malicious
or suspicious detections are **medium**. Zero detections remain **unknown**, because no
detections is not proof that a domain is safe.

These thresholds are a teaching aid, not a production-grade risk measurement.

## Tests

The suite uses local fixtures and does not require secrets or live API access.

```bash
pip install -r requirements-dev.txt
ruff check .
pytest
```

## Limits and intended use

- Research only domains you are authorized to investigate.
- Verify important conclusions against the linked source report.
- Do not treat the result as a substitute for professional incident response.
- Never put real API keys in issues, screenshots, fixtures, or commits.

See [ACCEPTABLE_USE.md](ACCEPTABLE_USE.md) and [SECURITY.md](SECURITY.md) for the project
boundaries and reporting process.
