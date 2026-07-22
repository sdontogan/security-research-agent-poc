---
title: AI Security Research Agent POC
eyebrow: Agentic AI / Security research
summary: I built a read-only AI agent that researches one domain, shows its sources, and explains how it reached a verdict.
type: demo
featured: true
order: 1
technologies:
  - Python
  - Streamlit
  - Cloudflare Pages Functions
  - Passive DNS
  - VirusTotal API v3
  - Turnstile
  - TypeScript
  - Evidence-based scoring
challenges:
  - Keeping the agent useful without giving it arbitrary browsing, scanning, or execution access.
  - Accepting an optional VirusTotal key without storing it.
  - Explaining uncertainty without implying that a domain is safe.
results:
  - Researches validated public domains with DNS, RDAP, and Certificate Transparency data.
  - Supports optional, read-only VirusTotal enrichment with a visitor-supplied key.
  - Returns an LLM verdict with visible evidence, uncertainties, and confidence limits.
diagram: research-agent
demo: domain-research
sourceUrl: https://github.com/sdontogan/security-research-agent-poc
liveNote: Live agent — queries public DNS, registration, and certificate data in real time; VirusTotal enrichment is optional.
---

## Why I built it

I wanted to see how useful a security research agent could be without giving it broad access. No arbitrary browsing. No active scanning. No shell. Just a small set of passive sources and a result that a person can inspect.

The live demo above researches one public domain at a time. It shows what came back, what was missing, and how those facts shaped the verdict.

## How it works

1. The app validates one bare public domain.
2. It checks DNS, registration data, and Certificate Transparency. A visitor can optionally add an existing VirusTotal report with their own key.
3. The results are normalized before the LLM sees them.
4. Workers AI compares the evidence and returns a structured verdict.
5. Code-based guardrails cap confidence, preserve missing sources, and block unsafe claims.

The [public GitHub repository](https://github.com/sdontogan/security-research-agent-poc) also contains the original Python and Streamlit workbench.

## What it can—and cannot—do

It can:

- Check bounded DNS records.
- Read public registration and certificate records.
- Retrieve an existing VirusTotal domain report when a visitor supplies a key.
- Explain a verdict using only the returned evidence.

It cannot:

- Visit the submitted website.
- Scan a domain or submit it to a third party.
- Choose a different API host.
- Run commands or write to another system.
- Turn one request into a broader investigation.

## How I handle API keys

The LLM does not need a visitor API key; it runs through Cloudflare Workers AI. A VirusTotal key is optional. If supplied, it is used for that request only, sent to one fixed read-only endpoint, and cleared from the form afterward. It is not stored in browser storage, analytics, chat history, or the response.

Visitors should still use a limited, revocable key and follow VirusTotal’s terms.

## How I keep the verdict honest

The LLM can return **likely malicious**, **suspicious**, **no current threat evidence**, or **inconclusive**. It cannot call a domain safe.

Deterministic rules sit around the model. Reputation detections cannot be minimized. Confidence is capped when reputation data is missing. If most sources fail, the verdict becomes inconclusive.

This is still a proof of concept, not a production risk score. I want the limits to be as visible as the answer.

## What I would improve next

- Add dedicated rate limits and privacy-safe telemetry.
- Improve internationalized-domain handling.
- Add contract tests for upstream source changes.
- Evaluate evidence accuracy separately from explanation quality.
