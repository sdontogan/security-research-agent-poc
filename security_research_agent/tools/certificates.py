from __future__ import annotations

from typing import Any

from ..indicators import extract_domains
from ..models import ToolEvidence
from .base import ToolContext, ToolRequestError, get_json_value, unavailable_evidence


class CertificateTransparencyTool:
    name = "lookup_certificates"
    description = "Retrieve bounded existing certificate issuances from Certificate Transparency."

    def run(self, arguments: dict[str, Any], context: ToolContext) -> ToolEvidence:
        raw_value = str(arguments.get("domain", "")).strip()
        matches = extract_domains(raw_value)
        if len(matches) != 1 or matches[0].value != raw_value.lower():
            return unavailable_evidence(
                self.name, raw_value[:253], "Certificate lookup requires one public domain."
            )
        domain = matches[0].value
        if context.demo_mode:
            return ToolEvidence(
                tool=self.name,
                subject=domain,
                source="Certificate Transparency demo fixture",
                source_url="https://certificate.transparency.dev/",
                summary="The fixture contains a small, established certificate history.",
                data={
                    "issuance_count": 3,
                    "first_observed": "2024-01-01T00:00:00Z",
                    "last_observed": "2026-01-01T00:00:00Z",
                    "issuers": ["Demo CA"],
                    "fixture": True,
                },
                warnings=["Synthetic demonstration data; not a live certificate response."],
            )
        try:
            payload = get_json_value(
                "https://api.certspotter.com/v1/issuances",
                timeout_seconds=context.timeout_seconds,
                params={
                    "domain": domain,
                    "include_subdomains": "true",
                    "expand": "dns_names,issuer",
                    "match_wildcards": "true",
                },
                max_bytes=750_000,
            )
        except ToolRequestError:
            return unavailable_evidence(
                self.name, domain, "Certificate Transparency data was unavailable."
            )
        if not isinstance(payload, list):
            return unavailable_evidence(
                self.name, domain, "Certificate Transparency returned an unexpected format."
            )
        rows = [row for row in payload[:100] if isinstance(row, dict)]
        not_before = sorted(
            str(row["not_before"])[:50] for row in rows if isinstance(row.get("not_before"), str)
        )
        issuers = []
        for row in rows:
            issuer = row.get("issuer")
            if isinstance(issuer, dict) and issuer.get("name"):
                value = str(issuer["name"])[:160]
                if value not in issuers:
                    issuers.append(value)
        return ToolEvidence(
            tool=self.name,
            subject=domain,
            source="Certificate Transparency",
            source_url="https://certificate.transparency.dev/",
            summary=f"Certificate Transparency returned {len(rows)} bounded issuances.",
            data={
                "issuance_count": len(rows),
                "first_observed": not_before[0] if not_before else None,
                "last_observed": not_before[-1] if not_before else None,
                "issuers": issuers[:10],
            },
        )
