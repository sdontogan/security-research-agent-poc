from __future__ import annotations

from typing import Any

from ..indicators import extract_domains
from ..models import ToolEvidence
from .base import ToolContext, ToolRequestError, get_json, unavailable_evidence


class DnsTool:
    name = "lookup_dns"
    description = "Retrieve bounded passive A, AAAA, MX, and NS answers from Cloudflare DNS."

    def run(self, arguments: dict[str, Any], context: ToolContext) -> ToolEvidence:
        raw_value = str(arguments.get("domain", "")).strip()
        matches = extract_domains(raw_value)
        if len(matches) != 1 or matches[0].value != raw_value.lower():
            return unavailable_evidence(
                self.name, raw_value[:253], "DNS requires one public domain."
            )
        domain = matches[0].value
        if context.demo_mode:
            return ToolEvidence(
                tool=self.name,
                subject=domain,
                source="Cloudflare DNS demo fixture",
                source_url="https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/",
                summary="The fixture contains bounded address, mail, and nameserver records.",
                data={
                    "records": [
                        {"type": "A", "value": "192.0.2.1", "ttl": 300},
                        {"type": "MX", "value": "0 .", "ttl": 300},
                        {"type": "NS", "value": "a.iana-servers.net.", "ttl": 3600},
                    ],
                    "fixture": True,
                },
                warnings=["Synthetic demonstration data; not a live DNS response."],
            )

        records: list[dict[str, Any]] = []
        unavailable: list[str] = []
        for record_type in ("A", "AAAA", "MX", "NS"):
            try:
                payload = get_json(
                    "https://cloudflare-dns.com/dns-query",
                    timeout_seconds=context.timeout_seconds,
                    headers={"Accept": "application/dns-json"},
                    params={"name": domain, "type": record_type},
                    max_bytes=200_000,
                )
                answers = payload.get("Answer", [])
                if not isinstance(answers, list):
                    raise ToolRequestError("The DNS answer had an unexpected shape.")
                for answer in answers[:8]:
                    if not isinstance(answer, dict) or not isinstance(answer.get("data"), str):
                        continue
                    records.append(
                        {
                            "type": record_type,
                            "value": answer["data"][:300],
                            "ttl": max(0, min(int(answer.get("TTL", 0) or 0), 2_592_000)),
                        }
                    )
            except (ToolRequestError, TypeError, ValueError):
                unavailable.append(record_type)

        if not records and len(unavailable) == 4:
            return unavailable_evidence(self.name, domain, "Passive DNS sources were unavailable.")
        return ToolEvidence(
            tool=self.name,
            subject=domain,
            source="Cloudflare DNS",
            source_url=f"https://radar.cloudflare.com/domains/domain/{domain}",
            summary=f"Passive DNS returned {len(records)} bounded records.",
            data={"records": records[:24], "unavailable_types": unavailable},
            warnings=[f"Unavailable record types: {', '.join(unavailable)}"] if unavailable else [],
        )
