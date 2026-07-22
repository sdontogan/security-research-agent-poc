from __future__ import annotations

from typing import Any

from ..indicators import extract_domains
from ..models import ToolEvidence
from .base import ToolContext, ToolRequestError, get_json, unavailable_evidence


class RdapTool:
    name = "lookup_rdap"
    description = "Retrieve passive structured registration information through RDAP."

    def run(self, arguments: dict[str, Any], context: ToolContext) -> ToolEvidence:
        raw_value = str(arguments.get("domain", "")).strip()
        matches = extract_domains(raw_value)
        if len(matches) != 1 or matches[0].value != raw_value.lower():
            return unavailable_evidence(
                self.name, raw_value[:253], "RDAP requires one public domain."
            )
        domain = matches[0].value
        if context.demo_mode:
            return ToolEvidence(
                tool=self.name,
                subject=domain,
                source="RDAP demo fixture",
                source_url="https://www.icann.org/rdap/",
                summary="The fixture represents a long-established reserved example domain.",
                data={
                    "registrar": "RESERVED-Internet Assigned Numbers Authority",
                    "registration_date": "1995-08-14T04:00:00Z",
                    "expiration_date": None,
                    "statuses": ["client delete prohibited"],
                    "fixture": True,
                },
                warnings=["Synthetic demonstration data; not a live RDAP response."],
            )
        try:
            payload = get_json(
                f"https://rdap.org/domain/{domain}",
                timeout_seconds=context.timeout_seconds,
                max_bytes=500_000,
                follow_redirects=True,
            )
        except ToolRequestError:
            return unavailable_evidence(
                self.name, domain, "RDAP registration data was unavailable."
            )

        events = payload.get("events", [])
        entities = payload.get("entities", [])
        statuses = payload.get("status", [])
        registration_date = None
        expiration_date = None
        if isinstance(events, list):
            for event in events[:20]:
                if not isinstance(event, dict) or not isinstance(event.get("eventDate"), str):
                    continue
                action = str(event.get("eventAction", "")).lower()
                if action in {"registration", "registered"}:
                    registration_date = event["eventDate"][:50]
                elif action in {"expiration", "expiry"}:
                    expiration_date = event["eventDate"][:50]
        registrar = None
        if isinstance(entities, list):
            for entity in entities[:20]:
                if not isinstance(entity, dict):
                    continue
                roles = entity.get("roles", [])
                if isinstance(roles, list) and "registrar" in roles:
                    registrar = str(entity.get("handle", "Unknown"))[:160]
                    break
        normalized_statuses = (
            [str(value)[:120] for value in statuses[:15]] if isinstance(statuses, list) else []
        )
        return ToolEvidence(
            tool=self.name,
            subject=domain,
            source="RDAP registration data",
            source_url=f"https://lookup.icann.org/en/lookup?name={domain}",
            summary=(
                "RDAP returned registration metadata"
                + (f" dating to {registration_date[:10]}" if registration_date else "")
                + "."
            ),
            data={
                "registrar": registrar,
                "registration_date": registration_date,
                "expiration_date": expiration_date,
                "statuses": normalized_statuses,
            },
        )
