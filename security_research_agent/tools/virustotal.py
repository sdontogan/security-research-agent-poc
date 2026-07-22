from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from ..indicators import extract_domains
from ..models import ToolEvidence
from .base import ToolContext, ToolRequestError, get_json, unavailable_evidence


class VirusTotalTool:
    name = "lookup_virustotal"
    description = (
        "Retrieve an existing VirusTotal report for a validated public domain. "
        "This tool never submits content for scanning."
    )

    @staticmethod
    def _demo(value: str) -> ToolEvidence:
        return ToolEvidence(
            tool=VirusTotalTool.name,
            subject=value,
            source="VirusTotal demo fixture",
            source_url="https://www.virustotal.com/",
            summary="The offline fixture contains a small number of suspicious signals.",
            data={
                "domain": value,
                "malicious": 2,
                "suspicious": 1,
                "harmless": 61,
                "undetected": 8,
                "reputation": -3,
                "fixture": True,
            },
            warnings=["This is synthetic demonstration data, not a live VirusTotal report."],
        )

    def run(self, arguments: dict[str, Any], context: ToolContext) -> ToolEvidence:
        raw_value = str(arguments.get("domain", "")).strip()
        matches = extract_domains(raw_value)
        if len(matches) != 1 or matches[0].value != raw_value.lower():
            return unavailable_evidence(
                self.name,
                raw_value[:253],
                "VirusTotal requires one validated public domain.",
            )
        value = matches[0].value
        if context.demo_mode:
            if value != "example.com":
                return unavailable_evidence(
                    self.name,
                    value,
                    "The offline VirusTotal fixture is available for example.com only.",
                )
            return self._demo(value)
        if not context.api_keys.virustotal:
            return unavailable_evidence(
                self.name,
                value,
                "Add a VirusTotal API key in Connections to use this lookup.",
            )

        try:
            payload = get_json(
                f"https://www.virustotal.com/api/v3/domains/{value}",
                timeout_seconds=context.timeout_seconds,
                headers={"x-apikey": context.api_keys.virustotal},
            )
        except ToolRequestError as exc:
            return unavailable_evidence(self.name, value, str(exc))

        try:
            data = payload.get("data", {})
            if not isinstance(data, dict):
                raise TypeError
            attributes = data.get("attributes", {})
            if not isinstance(attributes, dict):
                raise TypeError
            stats = attributes.get("last_analysis_stats", {})
            tags = attributes.get("tags") or []
            categories = attributes.get("categories") or {}
            if not isinstance(stats, dict) or not isinstance(tags, list):
                raise TypeError
            if not isinstance(categories, dict):
                raise TypeError

            counts = {
                name: int(stats.get(name, 0) or 0)
                for name in ("malicious", "suspicious", "harmless", "undetected")
            }
            if any(value < 0 for value in counts.values()):
                raise ValueError

            last_analysis = attributes.get("last_analysis_date")
            if isinstance(last_analysis, (int, float)):
                last_analysis = datetime.fromtimestamp(last_analysis, tz=UTC).isoformat()
            elif last_analysis is not None:
                last_analysis = str(last_analysis)[:100]
        except (OSError, OverflowError, TypeError, ValueError):
            return unavailable_evidence(
                self.name, value, "VirusTotal returned data in an unexpected format."
            )

        malicious = counts["malicious"]
        suspicious = counts["suspicious"]
        return ToolEvidence(
            tool=self.name,
            subject=value,
            source="VirusTotal",
            source_url=f"https://www.virustotal.com/gui/domain/{value}",
            summary=(
                f"VirusTotal reports {malicious} malicious and {suspicious} suspicious detections."
            ),
            data={
                "domain": value,
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": counts["harmless"],
                "undetected": counts["undetected"],
                "reputation": attributes.get("reputation"),
                "last_analysis_date": last_analysis,
                "tags": [str(item)[:100] for item in tags[:10]],
                "categories": {
                    str(key)[:100]: str(category)[:200]
                    for key, category in list(categories.items())[:25]
                },
            },
        )
