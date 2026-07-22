from __future__ import annotations

from .models import Priority, ToolEvidence


def assess_priority(evidence: list[ToolEvidence]) -> tuple[Priority, list[str]]:
    successful = [item for item in evidence if item.status == "success"]
    if not successful:
        return Priority.UNKNOWN, ["No usable evidence was returned."]

    try:
        malicious = max(
            (int(item.data.get("malicious", 0) or 0) for item in successful),
            default=0,
        )
        suspicious = max(
            (int(item.data.get("suspicious", 0) or 0) for item in successful),
            default=0,
        )
    except (TypeError, ValueError):
        return Priority.UNKNOWN, ["The returned detection counts were not usable."]
    if malicious >= 5:
        return Priority.HIGH, [f"VirusTotal reports {malicious} malicious detections."]
    if malicious >= 1 or suspicious >= 1:
        return Priority.MEDIUM, [
            f"VirusTotal reports {malicious} malicious and {suspicious} suspicious detections."
        ]
    return Priority.UNKNOWN, [
        "No malicious detections were returned; that is not proof the indicator is safe."
    ]
