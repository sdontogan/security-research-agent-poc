from __future__ import annotations

from .contracts import load_json
from .models import Priority, ToolEvidence


def assess_priority(evidence: list[ToolEvidence]) -> tuple[Priority, list[str]]:
    thresholds = load_json("agent-policy.json")["priority_thresholds"]
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
    if malicious >= int(thresholds["high_malicious_detections"]):
        return Priority.HIGH, [f"VirusTotal reports {malicious} malicious detections."]
    if malicious >= int(thresholds["medium_malicious_detections"]) or suspicious >= int(
        thresholds["medium_suspicious_detections"]
    ):
        return Priority.MEDIUM, [
            f"VirusTotal reports {malicious} malicious and {suspicious} suspicious detections."
        ]
    return Priority.UNKNOWN, [
        "No malicious detections were returned; that is not proof the indicator is safe."
    ]
