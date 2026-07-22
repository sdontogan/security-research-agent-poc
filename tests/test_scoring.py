from security_research_agent.models import Priority, ToolEvidence
from security_research_agent.scoring import assess_priority


def evidence(**data: object) -> ToolEvidence:
    return ToolEvidence(
        tool="lookup_virustotal",
        subject="example.com",
        source="test",
        summary="fixture",
        data=data,
    )


def test_no_evidence_is_unknown() -> None:
    priority, _ = assess_priority([])

    assert priority == Priority.UNKNOWN


def test_five_malicious_detections_are_high() -> None:
    priority, reasons = assess_priority([evidence(malicious=5, suspicious=0)])

    assert priority == Priority.HIGH
    assert "5 malicious" in reasons[0]


def test_one_suspicious_detection_is_medium() -> None:
    priority, _ = assess_priority([evidence(malicious=0, suspicious=1)])

    assert priority == Priority.MEDIUM


def test_zero_detections_are_unknown_not_safe() -> None:
    priority, reasons = assess_priority([evidence(malicious=0, suspicious=0)])

    assert priority == Priority.UNKNOWN
    assert "not proof" in reasons[0]


def test_malformed_detection_counts_are_unknown() -> None:
    priority, reasons = assess_priority([evidence(malicious="unknown")])

    assert priority == Priority.UNKNOWN
    assert "not usable" in reasons[0]
