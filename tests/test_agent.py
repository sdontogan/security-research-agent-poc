from types import SimpleNamespace

import pytest

import security_research_agent.agent as agent_module
from security_research_agent.agent import SecurityResearchAgent
from security_research_agent.models import ApiKeys, Priority, ToolEvidence


def test_demo_agent_returns_domain_evidence_without_keys() -> None:
    result = SecurityResearchAgent().run(
        "Check example.com",
        api_keys=ApiKeys(),
        demo_mode=True,
    )

    assert result.mode == "demo"
    assert result.priority == Priority.MEDIUM
    assert len(result.evidence) == 1
    assert result.tools_used == ["lookup_virustotal"]
    assert "VirusTotal demo fixture" in result.message


def test_no_domain_returns_short_instructions() -> None:
    result = SecurityResearchAgent().run("How do I use this?", api_keys=ApiKeys())

    assert "What I can research" in result.message
    assert "public domain" in result.message
    assert not result.evidence


def test_multiple_domains_are_rejected() -> None:
    result = SecurityResearchAgent().run(
        "Compare example.com with example.org",
        api_keys=ApiKeys(),
        demo_mode=True,
    )

    assert "more than one domain" in result.message
    assert not result.evidence


@pytest.mark.parametrize(
    "message",
    [
        "Check CVE-2021-44228",
        "Check 8.8.8.8",
        "Check 2001:4860:4860::8888",
        "Check " + ("a" * 64),
        "Check https://example.com/login",
        "Check example.com/path",
        "Check analyst@example.com",
        "Check example.com and 8.8.8.8",
    ],
)
def test_unsupported_input_never_reaches_a_tool(monkeypatch, message: str) -> None:
    research_agent = SecurityResearchAgent()
    monkeypatch.setattr(
        research_agent,
        "_gather_evidence",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("tool called")),
    )

    result = research_agent.run(
        message,
        api_keys=ApiKeys(openai="test-key", virustotal="test-key"),
    )

    assert "Domain required" in result.message
    assert not result.evidence


def test_safety_help_does_not_need_openai() -> None:
    result = SecurityResearchAgent().run("Explain the safety limits", api_keys=ApiKeys())

    assert "Safety limits" in result.message
    assert "one fixed" in result.message
    assert "cannot run shell commands" in result.message


def test_long_prompt_is_rejected_before_tool_use() -> None:
    result = SecurityResearchAgent().run(
        "Check example.com " + ("x" * 2_100),
        api_keys=ApiKeys(openai="not-a-real-key"),
    )

    assert "under 2,000 characters" in result.message
    assert not result.evidence


def test_demo_mode_is_limited_to_example_domain() -> None:
    result = SecurityResearchAgent().run(
        "Check example.org",
        api_keys=ApiKeys(),
        demo_mode=True,
    )

    assert "example.com" in result.message
    assert not result.evidence


def test_openai_is_optional_interpretation_not_the_priority_source(monkeypatch) -> None:
    captured: dict[str, object] = {}

    class FakeResponses:
        def create(self, **kwargs):
            captured.update(kwargs)
            return SimpleNamespace(output_text="The supplied reputation evidence warrants review.")

    class FakeOpenAI:
        def __init__(self, **kwargs):
            self.responses = FakeResponses()

    research_agent = SecurityResearchAgent()
    evidence = ToolEvidence(
        tool="lookup_virustotal",
        subject="example.com",
        source="VirusTotal test fixture",
        summary="VirusTotal reports 7 malicious detections.",
        data={"malicious": 7, "suspicious": 0},
    )
    monkeypatch.setattr(agent_module, "OpenAI", FakeOpenAI)
    monkeypatch.setattr(
        research_agent,
        "_gather_evidence",
        lambda *args, **kwargs: ([evidence], ["lookup_virustotal"]),
    )

    result = research_agent.run(
        "Check example.com",
        api_keys=ApiKeys(openai="test-key"),
    )

    assert captured["store"] is False
    assert result.mode == "openai"
    assert result.priority == Priority.HIGH
    assert "classified as **HIGH** by the POC rules" in result.message
    assert "Model-assisted interpretation" in result.message
