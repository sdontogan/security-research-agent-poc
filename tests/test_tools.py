import pytest

import security_research_agent.tools.virustotal as virustotal_module
from security_research_agent.models import ApiKeys
from security_research_agent.tools import TOOLS
from security_research_agent.tools.base import ToolContext

DEMO_CONTEXT = ToolContext(api_keys=ApiKeys(), demo_mode=True)


def test_registry_contains_only_domain_connector() -> None:
    assert set(TOOLS) == {"lookup_virustotal"}


def test_demo_domain_does_not_need_a_key() -> None:
    result = TOOLS["lookup_virustotal"].run(
        {"domain": "example.com"},
        DEMO_CONTEXT,
    )

    assert result.status == "success"
    assert result.data["domain"] == "example.com"
    assert result.data["fixture"] is True


def test_demo_fixture_does_not_make_claims_about_other_domains() -> None:
    result = TOOLS["lookup_virustotal"].run(
        {"domain": "example.org"},
        DEMO_CONTEXT,
    )

    assert result.status == "unavailable"
    assert "example.com only" in result.summary


def test_live_domain_without_key_is_unavailable() -> None:
    result = TOOLS["lookup_virustotal"].run(
        {"domain": "example.com"},
        ToolContext(api_keys=ApiKeys(), demo_mode=False),
    )

    assert result.status == "unavailable"
    assert "API key" in result.summary


@pytest.mark.parametrize(
    "value",
    [
        "CVE-2021-44228",
        "8.8.8.8",
        "2001:4860:4860::8888",
        "a" * 64,
        "https://example.com/login",
        "example.com/path",
    ],
)
def test_connector_directly_rejects_non_domains(value: str) -> None:
    result = TOOLS["lookup_virustotal"].run(
        {"domain": value},
        ToolContext(api_keys=ApiKeys(virustotal="test-key")),
    )

    assert result.status == "unavailable"
    assert "validated public domain" in result.summary


def test_virustotal_malformed_counts_are_unavailable(monkeypatch) -> None:
    monkeypatch.setattr(
        virustotal_module,
        "get_json",
        lambda *args, **kwargs: {
            "data": {"attributes": {"last_analysis_stats": {"malicious": "unknown"}}}
        },
    )

    result = TOOLS["lookup_virustotal"].run(
        {"domain": "example.com"},
        ToolContext(api_keys=ApiKeys(virustotal="test-key")),
    )

    assert result.status == "unavailable"
    assert "unexpected format" in result.summary


def test_connector_uses_only_virustotal_domain_endpoint(monkeypatch) -> None:
    requested: dict[str, str] = {}

    def fake_get_json(url: str, **kwargs):
        requested["url"] = url
        return {"data": {"attributes": {"last_analysis_stats": {}}}}

    monkeypatch.setattr(virustotal_module, "get_json", fake_get_json)

    result = TOOLS["lookup_virustotal"].run(
        {"domain": "example.com"},
        ToolContext(api_keys=ApiKeys(virustotal="test-key")),
    )

    assert result.status == "success"
    assert requested["url"] == "https://www.virustotal.com/api/v3/domains/example.com"
