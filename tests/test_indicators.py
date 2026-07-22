import pytest

from security_research_agent.indicators import extract_domains


def test_extracts_and_normalizes_one_public_domain() -> None:
    domains = extract_domains("Can you check Login.Example.COM for me?")

    assert [item.value for item in domains] == ["login.example.com"]


def test_deduplicates_the_same_domain() -> None:
    domains = extract_domains("Compare example.com with EXAMPLE.COM")

    assert [item.value for item in domains] == ["example.com"]


def test_returns_two_distinct_domains_for_agent_rejection() -> None:
    domains = extract_domains("Compare example.com and example.org")

    assert [item.value for item in domains] == ["example.com", "example.org"]


@pytest.mark.parametrize(
    "value",
    [
        "CVE-2021-44228",
        "8.8.8.8",
        "2001:4860:4860::8888",
        "a" * 64,
        "https://example.com/login",
        "ftp://example.com/file",
        "example.com/path",
        "example.com:443",
        "example.com?next=home",
        "example.com#section",
        "analyst@example.com",
        "database.internal",
        "service.local",
    ],
)
def test_rejects_every_non_domain_input_shape(value: str) -> None:
    assert extract_domains(f"Check {value}") == []


@pytest.mark.parametrize(
    "unsupported",
    [
        "CVE-2021-44228",
        "8.8.8.8",
        "2001:4860:4860::8888",
        "a" * 64,
        "https://bad.example/path",
        "bad.example/path",
    ],
)
def test_rejects_mixed_domain_and_unsupported_input(unsupported: str) -> None:
    assert extract_domains(f"Check example.com and {unsupported}") == []
