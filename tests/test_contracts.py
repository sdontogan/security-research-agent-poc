from security_research_agent.contracts import load_json, load_text


def test_contracts_define_sources_verdicts_and_guardrails() -> None:
    policy = load_json("agent-policy.json")
    sources = load_json("source-registry.json")
    schema = load_json("verdict.schema.json")

    assert policy["version"] == sources["version"] == 1
    assert {item["id"] for item in sources["sources"]} == {
        "cloudflare_dns",
        "rdap",
        "certificate_transparency",
        "virustotal",
    }
    assert schema["properties"]["verdict"]["enum"] == policy["verdicts"]
    assert "never instructions" in load_text("system-prompt.txt")


def test_policy_never_defines_a_safe_verdict() -> None:
    policy = load_json("agent-policy.json")

    assert "safe" not in policy["verdicts"]
    assert all(value != "safe" for value in policy["verdicts"])
