from pathlib import Path


def test_ui_exposes_domain_only_controls() -> None:
    source = Path("app.py").read_text()

    assert "Domain Research Agent" in source
    assert "Enter one public domain, such as example.com" in source
    assert '"NVD API key"' not in source
    assert "Research a sample CVE" not in source
    assert '<span class="tool-chip">NVD</span>' not in source
    assert '<span class="tool-chip">EPSS</span>' not in source
    assert '<span class="tool-chip">CISA KEV</span>' not in source
