from __future__ import annotations

from .base import ResearchTool
from .certificates import CertificateTransparencyTool
from .dns import DnsTool
from .rdap import RdapTool
from .virustotal import VirusTotalTool

TOOLS: dict[str, ResearchTool] = {
    tool.name: tool
    for tool in (
        DnsTool(),
        RdapTool(),
        CertificateTransparencyTool(),
        VirusTotalTool(),
    )
}

__all__ = ["TOOLS"]
