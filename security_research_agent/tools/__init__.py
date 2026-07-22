from __future__ import annotations

from .base import ResearchTool
from .virustotal import VirusTotalTool

TOOLS: dict[str, ResearchTool] = {
    tool.name: tool for tool in (VirusTotalTool(),)
}

__all__ = ["TOOLS"]
