from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class Priority(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    UNKNOWN = "unknown"


class Domain(BaseModel):
    value: str


class ToolEvidence(BaseModel):
    tool: str
    subject: str
    status: str = "success"
    source: str
    source_url: str | None = None
    summary: str
    data: dict[str, Any] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)


class ResearchOutcome(BaseModel):
    message: str
    priority: Priority = Priority.UNKNOWN
    priority_reasons: list[str] = Field(default_factory=list)
    evidence: list[ToolEvidence] = Field(default_factory=list)
    tools_used: list[str] = Field(default_factory=list)
    mode: str = "local"


@dataclass(frozen=True)
class ApiKeys:
    openai: str | None = None
    virustotal: str | None = None
