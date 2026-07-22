from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Protocol

import httpx

from ..models import ApiKeys, ToolEvidence

DEFAULT_MAX_UPSTREAM_BYTES = 1_500_000


@dataclass(frozen=True)
class ToolContext:
    api_keys: ApiKeys
    timeout_seconds: int = 10
    demo_mode: bool = False


class ResearchTool(Protocol):
    name: str
    description: str

    def run(self, arguments: dict[str, Any], context: ToolContext) -> ToolEvidence: ...


class ToolRequestError(RuntimeError):
    pass


def get_json(
    url: str,
    *,
    timeout_seconds: int,
    headers: dict[str, str] | None = None,
    params: dict[str, str] | None = None,
    max_bytes: int = DEFAULT_MAX_UPSTREAM_BYTES,
    follow_redirects: bool = False,
) -> dict[str, Any]:
    payload = get_json_value(
        url,
        timeout_seconds=timeout_seconds,
        headers=headers,
        params=params,
        max_bytes=max_bytes,
        follow_redirects=follow_redirects,
    )
    if not isinstance(payload, dict):
        raise ToolRequestError("The upstream response had an unexpected shape.")
    return payload


def get_json_value(
    url: str,
    *,
    timeout_seconds: int,
    headers: dict[str, str] | None = None,
    params: dict[str, str] | None = None,
    max_bytes: int = DEFAULT_MAX_UPSTREAM_BYTES,
    follow_redirects: bool = False,
) -> Any:
    try:
        with (
            httpx.Client(
                timeout=timeout_seconds,
                follow_redirects=follow_redirects,
                headers={"User-Agent": "security-research-agent-poc/0.1"},
            ) as client,
            client.stream("GET", url, headers=headers, params=params) as response,
        ):
            response.raise_for_status()
            chunks: list[bytes] = []
            total = 0
            for chunk in response.iter_bytes():
                total += len(chunk)
                if total > max_bytes:
                    raise ToolRequestError("The upstream response exceeded the size limit.")
                chunks.append(chunk)
        payload = json.loads(b"".join(chunks))
    except ToolRequestError:
        raise
    except (httpx.HTTPError, json.JSONDecodeError) as exc:
        raise ToolRequestError("The upstream service did not return usable data.") from exc

    return payload


def unavailable_evidence(tool: str, subject: str, message: str) -> ToolEvidence:
    return ToolEvidence(
        tool=tool,
        subject=subject,
        status="unavailable",
        source=tool,
        summary=message,
        warnings=[message],
    )
