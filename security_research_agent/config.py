from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


def _positive_int(name: str, default: int) -> int:
    raw_value = os.getenv(name, str(default))
    try:
        value = int(raw_value)
    except ValueError:
        return default
    return value if value > 0 else default


@dataclass(frozen=True)
class Settings:
    openai_model: str = os.getenv("OPENAI_MODEL", "gpt-5-mini")
    request_timeout_seconds: int = _positive_int("REQUEST_TIMEOUT_SECONDS", 10)
    max_response_characters: int = _positive_int("MAX_RESPONSE_CHARACTERS", 12_000)
    demo_mode: bool = os.getenv("DEMO_MODE", "false").lower() in {"1", "true", "yes"}


def environment_key(name: str) -> str | None:
    value = os.getenv(name, "").strip()
    return value or None
