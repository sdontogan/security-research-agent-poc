"""Language-neutral contracts shared with the portfolio web adaptation."""

from __future__ import annotations

import json
from functools import cache
from importlib.resources import files
from typing import Any


@cache
def load_json(name: str) -> dict[str, Any]:
    resource = files(__package__).joinpath(name)
    value = json.loads(resource.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"Contract {name} must contain a JSON object.")
    return value


@cache
def load_text(name: str) -> str:
    return files(__package__).joinpath(name).read_text(encoding="utf-8").strip()


__all__ = ["load_json", "load_text"]
