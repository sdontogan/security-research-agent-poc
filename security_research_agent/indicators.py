from __future__ import annotations

import ipaddress
import re

from .models import Domain

CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")
SCHEME_URL_PATTERN = re.compile(
    r"\b[a-z][a-z0-9+.-]*://[^\s<>\"']+",
    re.IGNORECASE,
)
IP_TOKEN_PATTERN = re.compile(r"(?<![\w])\[?[0-9a-f:.]{2,}\]?(?![\w])", re.IGNORECASE)
DOMAIN_PATTERN = re.compile(
    r"(?<![@\w-])(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}(?![\w-])"
)
NON_PUBLIC_SUFFIXES = (".internal", ".invalid", ".lan", ".local", ".localhost", ".test")


def _contains_ip_address(text: str) -> bool:
    for match in IP_TOKEN_PATTERN.finditer(text):
        candidate = match.group(0).strip("[](){}<>,;!?")
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        return True
    return False


def _contains_url_shaped_domain(text: str) -> bool:
    for match in DOMAIN_PATTERN.finditer(text):
        suffix = text[match.end() :]
        if suffix.startswith("/") or re.match(r":\d+(?:\b|/)", suffix):
            return True
        if len(suffix) > 1 and suffix[0] in {"?", "#"} and not suffix[1].isspace():
            return True
    return False


def extract_domains(text: str) -> list[Domain]:
    """Return bare public domains and reject every other supported-input shape."""

    if (
        CVE_PATTERN.search(text)
        or SHA256_PATTERN.search(text)
        or SCHEME_URL_PATTERN.search(text)
        or _contains_ip_address(text)
        or _contains_url_shaped_domain(text)
    ):
        return []

    found: list[Domain] = []
    for match in DOMAIN_PATTERN.finditer(text):
        domain = match.group(0).lower().rstrip(".")
        if len(domain) > 253 or domain.endswith(NON_PUBLIC_SUFFIXES):
            continue
        if domain not in {item.value for item in found}:
            found.append(Domain(value=domain))

    return found[:2]
