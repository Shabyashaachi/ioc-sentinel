from __future__ import annotations

import re
from urllib.parse import urlparse

IP_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
HASH_RE = re.compile(r"(?<![A-Fa-f0-9])(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})(?![A-Fa-f0-9])")
DOMAIN_RE = re.compile(r"(?<![@\w.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}(?![\w.-])")


def valid_ipv4(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)


def extract_ips(text: str) -> list[str]:
    return sorted({value for value in IP_RE.findall(text) if valid_ipv4(value)})


def extract_hashes(text: str) -> list[str]:
    return sorted({value.lower() for value in HASH_RE.findall(text)})


def extract_urls(text: str) -> list[str]:
    candidates = re.findall(r"https?://[^\s'\"<>]+", text, flags=re.I)
    return sorted(set(candidate.rstrip(".,);]}") for candidate in candidates))


def extract_domains(text: str) -> list[str]:
    return sorted({domain.lower().rstrip(".") for domain in DOMAIN_RE.findall(text)})


def extract_all(text: str) -> dict[str, list[str]]:
    return {
        "ip": extract_ips(text),
        "hash": extract_hashes(text),
        "url": extract_urls(text),
        "domain": extract_domains(text),
    }


def normalize_ioc(value: str, ioc_type: str) -> str:
    value = value.strip().lower()
    if ioc_type == "url":
        parsed = urlparse(value)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip("/")
    return value.rstrip(".")
