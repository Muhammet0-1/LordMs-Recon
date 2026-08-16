"""Typed target records used throughout the pipeline."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urlparse


@dataclass(slots=True)
class Target:
    url: str
    status_code: int = 0
    title: str = ""
    content_length: int = 0
    webserver: str = ""
    technologies: list[str] = field(default_factory=list)
    score: int = 0
    risk: str = "LOW"
    reasons: list[str] = field(default_factory=list)

    @classmethod
    def from_httpx(cls, data: dict[str, Any]) -> "Target":
        url = data.get("url") or data.get("input")
        if not isinstance(url, str) or not url.strip():
            raise ValueError("httpx record does not contain a valid URL")
        url = url.strip()
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("httpx record URL must use HTTP(S) and contain a hostname")

        try:
            status_code = int(data.get("status_code") or 0)
        except (TypeError, ValueError):
            status_code = 0
        try:
            content_length = int(data.get("content_length") or 0)
        except (TypeError, ValueError):
            content_length = 0

        tech = data.get("tech") or data.get("technologies") or []
        if isinstance(tech, str):
            tech = [tech]
        elif not isinstance(tech, list):
            tech = []

        return cls(
            url=url,
            status_code=status_code,
            title=str(data.get("title") or ""),
            content_length=max(0, content_length),
            webserver=str(data.get("webserver") or data.get("web_server") or ""),
            technologies=[str(item) for item in tech],
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
