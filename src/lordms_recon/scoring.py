"""Transparent, heuristic target-prioritization rules."""

from __future__ import annotations

import statistics
from urllib.parse import urlparse

from .models import Target


RISK_LEVELS = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
KEYWORDS = {"dev", "test", "staging", "admin", "api", "beta", "internal"}


def risk_level(score: int) -> str:
    if score >= 70:
        return "CRITICAL"
    if score >= 40:
        return "HIGH"
    if score >= 20:
        return "MEDIUM"
    return "LOW"


def score_target(target: Target) -> Target:
    hostname = (urlparse(target.url).hostname or "").lower()
    title = target.title.lower()
    score = 0
    reasons: list[str] = []

    for label in hostname.split("."):
        if label in KEYWORDS:
            score += 15
            reasons.append(f"interesting hostname label: {label}")
    if target.status_code in {401, 403}:
        score += 10
        reasons.append("restricted response")
    if target.status_code >= 500:
        score += 20
        reasons.append("server error response")
    if "swagger" in title:
        score += 25
        reasons.append("Swagger title")
    if "index of" in title:
        score += 30
        reasons.append("directory listing title")
    if "admin" in hostname and target.status_code == 403:
        score += 20
        reasons.append("admin hostname with 403 response")

    target.score = score
    target.risk = risk_level(score)
    target.reasons = reasons or ["no prioritization signal"]
    return target


def apply_content_length_anomalies(targets: list[Target]) -> None:
    """Add a signal for values above mean + 2σ when enough samples exist."""
    if len(targets) < 6:
        return
    values = [target.content_length for target in targets]
    deviation = statistics.stdev(values)
    threshold = statistics.mean(values) + (2 * deviation)
    for target in targets:
        if deviation and target.content_length > threshold:
            target.score += 20
            target.risk = risk_level(target.score)
            target.reasons.append("content-length statistical outlier")

