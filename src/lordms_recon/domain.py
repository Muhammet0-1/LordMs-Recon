"""Domain validation and output-path safety."""

from __future__ import annotations

import re
from pathlib import Path


DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def validate_domain(domain: str) -> str:
    """Validate a hostname and return its normalized ASCII representation."""
    if not isinstance(domain, str) or not domain or domain != domain.strip():
        raise ValueError("Domain cannot be empty or contain surrounding whitespace.")
    if domain.endswith("."):
        raise ValueError("Domain cannot end with a dot.")

    try:
        normalized = domain.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("Invalid internationalized domain name.") from exc

    if len(normalized) > 253:
        raise ValueError("Domain cannot exceed 253 characters.")

    labels = normalized.split(".")
    if len(labels) < 2 or any(not DOMAIN_LABEL_RE.fullmatch(label) for label in labels):
        raise ValueError("Provide a hostname such as example.com, not a URL, path, port, or wildcard.")
    return normalized


def build_output_folder(domain: str, base_dir: str | Path | None = None) -> tuple[Path, str]:
    """Return a safe output folder contained directly below ``base_dir``."""
    normalized = validate_domain(domain)
    root = Path(base_dir or Path.cwd()).expanduser().resolve()
    folder = (root / f"recon_{normalized}").resolve()
    if folder.parent != root:
        raise ValueError("Output folder must remain directly below the selected root.")
    return folder, normalized

