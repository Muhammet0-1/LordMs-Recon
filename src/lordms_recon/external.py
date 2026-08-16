"""Safe wrappers around external reconnaissance tools."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Iterable, Sequence
from urllib.parse import urlparse

from .domain import validate_domain
from .models import Target


class ToolError(RuntimeError):
    """Raised when an external tool cannot be found or exits unsuccessfully."""


def resolve_binary(explicit: str | None, candidates: Sequence[str]) -> str:
    names = [explicit] if explicit else list(candidates)
    for name in names:
        if name and shutil.which(name):
            return name
    expected = explicit or " or ".join(candidates)
    raise ToolError(f"Required executable not found in PATH: {expected}")


def run_command(
    args: Sequence[str],
    *,
    input_text: str | None = None,
    timeout: int = 300,
) -> str:
    try:
        result = subprocess.run(
            list(args),
            input=input_text,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ToolError(f"Command timed out after {timeout}s: {args[0]}") from exc
    except OSError as exc:
        raise ToolError(f"Could not start {args[0]}: {exc}") from exc

    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "no diagnostic output"
        raise ToolError(f"{args[0]} exited with status {result.returncode}: {detail}")
    return result.stdout


def discover_subdomains(domain: str, *, binary: str | None, timeout: int) -> list[str]:
    executable = resolve_binary(binary, ("subfinder",))
    output = run_command([executable, "-d", domain, "-silent"], timeout=timeout)
    discovered: set[str] = set()
    for line in output.splitlines():
        try:
            hostname = validate_domain(line.strip())
        except ValueError:
            continue
        if hostname == domain or hostname.endswith(f".{domain}"):
            discovered.add(hostname)
    return sorted(discovered)


def probe_http(
    subdomains: Iterable[str],
    *,
    binary: str | None,
    timeout: int,
) -> tuple[list[Target], list[str]]:
    subdomain_list = list(subdomains)
    allowed_hosts = {item.lower() for item in subdomain_list}
    executable = resolve_binary(binary, ("httpx", "httpx-toolkit"))
    command = [
        executable,
        "-silent",
        "-json",
        "-title",
        "-status-code",
        "-tech-detect",
        "-web-server",
        "-content-length",
    ]
    output = run_command(command, input_text="\n".join(subdomain_list), timeout=timeout)

    targets: list[Target] = []
    warnings: list[str] = []
    for line_number, line in enumerate(output.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
            if not isinstance(record, dict):
                raise ValueError("record is not an object")
            target = Target.from_httpx(record)
            hostname = (urlparse(target.url).hostname or "").lower()
            if hostname not in allowed_hosts:
                raise ValueError(f"URL hostname is outside the discovered scope: {hostname}")
            targets.append(target)
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            warnings.append(f"Skipped httpx line {line_number}: {exc}")
    return targets, warnings


def run_nuclei(
    urls: list[str],
    folder: Path,
    *,
    binary: str | None,
    timeout: int,
    rate_limit: int,
) -> Path:
    executable = resolve_binary(binary, ("nuclei",))
    targets_path = folder / ".nuclei-targets.txt"
    output_path = folder / "nuclei.txt"
    targets_path.write_text("\n".join(urls) + "\n", encoding="utf-8")
    try:
        output = run_command(
            [
                executable,
                "-l",
                str(targets_path),
                "-severity",
                "critical,high",
                "-rate-limit",
                str(rate_limit),
                "-timeout",
                "5",
                "-retries",
                "1",
                "-silent",
                "-no-color",
            ],
            timeout=timeout,
        )
        output_path.write_text(output, encoding="utf-8")
    finally:
        targets_path.unlink(missing_ok=True)
    return output_path


def run_gowitness(
    urls: list[str],
    folder: Path,
    *,
    binary: str | None,
    timeout: int,
) -> Path:
    executable = resolve_binary(binary, ("gowitness",))
    targets_path = folder / ".gowitness-targets.txt"
    screenshots_path = folder / "screenshots"
    screenshots_path.mkdir(parents=True, exist_ok=True)
    targets_path.write_text("\n".join(urls) + "\n", encoding="utf-8")
    try:
        run_command(
            [
                executable,
                "scan",
                "file",
                "-f",
                str(targets_path),
                "--screenshot-path",
                str(screenshots_path),
            ],
            timeout=timeout,
        )
    finally:
        targets_path.unlink(missing_ok=True)
    return screenshots_path
