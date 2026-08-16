"""Command-line orchestration for LordMs Recon."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .dashboard import launch_dashboard
from .domain import build_output_folder
from .external import ToolError, discover_subdomains, probe_http, run_gowitness, run_nuclei
from .reporting import write_html_report, write_json_report
from .scoring import apply_content_length_anomalies, score_target


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lordms-recon",
        description="Authorized reconnaissance and heuristic target prioritization.",
    )
    parser.add_argument("-d", "--domain", required=True, help="Authorized hostname, for example example.com")
    parser.add_argument("--output-root", type=Path, default=Path.cwd(), help="Parent directory for recon_<domain>")
    parser.add_argument("--timeout", type=int, default=300, help="Per-tool timeout in seconds (default: 300)")
    parser.add_argument("--httpx-bin", help="Explicit httpx executable; auto-detects httpx/httpx-toolkit otherwise")
    parser.add_argument("--subfinder-bin", help="Explicit Subfinder executable")
    parser.add_argument("--dashboard", action="store_true", help="Serve report.html locally on 127.0.0.1:5000")

    active = parser.add_argument_group("explicit active integrations")
    active.add_argument("--run-nuclei", action="store_true", help="Run high/critical Nuclei templates on prioritized URLs")
    active.add_argument("--screenshots", action="store_true", help="Capture prioritized URLs with Gowitness")
    active.add_argument("--nuclei-bin", help="Explicit Nuclei executable")
    active.add_argument("--gowitness-bin", help="Explicit Gowitness executable")
    active.add_argument("--rate-limit", type=int, default=50, help="Nuclei request rate limit (default: 50)")
    return parser


def run(args: argparse.Namespace) -> int:
    if args.timeout <= 0:
        raise ValueError("--timeout must be greater than zero")
    if args.rate_limit <= 0:
        raise ValueError("--rate-limit must be greater than zero")

    folder, domain = build_output_folder(args.domain, args.output_root)
    folder.mkdir(parents=True, exist_ok=True)

    print(f"[+] Authorized target: {domain}")
    subdomains = discover_subdomains(domain, binary=args.subfinder_bin, timeout=args.timeout)
    print(f"[+] Subdomains: {len(subdomains)}")

    targets, warnings = probe_http(subdomains, binary=args.httpx_bin, timeout=args.timeout)
    for warning in warnings:
        print(f"[!] {warning}", file=sys.stderr)
    for target in targets:
        score_target(target)
    apply_content_length_anomalies(targets)
    targets.sort(key=lambda item: (-item.score, item.url))

    html_path = write_html_report(domain, targets, folder)
    json_path = write_json_report(domain, targets, folder)
    prioritized_urls = [target.url for target in targets if target.score >= 20]

    print(f"[+] HTTP targets: {len(targets)}")
    print(f"[+] Prioritized URLs: {len(prioritized_urls)}")
    print(f"[+] HTML report: {html_path}")
    print(f"[+] JSON report: {json_path}")

    if args.run_nuclei:
        if not prioritized_urls:
            print("[*] Nuclei skipped: no URL reached the prioritization threshold.")
        else:
            path = run_nuclei(
                prioritized_urls,
                folder,
                binary=args.nuclei_bin,
                timeout=args.timeout,
                rate_limit=args.rate_limit,
            )
            print(f"[+] Nuclei output: {path}")

    if args.screenshots:
        if not prioritized_urls:
            print("[*] Gowitness skipped: no URL reached the prioritization threshold.")
        else:
            path = run_gowitness(
                prioritized_urls,
                folder,
                binary=args.gowitness_bin,
                timeout=args.timeout,
            )
            print(f"[+] Screenshots: {path}")

    if args.dashboard:
        print("[+] Dashboard: http://127.0.0.1:5000")
        launch_dashboard(folder)
    return 0


def entrypoint(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return run(args)
    except (ToolError, RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(entrypoint())
