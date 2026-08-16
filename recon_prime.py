"""Backward-compatible entry point for existing users.

New installations should use the ``lordms-recon`` console command.
"""

from lordms_recon.cli import entrypoint
from lordms_recon.domain import build_output_folder, validate_domain
from lordms_recon.reporting import write_html_report


if __name__ == "__main__":
    raise SystemExit(entrypoint())
