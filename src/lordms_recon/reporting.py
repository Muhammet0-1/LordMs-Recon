"""Machine-readable and human-readable report generation."""

from __future__ import annotations

import html
import json
from pathlib import Path

from .models import Target
from .scoring import RISK_LEVELS


def write_json_report(domain: str, targets: list[Target], folder: Path) -> Path:
    path = folder / "report.json"
    payload = {"domain": domain, "target_count": len(targets), "targets": [target.to_dict() for target in targets]}
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


def write_html_report(domain: str, targets: list[Target], folder: Path) -> Path:
    path = folder / "report.html"
    rows: list[str] = []
    for target in targets:
        risk = target.risk if target.risk in RISK_LEVELS else "LOW"
        technology = ", ".join(target.technologies) or "—"
        reasons = ", ".join(target.reasons)
        rows.append(
            "<tr>"
            f'<td><a href="{html.escape(target.url, quote=True)}">{html.escape(target.url)}</a></td>'
            f"<td>{target.status_code}</td>"
            f"<td>{html.escape(target.title)}</td>"
            f"<td>{html.escape(target.webserver) or '—'}</td>"
            f"<td>{html.escape(technology)}</td>"
            f"<td>{target.content_length}</td>"
            f"<td>{target.score}</td>"
            f'<td><span class="badge {risk.lower()}">{risk}</span></td>'
            f"<td>{html.escape(reasons)}</td>"
            "</tr>"
        )

    empty = '<tr><td colspan="9" class="empty">No HTTP targets were returned.</td></tr>'
    document = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>LordMs Recon — {html.escape(domain)}</title>
  <style>
    :root {{ color-scheme: dark; --bg:#07111f; --panel:#0e1b2d; --line:#263850; --text:#e7edf6; --muted:#9fb0c7; }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; background:var(--bg); color:var(--text); font:14px/1.5 ui-sans-serif,system-ui,sans-serif; }}
    main {{ width:min(1500px,96vw); margin:40px auto; }}
    h1 {{ margin-bottom:4px; }} .summary {{ color:var(--muted); margin-top:0; }}
    .table-wrap {{ overflow:auto; border:1px solid var(--line); border-radius:12px; background:var(--panel); }}
    table {{ width:100%; border-collapse:collapse; white-space:nowrap; }}
    th,td {{ padding:12px; border-bottom:1px solid var(--line); text-align:left; vertical-align:top; }}
    th {{ position:sticky; top:0; background:#13243a; }} a {{ color:#7cc4ff; }}
    .badge {{ padding:3px 8px; border-radius:999px; font-weight:700; }}
    .low {{ background:#153b2a; color:#8ef0b3; }} .medium {{ background:#4a3b0c; color:#ffe28a; }}
    .high {{ background:#542f12; color:#ffb17a; }} .critical {{ background:#581b27; color:#ff9bad; }}
    .empty {{ color:var(--muted); text-align:center; }}
  </style>
</head>
<body><main>
  <h1>LordMs Recon</h1>
  <p class="summary">{html.escape(domain)} · {len(targets)} targets · heuristic prioritization, not confirmed findings</p>
  <div class="table-wrap"><table>
    <thead><tr><th>URL</th><th>Status</th><th>Title</th><th>Server</th><th>Technology</th><th>Bytes</th><th>Score</th><th>Priority</th><th>Signals</th></tr></thead>
    <tbody>{''.join(rows) or empty}</tbody>
  </table></div>
</main></body></html>
"""
    path.write_text(document, encoding="utf-8")
    return path

