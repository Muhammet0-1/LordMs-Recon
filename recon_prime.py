import subprocess
import json
import argparse
import shutil
import asyncio
import html as html_lib
import os
import re
import statistics
from pathlib import Path
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor


DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
RISK_LEVELS = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


def validate_domain(domain):
    """Validate and normalize a hostname supplied by the user."""
    if not isinstance(domain, str) or not domain or domain != domain.strip():
        raise ValueError("Domain boş olamaz veya başında/sonunda boşluk içeremez.")

    if domain.endswith("."):
        raise ValueError("Domain sonunda nokta bulunamaz.")

    try:
        normalized = domain.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("Geçersiz uluslararası domain.") from exc

    if len(normalized) > 253:
        raise ValueError("Domain 253 karakterden uzun olamaz.")

    labels = normalized.split(".")
    if len(labels) < 2 or any(not DOMAIN_LABEL_RE.fullmatch(label) for label in labels):
        raise ValueError("Geçerli bir hostname girin (ör. example.com).")

    return normalized


def build_output_folder(domain, base_dir=None):
    """Return a safe output path contained directly under base_dir."""
    normalized = validate_domain(domain)
    root = Path(base_dir or Path.cwd()).resolve()
    folder = (root / f"recon_{normalized}").resolve()

    if folder.parent != root:
        raise ValueError("Çıktı klasörü çalışma dizininin dışında olamaz.")

    return folder, normalized

# ==============================
# Dependency Check
# ==============================
def check_dependencies():
    required = ["subfinder", "httpx-toolkit"]
    return [tool for tool in required if shutil.which(tool) is None]

# ==============================
# Risk Level
# ==============================
def risk_level(score):
    if score >= 70:
        return "CRITICAL"
    elif score >= 40:
        return "HIGH"
    elif score >= 20:
        return "MEDIUM"
    return "LOW"

# ==============================
# Scoring Engine
# ==============================
def evaluate_target(data):
    score = 0
    reasons = []

    url = data.get("url", "")
    status_code = data.get("status_code", 0)
    title = str(data.get("title", "")).lower()

    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    parts = hostname.split(".")

    keywords = ["dev", "test", "staging", "admin", "api", "beta", "internal"]

    for part in parts:
        if part in keywords:
            score += 15
            reasons.append(f"Kritik Subdomain ({part})")

    if status_code in [401, 403]:
        score += 10
        reasons.append("Erişim Kısıtlı")

    if status_code >= 500:
        score += 20
        reasons.append("Sunucu Hatası")

    if "swagger" in title:
        score += 25
        reasons.append("Swagger Açık")

    if "index of" in title:
        score += 30
        reasons.append("Dizin Listeleme")

    if "admin" in hostname and status_code == 403:
        score += 20
        reasons.append("Admin + 403 Kombosu")

    if score == 0:
        reasons.append("Standart")

    return score, reasons

# ==============================
# Async HTTPX
# ==============================
async def run_httpx(subdomains):
    process = await asyncio.create_subprocess_exec(
        "httpx-toolkit",
        "-silent",
        "-json",
        "-title",
        "-status-code",
        "-tech-detect",
        "-web-server",
        "-content-length",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE
    )

    input_data = "\n".join(subdomains).encode()
    stdout, _ = await process.communicate(input=input_data)

    return stdout.decode().splitlines()

# ==============================
# HTML Report
# ==============================
def generate_html(domain, targets, folder):
    path = os.path.join(folder, "report.html")
    escaped_domain = html_lib.escape(str(domain), quote=True)

    html = f"""
    <html>
    <head>
    <title>LordMs Recon Report - {escaped_domain}</title>
    <style>
        body {{ background:#111; color:#eee; font-family:Arial; }}
        table {{ width:100%; border-collapse:collapse; }}
        th, td {{ border:1px solid #444; padding:8px; }}
        th {{ background:#222; }}
        .CRITICAL {{ color:red; font-weight:bold; }}
        .HIGH {{ color:orange; }}
        .MEDIUM {{ color:yellow; }}
        .LOW {{ color:lightgreen; }}
    </style>
    </head>
    <body>
    <h2>LordMs Recon Report - {escaped_domain}</h2>
    <table>
    <tr>
    <th>URL</th>
    <th>Status</th>
    <th>Score</th>
    <th>Risk</th>
    <th>Content-Length</th>
    <th>Reasons</th>
    </tr>
    """

    for t in targets:
        escaped_url = html_lib.escape(str(t.get("url", "")), quote=True)
        escaped_status = html_lib.escape(str(t.get("status_code", "")), quote=True)
        escaped_score = html_lib.escape(str(t.get("score", "")), quote=True)
        escaped_length = html_lib.escape(str(t.get("content_length", "")), quote=True)
        risk = str(t.get("risk", "LOW"))
        safe_risk = risk if risk in RISK_LEVELS else "LOW"
        reasons = ", ".join(str(reason) for reason in t.get("reasons", []))
        escaped_reasons = html_lib.escape(reasons, quote=True)
        html += f"""
        <tr>
        <td>{escaped_url}</td>
        <td>{escaped_status}</td>
        <td>{escaped_score}</td>
        <td class="{safe_risk}">{safe_risk}</td>
        <td>{escaped_length}</td>
        <td>{escaped_reasons}</td>
        </tr>
        """

    html += "</table></body></html>"

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)

    return path

# ==============================
# Plugins
# ==============================
def run_nuclei(urls, folder):
    if shutil.which("nuclei") is None:
        print("[-] Nuclei kurulu değil, atlanıyor.")
        return

    print(f"[*] Nuclei (optimized mode) {len(urls)} hedef için çalıştırılıyor...")

    output = os.path.join(folder, "nuclei.txt")
    temp_file = os.path.join(folder, "nuclei_targets.txt")

    with open(temp_file, "w", encoding="utf-8") as f:
        f.write("\n".join(urls))

    nuclei_command = [
        "nuclei",
        "-l", temp_file,
        "-severity", "critical,high",
        "-rate-limit", "50",
        "-timeout", "5",
        "-retries", "1",
        "-silent",
        "-no-color"
    ]

    with open(output, "w", encoding="utf-8") as out_f:
        subprocess.run(nuclei_command, stdout=out_f)

    os.remove(temp_file)
    print(f"[+] Nuclei taraması tamamlandı: {output}")

def run_screenshot(urls, folder):
    if shutil.which("gowitness") is None:
        return

    os.makedirs(os.path.join(folder, "screenshots"), exist_ok=True)
    print("[*] Screenshot alınıyor (değerli hedefler)...")
    subprocess.run(
        ["gowitness", "file", "-f", "-", "-P", os.path.join(folder, "screenshots")],
        input="\n".join(urls),
        text=True
    )

# ==============================
# Dashboard
# ==============================
def launch_dashboard(folder):
    try:
        from flask import Flask, send_from_directory
    except:
        print("[-] Flask yüklü değil.")
        return

    app = Flask(__name__)

    @app.route("/")
    def report():
        return send_from_directory(folder, "report.html")

    print("[*] Dashboard: http://127.0.0.1:5000")
    app.run()

# ==============================
# Main
# ==============================
async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--domain", required=True)
    parser.add_argument("--dashboard", action="store_true")
    args = parser.parse_args()

    try:
        folder, domain = build_output_folder(args.domain)
    except ValueError as exc:
        parser.error(str(exc))

    missing = check_dependencies()
    if missing:
        print("Eksik araçlar:", missing)
        return

    os.makedirs(folder, exist_ok=True)

    # Subfinder
    result = subprocess.run(
        ["subfinder", "-d", domain, "-silent"],
        capture_output=True,
        text=True
    )
    subdomains = result.stdout.splitlines()
    print(f"[+] {len(subdomains)} subdomain bulundu.")

    # HTTPX
    lines = await run_httpx(subdomains)

    # Target scoring
    targets = []
    content_lengths = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for line in lines:
            try:
                data = json.loads(line)
                futures.append(executor.submit(evaluate_target, data))
                cl = int(data.get("content_length", 0) or 0)
                content_lengths.append(cl)
                targets.append({
                    "url": data.get("url"),
                    "status_code": data.get("status_code"),
                    "content_length": cl
                })
            except:
                continue
        for i, future in enumerate(futures):
            score, reasons = future.result()
            targets[i]["score"] = score
            targets[i]["risk"] = risk_level(score)
            targets[i]["reasons"] = reasons

    # Anomaly detection
    if len(content_lengths) > 5:
        avg = statistics.mean(content_lengths)
        stdev = statistics.stdev(content_lengths)
        for t in targets:
            if t["content_length"] > avg + (2 * stdev):
                t["score"] += 20
                t["risk"] = risk_level(t["score"])
                t["reasons"].append("Content-Length Anomalisi")

    targets.sort(key=lambda x: x["score"], reverse=True)

    # Sadece değerli hedefler
    valuable_urls = [t['url'] for t in targets if t['score'] >= 20]

    print(f"\n[*] Toplam {len(targets)} hedef tarandı.")
    print(f"[+] {len(valuable_urls)} adet değerli hedef eklentilere gönderilecek.\n")

    generate_html(domain, targets, folder)

    if valuable_urls:
        run_nuclei(valuable_urls, folder)
        run_screenshot(valuable_urls, folder)

    print(f"[+] Rapor hazır: {folder}/report.html")

    if args.dashboard:
        launch_dashboard(folder)

if __name__ == "__main__":
    asyncio.run(main())
