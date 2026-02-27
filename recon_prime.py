import subprocess
import json
import argparse
import sys
import shutil
import asyncio
import os
import statistics
from urllib.parse import urlparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor


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

    html = f"""
    <html>
    <head>
    <title>LordMs Recon Report - {domain}</title>
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
    <h2>LordMs Recon Report - {domain}</h2>
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
        html += f"""
        <tr>
        <td>{t['url']}</td>
        <td>{t['status_code']}</td>
        <td>{t['score']}</td>
        <td class="{t['risk']}">{t['risk']}</td>
        <td>{t['content_length']}</td>
        <td>{", ".join(t['reasons'])}</td>
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
        return

    print("[*] Nuclei çalıştırılıyor (değerli hedefler)...")
    output = os.path.join(folder, "nuclei.txt")

    with open(output, "w") as f:
        subprocess.run(
            ["nuclei", "-l", "-", "-silent"],
            input="\n".join(urls),
            text=True,
            stdout=f
        )


def run_screenshot(urls, folder):
    if shutil.which("gowitness") is None:
        return

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

    domain = args.domain
    folder = f"recon_{domain}"
    os.makedirs(folder, exist_ok=True)

    missing = check_dependencies()
    if missing:
        print("Eksik araçlar:", missing)
        return

    result = subprocess.run(
        ["subfinder", "-d", domain, "-silent"],
        capture_output=True,
        text=True
    )

    subdomains = result.stdout.splitlines()
    print(f"[+] {len(subdomains)} subdomain bulundu.")

    lines = await run_httpx(subdomains)

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

    # Anomaly Detection
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
