# LordMs Recon Framework

**LordMs Recon Framework** – Gelişmiş ve optimize edilmiş bir bug bounty keşif aracıdır.  
Alt domain keşfi, HTTP analiz, risk skorlama, content-length anomalisi, HTML rapor ve opsiyonel screenshot & dashboard özellikleri içerir.  

---

## 🚀 Özellikler

- Subdomain keşfi (`subfinder`)  
- HTTP analiz ve başlık skorlama (`httpx-toolkit`)  
- Değerli hedef filtreleme (score >= 20)  
- Content-Length anomali tespiti  
- HTML rapor oluşturma (renkli tablo ile risk seviyeleri)  
- Opsiyonel screenshot (`gowitness`)  
- Opsiyonel dashboard (`Flask`)  

---

## 💻 Kurulum

### 1️⃣ Bağımlılıklar

```bash
sudo apt install python3 python3-pip
pip install flask

Go tabanlı araçlar: subfinder, httpx-toolkit

Opsiyonel: gowitness, nuclei

# Subfinder
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# HTTPX
go install github.com/projectdiscovery/httpx/cmd/httpx-toolkit@latest

# Nuclei
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# Gowitness (opsiyonel)
go install github.com/sensepost/gowitness@latest
🏹 Kullanım
Temel
python3 lordrecon.py -d example.com
Dashboard ile
python3 lordrecon.py -d example.com --dashboard
⚡ Performans Notları

Sadece değerli hedefler (score >= 20) Nuclei ve Screenshot’a gönderilir.

Büyük hedeflerde saatlerce sürecek taramaları önler ve WAF ban riskini azaltır.

📁 Çıktılar
recon_example.com/
├── report.html
├── nuclei.txt        # Nuclei çıktı dosyası (varsa)
├── screenshots/      # Gowitness screenshot klasörü (varsa)
