# LordMs Recon Framework

LordMs Recon Framework, bug bounty çalışmaları ve yalnızca açıkça yetkilendirilmiş güvenlik testleri için geliştirilmiş bir keşif ve hedef önceliklendirme aracıdır. Alt alan adlarını toplar, erişilebilir HTTP hedeflerini inceler ve operatörün hangi hedefleri önce değerlendirebileceğine ilişkin sezgisel bir puan üretir.

Üretilen puanlar ve `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` etiketleri doğrulanmış bir güvenlik açığı veya kesin risk seviyesi değildir. Bunlar yalnızca manuel inceleme önceliği oluşturmak için kullanılan sinyallerdir.

## Temel özellikler

- [Subfinder](https://github.com/projectdiscovery/subfinder) ile subdomain keşfi
- ProjectDiscovery [httpx](https://github.com/projectdiscovery/httpx) aracının `httpx-toolkit` çalıştırılabilir dosyası üzerinden canlı hedef ve metadata toplama
- Hostname, HTTP durum kodu, sayfa başlığı ve içerik uzunluğuna dayalı sezgisel hedef puanlama
- Puanı en az 20 olan hedefler için isteğe bağlı araçlar olarak Nuclei entegrasyonu ve Gowitness ekran görüntüleri
- Puan, gerekçe, durum kodu ve içerik uzunluğunu gösteren HTML raporu
- `--dashboard` ile isteğe bağlı yerel Flask sunucusu
- Hostname doğrulama, IDNA normalizasyonu ve çıktı klasörünü çalışma diziniyle sınırlama
- HTML raporundaki dinamik veriler için HTML escaping

## Çalışma akışı

1. `-d/--domain` girdisi doğrulanır, küçük harfe ve gerektiğinde IDNA biçimine dönüştürülür.
2. `subfinder` ve `httpx-toolkit` çalıştırılabilir dosyalarının `PATH` içinde bulunup bulunmadığı kontrol edilir.
3. `subfinder`, verilen domain için subdomain listesi üretir.
4. Liste standart girdi üzerinden `httpx-toolkit` aracına aktarılır; URL, başlık, durum kodu, teknoloji, web sunucusu ve content-length alanları istenir.
5. JSON satırları ayrıştırılır ve hedefler sezgisel olarak puanlanır. En az altı content-length değeri olduğunda istatistiksel uç değer kontrolü de uygulanır.
6. Hedefler puana göre sıralanır ve `report.html` oluşturulur.
7. Puanı en az 20 olan hedef varsa, kurulu olmaları durumunda Nuclei ve Gowitness otomatik olarak çalıştırılır.
8. `--dashboard` verilmişse rapor Flask geliştirme sunucusuyla `127.0.0.1:5000` adresinde sunulur.

`httpx-toolkit` tarafından döndürülen teknoloji ve web sunucusu metadatası mevcut sürümde rapora veya puanlamaya aktarılmaz.

## Gereksinimler

### Python

Projede kesin bir Python sürümü sabitlenmemiştir. Kaynak kod `asyncio.run()` kullandığı için en az Python 3.7 gerekir. Kullanılan tek üçüncü taraf Python paketi Flask'tır ve sürümü [`requirements.txt`](requirements.txt) içinde sabitlenmemiştir. Flask yalnızca dashboard özelliğinde kullanılır.

### Harici araçlar

| Araç | Durum | Kaynak kodun çağırdığı komut |
|---|---|---|
| Subfinder | Zorunlu | `subfinder` |
| ProjectDiscovery httpx | Zorunlu | `httpx-toolkit` |
| Nuclei | İsteğe bağlı; uygun hedef varsa otomatik çalışır | `nuclei` |
| Gowitness | İsteğe bağlı; uygun hedef varsa otomatik çalışır | `gowitness file -f - -P ...` |
| Flask | Yalnızca `--dashboard` için | Python paketi |

Buradaki HTTP aracı Python'daki `httpx` paketi değildir. ProjectDiscovery tarafından geliştirilen Go tabanlı CLI aracıdır.

> **Uyumluluk notu:** ProjectDiscovery'nin resmî Go kurulumu çalıştırılabilir dosyayı `httpx` adıyla oluşturur; bu proje ise şu anda `httpx-toolkit` adını arar ve çağırır. Kurulumunuzda uyumlu aracın `PATH` içinde gerçekten `httpx-toolkit` adıyla erişilebilir olması gerekir. Benzer biçimde Gowitness'ın CLI sözleşmesi sürümler arasında değişebilir; kullanılan sürümün yukarıdaki `file` komutunu desteklediğini doğrulayın.

## Kurulum

### 1. Depoyu alın

```bash
git clone https://github.com/Muhammet0-1/LordMs-Recon.git
cd LordMs-Recon
```

### 2. Python sanal ortamını hazırlayın

```bash
python3 -m venv venv
source venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
```

Sanal ortamı etkinleştirme komutu POSIX uyumlu kabuklar içindir. Diğer platformlarda Python belgelerindeki sanal ortam yönergelerini izleyin.

### 3. Harici araçları kurun

Kurulum yöntemi işletim sistemine göre değişebilir. Güncel ve platforma uygun yöntemler için araçların resmî belgelerini kullanın:

- [Subfinder kurulumu](https://docs.projectdiscovery.io/opensource/subfinder/install)
- [ProjectDiscovery httpx kurulumu](https://docs.projectdiscovery.io/opensource/httpx/install)
- [Nuclei kurulumu](https://docs.projectdiscovery.io/opensource/nuclei/install)
- [Gowitness kurulumu](https://github.com/sensepost/gowitness/wiki/Installation)

Go ortamı kullanan kurulumlara örnek:

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/sensepost/gowitness@latest
```

`@latest` zaman içinde farklı sürümler kurar ve tekrar üretilebilir bir araç zinciri sağlamaz. Kararlı kullanımda doğruladığınız sürüm etiketlerini sabitleyin. Ayrıca yukarıdaki `httpx` ve Gowitness uyumluluk notlarını dikkate alın; yalnızca bu komutların başarıyla tamamlanması mevcut kaynak kodla CLI uyumluluğunu garanti etmez.

Zorunlu komut adlarını kontrol edin:

```bash
command -v subfinder
command -v httpx-toolkit
```

İsteğe bağlı araçları da kullanacaksanız kontrol edin:

```bash
command -v nuclei
command -v gowitness
```

## Kullanım

Temel kullanım:

```bash
python3 recon_prime.py -d example.com
```

Yerel dashboard ile kullanım:

```bash
python3 recon_prime.py -d example.com --dashboard
```

CLI yalnızca şu seçenekleri destekler:

- `-d`, `--domain`: Zorunlu hostname girdisi
- `--dashboard`: Raporu yerel Flask sunucusunda açar

Domain girdisi yalnızca hostname olmalıdır. Büyük harfler küçük harfe, uluslararası karakterler IDNA biçimine dönüştürülür. URL, port, wildcard, yol, tek etiketli ad ve sondaki nokta kabul edilmez.

```text
Kabul edilir:   example.com
Kabul edilir:   api.example.com
Reddedilir:     https://example.com
Reddedilir:     example.com:443
Reddedilir:     *.example.com
Reddedilir:     example.com/admin
Reddedilir:     localhost
Reddedilir:     example.com.
```

## Örnek kullanım senaryosu

Aşağıdaki örnek yalnızca dokümantasyon için ayrılmış `example.com` alanını kullanır:

```bash
python3 recon_prime.py --domain example.com
```

Araç önce `example.com` için subdomain keşfi yapar, bulunan hedefleri HTTP açısından kontrol eder, raporu üretir ve puanı en az 20 olan hedefler varsa kurulu Nuclei/Gowitness entegrasyonlarını çalıştırır.

## Çıktı yapısı

Başarılı bir çalışma için çıktı klasörü geçerli ve normalize edilmiş domain adıyla çalışma dizininin doğrudan altında oluşturulur:

```text
recon_example.com/
├── report.html
├── nuclei.txt
└── screenshots/
```

- `report.html`, zorunlu keşif adımları tamamlanıp uygulama rapor aşamasına ulaştığında oluşturulur.
- `nuclei.txt`, puanı en az 20 olan hedef bulunduğunda ve `nuclei` kurulu olduğunda oluşturulur; bulgu yoksa boş olabilir.
- `screenshots/`, puanı en az 20 olan hedef bulunduğunda ve `gowitness` kurulu olduğunda oluşturulur. İçindeki gerçek ekran görüntüleri Gowitness çalışmasının başarısına bağlıdır.
- `nuclei_targets.txt` çalışma sırasında geçici olarak oluşturulur ve normal akış sonunda silinir; kalıcı çıktı olarak değerlendirilmez.

Araçlar eksikse, alt süreçler başarısız olursa veya uygun hedef bulunmazsa bu çıktıların bir bölümü oluşmayabilir.

## Puanlama ve sonuçların yorumlanması

Her hedef sıfır puanla başlar. Mevcut puanlama sinyalleri şunlardır:

| Sinyal | Puan |
|---|---:|
| Hostname etiketinde `dev`, `test`, `staging`, `admin`, `api`, `beta` veya `internal` bulunması | Her eşleşme için +15 |
| HTTP durumunun 401 veya 403 olması | +10 |
| HTTP durumunun 500 veya üzeri olması | +20 |
| Sayfa başlığında `swagger` bulunması | +25 |
| Sayfa başlığında `index of` bulunması | +30 |
| Hostname içinde `admin` bulunması ve durumun 403 olması | +20 |
| En az altı hedefte content-length değerinin ortalama + 2 standart sapmadan büyük olması | +20 |

Puan etiketleri:

| Puan | Etiket |
|---:|---|
| 0–19 | `LOW` |
| 20–39 | `MEDIUM` |
| 40–69 | `HIGH` |
| 70 ve üzeri | `CRITICAL` |

Bu etiketler bir zafiyetin varlığını veya etkisini doğrulamaz. Örneğin 403 yanıtı, Swagger başlığı ya da sıra dışı içerik uzunluğu tek başına güvenlik açığı değildir. Sonuçlar manuel olarak doğrulanmalıdır. Mevcut kod HTTP header skorlama yapmaz.

## Güvenlik önlemleri

Mevcut uygulamada aşağıdaki savunmalar bulunur:

- Domain sözdizimi ve etiket uzunlukları doğrulanır.
- Uluslararası domainler Python'ın IDNA kodlayıcısıyla ASCII biçimine dönüştürülür.
- Çözülmüş çıktı yolunun çalışma dizininin doğrudan altında kaldığı kontrol edilir.
- HTML raporundaki domain ve hedef alanları escape edilir; risk CSS sınıfı izin verilen dört değerle sınırlandırılır.
- Harici komutlar argüman listeleriyle çalıştırılır; `shell=True` kullanılmaz.

Bu önlemler mutlak bir güvenlik garantisi değildir. Araç halen dış programlara, onların çıktılarına ve çalıştırıldığı ortamın güvenli yapılandırılmasına bağlıdır.

## Testler

Mevcut `unittest` testlerini çalıştırmak için:

```bash
python3 -m unittest discover -s tests -v
```

Testler şu senaryoları kapsar:

- Geçerli domainlerin ve IDNA girdilerinin normalizasyonu
- URL, port, yol, path traversal ve bozuk hostname girdilerinin reddedilmesi
- Çıktı klasörünün seçilen kök dizinin doğrudan altında kalması
- Geçersiz girdide çıktı oluşturulmaması
- HTML raporundaki dinamik alanların escape edilmesi
- Risk CSS sınıfının izin verilen değerlerle sınırlandırılması

Puanlama, `httpx` JSON ayrıştırması ve dış süreç entegrasyonları için henüz test bulunmamaktadır.

## Sınırlamalar

- Temel çalışma Subfinder ve `httpx-toolkit` adlı harici çalıştırılabilir dosyalara bağlıdır.
- Harici araçların CLI seçenekleri ve çıktı formatları sürümler arasında değişebilir. Özellikle resmî `httpx` adı ile kodun beklediği `httpx-toolkit` adı ve Gowitness komut biçimi uyumluluk gerektirir.
- Puanlama sezgiseldir; doğrulanmış zafiyet veya kapsamlı risk analizi sağlamaz.
- `httpx` tarafından toplanan teknoloji ve web sunucusu alanları mevcut raporda kullanılmaz.
- Bazı bozuk `httpx` kayıtlarında ayrıştırma/puan eşleştirme davranışı geliştirilmeye ihtiyaç duyar.
- Alt süreçlerin return code ve stderr değerleri sistematik olarak işlenmez; süreç seviyesinde genel timeout yönetimi yoktur.
- Nuclei, puanı en az 20 olan hedef bulunduğunda ve kuruluysa ayrıca onay istemeden çalışır. Aktif tarama yalnızca açık izin ve doğru kapsamla kullanılmalıdır.
- Flask dashboard geliştirme sunucusudur; üretim servisi olarak tasarlanmamıştır.

## Etik ve yetkili kullanım

Bu aracı yalnızca sahibi tarafından açıkça izin verilen sistemlerde veya kapsamı açık biçimde tanımlanmış bug bounty programlarında kullanın. Hedefin program kapsamına dahil olduğunu, kullanılan tarama yöntemlerine izin verildiğini ve hız/otomasyon kurallarına uyulduğunu önceden doğrulayın.

Kullanıcı; hedef kapsamından, platform kurallarından, üçüncü taraf hizmet koşullarından ve yürürlükteki yerel mevzuata uyumdan sorumludur. Aracın erişilebilir bir hedef üzerinde çalışması, o hedefi tarama yetkisi vermez.

## Yol haritası

- Aktif Nuclei taramasını açık bir kullanıcı onayı veya CLI seçeneğine bağlamak
- Alt süreçlerde return code, stderr ve genel timeout yönetimi eklemek
- Puanlama, JSON ayrıştırma ve hata senaryoları için test kapsamını genişletmek
- CLI, keşif, puanlama, raporlama ve entegrasyon kodlarını modüllere ayırmak
- Python ve harici araç bağımlılıklarının doğrulanmış sürümlerini sabitlemek

## Lisans

Bu proje [MIT Lisansı](LICENSE) altında yayımlanmıştır. Ayrıntılar için `LICENSE` dosyasına bakın.
