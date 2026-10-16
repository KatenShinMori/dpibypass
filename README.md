# dpibypass — Windows İçin Yüksek Performanslı Hat Düzeyi (Wire-Level) DPI Atlama Motoru

[![Go Sürümü](https://img.shields.io/badge/Go-1.22%2B-blue.svg)](https://golang.org)
[![Platform](https://img.shields.io/badge/Platform-Windows%20x64-0078D6.svg)](https://microsoft.com)
[![Lisans: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Sürücü](https://img.shields.io/badge/Driver-WinDivert%202.2.2-green.svg)](https://reqcrypt.org/windivert.html)

**[English](README.en.md) | [Türkçe](README.md)**

**dpibypass**, Windows x64 işletim sistemleri için geliştirilmiş saf Go (pure Go) mimarisinde, hat düzeyinde (wire-level) Derin Paket İnceleme (DPI) atlatma motoru ve şeffaf DNS köprüsüdür. WinDivert aracılığıyla doğrudan çekirdek ağ katmanında çalışarak; harici vekil sunucu (proxy), VPN veya tarayıcı eklentisi gerektirmeden tüm sistem çapında TCP (TLS/HTTP) ve UDP trafiğini korur.

Özellikle Türk servis sağlayıcılarının (Türk Telekom, Turkcell Superonline vb.) durum bilgili (stateful) DPI filtrelerini (BTK kısıtlamaları ve bant genişliği daraltmaları) aşmak üzere optimize edilen **dpibypass**; Discord (yerel masaüstü istemcisi ve ses sunucuları), Roblox ve engellenen tüm web hedeflerini başarıyla açar.

---

## Temel Mimari Yenilikler

### 1. WinDivert ABI ile Saf Go Çekirdek Bağlantısı (Sıfır CGO)
Geleneksel C derleyicilerine veya harici hantal kütüphanelere bağımlı araçların aksine `dpibypass`, doğrudan Go standart kütüphanesinin sistem çağrıları (syscall) ve yapılandırılmış ABI tanımları üzerinden `WinDivert.dll` ve `WinDivert64.sys` ile haberleşir:
- **64 KiB Ön-Tahsisli Tampon Bellek:** Windows Large Send Offload (LSO/TSO) paket patlamalarını kayıpsız karşılar.
- **Mikrosaniye Seviyesinde Hat Filtreleme:** Hedef dışı ağ trafiğini sıfır gecikmeyle doğrudan hattan geçirir.

### 2. Post-Quantum TLS 1.3 Çok Paketlik (Multi-Packet) SNI Bölümleme
Modern Chromium tabanlı uygulamalar (Discord yerel Electron masaüstü istemcisi dahil), ~1.900 bayt boyutunda Post-Quantum (`X25519MLKEM768`) TLS 1.3 `ClientHello` paketleri gönderir:
- **Ön-Bölümlenmiş Paket 2 Takibi:** Büyük el sıkışmalarda Windows TCP yığını yükü ağ kartından çıkmadan önce böler; 1.216 baytlık anahtar paylaşımı Paket 1'de, Sunucu Adı Belirteci (SNI) ise Paket 2'de yer alır. `dpibypass`, TCP sıra numaralarını (SeqNum) dinamik takip ederek Paket 2'yi yakalar, SNI orta noktasından (`sni-mid`) böler.
- **Sırasız (Out-of-Order) Enjeksiyon:** Paket 2 Parça 2'yi Parça 1'den önce hatta ileterek middlebox inceleme motorlarının hedef alan adını yeniden birleştirmesini imkansız kılar.
- **MTU Güvenliği Alt-Bölümlemesi:** Enjekte edilen parçaları otomatik olarak `<= 1400` bayt sınırında tutarak Ethernet MTU paket düşmelerini engeller.

### 3. Düşük TTL ile Middlebox Zehirleme (Sentetik Sahte Paket Enjeksiyonu)
- Gerçek paketle birebir aynı 4'lü demete (Src/Dst IP/Port) ve TCP sıra numarasına sahip, zararsız bir SNI (`www.example.com`) taşıyan geçerli bir TLS `ClientHello` sentezler.
- Sahte paketi düşük bir sekme sayısı (örn. `TTL 3` veya `TTL 4`) ile hatta basarak servis sağlayıcının 3. sekmedeki DPI filtresini kör eder; paket hedef sunucuya varmadan hatta sönümlenir.
- ECMP rota değişimlerine karşı çoklu TTL (Multi-TTL) desteği barındırır.

### 4. Sıfır DNS Bağımlı DoH Bootstrap ve Otomatik Windows `hosts` Eşitlemesi
Servis sağlayıcıların DNS zehirleme altyapısı (alan adlarını `195.175.254.2` sinkhole IP'sine yönlendirme), Windows `Dnscache` ve Chromium'un bellek içi `net::HostCache` önbelleğini kilitler. `dpibypass` bunu tamamen ortadan kaldırır:
- **Sıfır DNS Bootstrap:** Anycast IP adreslerine (`1.1.1.1`, `8.8.8.8`) doğrudan HTTPS üzerinden bağlanır, önyükleme DNS kilitlenmelerini önler.
- **Otomatik `hosts` Eşitlemesi:** Başlangıçta Discord ve Roblox alan adları için temiz IPv4 adreslerini eşzamanlı çözer ve `C:\Windows\System32\drivers\etc\hosts` dosyasındaki `# BEGIN DPIBYPASS MANAGED HOSTS` bloğunu otomatik günceller.
- **Kaspersky WFP Impostor Yakalama:** Antivirüs yazılımlarının WFP filtreleri tarafından yeniden hatta sürülen UDP port 53 paketlerini (`impostor` bayrağıyla) yakalar ve RFC 768 yazılımsal sağlama toplamıyla yanıtlar.
- **Temiz Kurtarma:** Program kapandığında veya kurtarma modunda `hosts` dosyasını orijinal haline temizce geri döndürür.

### 5. IPv6 Happy Eyeballs Geri Düşüşü (RFC 8305)
Çift yığınlı (dual-stack) modemlerde bağlantıların filtrelenen veya takılan IPv6 rotasına girmesini önlemek için 80/443 portlarındaki giden IPv6 TCP SYN paketlerini bastırır ve IPv6 DNS sorgularına temiz `NODATA` yanıtı döner. Böylece istemciler 1ms içinde korumalı IPv4 rotasına yönlendirilir.

### 6. Gömülü Loopback Web Arayüzü & Anti-Cheat Güvenli Modu
`127.0.0.1:8787` adresinde çalışan gömülü kontrol paneli:
- Canlı istatistikler: yakalanan paketler, sahte paketler, bölünen segmentler ve DoH çözümleri.
- **Anti-Cheat Güvenli Modu (`Pause / Resume Driver`):** Easy Anti-Cheat, BattlEye ve Vanguard gibi çekirdek düzeyindeki hile koruma yazılımlarıyla çakışma yaşamadan oyunlara girmek için tek tıkla WinDivert sürücüsünü geçici olarak bellekten kaldırır ve istendiğinde tekrar devreye alır.

---

## Hızlı Başlangıç (Tek Tıkla Başlatıcılar)

Tüm toplu iş dosyaları (`.bat`) Windows'ta otomatik olarak Yönetici yetkisine yükselir:

| Betik / Komut | Amaç |
|---|---|
| **`launch-discord.bat`** | **Discord için Önerilen Başlatıcı.** DNS önbelleğini temizler, alan adlarının temiz çözüldüğünü doğrular, arka planda wire motorunu başlatır ve Discord masaüstü istemcisini açar. |
| **`start-bypass.bat`** | Paket motorunu `http://127.0.0.1:8787` adresindeki Web Arayüzü ile birlikte başlatır. |
| **`stop-and-recover.bat`** | Motoru durdurur, WinDivert sürücüsünü bellekten kaldırır, `hosts` dosyasındaki eklemeleri temizler ve DNS önbelleğini yeniler. |
| **`test-live.ps1`** | **İSS Karşılaştırmalı Test ve Profil Belirleyici.** Farklı sahte paket modlarını ve TTL sekme sayılarını (`TTL 3` - `TTL 6`, `multi-ttl`, `wrong-chksum` ve saf bölme) canlı hedefler (`updates.discord.com`, `discord.com`, `gateway.discord.gg`, `www.roblox.com`) üzerinde test eden ve bağlantınız için en iyi profili öneren 8 profilli otomatik kıyaslama aracı (`powershell -ExecutionPolicy Bypass -File .\test-live.ps1 -NoPause`). |

---

## Türkiye İSS Uyumluluğu ve İSS Ayarları

`dpibypass`, Türkiye'deki internet servis sağlayıcılarının (BTK / DPI filtre mimarisi) kısıtlamalarına karşı özel olarak test edilmiş ve doğrulanmıştır:

| İSS / Sağlayıcı | Durum & Önerilen Strateji | Teknik Notlar |
|---|---|---|
| **Türk Telekom** | **Doğrulandı: Kurulumsuz %100 Çalışır** (`fake_ttl: 4`, `sni-mid`) | DPI middlebox genellikle 3 veya 4. sekmede yer alır. `dpibypass`, Türk Telekom'un sinkhole IP'sine (`195.175.254.2`) giden paketleri anında gelen TCP `RST+ACK` ile düşürür, temiz Anycast IP'lerini DoH ile `hosts` dosyasına işler ve `TTL 4` sahte paketleriyle DPI'ı kör eder. |
| **Turkcell Superonline** | **Tam Desteklenir** (Otomatik Ayar `TTL 3`–`6` veya `TTL 4`) | Superonline giden UDP 53 portunu şeffaf olarak yönlendirir. `dpibypass`, doğrudan IP üzerinden çalışan DoH (`1.1.1.1:443`) ve yerel `hosts` eşitlemesiyle bunu tamamen aşar. Bölge ve fiber topolojisine göre DPI sekme mesafesi değişebildiğinden, en uygun değeri bulmak için `.\test-live.ps1` veya `dpibypass.exe tune --mode packet --domains discord.com,www.roblox.com --apply` çalıştırılabilir. |
| **Vodafone Net** | **Tam Desteklenir** (Varsayılan profil / `AutoLearner`) | QUIC engelleme (`drop_quic: true`), IPv6 Happy Eyeballs geri düşüşü ve kademeli yeniden iletim öğrenmesi (`TTL 4 -> 3 -> 5`) ile Vodafone DPI filtrelerini atlatır. |
| **Türksat Kablonet** | **Tam Desteklenir** (Varsayılan profil) | Docsis ve GPON altyapısında sırasız TLS kayıt bölümleme ve DoH-hosts eşitlemesi ile sorunsuz çalışır. |
| **TurkNet** | **Tam Desteklenir** (Varsayılan profil) | GigaFiber ve VDSL hatlarında ek yapılandırma gerektirmeden tam performansla çalışır. |

### Canlı Profil Kıyaslama Testini Çalıştırma
Bağlantınızda tüm 8 atlatma profilini test etmek için:
```powershell
powershell -ExecutionPolicy Bypass -File .\test-live.ps1 -NoPause
```

Hattınız için en küçük çalışan TTL değerini otomatik bulup kaydetmek için:
```powershell
.\dpibypass.exe tune --mode packet --domains discord.com,updates.discord.com,www.roblox.com --apply
```

---

## Yapılandırma (`config.json`)

Varsayılan yapılandırma günlük kullanım için optimize edilmiştir:

```json
{
  "mode": "packet",
  "default_profile": "packet-default",
  "packet": {
    "fake_mode": "ttl",
    "fake_ttl": 4,
    "fake_sni": "www.example.com",
    "split_offset": "sni-mid",
    "drop_quic": true,
    "intercept_dns": true,
    "desync_http": true,
    "auto_learn": true
  },
  "doh": {
    "enabled": true,
    "endpoints": [
      { "url": "https://cloudflare-dns.com/dns-query" },
      { "url": "https://dns.google/dns-query" }
    ]
  }
}
```

---

## Kaynak Koddan Derleme

### Gereksinimler
- **İşletim Sistemi:** Windows 10/11 x64
- **Go:** Sürüm 1.22 veya üzeri
- **Yetki:** Yönetici hakları (WinDivert sürücü erişimi için zorunludur)
- **WinDivert 2.2.2 Sürücü Dosyaları:**
  `dpibypass` paketleri yakalamak için resmi Microsoft imzalı WinDivert 2.2.2 sürücüsüne ihtiyaç duyar:
  1. Resmi `WinDivert-2.2.2-A.zip` dağıtım paketini [reqcrypt.org/windivert.html](https://reqcrypt.org/windivert.html) veya [GitHub Divert Sürümleri](https://github.com/basil00/Divert/releases/tag/v2.2.2) sayfasından indirin.
  2. Arşiv içerisindeki `x64\WinDivert.dll` ve `x64\WinDivert64.sys` dosyalarını proje kök dizinine (`dpibypass.exe` yanına) çıkarın.

### Derleme Komutları
Proje kök dizininde PowerShell derleme betiğini çalıştırın:

```powershell
powershell -ExecutionPolicy Bypass -File .\build.ps1
```

Bu betik `dpibypass.exe` dosyasını derler, sürüm ve taahhüt (commit) etiketlerini bağlar, otomatik duman testini (smoke test) yürütür ve SHA-256 doğrulama kodunu görüntüler.

Alternatif olarak standart Go ile derlemek için:
```powershell
go build -o dpibypass.exe ./cmd/dpibypass
```

### Testleri Çalıştırma

```powershell
go test -count=1 ./...
```

---

## Komut Satırı Kullanımı

```text
Kullanım: dpibypass <komut> [seçenekler]

Komutlar:
  run [--mode packet|proxy] [--config <dosya>] [--webui 127.0.0.1:8787]
      Hat atlatma motorunu başlatır (WinDivert paket modu veya kullanıcı alanı vekili)

  recover [--check-only] [--status] [--force]
      Birleşik kurtarma: sistem vekilini geri yükler, hosts dosyasını temizler, WinDivert sürücüsünü durdurur

  tune --domains <d1,d2> [--apply]
      Hedef alan adları için minimum çalışan TTL sekme sayısını otomatik kalibre eder

  config validate [--config <dosya>]
      Yapılandırma dosyasının sözdizimini, sınırlarını ve loopback güvenliğini doğrular

  version
      Sürüm ve derleme meta verilerini yazdırır
```

---

## Lisans

Bu proje [MIT Lisansı](LICENSE) ile lisanslanmıştır.
WinDivert, GNU Kısıtlı Genel Kamu Lisansı (LGPL) v3 veya GNU Genel Kamu Lisansı (GPL) v2 ile lisanslanmıştır.
