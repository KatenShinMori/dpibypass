# dpibypass — Windows İçin Hat Düzeyi (Wire-Level) DPI Atlama Motoru

[![Go Sürümü](https://img.shields.io/badge/Go-1.22%2B-blue.svg)](https://golang.org)
[![Platform](https://img.shields.io/badge/Platform-Windows%20x64-0078D6.svg)](https://microsoft.com)
[![Lisans: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Sürücü](https://img.shields.io/badge/Driver-WinDivert%202.2.2-green.svg)](https://reqcrypt.org/windivert.html)

**[English](README.en.md) | [Türkçe](README.md)**

**dpibypass**, Windows x64 işletim sistemleri için geliştirilmiş, Go dilinde yazılmış bir hat düzeyi (wire-level) Derin Paket İnceleme (DPI) atlatma aracı ve DNS köprüsüdür. WinDivert aracılığıyla çekirdek ağ katmanında paketleri yakalayarak ve yeniden düzenleyerek harici vekil sunucu (proxy) veya VPN gerektirmeden TCP (TLS/HTTP) ve UDP trafiğinde DPI manipülasyonu uygular.

Özellikle servis sağlayıcıların SNI tabanlı filtreleme ve DPI kısıtlamalarını aşmayı amaçlayan araç; Discord (masaüstü istemcisi ve ses bağlantıları) ve Roblox gibi hizmetlerde yaşanan DPI kaynaklı erişim sorunlarını gidermeye yönelik teknikler içerir.

---

## Kısıtlamalar (Limitations)

- **Yalnızca SNI/DPI Engelleri:** Sadece alan adı (SNI) ve paket içeriği incelemesine dayalı engellemelerde etkilidir. IP bloklama, BGP rotası engeli veya erişim noktası düzeyindeki doğrudan kesintileri aşamaz.
- **Yalnızca Windows 10/11 x64:** WinDivert 2.2.2 x64 sürücüsü gerektirir; 32-bit Windows veya Linux/macOS desteklenmez.
- **Yönetici Yetkisi Zorunludur:** WinDivert çekirdek sürücüsünü yüklemek ve `hosts` dosyasını yönetmek için Administrator hakları şarttır.
- **Antivirüs Uyarıları (Yanlış Pozitif):** WinDivert bir ağ paket yakalama sürücüsü olduğu için bazı antivirüs yazılımları aracı şüpheli veya zararlı olarak işaretleyebilir.
- **Anti-Cheat (Hile Koruma) Çakışmaları:** Easy Anti-Cheat, BattlEye, Riot Vanguard gibi çekirdek düzeyinde çalışan hile koruma sistemleriyle çakışabilir. Oyun başlatmadan önce sürücüyü duraklatmanız veya aracı kapatmanız gerekebilir.
- **İSS ve Bölge Değişkenliği:** DPI donanımları, filtre kuralları ve ağ topolojisi servis sağlayıcıya, şehre veya bağlantı türüne göre farklılık gösterir. Bir hatta çalışan ayarlar başka bir hatta çalışmayabilir.

---

## Bu Araç Sisteminizde Neleri Değiştirir?

1. **WinDivert Çekirdek Sürücüsü:** Paketleri yakalamak ve enjekte etmek için geçici olarak `WinDivert64.sys` sürücüsünü sisteme yükler ve Windows servis kaydı açar.
2. **Windows `hosts` Dosyası:** Belirlenen alan adlarının (örn. Discord, Roblox) temiz IP adreslerini DoH üzerinden çözerek `C:\Windows\System32\drivers\etc\hosts` dosyasına `# BEGIN DPIBYPASS MANAGED HOSTS` ve `# END DPIBYPASS MANAGED HOSTS` etiketleri arasına yazar. Öncesinde orijinal dosyanın yedeğini alır.
3. **Yerel Web Arayüzü:** Durum ve istatistik takibi için yalnızca yerel loopback adresinde (`127.0.0.1:8787`) hafif bir HTTP sunucusu çalıştırır.

### Kurtarma (`recover`) Bu Değişiklikleri Nasıl Geri Alır?
`dpibypass recover` komutu veya `stop-and-recover.bat` çalıştırıldığında:
- `hosts` dosyasındaki `# BEGIN DPIBYPASS MANAGED HOSTS` bloğunu temizler (veya yedekten geri yükler).
- WinDivert sürücü servisini durdurur ve bellekten kaldırır (`sc stop WinDivert` / servis silme).
- Varsa ayarlanmış sistem vekil sunucu (proxy) kayıtlarını temizler.
- Windows DNS önbelleğini temizler (`ipconfig /flushdns`).

---

## Sorumlu Kullanım ve Yasal Uyarı

Bu araç, ağ filtreleme davranışlarını ve DPI teknolojilerini analiz etmek amacıyla eğitim ve test amaçlı geliştirilmiştir. Aracın kullanımından doğabilecek yasal sorumluluklar, servis şartları uyumu ve kullanım şekli tamamen kullanıcıya aittir. Geliştirici hiçbir garanti vermez ve olası kesintilerden veya yazılım çakışmalarından sorumlu tutulamaz.

---

## Temel Mimari ve Özellikler

### 1. WinDivert ABI ile Saf Go Çekirdek Bağlantısı
Geleneksel C derleyicilerine bağımlı olmadan doğrudan Go standart kütüphanesinin sistem çağrıları (syscall) ve yapılandırılmış ABI tanımları üzerinden `WinDivert.dll` ve `WinDivert64.sys` ile haberleşir:
- **64 KiB Ön-Tahsisli Tampon Bellek:** Windows Large Send Offload (LSO/TSO) paket patlamalarını karşılar.
- **Hat Filtreleme:** Hedef dışı ağ trafiğini doğrudan hattan geçirir.

### 2. TLS 1.3 Çok Paketlik (Multi-Packet) SNI Bölümleme
Modern Chromium tabanlı uygulamalar (Discord yerel Electron masaüstü istemcisi dahil), büyük anahtar paylaşımları (örn. `X25519MLKEM768`) nedeniyle ~1.900 bayt boyutunda TLS 1.3 `ClientHello` paketleri gönderebilir.
- **Ön-Bölümlenmiş Paket 2 Takibi:** Windows TCP yığını yükü ağ kartından çıkmadan önce böldüğünde, SNI uzantısı genellikle ikinci pakete denk gelir. `dpibypass`, TCP sıra numaralarını (SeqNum) takip ederek SNI uzantısını tespit eder ve SNI ortasından (`sni-mid`) böler.
- **Sırasız (Out-of-Order) Enjeksiyon:** Segmentleri sırasız ileterek basit middlebox inceleme motorlarının hedef alan adını doğrudan okumasını zorlaştırır.
- **MTU Sınırlandırması:** Enjekte edilen parçaları `<= 1400` bayt sınırında tutarak Ethernet MTU paket düşmelerini önlemeyi hedefler.

### 3. Düşük TTL ile Middlebox Yanıltma (Sahte Paket Enjeksiyonu)
- Gerçek paketle aynı 4'lü demete (Src/Dst IP/Port) ve TCP sıra numarasına sahip, zararsız bir SNI (`www.example.com`) taşıyan geçerli bir TLS `ClientHello` sentezler.
- Sahte paketi düşük bir sekme sayısı (örn. `TTL 3` veya `TTL 4`) ile hatta basarak servis sağlayıcının DPI filtresine ulaşıp hedef sunucuya varmadan hatta sönümlenmesini amaçlar.
- ECMP rota değişimlerine karşı çoklu TTL desteği barındırır.

### 4. DoH Bootstrap ve Windows `hosts` Eşitlemesi
- **DoH Bootstrap:** Anycast IP adreslerine (`1.1.1.1`, `8.8.8.8`) doğrudan HTTPS üzerinden bağlanarak yerel DNS engellemelerini atlatmayı amaçlar.
- **Otomatik `hosts` Eşitlemesi:** Discord ve Roblox alan adları için temiz IPv4 adreslerini çözerek `C:\Windows\System32\drivers\etc\hosts` dosyasındaki yönetilen bloğu günceller.
- **UDP Port 53 Yakalama:** Yerel DNS sorgularını yakalayıp DoH üzerinden yanıt döner.
- **Temiz Kurtarma:** Program kapandığında veya kurtarma modunda `hosts` dosyasını orijinal haline geri döndürür.

### 5. IPv6 Happy Eyeballs Geri Düşüşü (RFC 8305)
Çift yığınlı (dual-stack) modemlerde bağlantıların filtrelenen IPv6 rotasına girmesini önlemek için 80/443 portlarındaki giden IPv6 TCP SYN paketlerini bastırır ve IPv6 DNS sorgularına `NODATA` yanıtı döner. Böylece istemciler IPv4 rotasına yönlendirilir.

### 6. Gömülü Web Arayüzü & Anti-Cheat Güvenli Modu
`127.0.0.1:8787` adresinde çalışan kontrol paneli:
- Canlı istatistikler: yakalanan paketler, sahte paketler, bölünen segmentler ve DoH çözümleri.
- **Anti-Cheat Güvenli Modu (`Pause / Resume Driver`):** Hile koruma yazılımlarıyla çakışma riskini azaltmak için WinDivert sürücüsünü geçici olarak bellekten kaldırır ve istendiğinde tekrar devreye alır.

---

## Hızlı Başlangıç (Tek Tıkla Başlatıcılar)

Tüm toplu iş dosyaları (`.bat`) Windows'ta otomatik olarak Yönetici yetkisine yükselir:

| Betik / Komut | Amaç |
|---|---|
| **`launch-discord.bat`** | **Discord için Başlatıcı.** DNS önbelleğini temizler, alan adlarının temiz çözüldüğünü doğrular, arka planda wire motorunu başlatır ve Discord masaüstü istemcisini açar. |
| **`start-bypass.bat`** | Paket motorunu `http://127.0.0.1:8787` adresindeki Web Arayüzü ile birlikte başlatır. |
| **`stop-and-recover.bat`** | Motoru durdurur, WinDivert sürücüsünü bellekten kaldırır, `hosts` dosyasındaki eklemeleri temizler ve DNS önbelleğini yeniler. |
| **`test-live.ps1`** | **İSS Karşılaştırmalı Test ve Profil Belirleyici.** Farklı sahte paket modlarını ve TTL sekme sayılarını canlı hedefler üzerinde test eden PowerShell aracı. |

---

## Türkiye İSS Uyumluluğu ve Ayarları

Farklı servis sağlayıcıların ağ topolojileri ve DPI kuralları değişiklik gösterebilir:

| İSS / Sağlayıcı | Durum | Strateji / Teknik Notlar |
|---|---|---|
| **Türk Telekom** | Yazar tarafından test edildi | `fake_ttl: 4` ve `sni-mid` ile test edilmiştir. DPI filtresi genellikle 3 veya 4. sekmede bulunur. Sinkhole yönlendirmelerini engeller, temiz IP'leri DoH ile `hosts` dosyasına işler ve düşük TTL sahte paketleriyle incelemeyi atlatmayı dener. |
| **Turkcell Superonline** | Test edilmedi - geri bildirim bekleniyor | Şeffaf UDP 53 yönlendirmesi DoH ve `hosts` eşitlemesi ile hedeflenir. Sekme mesafesi bölgeye göre değişebileceğinden `.\test-live.ps1` veya `tune` ile yerel TTL kalibrasyonu yapılabilir. |
| **Vodafone Net** | Test edilmedi - geri bildirim bekleniyor | QUIC engelleme (`drop_quic: true`), IPv6 TCP SYN bastırma ve kademeli yeniden iletim stratejisi içerir. |
| **Türksat Kablonet** | Test edilmedi - geri bildirim bekleniyor | Sırasız TLS kayıt bölümleme ve DoH-hosts eşitlemesi yapılandırması hedeflenir. |
| **TurkNet** | Test edilmedi - geri bildirim bekleniyor | Standart varsayılan paket profili yapılandırması hedeflenir. |

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
  "hosts_sync": {
    "domains": [
      "discord.com",
      "updates.discord.com",
      "gateway.discord.gg",
      "cdn.discordapp.com",
      "www.roblox.com"
    ]
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

- `hosts_sync.domains`: Başlangıçta DoH üzerinden temiz IP adresleri çözülecek ve Windows `hosts` dosyasındaki `# BEGIN/END DPIBYPASS MANAGED HOSTS` bloğuna işlenecek alan adlarıdır. Belirtilmediğinde varsayılan Discord ve Roblox alan adı listesi kullanılır. `config validate` ile doğrulanabilir (joker karakter `*` desteklenmez; doğrudan alan adı yazılmalıdır).

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
