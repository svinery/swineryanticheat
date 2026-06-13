# Swinery Anti-Cheat (Cross-Platform Forensics Tool)

Swinery Anti-Cheat, hem **Windows** hem de **Linux** işletim sistemlerinde çalışabilen, sunucu yöneticileri ve adli bilişim (forensics) analistleri için geliştirilmiş gelişmiş bir sistem tarama ve güvenlik denetim aracıdır. Başta CS2 olmak üzere rekabetçi oyun sunucularında şüpheli oyuncuların bilgisayarlarını derinlemesine analiz etmek için tasarlanmıştır.

## 🌟 Özellikler

Swinery AC, sistemin en derin noktalarına inerek potansiyel güvenlik ihlallerini, hile yazılımlarını (cheats), ve yetki yükseltme (BYOVD) girişimlerini tespit eder:

* **🛠️ File & History Scanner:** Linux'ta `bash/zsh` geçmişini tarar, Windows'ta `Prefetch` kalıntılarını analiz ederek silinmiş hileleri bulur.
* **⚙️ Process & Memory Scanner:** Gizli pencereleri, arka planda çalışan süreçleri ve Linux bellek haritalarını (`/proc/[PID]/maps`) tarayarak enjekte edilmiş kütüphaneleri (`.so` / `.dll`) tespit eder.
* **🔌 Hardware & USB Scanner:** Linux çekirdek mesajlarını (`dmesg`) ve Windows Kayıt Defterini okuyarak sisteme takılıp çıkarılan şüpheli USB cihazlarını (DMA donanımları vb.) ve seri numaralarını listeler.
* **🌐 Network Scanner:** Aktif soket bağlantılarını (`ss -tuap` / Windows API) dinleyerek kara listedeki bilinen hile sunucularına yapılan bağlantıları anında yakalar.
* **🛡️ Kernel Driver Scanner:** Linux çekirdek modüllerini (`lsmod`) ve Windows WMI sürücülerini tarayarak Ring0 (Kernel) seviyesindeki Rootkit ve savunmasız sürücü (BYOVD) istismarlarını ortaya çıkarır.

## 🚀 Derleme ve Kurulum

Swinery AC, .NET 8 altyapısı kullanılarak geliştirilmiştir. Kendi makinenizde bağımsız (Self-Contained) ve tek dosya (Single-File) olarak derlemek için terminalde şu komutları kullanabilirsiniz:

**Linux İçin:**
```bash
dotnet publish -c Release -r linux-x64 --self-contained true -p:PublishSingleFile=true
```

**Windows İçin:**
```bash
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true
```

Çıktılar `bin/Release/net8.0/` klasörü altında bulunacaktır.

## 📖 Kullanım

1. Derlenen dosyayı (Örn: `ELDENCS.exe` veya Linux için `ELDENCS`) şüpheli bilgisayara indirin.
2. `blacklist.txt` dosyasının programla aynı dizinde olduğundan emin olun.
3. Aracı **Yönetici (Administrator)** veya Linux üzerinde **Root (sudo)** yetkileriyle çalıştırın.
4. Tarama tamamlandığında masaüstünüze detaylı bir `.txt` analiz raporu kaydedilecektir.

## ⚠️ Uyarı ve Feragatname
Bu yazılım tamamen sunucu güvenliği ve sistem yönetimi amacıyla geliştirilmiştir. Yasadışı veri toplama işlemleri için kullanılamaz. Tüm sorumluluk son kullanıcıya aittir.

---
*Geliştirici: **swinery***
*Discord : zswi
