using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace SwineryAntiCheat.Scanners
{
    public class UsbRecord
    {
        public string DeviceName { get; set; } = string.Empty;
        public string SerialNumber { get; set; } = string.Empty;
        public DateTime LastPluggedTime { get; set; }
    }

    public class HardwareScanner
    {
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        private static extern int RegQueryInfoKey(
            SafeRegistryHandle hKey,
            StringBuilder? lpClass,
            ref uint lpcchClass,
            IntPtr lpReserved,
            out uint lpcSubKeys,
            out uint lpcbMaxSubKeyLen,
            out uint lpcbMaxClassLen,
            out uint lpcValues,
            out uint lpcbMaxValueNameLen,
            out uint lpcbMaxValueLen,
            out uint lpcbSecurityDescriptor,
            out long lpftLastWriteTime);

        private DateTime GetKeyLastWriteTime(RegistryKey key)
        {
            uint lpcchClass = 0;
            long lpftLastWriteTime = 0;
            
            try
            {
                if (!OperatingSystem.IsWindows()) return DateTime.MinValue;

                int result = RegQueryInfoKey(
                    key.Handle, null, ref lpcchClass, IntPtr.Zero,
                    out _, out _, out _, out _, out _, out _, out _,
                    out lpftLastWriteTime);

                if (result == 0 && lpftLastWriteTime > 0)
                {
                    return DateTime.FromFileTime(lpftLastWriteTime);
                }
            }
            catch { }
            return DateTime.MinValue;
        }

        public List<UsbRecord> GetUsbHistory()
        {
            var usbList = new List<UsbRecord>();
            try
            {
                if (!OperatingSystem.IsWindows()) return usbList;

                string usbStorPath = @"SYSTEM\CurrentControlSet\Enum\USBSTOR";
                using (RegistryKey? rootKey = Registry.LocalMachine.OpenSubKey(usbStorPath))
                {
                    if (rootKey != null)
                    {
                        foreach (string deviceType in rootKey.GetSubKeyNames())
                        {
                            using (RegistryKey? deviceKey = rootKey.OpenSubKey(deviceType))
                            {
                                if (deviceKey == null) continue;

                                foreach (string deviceId in deviceKey.GetSubKeyNames())
                                {
                                    using (RegistryKey? idKey = deviceKey.OpenSubKey(deviceId))
                                    {
                                        if (idKey != null)
                                        {
                                            string friendlyName = idKey.GetValue("FriendlyName")?.ToString() ?? deviceType;
                                            DateTime lastTime = GetKeyLastWriteTime(idKey);
                                            
                                            usbList.Add(new UsbRecord
                                            {
                                                DeviceName = friendlyName,
                                                SerialNumber = deviceId,
                                                LastPluggedTime = lastTime
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Hata] USB geçmişi okunurken hata: {ex.Message}");
            }
            return usbList;
        }

        public string GetDnsCache()
        {
            string output = string.Empty;
            try
            {
                var processStartInfo = new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = "/c ipconfig /displaydns",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    StandardOutputEncoding = System.Text.Encoding.UTF8
                };

                using var process = Process.Start(processStartInfo);
                if (process != null)
                {
                    output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Hata] DNS önbelleği okunurken hata: {ex.Message}");
            }
            return output;
        }

        public List<string> ScanLinuxUsbHistory()
        {
            var results = new List<string>();
            if (!OperatingSystem.IsLinux()) return results;

            try
            {
                var processStartInfo = new ProcessStartInfo
                {
                    FileName = "dmesg",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var process = Process.Start(processStartInfo);
                if (process != null)
                {
                    // dmesg çıktısı çok büyük olabilir: satır satır akıtarak okuruz.
                    string? line;
                    while ((line = process.StandardOutput.ReadLine()) != null)
                    {
                        if (line.Contains("usb", StringComparison.OrdinalIgnoreCase) &&
                            line.Contains("SerialNumber:", StringComparison.OrdinalIgnoreCase))
                        {
                            results.Add($"[LINUX USB] {line.Trim()}");
                        }
                    }
                    process.WaitForExit();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Hata] Linux dmesg (USB) okunurken hata: {ex.Message}");
            }
            return results;
        }

        public List<string> RunScan()
        {
            var findings = new List<string>();
            Console.WriteLine("\n[*] Donanım (USB) ve Ağ (DNS) İzleri Taranıyor...");
            Console.WriteLine(new string('-', 70));

            // 1. USB Geçmişi Kontrolü
            var usbHistory = GetUsbHistory().OrderByDescending(u => u.LastPluggedTime).ToList();
            Console.WriteLine($"[Bilgi] Sistemde toplam {usbHistory.Count} adet USB depolama cihazı kaydı bulundu.");
            Console.WriteLine($"\n{"SON İŞLEM",-22} | {"CİHAZ ADI",-30} | {"SERİ NO"}");
            Console.WriteLine(new string('-', 70));

            int displayCount = Math.Min(usbHistory.Count, 5); // Son 5 cihazı gösterelim
            for (int i = 0; i < displayCount; i++)
            {
                string timeStr = usbHistory[i].LastPluggedTime == DateTime.MinValue 
                                 ? "Bilinmiyor" 
                                 : usbHistory[i].LastPluggedTime.ToString("yyyy-MM-dd HH:mm:ss");
                                 
                Console.WriteLine($"  {timeStr,-20} | {usbHistory[i].DeviceName,-30} | {usbHistory[i].SerialNumber}");
            }
            
            if (usbHistory.Count > displayCount)
            {
                Console.WriteLine($"  ... ve {usbHistory.Count - displayCount} cihaz daha.");
            }
            Console.WriteLine();
            
            if (OperatingSystem.IsLinux())
            {
                var linuxUsb = ScanLinuxUsbHistory();
                Console.WriteLine($"[Bilgi] Linux dmesg üzerinden {linuxUsb.Count} adet USB seri no kaydı bulundu.");
                findings.AddRange(linuxUsb);
            }

            // 2. DNS Önbelleği Kontrolü
            Console.WriteLine("[*] DNS Önbelleği Çözümleniyor...");
            string dnsOutput = GetDnsCache();
            bool foundSuspiciousDomain = false;

            if (OperatingSystem.IsWindows() && string.IsNullOrWhiteSpace(dnsOutput))
            {
                Console.WriteLine("[-] DNS önbelleği boş veya DNS Client servisi durdurulmuş.");
            }
            else if (OperatingSystem.IsWindows())
            {
                string[] lines = dnsOutput.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                var resolvedDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                
                foreach (var line in lines)
                {
                    string trimmed = line.Trim();
                    // "Record Name . . . . . : unknowncheats.me" (İngilizce Windows)
                    if (trimmed.StartsWith("Record Name", StringComparison.OrdinalIgnoreCase))
                    {
                        string[] parts = trimmed.Split(new[] { ':' }, 2);
                        if (parts.Length == 2)
                        {
                            resolvedDomains.Add(parts[1].Trim());
                        }
                    }
                    // "Kayıt Adı . . . . . :" (Türkçe Windows)
                    else if (trimmed.StartsWith("Kayıt Adı", StringComparison.OrdinalIgnoreCase) || 
                             trimmed.StartsWith("Kayit Adi", StringComparison.OrdinalIgnoreCase))
                    {
                        string[] parts = trimmed.Split(new[] { ':' }, 2);
                        if (parts.Length == 2)
                        {
                            resolvedDomains.Add(parts[1].Trim());
                        }
                    }
                }

                foreach (var domain in resolvedDomains)
                {
                    bool isSuspicious = BlacklistManager.DnsDomains.Any(s => domain.Contains(s, StringComparison.OrdinalIgnoreCase));
                    if (isSuspicious)
                    {
                        foundSuspiciousDomain = true;
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine($"[!] ŞÜPHELİ AĞ BAĞLANTISI (DNS): {domain}");
                        Console.ResetColor();
                        findings.Add($"[DNS BAĞLANTISI] Çözümlenen Şüpheli Domain: {domain}");
                    }
                }
            }

            if (!foundSuspiciousDomain)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("[+] Ağ izleri temiz. Bilinen hile sağlayıcısı/forum bağlantısı tespit edilmedi.");
                Console.ResetColor();
            }

            Console.WriteLine(new string('-', 70));
            return findings;
        }
    }
}
