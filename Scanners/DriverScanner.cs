using System;
using System.Collections.Generic;
using System.Management;

namespace SwineryAntiCheat.Scanners
{
    public class DriverRecord
    {
        public string Name { get; set; } = string.Empty;
        public string DisplayName { get; set; } = string.Empty;
        public string PathName { get; set; } = string.Empty;
        public string State { get; set; } = string.Empty;
    }

    public class DriverScanner
    {
        public List<DriverRecord> GetRunningDrivers()
        {
            var drivers = new List<DriverRecord>();
            try
            {
                if (!OperatingSystem.IsWindows()) return drivers;

                // WMI sorgusu ile çalışan servis/sürücüleri çekme
                ObjectQuery query = new ObjectQuery("SELECT * FROM Win32_SystemDriver WHERE State = 'Running'");
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(query))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        string name = obj["Name"]?.ToString() ?? string.Empty;
                        string displayName = obj["DisplayName"]?.ToString() ?? string.Empty;
                        string pathName = obj["PathName"]?.ToString() ?? string.Empty;
                        string state = obj["State"]?.ToString() ?? string.Empty;

                        drivers.Add(new DriverRecord
                        {
                            Name = name,
                            DisplayName = displayName,
                            PathName = pathName,
                            State = state
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Hata] Sürücüler okunurken hata (System.Management WMI yetkisi gerekebilir): {ex.Message}");
            }
            return drivers;
        }

        public List<string> ScanLinuxKernelModules()
        {
            var results = new List<string>();
            if (!OperatingSystem.IsLinux()) return results;

            try
            {
                var processStartInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "lsmod",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var process = System.Diagnostics.Process.Start(processStartInfo);
                if (process != null)
                {
                    // lsmod çıktısını satır satır akıtarak okuruz.
                    string? line;
                    while ((line = process.StandardOutput.ReadLine()) != null)
                    {
                        bool isSuspicious = BlacklistManager.VulnerableDrivers.Any(d =>
                            line.Contains(d.Replace(".sys", "", StringComparison.OrdinalIgnoreCase), StringComparison.OrdinalIgnoreCase));

                        if (isSuspicious)
                        {
                            results.Add($"[LINUX KERNEL MODÜLÜ] Şüpheli: {line.Trim()}");
                        }
                    }
                    process.WaitForExit();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Hata] Linux kernel modülleri (lsmod) okunurken hata: {ex.Message}");
            }
            return results;
        }

        public List<string> RunScan()
        {
            var findings = new List<string>();
            Console.WriteLine("\n[*] Kernel Sürücüleri (BYOVD Analizi) Taranıyor...");
            Console.WriteLine(new string('-', 70));

            var runningDrivers = GetRunningDrivers();
            Console.WriteLine($"[Bilgi] Sistemde toplam {runningDrivers.Count} adet aktif çekirdek (kernel) sürücüsü bulundu.");

            bool foundVulnerable = false;

            foreach (var driver in runningDrivers)
            {
                bool isVulnerable = false;

                foreach (var vulDriver in BlacklistManager.VulnerableDrivers)
                {
                    if (driver.Name.Contains(vulDriver, StringComparison.OrdinalIgnoreCase) ||
                        driver.DisplayName.Contains(vulDriver, StringComparison.OrdinalIgnoreCase) ||
                        driver.PathName.Contains(vulDriver, StringComparison.OrdinalIgnoreCase))
                    {
                        isVulnerable = true;
                        break;
                    }
                }

                if (isVulnerable)
                {
                    foundVulnerable = true;
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"[!] ŞÜPHELİ SÜRÜCÜ (BYOVD) TESPİT EDİLDİ: {driver.Name} | Yol: {driver.PathName}");
                    Console.ResetColor();

                    findings.Add($"[KERNEL DRIVER] Şüpheli Ring 0 Sürücüsü: {driver.Name,-15} | Yol: {driver.PathName}");
                }
            }

            if (!foundVulnerable && !OperatingSystem.IsLinux())
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("[+] Kernel sürücüleri temiz. Bilinen savunmasız sürücü (BYOVD) izine rastlanmadı.");
                Console.ResetColor();
            }

            if (OperatingSystem.IsLinux())
            {
                var linuxModules = ScanLinuxKernelModules();
                if (linuxModules.Count > 0)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"[!] LINUX KERNEL'İNDE ŞÜPHELİ MODÜLLER (.ko) BULUNDU! Toplam: {linuxModules.Count}");
                    Console.ResetColor();
                    findings.AddRange(linuxModules);
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("[+] Linux kernel modülleri temiz.");
                    Console.ResetColor();
                }
            }

            Console.WriteLine(new string('-', 70));
            return findings;
        }
    }
}
