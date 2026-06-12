using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace SwineryAntiCheat.Scanners
{
    public class ProcessRecord
    {
        public int ProcessId { get; set; }
        public string ProcessName { get; set; } = string.Empty;
    }

    public class HiddenWindowRecord
    {
        public IntPtr Hwnd { get; set; }
        public string WindowTitle { get; set; } = string.Empty;
        public int ProcessId { get; set; }
    }

    public class ProcessScanner
    {
        // Windows API Imports (user32.dll)
        private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

        [DllImport("user32.dll")]
        private static extern bool EnumWindows(EnumWindowsProc enumProc, IntPtr lParam);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool IsWindowVisible(IntPtr hWnd);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern int GetWindowText(IntPtr hWnd, StringBuilder strText, int maxCount);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern int GetWindowTextLength(IntPtr hWnd);

        [DllImport("user32.dll")]
        private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

        public List<ProcessRecord> GetRunningProcesses()
        {
            var results = new List<ProcessRecord>();
            try
            {
                var processes = Process.GetProcesses();
                foreach (var p in processes)
                {
                    try
                    {
                        results.Add(new ProcessRecord
                        {
                            ProcessId = p.Id,
                            ProcessName = p.ProcessName
                        });
                    }
                    catch { } // Erişim reddedilen işlemler atlanır
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Hata] Process listesi alınırken hata: {ex.Message}");
            }
            return results;
        }

        public List<HiddenWindowRecord> GetHiddenWindows()
        {
            var hiddenWindows = new List<HiddenWindowRecord>();

            if (!OperatingSystem.IsWindows()) return hiddenWindows;

            EnumWindowsProc enumProc = (hWnd, lParam) =>
            {
                bool isVisible = IsWindowVisible(hWnd);
                
                // Sadece gizli (görünmez) pencerelerle ilgileniyoruz
                if (!isVisible)
                {
                    int length = GetWindowTextLength(hWnd);
                    if (length > 0)
                    {
                        StringBuilder sb = new StringBuilder(length + 1);
                        GetWindowText(hWnd, sb, sb.Capacity);
                        string title = sb.ToString();

                        // Başlığı olan gizli pencereleri filtreleyelim
                        if (!string.IsNullOrWhiteSpace(title) && title != "Default IME" && title != "MSCTFIME UI")
                        {
                            GetWindowThreadProcessId(hWnd, out uint processId);
                            hiddenWindows.Add(new HiddenWindowRecord
                            {
                                Hwnd = hWnd,
                                WindowTitle = title,
                                ProcessId = (int)processId
                            });
                        }
                    }
                }
                return true; // Taramaya devam et
            };

            EnumWindows(enumProc, IntPtr.Zero);
            return hiddenWindows;
        }

        public List<string> ScanLinuxProcMaps()
        {
            var results = new List<string>();
            if (!OperatingSystem.IsLinux()) return results;

            try
            {
                foreach (var dir in System.IO.Directory.GetDirectories("/proc"))
                {
                    // /proc altında sadece sayısal (PID) dizinleri işle.
                    string pidStr = System.IO.Path.GetFileName(dir);
                    if (!int.TryParse(pidStr, out int pid)) continue;

                    string mapsPath = System.IO.Path.Combine(dir, "maps");
                    if (System.IO.File.Exists(mapsPath))
                    {
                        ScanSingleProcMaps(pid, mapsPath, results);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Hata] Linux bellek (maps) taranırken hata: {ex.Message}");
            }
            return results;
        }

        // Tek bir /proc/<pid>/maps dosyasını akış halinde okur, şüpheli .so kütüphanelerini bulur.
        private void ScanSingleProcMaps(int pid, string mapsPath, List<string> results)
        {
            try
            {
                // File.ReadLines: satır satır akış; büyük maps dosyalarında belleği şişirmez.
                foreach (var line in System.IO.File.ReadLines(mapsPath))
                {
                    if (!line.Contains(".so", StringComparison.OrdinalIgnoreCase)) continue;

                    bool isSuspicious = BlacklistManager.ProcessAndFileKeywords.Any(k =>
                        line.Contains(k, StringComparison.OrdinalIgnoreCase));

                    if (isSuspicious)
                    {
                        results.Add($"[LINUX MEMORY] PID: {pid,-6} | Kütüphane (.so): {line}");
                    }
                }
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or System.IO.IOException)
            {
                // Erişim reddi / yarışta sonlanan süreç: bu PID'i atla, taramaya devam et.
            }
        }

        public List<string> RunScan()
        {
            var findings = new List<string>();
            Console.WriteLine("\n[*] Çalışan Süreçler (Processes) ve Gizli Pencereler Taranıyor...");
            Console.WriteLine(new string('-', 70));

            var processes = GetRunningProcesses();
            var hiddenWindows = GetHiddenWindows();

            // 1. Blacklist Kontrolü
            bool foundSuspiciousProcess = false;

            foreach (var p in processes)
            {
                bool isBlacklisted = BlacklistManager.ProcessAndFileKeywords.Any(b => 
                    p.ProcessName.Contains(b, StringComparison.OrdinalIgnoreCase));

                if (isBlacklisted)
                {
                    foundSuspiciousProcess = true;
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"[!] ŞÜPHELİ SÜREÇ BULUNDU: PID: {p.ProcessId,-6} | Adı: {p.ProcessName}");
                    Console.ResetColor();
                    findings.Add($"[PROCESS] PID: {p.ProcessId,-6} | Adı: {p.ProcessName}");
                }
            }

            if (!foundSuspiciousProcess)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("[+] Çalışan süreçler temiz, kara listedeki yazılımlara rastlanmadı.");
                Console.ResetColor();
            }

            Console.WriteLine();

            // 2. Gizli Pencere (Hidden Window) Kontrolü
            bool foundSuspiciousWindow = false;
            Console.WriteLine($"[Bilgi] Sistemde toplam {hiddenWindows.Count} adet başlığı olan gizli pencere tespit edildi.");

            foreach (var hw in hiddenWindows)
            {
                bool isSuspiciousTitle = BlacklistManager.ProcessAndFileKeywords.Any(s => 
                    hw.WindowTitle.Contains(s, StringComparison.OrdinalIgnoreCase));

                if (isSuspiciousTitle)
                {
                    foundSuspiciousWindow = true;
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"[!] ŞÜPHELİ GİZLİ PENCERE: PID: {hw.ProcessId,-6} | Başlık: \"{hw.WindowTitle}\"");
                    Console.ResetColor();
                    findings.Add($"[GİZLİ PENCERE] PID: {hw.ProcessId,-6} | Başlık: \"{hw.WindowTitle}\"");
                }
            }

            if (!foundSuspiciousWindow)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("[+] Gizli pencereler temiz, şüpheli (hile menüsü vb.) başlık bulunamadı.");
                Console.ResetColor();
            }

            if (OperatingSystem.IsLinux())
            {
                var linuxMapsFindings = ScanLinuxProcMaps();
                if (linuxMapsFindings.Count > 0)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"[!] LINUX BELLEKTE ŞÜPHELİ (.so) KÜTÜPHANELER BULUNDU! Toplam: {linuxMapsFindings.Count}");
                    Console.ResetColor();
                    findings.AddRange(linuxMapsFindings);
                }
            }
            Console.WriteLine(new string('-', 70));
            return findings;
        }
    }
}
