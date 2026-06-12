using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.Win32;

namespace SwineryAntiCheat.Scanners
{
    public class ScanRecord
    {
        public string ExecutableName { get; set; } = string.Empty;
        public DateTime ExecutionTime { get; set; }
        public string Source { get; set; } = string.Empty;
    }

    public class FileScanner
    {
        private readonly string[] SuspiciousKeywords = { "cheat", "aim", "injector", "bypass", "hack", "loader" };

        public List<ScanRecord> ScanPrefetch()
        {
            var results = new List<ScanRecord>();
            if (!OperatingSystem.IsWindows()) return results;
            try
            {
                string prefetchPath = @"C:\Windows\Prefetch";
                if (Directory.Exists(prefetchPath))
                {
                    var files = Directory.GetFiles(prefetchPath, "*.pf");
                    DateTime threshold = DateTime.Now.AddHours(-48);

                    foreach (var file in files)
                    {
                        var fileInfo = new FileInfo(file);
                        if (fileInfo.LastWriteTime >= threshold || fileInfo.CreationTime >= threshold)
                        {
                            string execName = Path.GetFileNameWithoutExtension(fileInfo.Name);
                            int dashIndex = execName.LastIndexOf('-');
                            if (dashIndex > 0)
                            {
                                execName = execName.Substring(0, dashIndex);
                            }

                            results.Add(new ScanRecord
                            {
                                ExecutableName = execName,
                                ExecutionTime = fileInfo.LastWriteTime > fileInfo.CreationTime ? fileInfo.LastWriteTime : fileInfo.CreationTime,
                                Source = "Prefetch"
                            });
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Hata] Prefetch taranırken hata oluştu (Yönetici izni olmayabilir): {ex.Message}");
            }
            return results;
        }

        public List<ScanRecord> ScanBAM()
        {
            var results = new List<ScanRecord>();
            try
            {
                if (!OperatingSystem.IsWindows()) return results;

                string bamPath = @"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings";
                using (RegistryKey? rootKey = Registry.LocalMachine.OpenSubKey(bamPath))
                {
                    if (rootKey != null)
                    {
                        foreach (string sid in rootKey.GetSubKeyNames())
                        {
                            using (RegistryKey? userKey = rootKey.OpenSubKey(sid))
                            {
                                if (userKey == null) continue;

                                foreach (string valueName in userKey.GetValueNames())
                                {
                                    if (valueName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                                    {
                                        byte[]? data = userKey.GetValue(valueName) as byte[];
                                        DateTime execTime = DateTime.MinValue;
                                        
                                        // BAM stores FILETIME in the first 8 bytes of the binary data
                                        if (data != null && data.Length >= 8)
                                        {
                                            try
                                            {
                                                long fileTime = BitConverter.ToInt64(data, 0);
                                                if (fileTime > 0)
                                                    execTime = DateTime.FromFileTime(fileTime);
                                            }
                                            catch { }
                                        }

                                        results.Add(new ScanRecord
                                        {
                                            ExecutableName = Path.GetFileName(valueName),
                                            ExecutionTime = execTime,
                                            Source = $"BAM"
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Hata] BAM taranırken hata oluştu: {ex.Message}");
            }
            return results;
        }

        public List<ScanRecord> ScanUserAssist()
        {
            var results = new List<ScanRecord>();
            try
            {
                if (!OperatingSystem.IsWindows()) return results;

                string userAssistPath = @"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";
                using (RegistryKey? rootKey = Registry.CurrentUser.OpenSubKey(userAssistPath))
                {
                    if (rootKey != null)
                    {
                        foreach (string guid in rootKey.GetSubKeyNames())
                        {
                            using (RegistryKey? countKey = rootKey.OpenSubKey($@"{guid}\Count"))
                            {
                                if (countKey == null) continue;

                                foreach (string valueName in countKey.GetValueNames())
                                {
                                    string decodedName = DecodeROT13(valueName);
                                    if (decodedName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                                    {
                                        byte[]? data = countKey.GetValue(valueName) as byte[];
                                        DateTime execTime = DateTime.MinValue;
                                        
                                        // UserAssist typically stores execution time at offset 60 (0x3C)
                                        if (data != null && data.Length >= 68) 
                                        {
                                            try
                                            {
                                                long fileTime = BitConverter.ToInt64(data, 60);
                                                if (fileTime > 0)
                                                    execTime = DateTime.FromFileTimeUtc(fileTime).ToLocalTime();
                                            }
                                            catch { }
                                        }

                                        results.Add(new ScanRecord
                                        {
                                            ExecutableName = Path.GetFileName(decodedName),
                                            ExecutionTime = execTime,
                                            Source = "UserAssist"
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Hata] UserAssist taranırken hata oluştu: {ex.Message}");
            }
            return results;
        }

        public List<ScanRecord> ScanLinuxHistory()
        {
            var results = new List<ScanRecord>();
            if (!OperatingSystem.IsLinux()) return results;

            try
            {
                string homeDir = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                string[] historyFiles = { ".bash_history", ".zsh_history" };

                foreach (var histFile in historyFiles)
                {
                    string path = Path.Combine(homeDir, histFile);
                    if (File.Exists(path))
                    {
                        ScanHistoryFile(path, histFile, results);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Hata] Linux komut geçmişi taranırken hata: {ex.Message}");
            }
            return results;
        }

        // Tek bir history dosyasını akış halinde okur. Dosya okunamazsa diğerleri etkilenmez.
        private void ScanHistoryFile(string path, string sourceName, List<ScanRecord> results)
        {
            try
            {
                // File.ReadLines: satır satır akış; büyük history dosyalarında belleği şişirmez.
                foreach (var line in File.ReadLines(path))
                {
                    bool isSuspicious = BlacklistManager.ProcessAndFileKeywords.Any(k =>
                        line.Contains(k, StringComparison.OrdinalIgnoreCase));

                    if (!isSuspicious) continue;

                    results.Add(new ScanRecord
                    {
                        ExecutableName = line.Length > 50 ? line.Substring(0, 50) + "..." : line,
                        ExecutionTime = DateTime.MinValue,
                        Source = sourceName
                    });
                }
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
            {
                Console.WriteLine($"[Atlandı] '{sourceName}' okunamadı (erişim/IO): {ex.Message}");
            }
        }

        private string DecodeROT13(string input)
        {
            char[] array = input.ToCharArray();
            for (int i = 0; i < array.Length; i++)
            {
                int number = (int)array[i];

                if (number >= 'a' && number <= 'z')
                {
                    if (number > 'm') number -= 13;
                    else number += 13;
                }
                else if (number >= 'A' && number <= 'Z')
                {
                    if (number > 'M') number -= 13;
                    else number += 13;
                }
                array[i] = (char)number;
            }
            return new string(array);
        }

        public List<string> RunScan()
        {
            var findings = new List<string>();
            Console.WriteLine("\n[*] Dosya ve Kayıt Defteri İzleri Taranıyor...");

            var allRecords = new List<ScanRecord>();
            
            if (OperatingSystem.IsWindows())
            {
                allRecords.AddRange(ScanPrefetch());
                allRecords.AddRange(ScanBAM());
                allRecords.AddRange(ScanUserAssist());
            }
            else if (OperatingSystem.IsLinux())
            {
                allRecords.AddRange(ScanLinuxHistory());
            }

            // Aynı isim+kaynaklı kayıtları teke indir ve en yeni tarihe göre sırala.
            // Adımlara bölündü ki her aşama (filtre -> grupla -> en yeniyi seç -> sırala) açık olsun.
            var namedRecords = allRecords
                .Where(r => !string.IsNullOrWhiteSpace(r.ExecutableName));

            var deduplicatedRecords = namedRecords
                .GroupBy(r => new { r.ExecutableName, r.Source })
                .Select(group => group.OrderByDescending(x => x.ExecutionTime).First());

            var uniqueRecords = deduplicatedRecords
                .OrderByDescending(r => r.ExecutionTime)
                .ToList();

            Console.WriteLine($"\n[+] Toplam {uniqueRecords.Count} benzersiz iz bulundu. Şüpheli dosyalar kontrol ediliyor...\n");
            Console.WriteLine($"{"TARİH",-22} | {"DOSYA ADI",-30} | {"KAYNAK"}");
            Console.WriteLine(new string('-', 70));

            foreach (var record in uniqueRecords)
            {
                bool isSuspicious = BlacklistManager.ProcessAndFileKeywords.Any(k => 
                    record.ExecutableName.Contains(k, StringComparison.OrdinalIgnoreCase));

                string timeStr = record.ExecutionTime == DateTime.MinValue ? "Bilinmiyor" : record.ExecutionTime.ToString("yyyy-MM-dd HH:mm:ss");

                if (isSuspicious)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"[!] {timeStr,-18} | {record.ExecutableName,-30} | {record.Source}");
                    Console.ResetColor();
                    findings.Add($"[DOSYA] Tarih: {timeStr,-19} | Dosya: {record.ExecutableName,-25} | Kaynak: {record.Source}");
                }
                else
                {
                    Console.WriteLine($"    {timeStr,-18} | {record.ExecutableName,-30} | {record.Source}");
                }
            }
            return findings;
        }
    }
}
