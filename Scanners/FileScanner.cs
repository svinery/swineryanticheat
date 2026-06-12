using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
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

        // --- KATMAN 2: İçerik (hash) tabanlı tespit ---
        // Dosya adı her indirmede değişse bile içerik aynıysa SHA256 sabit kalır.

        // Dosyanın SHA256'sını AKIŞ halinde hesaplar; tüm dosyayı belleğe almaz (büyük .exe'lerde önemli).
        private string ComputeSha256(string path)
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            byte[] hash = SHA256.HashData(stream); // .NET 8: stream'i parça parça okur
            return Convert.ToHexString(hash);      // büyük harf hex; karşılaştırma OrdinalIgnoreCase
        }

        // Hilelerin sıkça düştüğü dizinler (indirme/geçici/çalıştırma konumları), platforma göre.
        private IEnumerable<string> GetDirectoriesToHashScan()
        {
            var dirs = new List<string>();
            string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

            if (!string.IsNullOrEmpty(home))
            {
                dirs.Add(Path.Combine(home, "Downloads"));
                dirs.Add(Path.Combine(home, "Desktop"));
            }

            if (OperatingSystem.IsWindows())
            {
                dirs.Add(Path.GetTempPath()); // %LOCALAPPDATA%\Temp
                string appData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                if (!string.IsNullOrEmpty(appData)) dirs.Add(appData);
            }
            else if (OperatingSystem.IsLinux())
            {
                dirs.Add("/tmp");
                dirs.Add("/dev/shm");
            }

            return dirs.Where(Directory.Exists).Distinct();
        }

        // Bir çalıştırılabilir mi? (Win: .exe/.dll/.scr | Linux: .so/.ko/.elf veya uzantısız ELF olabilir)
        private bool IsExecutableCandidate(string path)
        {
            string ext = Path.GetExtension(path).ToLowerInvariant();
            return ext is ".exe" or ".dll" or ".scr" or ".so" or ".ko" or ".elf" or ".bin";
        }

        // Şüpheli dizinlerdeki çalıştırılabilirleri hash'ler; bilinen-kötü hash veya rastgele ad ile işaretler.
        public List<string> ScanSuspiciousDirectories()
        {
            var findings = new List<string>();
            const long maxFileSizeBytes = 150 * 1024 * 1024; // 150MB üstünü atla (performans)

            foreach (var dir in GetDirectoriesToHashScan())
            {
                IEnumerable<string> files;
                try
                {
                    // Sadece üst seviye; alt dizinlerde kaybolmamak ve izin hatalarını sınırlamak için.
                    files = Directory.EnumerateFiles(dir, "*", SearchOption.TopDirectoryOnly);
                }
                catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
                {
                    continue; // dizin okunamadı, atla
                }

                foreach (var file in files)
                {
                    if (!IsExecutableCandidate(file)) continue;
                    InspectFileByHash(file, maxFileSizeBytes, findings);
                }
            }

            return findings;
        }

        // Tek bir dosyayı hash + ad sezgisiyle inceler. Okunamayan dosyalar atlanır (çökme yok).
        private void InspectFileByHash(string file, long maxFileSizeBytes, List<string> findings)
        {
            try
            {
                var info = new FileInfo(file);
                if (info.Length == 0 || info.Length > maxFileSizeBytes) return;

                string hash = ComputeSha256(file);
                string fileName = Path.GetFileName(file);

                if (BlacklistManager.KnownBadHashes.Contains(hash))
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"[!] BİLİNEN ZARARLI HASH: {fileName} | SHA256: {hash}");
                    Console.ResetColor();
                    findings.Add($"[HASH] Bilinen zararlı dosya: {fileName} | Yol: {file} | SHA256: {hash}");
                    return;
                }

                // KATMAN 3: imphash — içerik repack edilip SHA256 değişse bile import tablosu aynıysa yakalar.
                if (BlacklistManager.KnownBadImphashes.Count > 0)
                {
                    string? imphash = PeImportHash.TryCompute(file);
                    if (imphash != null && BlacklistManager.KnownBadImphashes.Contains(imphash))
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine($"[!] BİLİNEN ZARARLI IMPHASH (polimorf varyant): {fileName} | Imphash: {imphash}");
                        Console.ResetColor();
                        findings.Add($"[IMPHASH] Bilinen zararlı import tablosu: {fileName} | Yol: {file} | Imphash: {imphash} | SHA256: {hash}");
                        return;
                    }
                }

                // Hash listede yok ama adı rastgele görünüyorsa: ad+konum birleşimi şüphe yaratır.
                string nameNoExt = Path.GetFileNameWithoutExtension(fileName);
                if (NameHeuristics.IsLikelyRandom(nameNoExt, out string reason))
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine($"[!] RASTGELE ADLI ÇALIŞTIRILABİLİR: {fileName} | SHA256: {hash}");
                    Console.ResetColor();
                    findings.Add($"[HASH+RASTGELE İSİM] {fileName} | Yol: {file} | SHA256: {hash} | Sinyaller: {reason}");
                }
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
            {
                // Kilitli / izin yok / yarışta silinmiş: bu dosyayı atla, taramaya devam et.
            }
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
                    continue;
                }

                // Kara listeye takılmadıysa: ismin rastgele üretilmiş gibi görünüp görünmediğini denetle.
                // (afa8fy92988q9ahag.exe gibi her indirmede değişen isimleri yakalamak için.)
                // Boşluk içerenler komut satırıdır (örn. bash_history), dosya adı değil → heuristik uygulanmaz.
                string nameNoExt = Path.GetFileNameWithoutExtension(record.ExecutableName);
                bool looksLikeFileName = !record.ExecutableName.Contains(' ');
                if (looksLikeFileName && NameHeuristics.IsLikelyRandom(nameNoExt, out string reason))
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine($"[!] {timeStr,-18} | {record.ExecutableName,-30} | {record.Source} (RASTGELE İSİM)");
                    Console.ResetColor();
                    findings.Add($"[DOSYA-RASTGELE İSİM] Tarih: {timeStr,-19} | Dosya: {record.ExecutableName,-25} | Kaynak: {record.Source} | Sinyaller: {reason}");
                }
                else
                {
                    Console.WriteLine($"    {timeStr,-18} | {record.ExecutableName,-30} | {record.Source}");
                }
            }

            // KATMAN 2: indirme/geçici dizinlerdeki dosyaları içerik hash'iyle tara (ad değişse de yakala).
            Console.WriteLine("\n[*] İndirme/geçici dizinler içerik hash'i (SHA256) ile taranıyor...");
            var hashFindings = ScanSuspiciousDirectories();
            if (hashFindings.Count == 0)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("[+] Hash taraması temiz. Bilinen zararlı içerik veya rastgele adlı çalıştırılabilir bulunamadı.");
                Console.ResetColor();
            }
            else
            {
                findings.AddRange(hashFindings);
            }

            return findings;
        }
    }
}
