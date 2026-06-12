using System;
using System.Collections.Generic;
using System.IO;

namespace SwineryAntiCheat.Scanners
{
    public static class BlacklistManager
    {
        public static HashSet<string> ProcessAndFileKeywords { get; private set; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public static HashSet<string> DnsDomains { get; private set; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public static HashSet<string> VulnerableDrivers { get; private set; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // Bilinen-kötü dosya içerik hash'leri (SHA256). Dosya adı değişse de içerik aynıysa yakalanır.
        public static HashSet<string> KnownBadHashes { get; private set; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        public static void LoadBlacklist()
        {
            string filePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "blacklist.txt");

            if (!File.Exists(filePath))
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("[!] Uyarı: 'blacklist.txt' dosyası bulunamadı. Lütfen program klasöründe olduğundan emin olun.");
                Console.WriteLine("[!] Tarama sınırlı yeteneklerle (dahili kısa liste ile) devam edecek...\n");
                Console.ResetColor();
                LoadDefaults();
                return;
            }

            try
            {
                string currentSection = "";
                // File.ReadLines: satırları lazy (akış halinde) okur, tüm dosyayı belleğe almaz.
                foreach (var line in File.ReadLines(filePath))
                {
                    string trimmed = line.Trim();
                    if (string.IsNullOrWhiteSpace(trimmed) || trimmed.StartsWith("#") || trimmed.StartsWith("//"))
                        continue;

                    if (trimmed.StartsWith("[") && trimmed.EndsWith("]"))
                    {
                        currentSection = trimmed.ToUpperInvariant();
                        continue;
                    }

                    switch (currentSection)
                    {
                        case "[PROCESS_AND_FILE]":
                            ProcessAndFileKeywords.Add(trimmed);
                            break;
                        case "[DNS_DOMAINS]":
                            DnsDomains.Add(trimmed);
                            break;
                        case "[DRIVERS_BYOVD]":
                            VulnerableDrivers.Add(trimmed);
                            break;
                        case "[HASHES]":
                            // Boşluk/ayraç temizle; karşılaştırma OrdinalIgnoreCase olduğu için büyük/küçük fark etmez.
                            KnownBadHashes.Add(trimmed.Replace(" ", "").Replace(":", ""));
                            break;
                    }
                }
                
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"[+] Kara liste (blacklist.txt) başarıyla yüklendi!");
                Console.WriteLine($"    -> {ProcessAndFileKeywords.Count} Dosya/Süreç, {DnsDomains.Count} Domain, {VulnerableDrivers.Count} Sürücü (BYOVD), {KnownBadHashes.Count} Hash kuralı aktif.\n");
                Console.ResetColor();
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                Console.WriteLine($"[Hata] blacklist.txt okunamadı (erişim/IO): {ex.Message}");
                LoadDefaults();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Hata] blacklist.txt okunurken sorun oluştu: {ex.Message}");
                LoadDefaults();
            }
        }

        private static void LoadDefaults()
        {
            ProcessAndFileKeywords = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "cheat", "aim", "injector", "bypass", "hack", "loader" };
            DnsDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "unknowncheats", "mpgh", "aimware" };
            VulnerableDrivers = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "capcom.sys", "gdrv.sys", "iqvw64e.sys" };
        }
    }
}
