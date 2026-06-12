using System;

namespace SwineryAntiCheat
{
    class Program
    {
        static void Main(string[] args)
        {
            // ASCII Logo
            Console.ForegroundColor = ConsoleColor.Cyan;
            string logo = @"
  ____          _                       _    ____ 
 / ___|__      _(_)_ __   ___ _ __ _   / \  / ___|
 \___ \\ \ /\ / / | '_ \ / _ \ '__| | / _ \| |    
  ___) |\ V  V /| | | | |  __/ |  | |/ ___ \ |___ 
 |____/  \_/\_/ |_|_| |_|\___|_|  | /_/   \_\____|
                                 |__/             
";
            Console.WriteLine(logo);
            Console.ResetColor();

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("Tarama Başlatılıyor...");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("--------------------------------------------------");
            Console.WriteLine("              Geliştirici: swinery                ");
            Console.WriteLine("--------------------------------------------------");
            Console.ResetColor();
            
            // Basit Başlangıç Menüsü
            Console.WriteLine("[1] Taramayı Başlat");
            Console.WriteLine("[2] Çıkış");
            Console.Write("Seçiminiz: ");
            
            string? input = Console.ReadLine();
            
            if (input == "1")
            {
                Console.WriteLine("\nSistem taranıyor... (Bu işlem yönetici / root hakları gerektirir)\n");
                
                SwineryAntiCheat.Scanners.BlacklistManager.LoadBlacklist();

                if (OperatingSystem.IsWindows())
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("[+] Windows İşletim Sistemi Tespit Edildi. Taramalar Windows mimarisine göre başlatılıyor...\n");
                    Console.ResetColor();
                }
                else if (OperatingSystem.IsLinux())
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("[+] Linux İşletim Sistemi Tespit Edildi. Taramalar Linux (Kernel) mimarisine göre başlatılıyor...\n");
                    Console.ResetColor();
                }
                else
                {
                    Console.WriteLine("[!] Desteklenmeyen bir işletim sistemi! Taramalar eksik sonuç verebilir.");
                }
                
                System.Collections.Generic.List<string> allFindings = new System.Collections.Generic.List<string>();

                Console.WriteLine("[1/5] Dosya Geçmişi Taranıyor...");
                var fileScanner = new SwineryAntiCheat.Scanners.FileScanner();
                allFindings.AddRange(fileScanner.RunScan());

                Console.WriteLine("\n[2/5] Süreç (Process) ve Gizli Pencereler Taranıyor...");
                var processScanner = new SwineryAntiCheat.Scanners.ProcessScanner();
                allFindings.AddRange(processScanner.RunScan());

                Console.WriteLine("\n[3/5] Donanım ve Ağ İzleri Taranıyor...");
                var hardwareScanner = new SwineryAntiCheat.Scanners.HardwareScanner();
                allFindings.AddRange(hardwareScanner.RunScan());

                Console.WriteLine("\n[4/5] Aktif Ağ Bağlantıları (TCP/UDP) Taranıyor...");
                var networkScanner = new SwineryAntiCheat.Scanners.NetworkScanner();
                allFindings.AddRange(networkScanner.RunScan());

                Console.WriteLine("\n[5/5] Kernel Sürücüleri (BYOVD) Taranıyor...");
                var driverScanner = new SwineryAntiCheat.Scanners.DriverScanner();
                allFindings.AddRange(driverScanner.RunScan());

                // Rapor Dosyasını Oluşturma
                string desktopPath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
                string reportPath = System.IO.Path.Combine(desktopPath, "SwineryAC_Tarama_Raporu.txt");
                
                using (System.IO.StreamWriter writer = new System.IO.StreamWriter(reportPath))
                {
                    writer.WriteLine("========================================");
                    writer.WriteLine("          Swinery AC Tarama Raporu      ");
                    writer.WriteLine("========================================");
                    writer.WriteLine($"Tarih/Saat  : {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                    writer.WriteLine($"Kullanıcı   : {Environment.UserName}");
                    writer.WriteLine($"Bilgisayar  : {Environment.MachineName}");
                    writer.WriteLine("========================================\n");

                    if (allFindings.Count > 0)
                    {
                        writer.WriteLine("ŞÜPHELİ BULGULAR (RED FLAGS):");
                        writer.WriteLine("----------------------------------------");
                        foreach (var finding in allFindings)
                        {
                            writer.WriteLine(finding);
                        }
                    }
                    else
                    {
                        writer.WriteLine("Herhangi bir şüpheli ize rastlanmadı. Sistem temiz.");
                    }
                }

                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine($"\n[✓] TARAMA TAMAMLANDI! Rapor masaüstüne kaydedildi:");
                Console.WriteLine($"    Dosya Yolu: {reportPath}");
                Console.ResetColor();
            }
            else
            {
                Console.WriteLine("\nÇıkılıyor...");
            }
            
            Console.WriteLine("\nDevam etmek için bir tuşa basın...");
            Console.ReadKey();
        }
    }
}
