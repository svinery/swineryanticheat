using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Documents;
using System.Windows.Media;
using SwineryAntiCheat.Scanners;

namespace SwineryAntiCheat.WPF
{
    public partial class MainWindow : Window
    {
        private CancellationTokenSource? _cts;
        private readonly List<string> _allFindings = new();
        private string? _reportPath;

        public MainWindow()
        {
            InitializeComponent();
            BlacklistManager.LoadBlacklist();
        }

        // Kapatılırken arkaplan görevini iptal et.
        protected override void OnClosed(EventArgs e)
        {
            _cts?.Cancel();
            base.OnClosed(e);
        }

        private async void BtnStartScan_Click(object sender, RoutedEventArgs e)
        {
            // Yeni tarama için durumu sıfırla.
            BtnStartScan.IsEnabled = false;
            BtnOpenReport.IsEnabled = false;
            _allFindings.Clear();
            _reportPath = null;
            TxtThreatCount.Text = "0";
            TxtThreatCount.Foreground = Brushes.LimeGreen;
            LogParagraph.Inlines.Clear();
            UpdateProgress(10, "Tarama yürütülüyor...");

            AppendLog("[*] Swinery Anti-Cheat Başlatıldı...");

            _cts = new CancellationTokenSource();

            try
            {
                await Task.Run(() => RunScanners(_cts.Token), _cts.Token);
                UpdateProgress(100, "Tarama tamamlandı.");
            }
            catch (OperationCanceledException)
            {
                AppendLog("[UYARI] Tarama iptal edildi.");
                TxtStatus.Text = "İptal edildi.";
            }
            finally
            {
                BtnStartScan.IsEnabled = true;
                _cts.Dispose();
                _cts = null;
            }
        }

        private void RunScanners(CancellationToken token)
        {
            // Scanner sınıfları çıktıyı Console'a basıyor. Console.Out'u arayüze köprüleyerek
            // tüm tablo/bilgi/uyarı satırlarını (sadece findings değil) GUI'de gösteriyoruz.
            TextWriter originalOut = Console.Out;
            Console.SetOut(new ControlWriter(line => AppendLog(line)));

            try
            {
                RunModule(token, 30, "Bellek ve Süreçler Taranıyor...", () => new ProcessScanner().RunScan(), "Process");
                RunModule(token, 50, "Dosya Sistemi Taranıyor...", () => new FileScanner().RunScan(), "File");
                RunModule(token, 70, "Kernel Sürücüleri Taranıyor...", () => new DriverScanner().RunScan(), "Driver");
                RunModule(token, 90, "Ağ Bağlantıları Kontrol Ediliyor...", () => new NetworkScanner().RunScan(), "Network");

                token.ThrowIfCancellationRequested();
                UpdateProgress(95, "Rapor Oluşturuluyor...");
                AppendLog("[*] Tarama işlemleri sonlandırıldı.");
                SaveReportToDesktop();
            }
            finally
            {
                // Console.Out'u her durumda eski haline döndür.
                Console.SetOut(originalOut);
            }
        }

        // Tek bir tarama modülünü çalıştırır; bulguları toplar, iptal'i yukarı taşır, diğer hataları izole eder.
        private void RunModule(CancellationToken token, int progress, string status,
                               Func<List<string>> scan, string moduleName)
        {
            try
            {
                token.ThrowIfCancellationRequested();
                UpdateProgress(progress, status);
                List<string> findings = scan(); // Çıktı Console köprüsü üzerinden zaten UI'a akıyor.
                if (findings.Count > 0)
                {
                    _allFindings.AddRange(findings);
                    UpdateThreatCount();
                }
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception)
            {
                AppendLog($"[UYARI] {moduleName} modülü yetki hatası nedeniyle atlandı.");
            }
        }

        // Tarama sonucunu masaüstüne .txt rapor olarak yazar ve "Raporu Aç" butonunu etkinleştirir.
        private void SaveReportToDesktop()
        {
            try
            {
                string desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
                if (string.IsNullOrEmpty(desktop))
                    desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);

                string path = Path.Combine(desktop, "SwineryAC_Tarama_Raporu.txt");

                var sb = new StringBuilder();
                sb.AppendLine("========================================");
                sb.AppendLine("        Swinery AC Tarama Raporu        ");
                sb.AppendLine("========================================");
                sb.AppendLine($"Tarih/Saat : {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                sb.AppendLine($"Kullanıcı  : {Environment.UserName}");
                sb.AppendLine($"Bilgisayar : {Environment.MachineName}");
                sb.AppendLine($"Tespit     : {_allFindings.Count} şüpheli bulgu");
                sb.AppendLine("========================================");
                sb.AppendLine();

                if (_allFindings.Count > 0)
                {
                    sb.AppendLine("ŞÜPHELİ BULGULAR (RED FLAGS):");
                    sb.AppendLine("----------------------------------------");
                    foreach (string finding in _allFindings)
                        sb.AppendLine(finding);
                }
                else
                {
                    sb.AppendLine("Herhangi bir şüpheli ize rastlanmadı. Sistem temiz.");
                }

                File.WriteAllText(path, sb.ToString());
                _reportPath = path;

                Dispatcher.Invoke(() => BtnOpenReport.IsEnabled = true);
                AppendLog($"[+] Rapor masaüstüne kaydedildi: {path}");
            }
            catch (Exception ex)
            {
                AppendLog($"[Hata] Rapor kaydedilemedi: {ex.Message}");
            }
        }

        private void BtnOpenReport_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(_reportPath) || !File.Exists(_reportPath)) return;
            try
            {
                Process.Start(new ProcessStartInfo(_reportPath) { UseShellExecute = true });
            }
            catch (Exception ex)
            {
                AppendLog($"[Hata] Rapor açılamadı: {ex.Message}");
            }
        }

        private void AppendLog(string message)
        {
            Dispatcher.Invoke(() =>
            {
                Run run = new Run(message + "\n") { Foreground = ResolveColor(message) };
                LogParagraph.Inlines.Add(run);
                RtbLogs.ScrollToEnd();
            });
        }

        // Satır önekine göre renk seçer (Console'daki ForegroundColor mantığının karşılığı).
        private static SolidColorBrush ResolveColor(string message)
        {
            if (message.Contains("[!]")) return Brushes.Red;          // Şüpheli bulgu
            if (message.Contains("[+]")) return Brushes.LimeGreen;    // Temiz / başarılı
            if (message.Contains("[Hata]")) return Brushes.OrangeRed; // Okuma/erişim hatası
            if (message.Contains("[UYARI]")) return Brushes.Gray;     // Yetki/iptal uyarısı
            if (message.Contains("[*]") || message.Contains("[Bilgi]")) return Brushes.Cyan;
            return Brushes.Gainsboro;                                  // Tablo satırları / nötr
        }

        private void UpdateThreatCount()
        {
            Dispatcher.Invoke(() =>
            {
                TxtThreatCount.Text = _allFindings.Count.ToString();
                TxtThreatCount.Foreground = _allFindings.Count > 0 ? Brushes.Red : Brushes.LimeGreen;
            });
        }

        private void UpdateProgress(int value, string status)
        {
            Dispatcher.Invoke(() =>
            {
                ScanProgressBar.Value = value;
                TxtPercent.Text = $"%{value}";
                TxtStatus.Text = status;
            });
        }
    }
}
