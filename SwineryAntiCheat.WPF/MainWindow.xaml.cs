using System;
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

        public MainWindow()
        {
            InitializeComponent();
            BlacklistManager.LoadBlacklist();
        }

        // 3. Kapatılırken arkaplan görevini iptal etme
        protected override void OnClosed(EventArgs e)
        {
            _cts?.Cancel();
            base.OnClosed(e);
        }

        private async void BtnStartScan_Click(object sender, RoutedEventArgs e)
        {
            // 1. Buton tıklanmasını devre dışı bırak
            BtnStartScan.IsEnabled = false;
            TxtStatus.Text = "Tarama yürütülüyor...";
            ScanProgressBar.Value = 10;
            LogParagraph.Inlines.Clear();

            AppendLog("[*] Swinery Anti-Cheat Başlatıldı...");
            
            _cts = new CancellationTokenSource();
            
            try
            {
                await Task.Run(() => RunScanners(_cts.Token), _cts.Token);
                TxtStatus.Text = "Tarama tamamlandı.";
                ScanProgressBar.Value = 100;
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
                UpdateProgress(100, "Rapor Oluşturuluyor...");
                AppendLog("[*] Tarama işlemleri sonlandırıldı.");
            }
            finally
            {
                // Console.Out'u her durumda eski haline döndür.
                Console.SetOut(originalOut);
            }
        }

        // Tek bir tarama modülünü çalıştırır; iptal'i yukarı taşır, diğer hataları izole eder.
        private void RunModule(CancellationToken token, int progress, string status,
                               Func<List<string>> scan, string moduleName)
        {
            try
            {
                token.ThrowIfCancellationRequested();
                UpdateProgress(progress, status);
                scan(); // Çıktı Console köprüsü üzerinden zaten UI'a akıyor.
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception)
            {
                AppendLog($"[UYARI] {moduleName} modülü yetki hatası nedeniyle atlandı.");
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

        private void UpdateProgress(int value, string status)
        {
            Dispatcher.Invoke(() =>
            {
                ScanProgressBar.Value = value;
                TxtStatus.Text = status;
            });
        }
    }
}
