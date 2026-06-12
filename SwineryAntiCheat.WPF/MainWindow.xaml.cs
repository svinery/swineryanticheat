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

            AppendLog("[*] Swinery Anti-Cheat Başlatıldı...", false);
            
            _cts = new CancellationTokenSource();
            
            try
            {
                await Task.Run(() => RunScanners(_cts.Token), _cts.Token);
                TxtStatus.Text = "Tarama tamamlandı.";
                ScanProgressBar.Value = 100;
            }
            catch (OperationCanceledException)
            {
                AppendLog("[UYARI] Tarama iptal edildi.", false);
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
            Action<string, bool> uiCallback = (message, isWarning) => 
            {
                AppendLog(message, isWarning);
            };

            // 2. Try-catch blokları ile modülleri koruma
            try
            {
                token.ThrowIfCancellationRequested();
                UpdateProgress(30, "Bellek ve Süreçler Taranıyor...");
                var processScanner = new ProcessScanner();
                var processFindings = processScanner.RunScan();
                if (processFindings.Count == 0) uiCallback("[+] Bellek modülleri ve gizli pencereler temiz.", false);
                else foreach(var f in processFindings) uiCallback(f, true);
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception) { uiCallback("[UYARI] Process modülü yetki hatası nedeniyle atlandı.", false); }

            try
            {
                token.ThrowIfCancellationRequested();
                UpdateProgress(50, "Dosya Sistemi Taranıyor...");
                var fileScanner = new FileScanner();
                var fileFindings = fileScanner.RunScan();
                if (fileFindings.Count == 0) uiCallback("[+] Dosya sistemi temiz.", false);
                else foreach(var f in fileFindings) uiCallback(f, true);
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception) { uiCallback("[UYARI] File modülü yetki hatası nedeniyle atlandı.", false); }

            try
            {
                token.ThrowIfCancellationRequested();
                UpdateProgress(70, "Kernel Sürücüleri Taranıyor...");
                var driverScanner = new DriverScanner();
                var driverFindings = driverScanner.RunScan();
                if (driverFindings.Count == 0) uiCallback("[+] Kernel sürücüleri temiz.", false);
                else foreach(var f in driverFindings) uiCallback(f, true);
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception) { uiCallback("[UYARI] Driver modülü yetki hatası nedeniyle atlandı.", false); }

            try
            {
                token.ThrowIfCancellationRequested();
                UpdateProgress(90, "Ağ Bağlantıları Kontrol Ediliyor...");
                var networkScanner = new NetworkScanner();
                var netFindings = networkScanner.RunScan();
                if (netFindings.Count == 0) uiCallback("[+] Şüpheli ağ bağlantısı yok.", false);
                else foreach(var f in netFindings) uiCallback(f, true);
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception) { uiCallback("[UYARI] Network modülü yetki hatası nedeniyle atlandı.", false); }

            token.ThrowIfCancellationRequested();
            UpdateProgress(100, "Rapor Oluşturuluyor...");
            uiCallback("[*] Tarama işlemleri sonlandırıldı.", false);
        }

        private void AppendLog(string message, bool isWarning)
        {
            Dispatcher.Invoke(() =>
            {
                SolidColorBrush color = isWarning ? Brushes.Red : Brushes.LimeGreen;
                if (message.Contains("[*]")) color = Brushes.Cyan;
                if (message.Contains("[UYARI]")) color = Brushes.Gray; // Gri renk yetki/iptal uyarıları için

                Run run = new Run(message + "\n") { Foreground = color };
                LogParagraph.Inlines.Add(run);
                RtbLogs.ScrollToEnd();
            });
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
