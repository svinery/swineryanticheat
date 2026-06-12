using System;
using System.IO;
using System.Windows;
using System.Windows.Threading;

namespace SwineryAntiCheat.WPF
{
    public partial class App : Application
    {
        // Başlangıçta sessiz çökmeyi önlemek için: yakalanmayan tüm hataları
        // exe'nin yanına log dosyası yazıp kullanıcıya MessageBox ile göster.
        protected override void OnStartup(StartupEventArgs e)
        {
            DispatcherUnhandledException += (_, args) =>
            {
                LogAndShow(args.Exception);
                args.Handled = true; // uygulamayı ayakta tut
            };
            AppDomain.CurrentDomain.UnhandledException += (_, args) =>
            {
                if (args.ExceptionObject is Exception ex) LogAndShow(ex);
            };
            base.OnStartup(e);
        }

        private static void LogAndShow(Exception ex)
        {
            try
            {
                string path = Path.Combine(AppContext.BaseDirectory, "swineryac_crash.txt");
                File.WriteAllText(path, $"{DateTime.Now:yyyy-MM-dd HH:mm:ss}\n\n{ex}");
            }
            catch
            {
                // log yazılamazsa yine de kullanıcıya göstermeye çalış
            }

            MessageBox.Show(ex.Message, "SwineryAC - Başlatma Hatası",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }
}
