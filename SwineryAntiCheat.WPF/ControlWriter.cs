using System;
using System.IO;
using System.Text;

namespace SwineryAntiCheat.WPF
{
    // Console.Out'u arayüze köprüler: scanner'ların Console.WriteLine ile bastığı
    // her satır (tablolar, bilgi/uyarı satırları dahil) UI callback'ine iletilir.
    // Böylece Scanner sınıflarını hiç değiştirmeden tüm çıktı GUI'de görünür.
    public class ControlWriter : TextWriter
    {
        private readonly Action<string> _onLine;
        private readonly StringBuilder _buffer = new StringBuilder();

        public ControlWriter(Action<string> onLine) => _onLine = onLine;

        public override Encoding Encoding => Encoding.UTF8;

        public override void Write(char value)
        {
            if (value == '\n')
            {
                EmitLine();
            }
            else if (value != '\r') // \r'yi yut; satır sonu yalnız \n ile tetiklenir
            {
                _buffer.Append(value);
            }
        }

        public override void Write(string? value)
        {
            if (string.IsNullOrEmpty(value)) return;
            foreach (char c in value)
            {
                Write(c);
            }
        }

        // Tamponda biriken satırı tek seferde gönderir.
        private void EmitLine()
        {
            _onLine(_buffer.ToString());
            _buffer.Clear();
        }

        // Akış sonunda newline ile bitmeyen artık metin kaybolmasın.
        public override void Flush()
        {
            if (_buffer.Length > 0)
            {
                EmitLine();
            }
        }
    }
}
