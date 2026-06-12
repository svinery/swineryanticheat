using System;
using System.Collections.Generic;

namespace SwineryAntiCheat.Scanners
{
    // İsim tabanlı sezgisel (heuristik) tespit.
    // Bazı hileler her indirildiğinde rastgele bir ada bürünür (afa8fy92988q9ahag.exe gibi).
    // Statik kara liste bunları kaçırır; burada ismin "rastgele/telaffuz edilemez"
    // olup olmadığını istatistiksel sinyallerle puanlarız.
    public static class NameHeuristics
    {
        private const string Vowels = "aeiou";

        // Shannon entropisi: karakter çeşitliliği ölçüsü. Rastgele alfanümerik
        // diziler yüksek (~3.3+ bit), gerçek kelimeler düşük entropi üretir.
        public static double ShannonEntropy(string text)
        {
            if (string.IsNullOrEmpty(text)) return 0;

            var counts = new Dictionary<char, int>();
            foreach (char c in text)
            {
                counts[c] = counts.TryGetValue(c, out int n) ? n + 1 : 1;
            }

            double entropy = 0;
            int length = text.Length;
            foreach (var pair in counts)
            {
                double probability = (double)pair.Value / length;
                entropy -= probability * Math.Log2(probability);
            }
            return entropy;
        }

        // İsmin rastgele üretilmiş gibi görünüp görünmediğini puan tabanlı değerlendirir.
        // Tek bir sinyal yanılabilir; bu yüzden 2+ sinyal birleşince işaretleriz (yanlış pozitifi azaltır).
        public static bool IsLikelyRandom(string nameWithoutExtension, out string reason)
        {
            reason = string.Empty;
            string name = (nameWithoutExtension ?? string.Empty).Trim().ToLowerInvariant();

            // Çok kısa isimler güvenilir sinyal vermez (svchost, cmd vb. de kısa).
            if (name.Length < 8) return false;

            int letterCount = 0;
            int vowelCount = 0;
            int digitCount = 0;
            int maxConsonantRun = 0;
            int currentRun = 0;

            foreach (char c in name)
            {
                if (c >= '0' && c <= '9')
                {
                    digitCount++;
                    currentRun = 0;
                }
                else if (c >= 'a' && c <= 'z')
                {
                    letterCount++;
                    if (Vowels.IndexOf(c) >= 0)
                    {
                        vowelCount++;
                        currentRun = 0;
                    }
                    else
                    {
                        currentRun++;
                        if (currentRun > maxConsonantRun) maxConsonantRun = currentRun;
                    }
                }
                else
                {
                    // Ayraç / ascii dışı: dizi sayacını sıfırla.
                    currentRun = 0;
                }
            }

            double entropy = ShannonEntropy(name);
            double vowelRatio = letterCount > 0 ? (double)vowelCount / letterCount : 0;

            // Sinyaller — her biri 1 puan:
            int score = 0;
            if (entropy >= 3.3) score++;                                   // yüksek karakter çeşitliliği
            if (letterCount >= 6 && vowelRatio < 0.25) score++;            // telaffuz edilemez (sesli az)
            if (maxConsonantRun >= 5) score++;                            // arka arkaya çok sessiz harf
            if (digitCount > 0 && letterCount > 0 && name.Length >= 12) score++; // uzun harf+rakam karışımı

            if (score >= 2)
            {
                reason = $"entropi={entropy:F2}, sesliOran={vowelRatio:F2}, sessizDizi={maxConsonantRun}, uzunluk={name.Length}";
                return true;
            }
            return false;
        }
    }
}
