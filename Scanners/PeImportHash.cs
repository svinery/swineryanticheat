using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace SwineryAntiCheat.Scanners
{
    // KATMAN 3: imphash (Import Hash) — PE'nin import tablosunun MD5'i.
    // İçerik repack/crypter ile değişse bile aynı derleme zinciri/aynı API çağrıları
    // genelde aynı import sırasını korur => imphash sabit kalır. Böylece SHA256'nın
    // kaçırdığı polimorf varyantlar yakalanabilir (endüstri standardı: pefile.get_imphash()).
    //
    // Harici bağımlılık eklemeden elle PE parse edilir. Her hata durumunda null döner
    // (bozuk/PE olmayan dosya => imphash yok, çökme yok).
    public static class PeImportHash
    {
        // Çok büyük dosyaları belleğe almamak için imphash üst sınırı (loader'lar küçüktür).
        private const int MaxBytesForImphash = 64 * 1024 * 1024;

        // pefile davranışı: yalnızca bu uzantılar küçük harfe çevrilip kütüphane adından atılır.
        private static readonly string[] StrippedExtensions = { ".ocx", ".sys", ".dll" };

        public static string? TryCompute(string filePath)
        {
            string? input = TryBuildImportString(filePath);
            if (string.IsNullOrEmpty(input)) return null;
            byte[] md5 = MD5.HashData(Encoding.ASCII.GetBytes(input));
            return Convert.ToHexString(md5); // büyük harf hex; karşılaştırma OrdinalIgnoreCase
        }

        // imphash'in MD5'ten önceki ham girdi dizisini döndürür (kütüphane.fonksiyon, virgülle).
        // Operatör blacklist kurarken doğrulamak için faydalı; pefile çıktısıyla bire bir karşılaştırılır.
        internal static string? TryBuildImportString(string filePath)
        {
            try
            {
                var info = new System.IO.FileInfo(filePath);
                if (info.Length < 64 || info.Length > MaxBytesForImphash) return null;

                byte[] data = System.IO.File.ReadAllBytes(filePath);
                return BuildImportString(data);
            }
            catch
            {
                return null; // erişim/IO/parse hatası => imphash yok
            }
        }

        private static string? BuildImportString(byte[] data)
        {
            // --- DOS header ---
            if (data.Length < 0x40 || data[0] != 'M' || data[1] != 'Z') return null;
            int peOffset = ReadInt32(data, 0x3C);
            if (peOffset <= 0 || peOffset + 24 > data.Length) return null;

            // --- PE signature ---
            if (data[peOffset] != 'P' || data[peOffset + 1] != 'E' ||
                data[peOffset + 2] != 0 || data[peOffset + 3] != 0) return null;

            int coff = peOffset + 4;
            int numberOfSections = ReadUInt16(data, coff + 2);
            int sizeOfOptionalHeader = ReadUInt16(data, coff + 16);
            int optionalHeader = coff + 20;
            if (optionalHeader + sizeOfOptionalHeader > data.Length) return null;

            // --- Optional header: PE32 mi PE32+ mı? ---
            int magic = ReadUInt16(data, optionalHeader);
            bool isPe32Plus = magic == 0x20b;
            if (magic != 0x10b && magic != 0x20b) return null;

            // Data directory'ler optional header içinde sabit ofsette başlar.
            int dataDirOffset = optionalHeader + (isPe32Plus ? 112 : 96);
            // Index 1 = Import Directory.
            int importDirEntry = dataDirOffset + 1 * 8;
            if (importDirEntry + 8 > data.Length) return null;
            int importRva = ReadInt32(data, importDirEntry);
            if (importRva == 0) return null; // import yok

            // --- Section header tablosu (RVA -> dosya ofseti çevirimi için) ---
            int sectionTable = optionalHeader + sizeOfOptionalHeader;
            var sections = ReadSections(data, sectionTable, numberOfSections);
            if (sections.Count == 0) return null;

            int importOffset = RvaToOffset(importRva, sections, data.Length);
            if (importOffset < 0) return null;

            // --- Import descriptor'lar (20 byte; tamamı sıfır olan ile biter) ---
            var entries = new List<string>();
            int descPtr = importOffset;
            int guard = 0;
            while (descPtr + 20 <= data.Length && guard++ < 4096)
            {
                int originalFirstThunk = ReadInt32(data, descPtr + 0);
                int nameRva = ReadInt32(data, descPtr + 12);
                int firstThunk = ReadInt32(data, descPtr + 16);

                if (originalFirstThunk == 0 && nameRva == 0 && firstThunk == 0) break; // sonlandırıcı

                string rawLib = ReadRawLibName(data, nameRva, sections); // uzantı dahil, küçük harf
                if (string.IsNullOrEmpty(rawLib)) { descPtr += 20; continue; }
                string libName = StripExtension(rawLib); // imphash girdisinde uzantısız kullanılır

                int thunkRva = originalFirstThunk != 0 ? originalFirstThunk : firstThunk;
                AppendThunkFunctions(data, thunkRva, sections, libName, rawLib, isPe32Plus, entries);

                descPtr += 20;
            }

            if (entries.Count == 0) return null;
            return string.Join(",", entries);
        }

        private static void AppendThunkFunctions(byte[] data, int thunkRva, List<Section> sections,
                                                 string libName, string rawLib, bool isPe32Plus, List<string> entries)
        {
            int thunkOffset = RvaToOffset(thunkRva, sections, data.Length);
            if (thunkOffset < 0) return;

            int thunkSize = isPe32Plus ? 8 : 4;
            ulong ordinalFlag = isPe32Plus ? 0x8000000000000000UL : 0x80000000UL;

            int ptr = thunkOffset;
            int guard = 0;
            while (ptr + thunkSize <= data.Length && guard++ < 65536)
            {
                ulong thunk = isPe32Plus ? ReadUInt64(data, ptr) : (uint)ReadInt32(data, ptr);
                if (thunk == 0) break; // thunk dizisi sonu

                string funcName;
                if ((thunk & ordinalFlag) != 0)
                {
                    // Ordinal ile import: pefile bilinen DLL'lerde (oleaut32/ws2_32) gerçek isme çevirir,
                    // bulamazsa "ord{n}" kullanır. imphash'i pefile ile aynı tutmak için aynısını yaparız.
                    int ordinal = (int)(thunk & 0xFFFF);
                    funcName = OrdinalLookup.Resolve(rawLib, ordinal) ?? $"ord{ordinal}";
                }
                else
                {
                    // İsim ile import: RVA -> IMAGE_IMPORT_BY_NAME (2 byte hint + ASCII ad).
                    int byNameOffset = RvaToOffset((int)(thunk & 0x7FFFFFFF), sections, data.Length);
                    if (byNameOffset < 0 || byNameOffset + 2 >= data.Length) { ptr += thunkSize; continue; }
                    funcName = ReadAsciiString(data, byNameOffset + 2);
                }

                if (!string.IsNullOrEmpty(funcName))
                {
                    entries.Add($"{libName}.{funcName.ToLowerInvariant()}");
                }
                ptr += thunkSize;
            }
        }

        // Kütüphane adını uzantısıyla, küçük harf olarak okur (ordinal tablosu seçimi için gerekir).
        private static string ReadRawLibName(byte[] data, int nameRva, List<Section> sections)
        {
            int offset = RvaToOffset(nameRva, sections, data.Length);
            if (offset < 0) return string.Empty;
            return ReadAsciiString(data, offset).ToLowerInvariant();
        }

        // pefile uyumlu uzantı atma (.ocx/.sys/.dll).
        private static string StripExtension(string name)
        {
            foreach (var ext in StrippedExtensions)
            {
                if (name.EndsWith(ext, StringComparison.Ordinal))
                {
                    return name.Substring(0, name.Length - ext.Length);
                }
            }
            return name;
        }

        // --- Yardımcılar ---

        private readonly struct Section
        {
            public readonly int VirtualAddress;
            public readonly int VirtualSize;
            public readonly int PointerToRawData;
            public readonly int SizeOfRawData;
            public Section(int va, int vs, int ptr, int raw)
            {
                VirtualAddress = va; VirtualSize = vs; PointerToRawData = ptr; SizeOfRawData = raw;
            }
        }

        private static List<Section> ReadSections(byte[] data, int sectionTable, int count)
        {
            var list = new List<Section>();
            for (int i = 0; i < count; i++)
            {
                int baseOff = sectionTable + i * 40;
                if (baseOff + 40 > data.Length) break;
                int virtualSize = ReadInt32(data, baseOff + 8);
                int virtualAddress = ReadInt32(data, baseOff + 12);
                int sizeOfRawData = ReadInt32(data, baseOff + 16);
                int pointerToRawData = ReadInt32(data, baseOff + 20);
                list.Add(new Section(virtualAddress, virtualSize, pointerToRawData, sizeOfRawData));
            }
            return list;
        }

        private static int RvaToOffset(int rva, List<Section> sections, int fileLength)
        {
            foreach (var s in sections)
            {
                int size = Math.Max(s.VirtualSize, s.SizeOfRawData);
                if (rva >= s.VirtualAddress && rva < s.VirtualAddress + size)
                {
                    int offset = rva - s.VirtualAddress + s.PointerToRawData;
                    return (offset >= 0 && offset < fileLength) ? offset : -1;
                }
            }
            return -1;
        }

        private static string ReadAsciiString(byte[] data, int offset)
        {
            if (offset < 0 || offset >= data.Length) return string.Empty;
            int end = offset;
            while (end < data.Length && data[end] != 0) end++;
            return Encoding.ASCII.GetString(data, offset, end - offset);
        }

        private static int ReadInt32(byte[] data, int offset) =>
            BitConverter.ToInt32(data, offset);

        private static ushort ReadUInt16(byte[] data, int offset) =>
            BitConverter.ToUInt16(data, offset);

        private static ulong ReadUInt64(byte[] data, int offset) =>
            BitConverter.ToUInt64(data, offset);
    }
}
