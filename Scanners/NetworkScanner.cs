using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;

namespace SwineryAntiCheat.Scanners
{
    public class NetworkConnection
    {
        public string Protocol { get; set; } = string.Empty;
        public string ProcessName { get; set; } = string.Empty;
        public int ProcessId { get; set; }
        public string LocalAddress { get; set; } = string.Empty;
        public ushort LocalPort { get; set; }
        public string RemoteAddress { get; set; } = string.Empty;
        public ushort RemotePort { get; set; }
        public string State { get; set; } = string.Empty;
    }

    public class NetworkScanner
    {
        // --- Windows API Tanımlamaları ---
        public enum TcpTableClass { TCP_TABLE_OWNER_PID_ALL = 5 }
        public enum UdpTableClass { UDP_TABLE_OWNER_PID = 1 }

        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_TCPROW_OWNER_PID
        {
            public uint state;
            public uint localAddr;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)] public byte[] localPort;
            public uint remoteAddr;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)] public byte[] remotePort;
            public uint owningPid;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_UDPROW_OWNER_PID
        {
            public uint localAddr;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)] public byte[] localPort;
            public uint owningPid;
        }

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int dwOutBufLen, bool sort, int ipVersion, TcpTableClass tblClass, uint reserved = 0);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedUdpTable(IntPtr pUdpTable, ref int dwOutBufLen, bool sort, int ipVersion, UdpTableClass tblClass, uint reserved = 0);

        // --- Şüpheli IP ve Port Listesi ---
        // (Bu listeleri kendi anti-hile veritabanına göre genişletebilirsin)
        private readonly HashSet<string> SuspiciousIPs = new HashSet<string>
        {
            "104.21.36.216", // Örnek IP 1 (UnknownCheats CF)
            "185.152.65.112",// Örnek IP 2
            "45.13.22.11"    // Örnek IP 3
        };

        private readonly HashSet<ushort> SuspiciousPorts = new HashSet<ushort>
        {
            1337, 31337, 6667, 8888, 9999, 4444 // Genelde reverse shell veya injector haberleşme portları
        };

        public enum TcpState
        {
            Closed = 1, Listen = 2, SynSent = 3, SynRcvd = 4, Established = 5,
            FinWait1 = 6, FinWait2 = 7, CloseWait = 8, Closing = 9, LastAck = 10,
            TimeWait = 11, DeleteTcb = 12
        }

        // 1. TCP Bağlantılarını Çek
        private List<NetworkConnection> GetTcpConnections()
        {
            var connections = new List<NetworkConnection>();
            if (!OperatingSystem.IsWindows()) return connections;

            int bufferSize = 0;
            GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, 2 /* AF_INET */, TcpTableClass.TCP_TABLE_OWNER_PID_ALL);
            IntPtr tcpTablePtr = Marshal.AllocHGlobal(bufferSize);
            
            try
            {
                uint result = GetExtendedTcpTable(tcpTablePtr, ref bufferSize, true, 2, TcpTableClass.TCP_TABLE_OWNER_PID_ALL);
                if (result == 0) 
                {
                    int numEntries = Marshal.ReadInt32(tcpTablePtr);
                    IntPtr rowPtr = IntPtr.Add(tcpTablePtr, 4);

                    for (int i = 0; i < numEntries; i++)
                    {
                        var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                        
                        string localIp = new IPAddress(row.localAddr).ToString();
                        string remoteIp = new IPAddress(row.remoteAddr).ToString();
                        ushort localPort = (ushort)(row.localPort[0] << 8 | row.localPort[1]);
                        ushort remotePort = (ushort)(row.remotePort[0] << 8 | row.remotePort[1]);

                        connections.Add(new NetworkConnection
                        {
                            Protocol = "TCP",
                            ProcessId = (int)row.owningPid,
                            ProcessName = GetProcessName((int)row.owningPid),
                            LocalAddress = localIp,
                            LocalPort = localPort,
                            RemoteAddress = remoteIp,
                            RemotePort = remotePort,
                            State = ((TcpState)row.state).ToString()
                        });

                        rowPtr = IntPtr.Add(rowPtr, Marshal.SizeOf<MIB_TCPROW_OWNER_PID>());
                    }
                }
            }
            finally { Marshal.FreeHGlobal(tcpTablePtr); }
            return connections;
        }

        // 2. UDP Dinleyicilerini Çek
        private List<NetworkConnection> GetUdpConnections()
        {
            var connections = new List<NetworkConnection>();
            if (!OperatingSystem.IsWindows()) return connections;

            int bufferSize = 0;
            GetExtendedUdpTable(IntPtr.Zero, ref bufferSize, true, 2 /* AF_INET */, UdpTableClass.UDP_TABLE_OWNER_PID);
            IntPtr udpTablePtr = Marshal.AllocHGlobal(bufferSize);

            try
            {
                uint result = GetExtendedUdpTable(udpTablePtr, ref bufferSize, true, 2, UdpTableClass.UDP_TABLE_OWNER_PID);
                if (result == 0)
                {
                    int numEntries = Marshal.ReadInt32(udpTablePtr);
                    IntPtr rowPtr = IntPtr.Add(udpTablePtr, 4);

                    for (int i = 0; i < numEntries; i++)
                    {
                        var row = Marshal.PtrToStructure<MIB_UDPROW_OWNER_PID>(rowPtr);
                        
                        string localIp = new IPAddress(row.localAddr).ToString();
                        ushort localPort = (ushort)(row.localPort[0] << 8 | row.localPort[1]);

                        connections.Add(new NetworkConnection
                        {
                            Protocol = "UDP",
                            ProcessId = (int)row.owningPid,
                            ProcessName = GetProcessName((int)row.owningPid),
                            LocalAddress = localIp,
                            LocalPort = localPort,
                            RemoteAddress = "N/A", // UDP is connectionless
                            RemotePort = 0,
                            State = "Listening"
                        });

                        rowPtr = IntPtr.Add(rowPtr, Marshal.SizeOf<MIB_UDPROW_OWNER_PID>());
                    }
                }
            }
            finally { Marshal.FreeHGlobal(udpTablePtr); }
            return connections;
        }

        private string GetProcessName(int pid)
        {
            if (pid == 0) return "System Idle Process";
            if (pid == 4) return "System";
            try
            {
                var process = Process.GetProcessById(pid);
                return process.ProcessName;
            }
            catch { return "Bilinmiyor"; }
        }

        public List<string> ScanLinuxNetwork()
        {
            var results = new List<string>();
            if (!OperatingSystem.IsLinux()) return results;

            try
            {
                var processStartInfo = new ProcessStartInfo
                {
                    FileName = "ss",
                    Arguments = "-tuap",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var process = Process.Start(processStartInfo);
                if (process != null)
                {
                    // Çıktıyı satır satır akıtarak okuruz; tüm 'ss' çıktısını belleğe yığmayız.
                    string? line;
                    while ((line = process.StandardOutput.ReadLine()) != null)
                    {
                        bool isSuspicious =
                            SuspiciousIPs.Any(ip => line.Contains(ip, StringComparison.OrdinalIgnoreCase)) ||
                            SuspiciousPorts.Any(port => line.Contains($":{port}", StringComparison.OrdinalIgnoreCase));

                        if (isSuspicious)
                        {
                            results.Add($"[LINUX NETWORK] Şüpheli Bağlantı: {line.Trim()}");
                        }
                    }
                    process.WaitForExit();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Hata] Linux ağ bağlantıları okunurken hata: {ex.Message}");
            }
            return results;
        }

        public List<string> RunScan()
        {
            var findings = new List<string>();
            Console.WriteLine("\n[*] Aktif Ağ Bağlantıları (TCP/UDP) Taranıyor...");
            Console.WriteLine(new string('-', 70));

            var allConnections = new List<NetworkConnection>();
            allConnections.AddRange(GetTcpConnections());
            allConnections.AddRange(GetUdpConnections());

            Console.WriteLine($"[Bilgi] Sistemde toplam {allConnections.Count} adet aktif TCP/UDP bağlantısı ve dinleyicisi tespit edildi.");

            bool foundSuspicious = false;

            foreach (var conn in allConnections)
            {
                bool isSuspiciousIp = SuspiciousIPs.Contains(conn.RemoteAddress) || SuspiciousIPs.Contains(conn.LocalAddress);
                bool isSuspiciousPort = SuspiciousPorts.Contains(conn.RemotePort) || SuspiciousPorts.Contains(conn.LocalPort);

                if (isSuspiciousIp || isSuspiciousPort)
                {
                    foundSuspicious = true;
                    string reason = isSuspiciousIp ? "Kara Listede Olan IP" : "Şüpheli Haberleşme Portu";
                    string target = conn.Protocol == "UDP" ? $"Port: {conn.LocalPort}" : $"{conn.RemoteAddress}:{conn.RemotePort}";

                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"[!] ŞÜPHELİ BAĞLANTI: PID: {conn.ProcessId,-5} | {conn.ProcessName,-15} | Protocol: {conn.Protocol} | Hedef: {target} | Sebep: {reason}");
                    Console.ResetColor();

                    findings.Add($"[NETWORK] PID: {conn.ProcessId,-6} | Süreç: {conn.ProcessName,-20} | Hedef: {target,-15} | Sebep: {reason}");
                }
            }

            if (!foundSuspicious && !OperatingSystem.IsLinux())
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("[+] Aktif ağ bağlantıları temiz. Bilinen zararlı sunucu IP'lerine veya şüpheli portlara bağlantı bulunamadı.");
                Console.ResetColor();
            }

            if (OperatingSystem.IsLinux())
            {
                var linuxNet = ScanLinuxNetwork();
                if (linuxNet.Count > 0)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"[!] LINUX AĞINDA ŞÜPHELİ BAĞLANTILAR BULUNDU! Toplam: {linuxNet.Count}");
                    Console.ResetColor();
                    findings.AddRange(linuxNet);
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("[+] Linux ağ bağlantıları temiz.");
                    Console.ResetColor();
                }
            }

            Console.WriteLine(new string('-', 70));
            return findings;
        }
    }
}
