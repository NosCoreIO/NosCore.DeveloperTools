using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

namespace NosCore.DeveloperTools.Hook;

/// <summary>
/// Walks the target's own committed private pages looking for the
/// already-formatted NosMall URL. The in-client CEF navigate path builds
/// this URL into the Delphi heap with every <c>%s</c> substituted — so a
/// plain ASCII scan for <c>http(s)://…?sid=</c> (new flow) or
/// <c>?server_index=</c> (legacy flow) returns the live URL with real
/// account/character values, without needing to hook the formatter.
/// </summary>
internal static class HeapScanner
{
    private const uint MEM_COMMIT = 0x00001000;
    private const uint MEM_PRIVATE = 0x00020000;
    private const uint PAGE_NOACCESS = 0x01;
    private const uint PAGE_READONLY = 0x02;
    private const uint PAGE_READWRITE = 0x04;
    private const uint PAGE_WRITECOPY = 0x08;
    private const uint PAGE_EXECUTE_READ = 0x20;
    private const uint PAGE_EXECUTE_READWRITE = 0x40;
    private const uint PAGE_EXECUTE_WRITECOPY = 0x80;
    private const uint PAGE_GUARD = 0x100;
    private const uint READABLE = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY
                                  | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

    // Real-client filled NosMall URL lives in CEF's large private arena
    // (~256 MB), not in Delphi's smaller heap — so we have to scan those
    // too. ReadProcessMemory + 64 KB chunking keeps each read safe.
    private const long MaxRegionBytes = 256L * 1024 * 1024;
    private const int ChunkBytes = 64 * 1024;

    // Require a digit immediately after the first query-value separator so
    // unfilled templates (`?sid=%s`, `/Mall?sid=%s`, `/nosmall.php?server_index=%s`)
    // are skipped — we only want the fully-formatted URL.
    private static readonly Regex UrlRegex = new(
        @"https?://[^\x00-\x1F""'\s<>]+(?:/Mall\?sid=\d|/nosmall\.php\?server_index=\d|\?sid=\d)[^\x00-\x1F""'\s<>]+",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    [DllImport("kernel32.dll")]
    private static extern int VirtualQuery(IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out int lpNumberOfBytesRead);

    public static string? FindNosMallUrl()
    {
        try
        {
            var self = GetCurrentProcess();
            var addr = IntPtr.Zero;
            var mbiSize = (uint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>();
            var buffer = new byte[ChunkBytes];

            while (VirtualQuery(addr, out var mbi, mbiSize) != 0)
            {
                var regionSize = mbi.RegionSize.ToInt64();
                if (regionSize <= 0) break;

                // Always advance before any early-continue so we can't loop.
                var nextAddr = new IntPtr(mbi.BaseAddress.ToInt64() + regionSize);
                try
                {
                    if (mbi.State != MEM_COMMIT) continue;
                    if (mbi.Type != MEM_PRIVATE) continue;
                    if ((mbi.Protect & PAGE_GUARD) != 0) continue;
                    if ((mbi.Protect & READABLE) == 0) continue;
                    if (regionSize > MaxRegionBytes) continue;

                    var url = ScanRegion(self, mbi.BaseAddress, regionSize, buffer);
                    if (url is not null) return url;
                }
                finally
                {
                    addr = nextAddr;
                }
            }
        }
        catch
        {
            // Never throw out of a hook-initiated scan.
        }
        return null;
    }

    private static string? ScanRegion(IntPtr self, IntPtr baseAddress, long size, byte[] buffer)
    {
        long offset = 0;
        while (offset < size)
        {
            var want = (int)Math.Min(buffer.Length, size - offset);
            if (!ReadProcessMemory(self, new IntPtr(baseAddress.ToInt64() + offset), buffer, want, out var read) || read <= 0)
            {
                return null;
            }
            var text = Encoding.ASCII.GetString(buffer, 0, read);
            var m = UrlRegex.Match(text);
            if (m.Success) return m.Value;
            offset += read;
        }
        return null;
    }
}
