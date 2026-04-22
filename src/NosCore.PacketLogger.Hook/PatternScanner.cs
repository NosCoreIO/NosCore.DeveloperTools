using System.Runtime.InteropServices;

namespace NosCore.PacketLogger.Hook;

internal static unsafe class PatternScanner
{
    [StructLayout(LayoutKind.Sequential)]
    private struct ModuleInfo
    {
        public IntPtr BaseOfDll;
        public uint SizeOfImage;
        public IntPtr EntryPoint;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr GetModuleHandleW(string? moduleName);

    [DllImport("psapi.dll", SetLastError = true)]
    private static extern bool GetModuleInformation(IntPtr process, IntPtr module, out ModuleInfo info, uint size);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    public static IntPtr ScanMainModule(string pattern)
    {
        var module = GetModuleHandleW(null);
        if (module == IntPtr.Zero) return IntPtr.Zero;

        if (!GetModuleInformation(GetCurrentProcess(), module, out var info, (uint)Marshal.SizeOf<ModuleInfo>()))
        {
            return IntPtr.Zero;
        }

        return Scan(info.BaseOfDll, (int)info.SizeOfImage, pattern);
    }

    public static IntPtr Scan(IntPtr regionBase, int regionSize, string pattern)
    {
        var (bytes, mask) = Compile(pattern);
        var haystack = (byte*)regionBase;
        var limit = regionSize - bytes.Length;
        for (var i = 0; i <= limit; i++)
        {
            var matched = true;
            for (var j = 0; j < bytes.Length; j++)
            {
                if (mask[j] && haystack[i + j] != bytes[j])
                {
                    matched = false;
                    break;
                }
            }

            if (matched)
            {
                return regionBase + i;
            }
        }

        return IntPtr.Zero;
    }

    private static (byte[] Bytes, bool[] Mask) Compile(string pattern)
    {
        var tokens = pattern.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
        var bytes = new byte[tokens.Length];
        var mask = new bool[tokens.Length];
        for (var i = 0; i < tokens.Length; i++)
        {
            var t = tokens[i];
            if (t == "?" || t == "??")
            {
                mask[i] = false;
                bytes[i] = 0;
            }
            else
            {
                mask[i] = true;
                bytes[i] = Convert.ToByte(t, 16);
            }
        }

        return (bytes, mask);
    }
}
