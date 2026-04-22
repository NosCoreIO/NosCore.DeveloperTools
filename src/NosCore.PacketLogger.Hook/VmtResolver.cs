using System.Runtime.InteropServices;
using System.Text;

namespace NosCore.PacketLogger.Hook;

/// <summary>
/// Runtime Delphi VMT resolution inside the target. Mirrors the static
/// pass we did on NosCore.exe: find the class name ShortString in the
/// main module, find DWORDs that point at it, treat each as a
/// vmtClassName field (VMT sits at ref + 0x2C — classic Delphi 7
/// layout), and verify with the self-pointer at VMT - 0x4C.
///
/// Class names don't drift across client builds, so a "TNosSndCmdList
/// virtual slot 1" reference survives patches that would invalidate a
/// byte-pattern signature on the function prologue.
/// </summary>
internal static unsafe class VmtResolver
{
    private const int VmtClassNameOffset = 0x2C;
    private const int VmtSelfPtrOffset = 0x4C;
    private const int VmtInstanceSizeOffset = 0x28;
    private const int VmtParentOffset = 0x24;

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

    public readonly struct VmtHandle
    {
        public readonly IntPtr Address;
        public readonly int InstanceSize;
        public readonly IntPtr ParentVmt;

        public VmtHandle(IntPtr vmt, int instanceSize, IntPtr parent)
        {
            Address = vmt;
            InstanceSize = instanceSize;
            ParentVmt = parent;
        }

        public bool IsValid => Address != IntPtr.Zero;
    }

    public static VmtHandle Find(string className)
    {
        if (!TryGetMainModuleBounds(out var baseAddr, out var size))
        {
            return default;
        }

        var nameBytes = EncodeShortString(className);
        var nameAddr = FindBytes(baseAddr, size, nameBytes);
        if (nameAddr == IntPtr.Zero)
        {
            return default;
        }

        // vmtClassName field points at the *length byte* of the ShortString.
        var nameFieldValue = nameAddr;

        var haystack = (byte*)baseAddr;
        var limit = size - 4;
        for (var i = 0; i <= limit; i++)
        {
            if (*(IntPtr*)(haystack + i) != nameFieldValue)
            {
                continue;
            }

            var refVa = baseAddr + i;
            var vmt = refVa + VmtClassNameOffset;
            if (!InBounds(vmt, 4, baseAddr, size))
            {
                continue;
            }

            var selfPtrAt = vmt - VmtSelfPtrOffset;
            if (!InBounds(selfPtrAt, 4, baseAddr, size))
            {
                continue;
            }

            if (*(IntPtr*)selfPtrAt != vmt)
            {
                continue;
            }

            var instanceSize = *(int*)(vmt - VmtInstanceSizeOffset);
            var parent = *(IntPtr*)(vmt - VmtParentOffset);
            return new VmtHandle(vmt, instanceSize, parent);
        }

        return default;
    }

    public static IntPtr GetVirtualMethod(VmtHandle vmt, int slotIndex)
    {
        if (!vmt.IsValid) return IntPtr.Zero;
        if (!TryGetMainModuleBounds(out var baseAddr, out var size)) return IntPtr.Zero;

        var slotAddr = vmt.Address + (slotIndex * 4);
        if (!InBounds(slotAddr, 4, baseAddr, size))
        {
            return IntPtr.Zero;
        }

        var method = *(IntPtr*)slotAddr;
        // Only return pointers that fall inside the main module (virtual slots
        // outside are almost certainly "past the VMT", i.e. invalid slot index).
        return InBounds(method, 1, baseAddr, size) ? method : IntPtr.Zero;
    }

    public static int CountVirtualSlots(VmtHandle vmt)
    {
        if (!vmt.IsValid) return 0;
        if (!TryGetMainModuleBounds(out var baseAddr, out var size)) return 0;

        var count = 0;
        for (var i = 0; i < 128; i++)
        {
            var m = *(IntPtr*)(vmt.Address + i * 4);
            if (!InBounds(m, 1, baseAddr, size)) break;
            count++;
        }
        return count;
    }

    private static bool TryGetMainModuleBounds(out IntPtr baseAddr, out int size)
    {
        baseAddr = IntPtr.Zero;
        size = 0;
        var module = GetModuleHandleW(null);
        if (module == IntPtr.Zero) return false;
        if (!GetModuleInformation(GetCurrentProcess(), module, out var info, (uint)Marshal.SizeOf<ModuleInfo>()))
        {
            return false;
        }
        baseAddr = info.BaseOfDll;
        size = (int)info.SizeOfImage;
        return true;
    }

    private static byte[] EncodeShortString(string name)
    {
        if (name.Length > 255)
        {
            throw new ArgumentException("Delphi ShortStrings cap at 255 bytes", nameof(name));
        }

        var payload = Encoding.ASCII.GetBytes(name);
        var result = new byte[payload.Length + 1];
        result[0] = (byte)payload.Length;
        Buffer.BlockCopy(payload, 0, result, 1, payload.Length);
        return result;
    }

    private static IntPtr FindBytes(IntPtr baseAddr, int size, byte[] needle)
    {
        if (needle.Length == 0 || needle.Length > size) return IntPtr.Zero;
        var hay = (byte*)baseAddr;
        var limit = size - needle.Length;
        for (var i = 0; i <= limit; i++)
        {
            var match = true;
            for (var j = 0; j < needle.Length; j++)
            {
                if (hay[i + j] != needle[j])
                {
                    match = false;
                    break;
                }
            }
            if (match) return baseAddr + i;
        }
        return IntPtr.Zero;
    }

    private static bool InBounds(IntPtr ptr, int len, IntPtr baseAddr, int size)
    {
        var p = (long)ptr;
        var b = (long)baseAddr;
        return p >= b && (p + len) <= (b + size);
    }
}
