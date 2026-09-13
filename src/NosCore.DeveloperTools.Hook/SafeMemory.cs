using System.Runtime.InteropServices;

namespace NosCore.DeveloperTools.Hook;

/// <summary>
/// Validity-checked reads of client memory. A signature that drifts
/// resolves to a plausible-looking but wrong pointer, and dereferencing
/// that inside the target raises an SEH access violation — which
/// NativeAOT does not surface as a catchable .NET exception, so the
/// client simply dies. Every pointer we derive from a scan therefore
/// goes through <see cref="IsReadable"/> first, turning a stale
/// signature into an error message instead of a crash.
/// </summary>
internal static unsafe class SafeMemory
{
    private const uint MemCommit = 0x1000;
    private const uint PageNoAccess = 0x01;
    private const uint PageGuard = 0x100;
    private const uint ReadableMask = 0x02 | 0x04 | 0x08 | 0x20 | 0x40 | 0x80;

    [StructLayout(LayoutKind.Sequential)]
    private struct MemoryBasicInformation
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public UIntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    [DllImport("kernel32.dll")]
    private static extern UIntPtr VirtualQuery(IntPtr address, out MemoryBasicInformation buffer, UIntPtr length);

    public static bool IsReadable(IntPtr address, int size)
    {
        if (address == IntPtr.Zero || size <= 0) return false;

        var queried = VirtualQuery(address, out var info, (UIntPtr)(uint)sizeof(MemoryBasicInformation));
        if (queried == UIntPtr.Zero) return false;
        if (info.State != MemCommit) return false;
        if ((info.Protect & PageGuard) != 0) return false;
        if ((info.Protect & PageNoAccess) != 0) return false;
        if ((info.Protect & ReadableMask) == 0) return false;

        // The requested span must not run past the end of this region —
        // the next one up may be uncommitted.
        var regionEnd = (ulong)info.BaseAddress + (ulong)info.RegionSize;
        return (ulong)address + (ulong)size <= regionEnd;
    }

    public static bool TryReadIntPtr(IntPtr address, out IntPtr value)
    {
        value = IntPtr.Zero;
        if (!IsReadable(address, sizeof(IntPtr))) return false;
        value = *(IntPtr*)address;
        return true;
    }

    public static bool TryReadInt32(IntPtr address, out int value)
    {
        value = 0;
        if (!IsReadable(address, sizeof(int))) return false;
        value = *(int*)address;
        return true;
    }

    public static bool TryReadUInt16(IntPtr address, out ushort value)
    {
        value = 0;
        if (!IsReadable(address, sizeof(ushort))) return false;
        value = *(ushort*)address;
        return true;
    }
}
