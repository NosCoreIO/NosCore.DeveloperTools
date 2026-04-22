using System.Runtime.InteropServices;
using System.Text;

namespace NosCore.PacketLogger.Hook;

/// <summary>
/// Calls Delphi "register" convention functions inside the target
/// process. Delphi's register convention uses <c>EAX, EDX, ECX</c> for
/// the first three args — no standard .NET calling-convention attribute
/// covers that, so we emit a tiny x86 thunk that takes <c>(EAX, EDX)</c>
/// as stack args (cdecl) and reloads them into registers before calling
/// the target.
///
/// Thunk layout (17 bytes):
///   8B 44 24 04      mov eax, [esp+4]
///   8B 54 24 08      mov edx, [esp+8]
///   B9 imm32         mov ecx, &lt;target&gt;
///   FF D1            call ecx
///   C3               ret          ; cdecl, caller cleans up
/// </summary>
internal static unsafe class ClientInvoker
{
    [Flags]
    private enum AllocationType : uint { Commit = 0x1000, Reserve = 0x2000 }

    [Flags]
    private enum MemoryProtection : uint { ReadWrite = 0x04, ExecuteRead = 0x20 }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr VirtualAlloc(IntPtr address, UIntPtr size, AllocationType type, MemoryProtection protect);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualProtect(IntPtr address, UIntPtr size, MemoryProtection newProtect, out MemoryProtection oldProtect);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll")]
    private static extern bool FlushInstructionCache(IntPtr process, IntPtr address, UIntPtr size);

    /// <summary>
    /// Build and return a cdecl-callable invoker for a Delphi register-
    /// convention function that takes (EAX, EDX). The caller should
    /// cache the returned pointer and cast it to
    /// <c>delegate* unmanaged[Cdecl]&lt;IntPtr, IntPtr, void&gt;</c>.
    /// </summary>
    public static IntPtr BuildRegisterInvoker(IntPtr target)
    {
        const int Size = 17;
        var thunk = VirtualAlloc(IntPtr.Zero, (UIntPtr)Size,
            AllocationType.Commit | AllocationType.Reserve, MemoryProtection.ReadWrite);
        if (thunk == IntPtr.Zero) return IntPtr.Zero;

        var t = (byte*)thunk;
        // mov eax, [esp+4]
        t[0] = 0x8B; t[1] = 0x44; t[2] = 0x24; t[3] = 0x04;
        // mov edx, [esp+8]
        t[4] = 0x8B; t[5] = 0x54; t[6] = 0x24; t[7] = 0x08;
        // mov ecx, <target>
        t[8] = 0xB9;
        t[9] = (byte)target; t[10] = (byte)((int)target >> 8);
        t[11] = (byte)((int)target >> 16); t[12] = (byte)((int)target >> 24);
        // call ecx
        t[13] = 0xFF; t[14] = 0xD1;
        // ret
        t[15] = 0xC3;
        // pad (one unused byte for alignment)
        t[16] = 0x90;

        if (!VirtualProtect(thunk, (UIntPtr)Size, MemoryProtection.ExecuteRead, out _))
            return IntPtr.Zero;
        FlushInstructionCache(GetCurrentProcess(), thunk, (UIntPtr)Size);
        return thunk;
    }

    /// <summary>
    /// Allocates a Delphi AnsiString the client can consume. Full header
    /// layout (Delphi 2009+):
    ///   -12: codepage (word)         — 1252 (ANSI Western)
    ///   -10: element size (word)     — 1 byte per char
    ///    -8: refcount (int)          — -1 (constant; RTL never frees)
    ///    -4: length (int)
    ///     0: payload + NUL terminator
    /// The traditional Delphi 7 layout only has refcount + length; our
    /// header is a superset so both readers are happy.
    /// Memory leaks on purpose — the cost is tiny and it avoids
    /// foreign-allocator cleanup issues.
    /// </summary>
    public static IntPtr AllocAnsiString(string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        const int HeaderSize = 12;
        var total = HeaderSize + bytes.Length + 1;
        var raw = Marshal.AllocHGlobal(total);
        var payload = raw + HeaderSize;

        Marshal.WriteInt16(raw, 0, 1252);               // codepage
        Marshal.WriteInt16(raw, 2, 1);                  // element size
        Marshal.WriteInt32(raw, 4, -1);                 // refcount = -1
        Marshal.WriteInt32(raw, 8, bytes.Length);       // length
        Marshal.Copy(bytes, 0, payload, bytes.Length);
        Marshal.WriteByte(payload, bytes.Length, 0);    // NUL terminator
        return payload;
    }
}
