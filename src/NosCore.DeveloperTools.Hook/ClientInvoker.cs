using System.Runtime.InteropServices;
using System.Text;

namespace NosCore.DeveloperTools.Hook;

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
    /// Build a cdecl-callable invoker for a Delphi register-convention
    /// function taking exactly three arguments in EAX, EDX and ECX, with
    /// nothing on the stack. Cast the result to
    /// <c>delegate* unmanaged[Cdecl]&lt;IntPtr, IntPtr, int, void&gt;</c>.
    ///
    ///   55           push ebp
    ///   8B EC        mov  ebp, esp
    ///   8B 45 08     mov  eax, [ebp+0x08]
    ///   8B 55 0C     mov  edx, [ebp+0x0C]
    ///   8B 4D 10     mov  ecx, [ebp+0x10]
    ///   E8 rel32     call target
    ///   8B E5        mov  esp, ebp
    ///   5D           pop  ebp
    ///   C3           ret
    /// </summary>
    public static IntPtr BuildRegisterInvoker3(IntPtr target)
    {
        const int Size = 21;
        const int CallOpcodeOffset = 12;

        var thunk = VirtualAlloc(IntPtr.Zero, (UIntPtr)Size,
            AllocationType.Commit | AllocationType.Reserve, MemoryProtection.ReadWrite);
        if (thunk == IntPtr.Zero) return IntPtr.Zero;

        var t = (byte*)thunk;
        t[0] = 0x55;
        t[1] = 0x8B; t[2] = 0xEC;
        t[3] = 0x8B; t[4] = 0x45; t[5] = 0x08;
        t[6] = 0x8B; t[7] = 0x55; t[8] = 0x0C;
        t[9] = 0x8B; t[10] = 0x4D; t[11] = 0x10;

        t[CallOpcodeOffset] = 0xE8;
        var afterCall = (long)thunk + CallOpcodeOffset + 5;
        var rel = (int)((long)target - afterCall);
        t[13] = (byte)rel; t[14] = (byte)(rel >> 8);
        t[15] = (byte)(rel >> 16); t[16] = (byte)(rel >> 24);

        t[17] = 0x8B; t[18] = 0xE5;
        t[19] = 0x5D;
        t[20] = 0xC3;

        if (!VirtualProtect(thunk, (UIntPtr)Size, MemoryProtection.ExecuteRead, out _))
            return IntPtr.Zero;
        FlushInstructionCache(GetCurrentProcess(), thunk, (UIntPtr)Size);
        return thunk;
    }

    /// <summary>
    /// Build a cdecl-callable invoker for a Delphi register-convention
    /// function taking four arguments: EAX, EDX, ECX and one stack
    /// dword. Cast the result to
    /// <c>delegate* unmanaged[Cdecl]&lt;IntPtr, int, int, int, void&gt;</c>.
    ///
    /// Unlike the two-argument thunk this one builds a real EBP frame
    /// and restores ESP from it rather than popping. Delphi's register
    /// convention makes the callee clean stack arguments, but a function
    /// that turns out to take only its register arguments cleans
    /// nothing — leaving ESP 4 bytes low and the return address off by
    /// one slot. Restoring from EBP is correct either way, so an
    /// argument-count guess that is wrong yields a no-op instead of a
    /// crash.
    ///
    ///   55           push ebp
    ///   8B EC        mov  ebp, esp
    ///   53           push ebx
    ///   8B 5D 14     mov  ebx, [ebp+0x14]   ; arg4
    ///   8B 45 08     mov  eax, [ebp+0x08]   ; arg1
    ///   8B 55 0C     mov  edx, [ebp+0x0C]   ; arg2
    ///   8B 4D 10     mov  ecx, [ebp+0x10]   ; arg3
    ///   53           push ebx               ; arg4 on the stack
    ///   E8 rel32     call target
    ///   8D 65 FC     lea  esp, [ebp-4]
    ///   5B           pop  ebx
    ///   5D           pop  ebp
    ///   C3           ret
    /// </summary>
    public static IntPtr BuildRegisterInvoker4(IntPtr target)
    {
        const int Size = 28;
        const int CallOpcodeOffset = 17;

        var thunk = VirtualAlloc(IntPtr.Zero, (UIntPtr)Size,
            AllocationType.Commit | AllocationType.Reserve, MemoryProtection.ReadWrite);
        if (thunk == IntPtr.Zero) return IntPtr.Zero;

        var t = (byte*)thunk;
        t[0] = 0x55;
        t[1] = 0x8B; t[2] = 0xEC;
        t[3] = 0x53;
        t[4] = 0x8B; t[5] = 0x5D; t[6] = 0x14;
        t[7] = 0x8B; t[8] = 0x45; t[9] = 0x08;
        t[10] = 0x8B; t[11] = 0x55; t[12] = 0x0C;
        t[13] = 0x8B; t[14] = 0x4D; t[15] = 0x10;
        t[16] = 0x53;

        t[CallOpcodeOffset] = 0xE8;
        var afterCall = (long)thunk + CallOpcodeOffset + 5;
        var rel = (int)((long)target - afterCall);
        t[18] = (byte)rel; t[19] = (byte)(rel >> 8);
        t[20] = (byte)(rel >> 16); t[21] = (byte)(rel >> 24);

        t[22] = 0x8D; t[23] = 0x65; t[24] = 0xFC;
        t[25] = 0x5B;
        t[26] = 0x5D;
        t[27] = 0xC3;

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
