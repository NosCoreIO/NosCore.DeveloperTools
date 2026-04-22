using System.Runtime.InteropServices;

namespace NosCore.PacketLogger.Hook;

/// <summary>
/// Classic 6-byte inline detour on x86. Overwrites the target with
/// <c>E9 rel32 NOP</c>, saves the displaced bytes into a trampoline,
/// and returns the trampoline address.
///
/// Trampoline layout (21 bytes):
///   60                   PUSHAD
///   9C                   PUSHFD
///   52                   PUSH EDX                 ; NosTale convention: packet ptr in EDX
///   E8 rel32             CALL hook                ; stdcall, pops its arg
///   9D                   POPFD
///   61                   POPAD
///   &lt;6 saved bytes&gt;      original instructions
///   E9 rel32             JMP back to target+6
/// </summary>
internal static unsafe class Detour
{
    [Flags]
    private enum AllocationType : uint
    {
        Commit = 0x1000,
        Reserve = 0x2000,
    }

    [Flags]
    private enum MemoryProtection : uint
    {
        ReadWrite = 0x04,
        ExecuteRead = 0x20,
        ExecuteReadWrite = 0x40,
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr VirtualAlloc(IntPtr address, UIntPtr size, AllocationType type, MemoryProtection protect);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualProtect(IntPtr address, UIntPtr size, MemoryProtection newProtect, out MemoryProtection oldProtect);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll")]
    private static extern bool FlushInstructionCache(IntPtr process, IntPtr address, UIntPtr size);

    /// <summary>
    /// Which register(s) the trampoline forwards to the managed hook.
    /// <see cref="Edx"/> — 1-arg hook receiving EDX (NosTale cleartext
    /// packet pointer on entry to per-packet handlers).
    /// <see cref="Ebp"/> — 1-arg hook receiving EBP (mid-function hooks
    /// where the packet lives at <c>[ebp-N]</c>; managed side
    /// dereferences).
    /// <see cref="EaxThenEdx"/> — 2-arg hook receiving (EAX, EDX);
    /// useful for send handlers where we want both the Delphi "self"
    /// context and the packet pointer.
    /// </summary>
    public enum HookArg : byte
    {
        Edx,
        Ebp,
        EaxThenEdx,
    }

    public static IntPtr Install(IntPtr target, IntPtr hook, int prologueSize = 6, HookArg arg = HookArg.Edx)
    {
        if (target == IntPtr.Zero || hook == IntPtr.Zero) return IntPtr.Zero;
        if (prologueSize < 5) return IntPtr.Zero;

        // Args section size: PUSH EDX / PUSH EBP = 1 byte; PUSH EDX + PUSH EAX = 2 bytes.
        var argsSize = arg == HookArg.EaxThenEdx ? 2 : 1;
        var trampolineSize = 1 + 1 + argsSize + 5 + 1 + 1 + prologueSize + 5;
        var trampoline = VirtualAlloc(IntPtr.Zero, (UIntPtr)trampolineSize,
            AllocationType.Commit | AllocationType.Reserve, MemoryProtection.ReadWrite);
        if (trampoline == IntPtr.Zero) return IntPtr.Zero;

        var t = (byte*)trampoline;
        var src = (byte*)target;
        var saved = stackalloc byte[prologueSize];
        for (var i = 0; i < prologueSize; i++) saved[i] = src[i];

        var pos = 0;
        t[pos++] = 0x60;                      // PUSHAD
        t[pos++] = 0x9C;                      // PUSHFD
        switch (arg)
        {
            case HookArg.Edx:
                t[pos++] = 0x52;              // PUSH EDX
                break;
            case HookArg.Ebp:
                t[pos++] = 0x55;              // PUSH EBP
                break;
            case HookArg.EaxThenEdx:
                // stdcall pushes args right-to-left; arg1=EAX must be topmost,
                // so push EDX first, then EAX.
                t[pos++] = 0x52;              // PUSH EDX
                t[pos++] = 0x50;              // PUSH EAX
                break;
        }
        t[pos++] = 0xE8;                      // CALL hook (rel32)
        var callOpAddr = (IntPtr)(t + pos - 1);
        WriteInt32(t + pos, (int)((long)hook - (long)callOpAddr - 5));
        pos += 4;
        t[pos++] = 0x9D;                      // POPFD
        t[pos++] = 0x61;                      // POPAD
        for (var i = 0; i < prologueSize; i++) t[pos++] = saved[i];

        t[pos++] = 0xE9;                      // JMP target+prologueSize
        var jmpOpAddr = (IntPtr)(t + pos - 1);
        WriteInt32(t + pos, (int)((long)(target + prologueSize) - (long)jmpOpAddr - 5));

        if (!VirtualProtect(trampoline, (UIntPtr)trampolineSize, MemoryProtection.ExecuteRead, out _))
            return IntPtr.Zero;
        FlushInstructionCache(GetCurrentProcess(), trampoline, (UIntPtr)trampolineSize);

        if (!VirtualProtect(target, (UIntPtr)prologueSize, MemoryProtection.ExecuteReadWrite, out var oldTargetProt))
            return IntPtr.Zero;

        src[0] = 0xE9;
        WriteInt32(src + 1, (int)((long)trampoline - (long)target - 5));
        // Fill remainder with NOPs so the extra displaced bytes parse cleanly.
        for (var i = 5; i < prologueSize; i++) src[i] = 0x90;

        VirtualProtect(target, (UIntPtr)prologueSize, oldTargetProt, out _);
        FlushInstructionCache(GetCurrentProcess(), target, (UIntPtr)prologueSize);

        return trampoline;
    }

    private static void WriteInt32(byte* dst, int value)
    {
        dst[0] = (byte)value;
        dst[1] = (byte)(value >> 8);
        dst[2] = (byte)(value >> 16);
        dst[3] = (byte)(value >> 24);
    }

    /// <summary>
    /// Hooks the point **immediately after** an <c>E8 rel32</c> call
    /// returns, reading <c>[EBP-0x08]</c> (a local the callee populated
    /// in the caller's frame) and forwarding it to
    /// <paramref name="hookAfter"/>. Used for NosTale's login-recv
    /// decrypt: cleartext lives at <c>[ebp-0x08]</c> once the decrypt
    /// function returns.
    ///
    /// The naïve "wrap with CALL" approach doesn't work here because
    /// decrypt also takes **stack arguments**: the dispatcher pushes
    /// two dwords before the call and decrypt reads them via
    /// <c>[ebp+0x08]</c> / <c>[ebp+0x0C]</c>. Inserting a CALL between
    /// would shift those offsets by 4 and make decrypt read garbage.
    ///
    /// Instead we patch the <c>E8</c> → <c>E9</c> (JMP, not CALL) so no
    /// extra return address gets pushed. The thunk fakes the missing
    /// return address by <c>push</c>ing the post-hook address manually,
    /// then jumps into the original callee. The callee RETs straight
    /// back into our post-hook, which reads the local, invokes the
    /// managed hook, then JMPs to the instruction after the original
    /// call.
    ///
    /// Thunk layout (27 bytes):
    ///   68 imm32  PUSH post-hook address   ; faked return addr for callee
    ///   E9 rel32  JMP original callee
    /// post-hook:
    ///   60        PUSHAD
    ///   9C        PUSHFD
    ///   FF 75 F8  PUSH DWORD [EBP-0x08]
    ///   E8 rel32  CALL hookAfter            ; stdcall pops its arg
    ///   9D        POPFD
    ///   61        POPAD
    ///   E9 rel32  JMP instruction-after-original-call
    /// </summary>
    public static bool WrapCallSite(IntPtr callSite, IntPtr hookAfter)
    {
        if (callSite == IntPtr.Zero || hookAfter == IntPtr.Zero) return false;
        var siteBytes = (byte*)callSite;
        if (siteBytes[0] != 0xE8) return false;

        var originalRel = *(int*)(siteBytes + 1);
        var original = callSite + 5 + originalRel;
        var afterCall = callSite + 5;

        const int ThunkSize = 27;
        var thunk = VirtualAlloc(IntPtr.Zero, (UIntPtr)ThunkSize,
            AllocationType.Commit | AllocationType.Reserve, MemoryProtection.ReadWrite);
        if (thunk == IntPtr.Zero) return false;

        var t = (byte*)thunk;
        var postHook = thunk + 10;

        // 68 imm32                PUSH post-hook absolute
        t[0] = 0x68;
        WriteInt32(t + 1, (int)(long)postHook);

        // E9 rel32                JMP original (tail-call so its [ebp+8]/+C are unchanged)
        t[5] = 0xE9;
        WriteInt32(t + 6, (int)((long)original - (long)(thunk + 10)));

        // post-hook at thunk+10
        t[10] = 0x60;                       // PUSHAD
        t[11] = 0x9C;                       // PUSHFD
        t[12] = 0xFF; t[13] = 0x75; t[14] = 0xF8; // PUSH [EBP-0x08]
        t[15] = 0xE8;                       // CALL hookAfter
        WriteInt32(t + 16, (int)((long)hookAfter - (long)(thunk + 20)));
        t[20] = 0x9D;                       // POPFD
        t[21] = 0x61;                       // POPAD
        t[22] = 0xE9;                       // JMP afterCall
        WriteInt32(t + 23, (int)((long)afterCall - (long)(thunk + 27)));

        if (!VirtualProtect(thunk, (UIntPtr)ThunkSize, MemoryProtection.ExecuteRead, out _))
            return false;
        FlushInstructionCache(GetCurrentProcess(), thunk, (UIntPtr)ThunkSize);

        if (!VirtualProtect(callSite, (UIntPtr)5, MemoryProtection.ExecuteReadWrite, out var oldProt))
            return false;

        // Patch E8 -> E9 (CALL -> JMP) so no extra return address is pushed.
        siteBytes[0] = 0xE9;
        WriteInt32(siteBytes + 1, (int)((long)thunk - (long)(callSite + 5)));

        VirtualProtect(callSite, (UIntPtr)5, oldProt, out _);
        FlushInstructionCache(GetCurrentProcess(), callSite, (UIntPtr)5);

        return true;
    }
}
