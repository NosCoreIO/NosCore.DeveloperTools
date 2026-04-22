using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace NosCore.PacketLogger.Hook;

/// <summary>
/// Boots the hook when the DLL is loaded into the target via the
/// exported <c>NosCorePacketLoggerHookInit</c> function. The injector
/// calls this explicitly via a second <c>CreateRemoteThread</c> right
/// after <c>LoadLibraryW</c>. We intentionally do NOT use
/// <see cref="ModuleInitializerAttribute"/> — it would also fire if
/// anything loaded the DLL outside the target (e.g. an antivirus
/// sandbox, or our own process if we ever had to introspect it),
/// spawning the worker thread in the wrong process.
/// </summary>
internal static unsafe class HookEntry
{
    private static readonly Lock StartupLock = new();
    private static bool _started;

    // Signature matches Win32 LPTHREAD_START_ROUTINE so CreateRemoteThread
    // can invoke it directly: DWORD WINAPI(LPVOID). stdcall with one arg
    // means the callee pops 4 bytes on return; omitting the arg would
    // misalign the stack and silently crash the remote thread.
    [UnmanagedCallersOnly(EntryPoint = "NosCorePacketLoggerHookInit", CallConvs = new[] { typeof(CallConvStdcall) })]
    public static uint Init(IntPtr parameter)
    {
        StartWorker();
        return 0;
    }

    private static void StartWorker()
    {
        lock (StartupLock)
        {
            if (_started) return;
            _started = true;

            delegate* unmanaged[Stdcall]<IntPtr, uint> start = &WorkerThreadProc;
            NativeThread.CreateThread(
                IntPtr.Zero, UIntPtr.Zero, (IntPtr)start, IntPtr.Zero, 0, out _);
        }
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
    private static uint WorkerThreadProc(IntPtr parameter)
    {
        try
        {
            InstallHooks();
            PipeServer.Run();
        }
        catch
        {
            // Never propagate out of the target.
        }
        return 0;
    }

    private static void InstallHooks()
    {
        try
        {
            var result = Hooks.Install();
            PipeServer.Announce(
                $"hooks: send={Fmt(result.SendAddress, result.SendHooked)} recv={Fmt(result.RecvAddress, result.RecvHooked)} login-recv={Fmt(result.LoginRecvAddress, result.LoginRecvHooked)}");
        }
        catch (Exception ex)
        {
            PipeServer.Announce($"hook install failed: {ex.Message}");
        }
    }

    private static string Fmt(IntPtr addr, bool hooked)
    {
        if (addr == IntPtr.Zero) return "NOT-FOUND";
        return hooked ? $"0x{addr.ToInt64():X}" : $"0x{addr.ToInt64():X} (found, detour failed)";
    }
}

internal static class NativeThread
{
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateThread(
        IntPtr lpThreadAttributes, UIntPtr dwStackSize, IntPtr lpStartAddress,
        IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);
}
