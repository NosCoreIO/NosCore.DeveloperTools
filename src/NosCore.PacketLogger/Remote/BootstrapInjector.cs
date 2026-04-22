using System.ComponentModel;
using System.Text;

namespace NosCore.PacketLogger.Remote;

/// <summary>
/// Remote-thread DLL injection in two steps:
///   1. <c>CreateRemoteThread(LoadLibraryW, dllPath)</c> — returns the
///      target HMODULE of our DLL as the thread exit code.
///   2. <c>CreateRemoteThread(targetHModule + initRva, 0)</c> — calls
///      the hook DLL's <c>NosCorePacketLoggerHookInit</c> export, which
///      is how the pipe server actually starts (NativeAOT shared libs
///      don't reliably fire managed module initializers on DllMain).
///
/// kernel32.dll is mapped at the same base in every 32-bit process on a
/// given Windows build, so LoadLibraryW's address from our own process
/// is valid in the target.
/// </summary>
internal static class BootstrapInjector
{
    public static InjectionResult Inject(int processId, string dllPath, string initExport)
    {
        if (!File.Exists(dllPath))
        {
            throw new FileNotFoundException("Hook DLL missing at injection time.", dllPath);
        }

        var loadLibrary = ResolveLoadLibraryW();
        // Parse the DLL's export table off disk. We deliberately don't call
        // LoadLibrary on it in our own process — that would fire the hook's
        // DllMain in the injector (wrong pid!) and can trip AV on the main exe.
        var initRva = PeExportReader.GetExportRva(dllPath, initExport);

        using var process = NativeMethods.OpenProcess(NativeMethods.ProcessAccess.Inject, false, processId);
        if (process.IsInvalid)
        {
            throw NativeMethods.LastWin32($"OpenProcess({processId})");
        }

        var pathBytes = Encoding.Unicode.GetBytes(dllPath + "\0");
        var remote = NativeMethods.VirtualAllocEx(
            process, IntPtr.Zero, (UIntPtr)pathBytes.Length,
            NativeMethods.AllocationType.Commit | NativeMethods.AllocationType.Reserve,
            NativeMethods.MemoryProtection.ReadWrite);
        if (remote == IntPtr.Zero)
        {
            throw NativeMethods.LastWin32("VirtualAllocEx");
        }

        try
        {
            if (!NativeMethods.WriteProcessMemory(process, remote, pathBytes, (UIntPtr)pathBytes.Length, out _))
            {
                throw NativeMethods.LastWin32("WriteProcessMemory");
            }

            var loadThread = NativeMethods.CreateRemoteThread(
                process, IntPtr.Zero, UIntPtr.Zero, loadLibrary, remote, 0, out _);
            if (loadThread == IntPtr.Zero)
            {
                throw NativeMethods.LastWin32("CreateRemoteThread(LoadLibraryW)");
            }

            uint targetHModule;
            try
            {
                var wait = NativeMethods.WaitForSingleObject(loadThread, 10_000);
                if (wait != 0)
                {
                    throw new Win32Exception($"LoadLibraryW remote thread didn't complete (wait=0x{wait:X}).");
                }

                if (!NativeMethods.GetExitCodeThread(loadThread, out targetHModule))
                {
                    throw NativeMethods.LastWin32("GetExitCodeThread(LoadLibraryW)");
                }
            }
            finally
            {
                NativeMethods.CloseHandle(loadThread);
            }

            if (targetHModule == 0)
            {
                throw new InvalidOperationException(
                    $"LoadLibraryW returned 0 in the target — the DLL didn't load. " +
                    $"Path: {dllPath}. Defender may have quarantined the payload, or the " +
                    $"target blocks DLL injection.");
            }

            var initAddr = new IntPtr((int)targetHModule + (int)initRva);
            var initThread = NativeMethods.CreateRemoteThread(
                process, IntPtr.Zero, UIntPtr.Zero, initAddr, IntPtr.Zero, 0, out _);
            if (initThread == IntPtr.Zero)
            {
                throw NativeMethods.LastWin32("CreateRemoteThread(hook init)");
            }

            try
            {
                NativeMethods.WaitForSingleObject(initThread, 5_000);
            }
            finally
            {
                NativeMethods.CloseHandle(initThread);
            }

            return new InjectionResult(new IntPtr((int)targetHModule), initAddr);
        }
        finally
        {
            NativeMethods.VirtualFreeEx(process, remote, UIntPtr.Zero, NativeMethods.FreeType.Release);
        }
    }

    private static IntPtr ResolveLoadLibraryW()
    {
        var kernel32 = NativeMethods.GetModuleHandleW("kernel32.dll");
        if (kernel32 == IntPtr.Zero)
        {
            throw NativeMethods.LastWin32("GetModuleHandleW(kernel32.dll)");
        }
        var addr = NativeMethods.GetProcAddress(kernel32, "LoadLibraryW");
        if (addr == IntPtr.Zero)
        {
            throw NativeMethods.LastWin32("GetProcAddress(LoadLibraryW)");
        }
        return addr;
    }
}

internal readonly record struct InjectionResult(IntPtr TargetHModule, IntPtr InitFunctionAddress);
