namespace NosCore.PacketLogger.Remote;

internal sealed record RemoteModule(string Name, IntPtr BaseAddress, int Size, string Path);

internal static class ModuleEnumerator
{
    public static IReadOnlyList<RemoteModule> List(int processId)
    {
        var snapshot = NativeMethods.CreateToolhelp32Snapshot(NativeMethods.SnapshotFlags.Module, (uint)processId);
        if (snapshot == NativeMethods.InvalidHandleValue)
        {
            throw NativeMethods.LastWin32($"CreateToolhelp32Snapshot({processId})");
        }

        try
        {
            var modules = new List<RemoteModule>();
            var entry = new NativeMethods.ModuleEntry32
            {
                dwSize = (uint)System.Runtime.InteropServices.Marshal.SizeOf<NativeMethods.ModuleEntry32>(),
            };

            if (!NativeMethods.Module32FirstW(snapshot, ref entry))
            {
                return modules;
            }

            do
            {
                modules.Add(new RemoteModule(
                    Name: entry.szModule ?? string.Empty,
                    BaseAddress: entry.modBaseAddr,
                    Size: (int)entry.modBaseSize,
                    Path: entry.szExePath ?? string.Empty));
                entry.dwSize = (uint)System.Runtime.InteropServices.Marshal.SizeOf<NativeMethods.ModuleEntry32>();
            }
            while (NativeMethods.Module32NextW(snapshot, ref entry));

            return modules;
        }
        finally
        {
            NativeMethods.CloseHandle(snapshot);
        }
    }
}
