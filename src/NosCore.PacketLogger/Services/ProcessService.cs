using System.Diagnostics;
using System.Runtime.InteropServices;
using NosCore.PacketLogger.Remote;

namespace NosCore.PacketLogger.Services;

public sealed record ProcessEntry(int Id, string Name, string? WindowTitle)
{
    public override string ToString() => string.IsNullOrEmpty(WindowTitle)
        ? $"{Name} (pid {Id})"
        : $"{Name} (pid {Id}) — {WindowTitle}";
}

public sealed class ProcessService
{
    public IReadOnlyList<ProcessEntry> Enumerate(string? filter = null)
    {
        var parents = BuildParentMap();

        var results = new List<ProcessEntry>();
        foreach (var p in Process.GetProcesses())
        {
            try
            {
                if (!string.IsNullOrEmpty(filter)
                    && !p.ProcessName.Contains(filter, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (IsSameNameChildOf(p.Id, p.ProcessName, parents))
                {
                    continue;
                }

                var title = p.MainWindowTitle;
                results.Add(new ProcessEntry(p.Id, p.ProcessName, string.IsNullOrEmpty(title) ? null : title));
            }
            catch
            {
                // process went away or access denied — skip
            }
            finally
            {
                p.Dispose();
            }
        }

        results.Sort((a, b) => string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase));
        return results;
    }

    private static Dictionary<int, (int ParentId, string Name)> BuildParentMap()
    {
        var map = new Dictionary<int, (int ParentId, string Name)>();
        var snapshot = NativeMethods.CreateToolhelp32Snapshot(NativeMethods.SnapshotFlags.Process, 0);
        if (snapshot == NativeMethods.InvalidHandleValue)
        {
            return map;
        }

        try
        {
            var entry = new NativeMethods.ProcessEntry32
            {
                dwSize = (uint)Marshal.SizeOf<NativeMethods.ProcessEntry32>(),
            };

            if (!NativeMethods.Process32FirstW(snapshot, ref entry))
            {
                return map;
            }

            do
            {
                var name = Path.GetFileNameWithoutExtension(entry.szExeFile ?? string.Empty);
                map[(int)entry.th32ProcessID] = ((int)entry.th32ParentProcessID, name);
                entry.dwSize = (uint)Marshal.SizeOf<NativeMethods.ProcessEntry32>();
            }
            while (NativeMethods.Process32NextW(snapshot, ref entry));
        }
        finally
        {
            NativeMethods.CloseHandle(snapshot);
        }

        return map;
    }

    private static bool IsSameNameChildOf(int pid, string name, Dictionary<int, (int ParentId, string Name)> parents)
    {
        if (!parents.TryGetValue(pid, out var self))
        {
            return false;
        }

        if (!parents.TryGetValue(self.ParentId, out var parent))
        {
            return false;
        }

        return string.Equals(parent.Name, name, StringComparison.OrdinalIgnoreCase);
    }
}
