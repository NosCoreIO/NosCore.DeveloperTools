using System.Text;
using Microsoft.Win32.SafeHandles;

namespace NosCore.PacketLogger.Remote;

/// <summary>
/// Owns an open handle to the target process and exposes typed
/// Read/Write helpers on top of kernel32 memory APIs. Disposable — the
/// handle is the only Win32 resource held.
/// </summary>
internal sealed class RemoteProcess : IDisposable
{
    private readonly SafeProcessHandle _handle;

    private RemoteProcess(SafeProcessHandle handle, int processId, bool isWow64)
    {
        _handle = handle;
        ProcessId = processId;
        IsWow64 = isWow64;
    }

    public int ProcessId { get; }

    public bool IsWow64 { get; }

    public SafeProcessHandle Handle => _handle;

    public static RemoteProcess Open(int processId, bool writable = false)
    {
        var access = writable ? NativeMethods.ProcessAccess.ReadWrite : NativeMethods.ProcessAccess.ReadOnly;
        var handle = NativeMethods.OpenProcess(access, false, processId);
        if (handle.IsInvalid)
        {
            throw NativeMethods.LastWin32($"OpenProcess({processId})");
        }

        var isWow64 = false;
        try
        {
            NativeMethods.IsWow64Process(handle, out isWow64);
        }
        catch
        {
            // Best effort: stays false
        }

        return new RemoteProcess(handle, processId, isWow64);
    }

    public byte[] ReadBytes(IntPtr address, int length)
    {
        var buffer = new byte[length];
        if (!NativeMethods.ReadProcessMemory(_handle, address, buffer, (UIntPtr)length, out var bytesRead)
            || (int)bytesRead != length)
        {
            throw NativeMethods.LastWin32($"ReadProcessMemory(0x{address.ToInt64():X16}, len={length})");
        }

        return buffer;
    }

    public int TryReadBytes(IntPtr address, byte[] buffer)
    {
        if (!NativeMethods.ReadProcessMemory(_handle, address, buffer, (UIntPtr)buffer.Length, out var bytesRead))
        {
            return 0;
        }

        return (int)bytesRead;
    }

    public void WriteBytes(IntPtr address, byte[] data)
    {
        if (!NativeMethods.WriteProcessMemory(_handle, address, data, (UIntPtr)data.Length, out var bytesWritten)
            || (int)bytesWritten != data.Length)
        {
            throw NativeMethods.LastWin32($"WriteProcessMemory(0x{address.ToInt64():X16}, len={data.Length})");
        }
    }

    public string ReadAsciiString(IntPtr address, int maxLength)
    {
        var buffer = new byte[maxLength];
        var n = TryReadBytes(address, buffer);
        if (n == 0)
        {
            return string.Empty;
        }

        var terminator = Array.IndexOf(buffer, (byte)0, 0, n);
        if (terminator < 0) terminator = n;
        return Encoding.ASCII.GetString(buffer, 0, terminator);
    }

    public void Dispose()
    {
        _handle.Dispose();
    }
}
