using System.Text;

namespace NosCore.PacketLogger.Hook;

/// <summary>
/// NosTale (Delphi) AnsiString reader. Pointer passed in EDX points to
/// the payload bytes; the length lives at <c>ptr - 4</c> and the
/// refcount at <c>ptr - 8</c>. Valid packets never contain NUL so we
/// trust the declared length rather than scanning.
/// </summary>
internal static unsafe class DelphiString
{
    public static string? Read(IntPtr payload)
    {
        if (payload == IntPtr.Zero) return null;

        try
        {
            var p = (byte*)payload;
            var length = *(int*)(p - 4);
            if (length <= 0 || length > 65536) return null;
            return Encoding.UTF8.GetString(p, length);
        }
        catch
        {
            return null;
        }
    }
}
