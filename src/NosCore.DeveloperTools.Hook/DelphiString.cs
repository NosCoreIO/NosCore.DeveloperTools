using System.Text;

namespace NosCore.DeveloperTools.Hook;

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

        // The try/catch below cannot save us here: an access violation is
        // an SEH fault, which NativeAOT does not turn into a catchable
        // exception, so an unchecked read of a wrong pointer takes the
        // client down instead of returning null. Validate first.
        if (!SafeMemory.IsReadable(payload - 4, 4)) return null;

        try
        {
            var p = (byte*)payload;
            var length = *(int*)(p - 4);
            if (length <= 0 || length > 65536) return null;
            if (!SafeMemory.IsReadable(payload, length)) return null;
            return Encoding.UTF8.GetString(p, length);
        }
        catch
        {
            return null;
        }
    }
}
