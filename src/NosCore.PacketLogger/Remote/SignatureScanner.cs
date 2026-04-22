using System.Text.RegularExpressions;

namespace NosCore.PacketLogger.Remote;

/// <summary>
/// Finds byte patterns inside a module's read-only/executable mapping.
/// Patterns are space-separated hex bytes; <c>??</c> is a wildcard.
/// </summary>
internal static class SignatureScanner
{
    public static IntPtr? FindInModule(RemoteProcess process, RemoteModule module, string pattern)
    {
        var (mask, bytes) = Compile(pattern);
        var region = process.ReadBytes(module.BaseAddress, module.Size);
        for (var i = 0; i <= region.Length - bytes.Length; i++)
        {
            var ok = true;
            for (var j = 0; j < bytes.Length; j++)
            {
                if (mask[j] && region[i + j] != bytes[j])
                {
                    ok = false;
                    break;
                }
            }

            if (ok)
            {
                return module.BaseAddress + i;
            }
        }

        return null;
    }

    internal static (bool[] Mask, byte[] Bytes) Compile(string pattern)
    {
        var tokens = Regex.Split(pattern.Trim(), "\\s+");
        var mask = new bool[tokens.Length];
        var bytes = new byte[tokens.Length];
        for (var i = 0; i < tokens.Length; i++)
        {
            var token = tokens[i];
            if (token is "??" or "?")
            {
                mask[i] = false;
                bytes[i] = 0;
            }
            else
            {
                mask[i] = true;
                bytes[i] = Convert.ToByte(token, 16);
            }
        }

        return (mask, bytes);
    }
}
