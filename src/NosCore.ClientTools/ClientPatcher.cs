using System.Text;

namespace NosCore.ClientTools;

/// <summary>
/// In-place byte patches against the Gameforge NosTale client
/// (<c>NostaleClientX.exe</c>): rewrites the embedded login-server
/// address, sends no-argument launches to the password login and
/// points the Gameforge wrapper import at our stub.
/// </summary>
public static class ClientPatcher
{
    public sealed record PatchResult(bool Success, string Log);

    /// <summary>
    /// Locate the login-server address by looking for a Delphi AnsiString
    /// whose payload is IP-shaped (ASCII digits and dots) and rewrite it.
    /// We don't text-search for any particular IP — we anchor on the
    /// binary layout of a Delphi constant AnsiString:
    ///   FF FF FF FF       refcount = -1 (constant)
    ///   LEN 00 00 00      4-byte length
    ///   &lt;payload bytes&gt;   N bytes of ASCII
    /// plus a plausibility check on the payload content (only 0-9 or '.').
    /// </summary>
    public static PatchResult PatchServerAddress(byte[] bytes, string newAddress)
    {
        if (string.IsNullOrWhiteSpace(newAddress))
        {
            return new PatchResult(false, "No 'new address' value provided.");
        }
        if (newAddress.Length > 15)
        {
            return new PatchResult(false, $"New address '{newAddress}' is too long ({newAddress.Length} > 15 bytes).");
        }

        var candidates = FindIpShapedAnsiStrings(bytes);
        if (candidates.Count == 0)
        {
            return new PatchResult(false, "No IP-shaped Delphi AnsiString found in the exe.");
        }

        var sb = new StringBuilder();
        var replacement = Encoding.ASCII.GetBytes(newAddress);

        foreach (var (payloadOffset, declaredLength, currentValue) in candidates)
        {
            if (replacement.Length > declaredLength)
            {
                sb.AppendLine($"Skip 0x{payloadOffset:X} ('{currentValue}'): new address won't fit in {declaredLength}-byte slot.");
                continue;
            }

            for (var i = 0; i < replacement.Length; i++)
            {
                bytes[payloadOffset + i] = replacement[i];
            }
            for (var i = replacement.Length; i < declaredLength; i++)
            {
                bytes[payloadOffset + i] = 0x00;
            }
            WriteInt32LittleEndian(bytes, payloadOffset - 4, replacement.Length);

            sb.AppendLine($"IP: patched 0x{payloadOffset:X} ('{currentValue}' -> '{newAddress}').");
        }

        return new PatchResult(true, sb.ToString());
    }

    private static List<(int PayloadOffset, int DeclaredLength, string CurrentValue)> FindIpShapedAnsiStrings(byte[] bytes)
    {
        var results = new List<(int, int, string)>();
        // Delphi constant AnsiString header: FF FF FF FF LEN(le32).
        for (var i = 0; i <= bytes.Length - 20; i++)
        {
            if (bytes[i] != 0xFF || bytes[i + 1] != 0xFF || bytes[i + 2] != 0xFF || bytes[i + 3] != 0xFF) continue;
            var len = BitConverter.ToInt32(bytes, i + 4);
            if (len < 7 || len > 15) continue;
            var payloadStart = i + 8;
            if (payloadStart + len > bytes.Length) continue;

            // Payload must be IP-shaped: digits and dots, stripping trailing NULs.
            var end = payloadStart + len;
            while (end > payloadStart && bytes[end - 1] == 0) end--;
            var trimmed = end - payloadStart;
            if (trimmed < 7) continue;

            var ok = true;
            var dots = 0;
            for (var k = payloadStart; k < payloadStart + trimmed; k++)
            {
                var b = bytes[k];
                if (b == '.') { dots++; continue; }
                if (b >= '0' && b <= '9') continue;
                ok = false;
                break;
            }
            if (!ok || dots != 3) continue;

            var value = Encoding.ASCII.GetString(bytes, payloadStart, trimmed);
            results.Add((payloadStart, len, value));
        }
        return results;
    }

    /// <summary>
    /// The entry point exits when <c>ParamCount - 1 &lt; 0</c> (<c>JL rel32</c>).
    /// Retarget that jump to the body shared by every login mode, so a launch
    /// without arguments reaches it with the Steam and GF flags still zero,
    /// which is the password (<c>EntwellNostaleClient</c>) login. Launches with
    /// an argument never take the jump and keep the original dispatch, so
    /// <c>gf &lt;N&gt;</c> still works. Nothing is skipped half way, so the stack
    /// stays balanced and the client exits cleanly.
    ///
    /// The shared body starts 34 bytes after the <c>EntwellNostaleClient</c>
    /// compare anchor (<c>Copy(ParamStr(1), 1, 20)</c>, compare, <c>JNZ rel32</c>).
    /// </summary>
    public static PatchResult PatchNoArgToPasswordLogin(byte[] bytes)
    {
        const string loginBodyPattern =
            "B9 14 00 00 00 BA 01 00 00 00 E8 ? ? ? ? 8B 45 CC BA ? ? ? ? E8 ? ? ? ? 0F 85";
        const string argcPattern = "E8 ? ? ? ? E8 ? ? ? ? 48 0F 8C";

        var compareBlock = FindPattern(bytes, loginBodyPattern, 0);
        if (compareBlock < 0)
        {
            return new PatchResult(false, "No-arg login: login mode compare pattern not found.");
        }
        var argcBlock = FindPattern(bytes, argcPattern, 0);
        if (argcBlock < 0)
        {
            return new PatchResult(false, "No-arg login: argc check pattern not found.");
        }

        var loginBody = compareBlock + 34;
        var jlOffset = argcBlock + 11;
        var rel32 = loginBody - (jlOffset + 6);
        WriteInt32LittleEndian(bytes, jlOffset + 2, rel32);

        return new PatchResult(true,
            $"No-arg login: JL at 0x{jlOffset:X} now targets the login body at 0x{loginBody:X}; launches without arguments open the password login, gf launches are unchanged.");
    }

    /// <summary>
    /// Rewrite the ASCII DLL-name literal <c>gf_wrapper.dll</c> in the PE
    /// import directory to <c>noscore_gf.dll</c>. The Windows loader
    /// resolves imports by that literal, so the patched client loads our
    /// NativeAOT stub DLL (shipped next to the patched exe) instead of
    /// the real Gameforge wrapper. Both names are 14 ASCII characters +
    /// one NUL terminator, so we can overwrite in place with no further
    /// PE edits.
    /// </summary>
    public static PatchResult PatchImportName(byte[] bytes)
    {
        var needle = Encoding.ASCII.GetBytes("gf_wrapper.dll\0");
        var replacement = Encoding.ASCII.GetBytes(GfStub.FileName + "\0");
        if (needle.Length != replacement.Length)
        {
            return new PatchResult(false, "Internal error: replacement DLL name must match original length.");
        }

        var offset = FindBytes(bytes, needle, 0);
        if (offset < 0)
        {
            return new PatchResult(false, "Import name 'gf_wrapper.dll' not found.");
        }
        for (var i = 0; i < replacement.Length; i++) bytes[offset + i] = replacement[i];

        return new PatchResult(true,
            $"Import rename: 'gf_wrapper.dll' -> '{GfStub.FileName}' at 0x{offset:X}. Drop {GfStub.FileName} next to the patched exe.");
    }

    private static int FindBytes(byte[] haystack, byte[] needle, int startOffset)
    {
        if (needle.Length == 0) return -1;
        for (var i = startOffset; i <= haystack.Length - needle.Length; i++)
        {
            var match = true;
            for (var j = 0; j < needle.Length; j++)
            {
                if (haystack[i + j] != needle[j])
                {
                    match = false;
                    break;
                }
            }
            if (match) return i;
        }
        return -1;
    }

    private static int FindPattern(byte[] haystack, string pattern, int startOffset)
    {
        var tokens = pattern.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var bytes = new byte[tokens.Length];
        var mask = new bool[tokens.Length];
        for (var i = 0; i < tokens.Length; i++)
        {
            if (tokens[i] == "?" || tokens[i] == "??")
            {
                mask[i] = false;
            }
            else
            {
                mask[i] = true;
                bytes[i] = Convert.ToByte(tokens[i], 16);
            }
        }

        for (var i = startOffset; i <= haystack.Length - bytes.Length; i++)
        {
            var match = true;
            for (var j = 0; j < bytes.Length; j++)
            {
                if (mask[j] && haystack[i + j] != bytes[j])
                {
                    match = false;
                    break;
                }
            }
            if (match) return i;
        }
        return -1;
    }

    private static void WriteInt32LittleEndian(byte[] dst, int offset, int value)
    {
        dst[offset + 0] = (byte)value;
        dst[offset + 1] = (byte)(value >> 8);
        dst[offset + 2] = (byte)(value >> 16);
        dst[offset + 3] = (byte)(value >> 24);
    }
}
