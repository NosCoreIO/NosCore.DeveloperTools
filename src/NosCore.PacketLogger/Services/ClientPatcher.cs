using System.Text;

namespace NosCore.PacketLogger.Services;

/// <summary>
/// In-place byte patches against the Gameforge NosTale client
/// (<c>NosCore.exe</c>): rewrites the embedded login-server address
/// and flips the multi-instance check into an unconditional allow.
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
    /// Neutralise the "another client is already running" check by flipping
    /// the `JL rel32` ahead of the lock acquire into a plain `JMP rel32` to
    /// the same post-check address. Bytes before / after patch:
    ///   0F 8C XX XX XX XX  ->  E9 YY YY YY YY 90
    /// where YY is a freshly computed rel32 targeting the end anchor.
    /// </summary>
    public static PatchResult PatchMultiClient(byte[] bytes)
    {
        // 0F 8C rel32 followed by `lea edx, [ebp-0x24]; mov eax, imm32; call imm32`.
        var startPattern = "0F 8C ? ? ? ? 8D 55 DC B8 ? ? ? ? E8 ? ? ? ?";
        // call ...; jne rel32; xor eax, eax; push ebp; push imm32 — end of the check.
        var endPattern = "E8 ? ? ? ? 0F 85 ? ? ? ? 33 C0 55 68 ? ? ? ?";

        var startOffset = FindPattern(bytes, startPattern, 0);
        if (startOffset < 0)
        {
            return new PatchResult(false, "Multi-client start pattern not found.");
        }

        var endOffset = FindPattern(bytes, endPattern, startOffset);
        if (endOffset < 0)
        {
            return new PatchResult(false, $"Multi-client end pattern not found after 0x{startOffset:X}.");
        }

        // Skip past the end-anchor's `E8 rel32` (5) + `0F 85 rel32` (6) = 11 bytes,
        // landing on the `33 C0 55 68 …` OK path.
        var jumpTarget = endOffset + 11;
        var rel32 = jumpTarget - (startOffset + 5);

        bytes[startOffset] = 0xE9;
        WriteInt32LittleEndian(bytes, startOffset + 1, rel32);
        bytes[startOffset + 5] = 0x90; // nop out the stale 6th byte of the old `0F 8C rel32`.

        return new PatchResult(true,
            $"Multiclient: start=0x{startOffset:X}, end=0x{endOffset:X}, patched JL -> JMP (rel32=0x{rel32:X8}).");
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
