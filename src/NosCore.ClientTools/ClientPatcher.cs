using System.Text;

namespace NosCore.ClientTools;

/// <summary>
/// In-place byte patches against the Gameforge NosTale client
/// (<c>NostaleClientX.exe</c>): rewrites the embedded login-server
/// address, neutralises the argc gate so no-arg launches don't exit,
/// and defaults unknown args into the Entwell standalone body while
/// leaving the <c>gf</c> / <c>gftest</c> GF-mode branches untouched.
/// </summary>
public enum EntryPatchMode
{
    DefaultToEntwell,
    OnlyEntwell,
    None,
}

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
    /// Make the client default to its "EntwellNostaleClient" standalone
    /// path regardless of the command-line argument. Leaves the `gf` /
    /// `gftest` branches intact so those still route to GF mode when the
    /// real Gameforge launcher drives the exe.
    ///
    /// Anchor signature (30 bytes, 3 absolute addresses wildcarded):
    ///
    ///   B9 14 00 00 00  BA 01 00 00 00  E8 ?? ?? ?? ??   ; mov ecx,14 / mov edx,1 / call
    ///   8B 45 CC  BA ?? ?? ?? ??  E8 ?? ?? ?? ??          ; load arg / load "EntwellNostaleClient" / call cmp
    ///   0F 85                                              ; JNZ rel32 (6 bytes with the rel32 following)
    ///
    /// An earlier version NOPped just the JNZ so mismatches fell through
    /// into the Entwell body, but the two <c>call</c>s before the JNZ have
    /// side effects (ref-counted AnsiString setup + case-folded compare)
    /// that the match-case naturally balances at shutdown and the
    /// fall-through case doesn't — producing a timing-sensitive
    /// <c>EOSError 1400 / Invalid window handle</c> on close.
    ///
    /// Instead, skip the whole compare block: overwrite bytes
    /// [pattern_start, pattern_start+34) — pattern + trailing JNZ rel32 —
    /// with a short <c>JMP +32</c> and NOP padding, landing exactly on the
    /// first instruction of the Entwell body. The side-effectful calls
    /// never run on our path, so shutdown balances cleanly.
    /// </summary>
    public static PatchResult PatchDefaultToEntwell(byte[] bytes)
    {
        const string pattern =
            "B9 14 00 00 00 BA 01 00 00 00 E8 ? ? ? ? 8B 45 CC BA ? ? ? ? E8 ? ? ? ? 0F 85";

        var offset = FindPattern(bytes, pattern, 0);
        if (offset < 0)
        {
            return new PatchResult(false, "Default-to-Entwell pattern not found.");
        }

        // EB 20 = short JMP, rel8 = +32, so next_ip (offset+2) + 32 = offset+34
        // which is the first byte after the original JNZ rel32 = Entwell body entry.
        bytes[offset + 0] = 0xEB;
        bytes[offset + 1] = 0x20;
        for (var i = 2; i < 34; i++) bytes[offset + i] = 0x90;

        return new PatchResult(true,
            $"Default-to-Entwell: JMP +32 over compare block at 0x{offset:X} — any non-gf/gftest launch skips straight into the Entwell body.");
    }

    /// <summary>
    /// Force the client into the Entwell standalone body unconditionally,
    /// regardless of command-line args. Replaces the early-entry argc
    /// <c>JL</c> with an unconditional <c>JMP</c> straight to the Entwell
    /// body (located via the <see cref="PatchDefaultToEntwell"/> pattern
    /// + 34). Skips the <c>gf</c> / <c>gftest</c> / <c>EntwellNostaleClient</c>
    /// compares entirely — so <c>gf</c> mode stops working — but avoids
    /// the timing-sensitive shutdown crash that both NOP-and-JMP variants
    /// of <see cref="PatchDefaultToEntwell"/> trigger when any of those
    /// compares runs beforehand.
    /// </summary>
    public static PatchResult PatchForceEntwell(byte[] bytes)
    {
        const string entwellPattern =
            "B9 14 00 00 00 BA 01 00 00 00 E8 ? ? ? ? 8B 45 CC BA ? ? ? ? E8 ? ? ? ? 0F 85";
        const string argcPattern = "E8 ? ? ? ? E8 ? ? ? ? 48 0F 8C";

        var entwellBlock = FindPattern(bytes, entwellPattern, 0);
        if (entwellBlock < 0)
        {
            return new PatchResult(false, "Force-Entwell: default-to-Entwell anchor pattern not found.");
        }
        var argcBlock = FindPattern(bytes, argcPattern, 0);
        if (argcBlock < 0)
        {
            return new PatchResult(false, "Force-Entwell: argc-gate anchor pattern not found.");
        }

        var entwellBody = entwellBlock + 34;
        var jlOffset = argcBlock + 11;
        // Overwrite `0F 8C rel32` (6 bytes) with `E9 rel32 90` (JMP rel32 + NOP).
        var rel32 = entwellBody - (jlOffset + 5);
        bytes[jlOffset + 0] = 0xE9;
        bytes[jlOffset + 1] = (byte)rel32;
        bytes[jlOffset + 2] = (byte)(rel32 >> 8);
        bytes[jlOffset + 3] = (byte)(rel32 >> 16);
        bytes[jlOffset + 4] = (byte)(rel32 >> 24);
        bytes[jlOffset + 5] = 0x90;

        return new PatchResult(true,
            $"Force-Entwell: JMP at 0x{jlOffset:X} → Entwell body 0x{entwellBody:X} (rel32=0x{rel32:X}). `gf` mode will no longer work.");
    }

    /// <summary>
    /// Neutralise the early-entry argc gate: the entry point calls
    /// <c>ParamCount()</c>, decrements it, and on a negative result
    /// <c>JL</c>s to the cleanup/exit path. Without a patch this means
    /// double-click (no-arg) launches bail out.
    ///
    /// Signature (13 bytes, 2 calls wildcarded):
    ///   E8 ?? ?? ?? ??   ; call ParamStr-ish helper
    ///   E8 ?? ?? ?? ??   ; call ParamCount
    ///   48                ; dec eax
    ///   0F 8C            ; JL — we overwrite these + the rel32 below
    ///
    /// NOPping the 6-byte <c>JL rel32</c> at pattern offset 11 lets
    /// execution flow into the arg dispatcher regardless of argc, which
    /// combined with <see cref="PatchDefaultToEntwell"/> drops any
    /// unknown arg into the Entwell body. <c>gf</c> / <c>gftest</c>
    /// branches remain fully functional.
    /// </summary>
    public static PatchResult PatchAllowNoArg(byte[] bytes)
    {
        const string pattern = "E8 ? ? ? ? E8 ? ? ? ? 48 0F 8C";
        var offset = FindPattern(bytes, pattern, 0);
        if (offset < 0)
        {
            return new PatchResult(false, "Allow-no-arg pattern not found.");
        }

        var jlOffset = offset + 11;
        for (var i = 0; i < 6; i++) bytes[jlOffset + i] = 0x90;

        return new PatchResult(true,
            $"Allow-no-arg: NOPped JL at 0x{jlOffset:X} — the argc gate no longer aborts on zero-arg launches.");
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
