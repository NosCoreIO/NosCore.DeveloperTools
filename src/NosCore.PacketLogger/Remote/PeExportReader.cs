using System.Text;

namespace NosCore.PacketLogger.Remote;

/// <summary>
/// Reads a 32-bit PE export table off disk and returns the RVA of a
/// named export. Lets us resolve the hook DLL's init function without
/// calling <c>LoadLibrary</c> on it in our own process — we don't want
/// the hook's DllMain firing inside the injector, and loading a DLL
/// that does remote-thread-ish things tends to trip AV on the main exe.
/// </summary>
internal static class PeExportReader
{
    public static uint GetExportRva(string dllPath, string exportName)
    {
        var bytes = File.ReadAllBytes(dllPath);
        if (bytes.Length < 0x40)
        {
            throw new InvalidDataException($"{dllPath}: too small to be a PE.");
        }

        if (bytes[0] != (byte)'M' || bytes[1] != (byte)'Z')
        {
            throw new InvalidDataException($"{dllPath}: missing MZ header.");
        }

        var peOffset = BitConverter.ToInt32(bytes, 0x3C);
        if (peOffset < 0 || peOffset + 24 > bytes.Length
            || bytes[peOffset] != (byte)'P' || bytes[peOffset + 1] != (byte)'E')
        {
            throw new InvalidDataException($"{dllPath}: missing PE header at offset 0x{peOffset:X}.");
        }

        var machine = BitConverter.ToUInt16(bytes, peOffset + 4);
        if (machine != 0x014C)
        {
            throw new InvalidDataException(
                $"{dllPath}: expected x86 PE (machine=0x14C), got 0x{machine:X4}.");
        }

        var sizeOfOptionalHeader = BitConverter.ToUInt16(bytes, peOffset + 20);
        var optionalHeaderOffset = peOffset + 24;
        // PE32 optional header: magic at +0 (0x10B)
        var magic = BitConverter.ToUInt16(bytes, optionalHeaderOffset);
        if (magic != 0x010B)
        {
            throw new InvalidDataException($"{dllPath}: expected PE32 optional header magic 0x10B, got 0x{magic:X4}.");
        }

        // Data directories start at optionalHeaderOffset + 96 for PE32; export directory is entry 0.
        const int dataDirectoriesOffsetInPE32 = 96;
        var dataDirOffset = optionalHeaderOffset + dataDirectoriesOffsetInPE32;
        if (dataDirOffset + 8 > bytes.Length)
        {
            throw new InvalidDataException($"{dllPath}: PE truncated before data directories.");
        }

        var exportDirRva = BitConverter.ToUInt32(bytes, dataDirOffset + 0);
        var exportDirSize = BitConverter.ToUInt32(bytes, dataDirOffset + 4);
        if (exportDirRva == 0 || exportDirSize == 0)
        {
            throw new InvalidDataException($"{dllPath}: no export directory.");
        }

        var sectionTableOffset = optionalHeaderOffset + sizeOfOptionalHeader;
        var numberOfSections = BitConverter.ToUInt16(bytes, peOffset + 6);

        uint RvaToFileOffset(uint rva)
        {
            for (var i = 0; i < numberOfSections; i++)
            {
                var s = sectionTableOffset + i * 40;
                var vAddr = BitConverter.ToUInt32(bytes, s + 12);
                var vSize = BitConverter.ToUInt32(bytes, s + 8);
                var rawPtr = BitConverter.ToUInt32(bytes, s + 20);
                if (rva >= vAddr && rva < vAddr + vSize)
                {
                    return rawPtr + (rva - vAddr);
                }
            }
            throw new InvalidDataException($"RVA 0x{rva:X} doesn't belong to any section.");
        }

        var exportDirOffset = RvaToFileOffset(exportDirRva);
        var numberOfNames = BitConverter.ToUInt32(bytes, (int)exportDirOffset + 24);
        var addressOfFunctionsRva = BitConverter.ToUInt32(bytes, (int)exportDirOffset + 28);
        var addressOfNamesRva = BitConverter.ToUInt32(bytes, (int)exportDirOffset + 32);
        var addressOfNameOrdinalsRva = BitConverter.ToUInt32(bytes, (int)exportDirOffset + 36);

        var namesOffset = RvaToFileOffset(addressOfNamesRva);
        var ordinalsOffset = RvaToFileOffset(addressOfNameOrdinalsRva);
        var functionsOffset = RvaToFileOffset(addressOfFunctionsRva);

        for (var i = 0; i < numberOfNames; i++)
        {
            var nameRva = BitConverter.ToUInt32(bytes, (int)namesOffset + i * 4);
            var nameOffset = (int)RvaToFileOffset(nameRva);
            var end = nameOffset;
            while (end < bytes.Length && bytes[end] != 0) end++;
            var name = Encoding.ASCII.GetString(bytes, nameOffset, end - nameOffset);
            if (name == exportName)
            {
                var ordinal = BitConverter.ToUInt16(bytes, (int)ordinalsOffset + i * 2);
                return BitConverter.ToUInt32(bytes, (int)functionsOffset + ordinal * 4);
            }
        }

        throw new InvalidDataException($"{dllPath}: export '{exportName}' not found.");
    }
}
