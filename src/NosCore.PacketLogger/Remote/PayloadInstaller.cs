using System.Security.Cryptography;

namespace NosCore.PacketLogger.Remote;

/// <summary>
/// Extracts the embedded NativeAOT hook DLL to
/// <c>%LOCALAPPDATA%\NosCore.PacketLogger\payload\hook-{sha8}.dll</c>.
/// Using a content-addressed filename means a new build never collides
/// with an older DLL still held open by a previously-attached target —
/// Windows locks mapped DLLs, so a plain "hook.dll" path would fail to
/// overwrite after the first successful attach.
/// </summary>
internal static class PayloadInstaller
{
    private const string ResourceName = "NosCore.PacketLogger.Hook.dll";

    public static string InstallHook()
    {
        var dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "NosCore.PacketLogger",
            "payload");
        Directory.CreateDirectory(dir);

        using var stream = typeof(PayloadInstaller).Assembly.GetManifestResourceStream(ResourceName)
            ?? throw new FileNotFoundException(
                $"Embedded hook DLL '{ResourceName}' missing from the main assembly. "
                + "Did NosCore.PacketLogger.Hook fail to build?");

        var bytes = new byte[stream.Length];
        var read = 0;
        while (read < bytes.Length)
        {
            var n = stream.Read(bytes, read, bytes.Length - read);
            if (n <= 0) break;
            read += n;
        }

        var shortHash = Convert.ToHexString(SHA256.HashData(bytes), 0, 4).ToLowerInvariant();
        var target = Path.Combine(dir, $"hook-{shortHash}.dll");

        if (!File.Exists(target))
        {
            File.WriteAllBytes(target, bytes);
        }

        return target;
    }
}
