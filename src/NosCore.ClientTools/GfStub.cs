using System.Reflection;

namespace NosCore.ClientTools;

/// <summary>
/// Access to the embedded <c>noscore_gf.dll</c> payload — the NativeAOT x86
/// replacement for the client's <c>gf_wrapper.dll</c>. A patched client
/// resolves its Gameforge imports against this file by name, so it has to sit
/// next to the patched exe under exactly <see cref="FileName"/>.
/// </summary>
public static class GfStub
{
    /// <summary>
    /// Import-table name the patched client loads the stub by. Must stay the
    /// same length as <c>gf_wrapper.dll</c> so
    /// <see cref="ClientPatcher.PatchImportName"/> can overwrite that literal
    /// in place without relocating the PE import directory.
    /// </summary>
    public const string FileName = "noscore_gf.dll";

    public static Stream OpenStream() =>
        typeof(GfStub).Assembly.GetManifestResourceStream(FileName)
        ?? throw new FileNotFoundException(
            $"{FileName} is not embedded in {Assembly.GetExecutingAssembly().GetName().Name}. " +
            "Build NosCore.ClientTools so its GfStub publish target runs.");

    /// <summary>Write the stub into <paramref name="directory"/> and return its full path.</summary>
    public static string DeployTo(string directory)
    {
        var path = Path.Combine(directory, FileName);
        using var source = OpenStream();
        using var destination = File.Create(path);
        source.CopyTo(destination);
        return path;
    }
}
