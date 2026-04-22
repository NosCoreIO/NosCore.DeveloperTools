namespace NosCore.PacketLogger;

/// <summary>
/// Append-only debug log at %LOCALAPPDATA%\NosCore.PacketLogger\diag.log.
/// Captures startup, attach steps and any exceptions even when the UI
/// can't render them — the file is the ground truth when "nothing
/// appears in the status bar".
/// </summary>
internal static class DiagnosticLog
{
    private static readonly string Path = System.IO.Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "NosCore.PacketLogger",
        "diag.log");

    private static readonly object Lock = new();

    public static string LogPath => Path;

    static DiagnosticLog()
    {
        try
        {
            System.IO.Directory.CreateDirectory(System.IO.Path.GetDirectoryName(Path)!);
        }
        catch
        {
            // If we can't even create the directory, swallow — this is diagnostic.
        }
    }

    public static void Info(string message)
    {
        Write("INFO ", message);
    }

    public static void Error(string context, Exception ex)
    {
        Write("ERROR", $"{context}: {ex.GetType().Name}: {ex.Message}\n{ex.StackTrace}");
    }

    private static void Write(string level, string message)
    {
        try
        {
            lock (Lock)
            {
                System.IO.File.AppendAllText(Path,
                    $"{DateTime.Now:HH:mm:ss.fff} {level} [pid {Environment.ProcessId}] {message}{Environment.NewLine}");
            }
        }
        catch
        {
            // swallow
        }
    }
}
