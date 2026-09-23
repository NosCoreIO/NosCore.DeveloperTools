using NosCore.ClientTools;

namespace NosCore.DeveloperTools.Models;

public sealed class AppSettings
{
    public string? LastProcessName { get; set; }

    public string ProcessFilterText { get; set; } = string.Empty;

    public MainWindowState MainWindow { get; set; } = new();

    public PacketFilters PacketFilters { get; set; } = new();

    public AuthSettings Auth { get; set; } = new();

    public ClientCreatorSettings ClientCreator { get; set; } = new();

    public NosMallSettings NosMall { get; set; } = new();
}

public sealed class NosMallSettings
{
    public string SourceDir { get; set; } = string.Empty;

    public string NewUrl { get; set; } = "https://localhost:7001/Mall";
}

public sealed class AuthSettings
{
    public string ServerUrl { get; set; } = "https://localhost:7001";

    public string Username { get; set; } = string.Empty;

    public string GfLang { get; set; } = "EN";

    public string Locale { get; set; } = "en_US";

    public string ClientExePath { get; set; } = string.Empty;
}

public sealed class ClientCreatorSettings
{
    public string NewAddress { get; set; } = string.Empty;

    public string ClientExePath { get; set; } = string.Empty;

    public string OutputName { get; set; } = string.Empty;

    public EntryPatchMode EntryPatchMode { get; set; } = EntryPatchMode.DefaultToEntwell;
}

public sealed class PacketFilters
{
    public bool CaptureSend { get; set; } = true;

    public bool CaptureReceive { get; set; } = true;

    // Packet headers. Whitelist = only these pass; blacklist = everything except these.
    public List<string> SendFilter { get; set; } = new();

    public List<string> ReceiveFilter { get; set; } = new();

    public bool SendFilterIsWhitelist { get; set; }

    public bool ReceiveFilterIsWhitelist { get; set; }
}

public sealed class MainWindowState
{
    public int Width { get; set; } = 1024;

    public int Height { get; set; } = 768;

    public int X { get; set; } = -1;

    public int Y { get; set; } = -1;
}
