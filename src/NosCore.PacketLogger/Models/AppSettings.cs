namespace NosCore.PacketLogger.Models;

public sealed class AppSettings
{
    public string? LastProcessName { get; set; }

    public string ProcessFilterText { get; set; } = string.Empty;

    public MainWindowState MainWindow { get; set; } = new();

    public PacketFilters PacketFilters { get; set; } = new();
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
    public int Width { get; set; } = 520;

    public int Height { get; set; } = 360;

    public int X { get; set; } = -1;

    public int Y { get; set; } = -1;
}
