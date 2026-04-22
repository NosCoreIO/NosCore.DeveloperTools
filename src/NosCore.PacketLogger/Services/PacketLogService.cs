using NosCore.PacketLogger.Models;

namespace NosCore.PacketLogger.Services;

/// <summary>
/// In-memory packet log. Consumers add captured packets and the UI
/// subscribes to <see cref="PacketLogged"/> for live display.
/// </summary>
public sealed class PacketLogService
{
    private readonly List<LoggedPacket> _entries = new();
    private readonly object _lock = new();

    public event EventHandler<LoggedPacket>? PacketLogged;

    public event EventHandler? Cleared;

    public IReadOnlyList<LoggedPacket> Snapshot()
    {
        lock (_lock)
        {
            return _entries.ToArray();
        }
    }

    public void Clear()
    {
        lock (_lock)
        {
            _entries.Clear();
        }
        Cleared?.Invoke(this, EventArgs.Empty);
    }

    public void Add(LoggedPacket packet)
    {
        lock (_lock)
        {
            _entries.Add(packet);
        }
        PacketLogged?.Invoke(this, packet);
    }
}
