using NosCore.PacketLogger.Models;

namespace NosCore.PacketLogger.Services;

public sealed class PacketCapturedEventArgs : EventArgs
{
    public PacketCapturedEventArgs(LoggedPacket packet)
    {
        Packet = packet;
    }

    public LoggedPacket Packet { get; }
}

public interface IInjectionService : IDisposable
{
    event EventHandler<PacketCapturedEventArgs>? PacketCaptured;

    event EventHandler<string>? StatusChanged;

    bool IsAttached { get; }

    int? AttachedProcessId { get; }

    Task AttachAsync(int processId, CancellationToken cancellationToken = default);

    Task DetachAsync();

    /// <summary>
    /// Inject a packet as if the client itself were sending / receiving it.
    /// Returns true on success; false if no session is connected or the
    /// direction/connection combo isn't yet supported on the hook side.
    /// </summary>
    bool InjectPacket(PacketDirection direction, PacketConnection connection, string payload);
}
