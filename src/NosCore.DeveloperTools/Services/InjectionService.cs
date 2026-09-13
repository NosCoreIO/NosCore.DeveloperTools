using NosCore.DeveloperTools.Models;

namespace NosCore.DeveloperTools.Services;

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

    event EventHandler<string>? NosMallUrlReceived;

    /// <summary>
    /// Replies to client-control commands (position, walk outcome,
    /// hook diagnostics), delivered verbatim so they can be read or
    /// parsed rather than being folded into the status line.
    /// </summary>
    event EventHandler<string>? ControlReplyReceived;

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

    /// <summary>
    /// Ask the injected hook to scan the client's heap for the
    /// already-formatted NosMall URL. Result arrives asynchronously via
    /// <see cref="NosMallUrlReceived"/>. Returns true if the request was
    /// sent (a pipe session is active); false otherwise.
    /// </summary>
    bool RequestNosMallUrl();

    /// <summary>
    /// Move the character by calling the client's own walk routine, so
    /// the client updates its local position and builds the outgoing
    /// packet itself. Outcome arrives via
    /// <see cref="ControlReplyReceived"/> as a <c>WALKRESULT</c> line.
    ///
    /// <paramref name="un0"/> / <paramref name="un1"/> switch the call
    /// to the four-argument form; the client's own call sites appear to
    /// use only the two register arguments, so leaving them null is the
    /// normal path.
    /// </summary>
    bool Walk(ushort x, ushort y, int? un0 = null, int? un1 = null);

    /// <summary>
    /// Ask for the character's live position. Answer arrives via
    /// <see cref="ControlReplyReceived"/> as <c>POS id x y</c>, or
    /// <c>POS unavailable</c> when not in-world.
    /// </summary>
    bool RequestPosition();

    /// <summary>
    /// Ask the hook which signatures resolved and whether the client
    /// thread is ticking. Answer arrives as a <c>DIAG</c> line.
    /// </summary>
    bool RequestDiagnostics();

    /// <summary>
    /// Ask the hook which of the player manager's fields lead to
    /// something shaped like a map object. Used to recover the player
    /// object's offset when a borrowed one does not fit this build.
    /// </summary>
    bool RequestPlayerScan();

    /// <summary>
    /// Hex dump of client memory, for reading a struct layout directly.
    /// </summary>
    bool RequestPeek(long address, int length);

    /// <summary>
    /// Restore and focus the client window, or report its geometry.
    /// Runs inside the client because the launcher elevates it, and
    /// UIPI drops window calls that come from lower integrity.
    /// </summary>
    bool RequestWindow(string mode);

    /// <summary>Post a left click in client coordinates.</summary>
    bool RequestClick(int x, int y);

    /// <summary>
    /// Open the world connection the way the channel button does,
    /// reusing the connection object recorded the first time the
    /// client connected on its own.
    /// </summary>
    bool RequestConnect(string host, int port);
}
