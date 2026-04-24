namespace NosCore.DeveloperTools.Models;

public enum PacketDirection
{
    Send,
    Receive,
}

public enum PacketConnection
{
    World,
    Login,
}

public sealed record LoggedPacket(
    DateTime Timestamp,
    PacketConnection Connection,
    PacketDirection Direction,
    string Header,
    string Raw)
{
    private readonly string _display = FormatDisplay(Timestamp, Connection, Direction, Raw);

    public override string ToString() => _display;

    private static string FormatDisplay(DateTime ts, PacketConnection conn, PacketDirection dir, string raw)
    {
        var c = conn == PacketConnection.Login ? "Login" : "World";
        // [Client] = originated on the game client (client→server); [Server] = originated on the server (server→client).
        var source = dir == PacketDirection.Send ? "Client" : "Server";
        return $"[{ts:HH:mm:ss.fff}] [{c}] [{source}] {raw}";
    }
}
