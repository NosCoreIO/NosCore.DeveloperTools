namespace NosCore.PacketLogger.Models;

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
    /// <summary>Full line with timestamp + tags. Used as the ListBox DisplayString.</summary>
    public override string ToString()
    {
        var conn = Connection == PacketConnection.Login ? "Login" : "World";
        var dir = Direction == PacketDirection.Send ? "Send" : "Recv";
        return $"[{Timestamp:HH:mm:ss.fff}] [{conn}] [{dir}] {Raw}";
    }
}
