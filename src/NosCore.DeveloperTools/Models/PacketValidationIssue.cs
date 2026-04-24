namespace NosCore.DeveloperTools.Models;

public enum ValidationCategory
{
    Missing,
    WrongStructure,
    WrongTag,
}

public sealed record PacketValidationIssue(
    DateTime Timestamp,
    ValidationCategory Category,
    LoggedPacket Packet,
    string Detail)
{
    private readonly string _display = Format(Timestamp, Category, Packet, Detail);

    public override string ToString() => _display;

    private static string Format(DateTime ts, ValidationCategory cat, LoggedPacket p, string detail)
    {
        var tag = cat switch
        {
            ValidationCategory.Missing => "[Missing]",
            ValidationCategory.WrongStructure => "[Wrong structure]",
            ValidationCategory.WrongTag => "[Wrong tag]",
            _ => $"[{cat}]",
        };
        var conn = p.Connection == PacketConnection.Login ? "Login" : "World";
        var src = p.Direction == PacketDirection.Send ? "Client" : "Server";
        return $"[{ts:HH:mm:ss.fff}] {tag} [{conn}] [{src}] {p.Raw}  — {detail}";
    }
}
