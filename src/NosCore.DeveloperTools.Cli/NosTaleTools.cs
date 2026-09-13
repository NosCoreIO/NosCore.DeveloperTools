using System.ComponentModel;
using System.Text.Json;
using ModelContextProtocol.Server;
using NosCore.DeveloperTools.Models;

namespace NosCore.DeveloperTools.Cli;

/// <summary>
/// MCP tools for driving the NosTale client, backed by a single shared
/// <see cref="ClientDriver"/> (one process, one pipe session, state kept
/// across calls). Every tool returns a compact JSON string so the model
/// gets structured results.
/// </summary>
[McpServerToolType]
public static class NosTaleTools
{
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = false };
    private static string J(object o) => JsonSerializer.Serialize(o, Json);
    private static TimeSpan Secs(double s) => TimeSpan.FromSeconds(s <= 0 ? 10 : s);

    [McpServerTool(Name = "nostale_launch")]
    [Description("Authenticate against the local NosCore server and start the patched NosTale client. Only the password is usually needed; username/serverUrl/clientExe fall back to the GUI's saved settings.")]
    public static async Task<string> Launch(
        ClientDriver driver,
        [Description("Account password")] string password,
        [Description("Account username (default: saved 'admin')")] string? username = null,
        [Description("NosCore auth server URL, e.g. https://localhost:7001 (default: saved)")] string? serverUrl = null,
        [Description("Path to the patched client exe (default: saved)")] string? clientExe = null)
    {
        var r = await driver.LaunchAsync(serverUrl, username ?? "admin", password, clientExe, null, null, null, CancellationToken.None);
        return J(new { r.ProcessId, r.AuthCode });
    }

    [McpServerTool(Name = "nostale_attach")]
    [Description("Inject the capture/control hook into the running client and open its pipe. Waits for the game window first. Pass a pid to attach to a specific client, otherwise attaches to the one just launched.")]
    public static async Task<string> Attach(ClientDriver driver, [Description("Target process id (optional)")] int? pid = null)
    {
        await driver.AttachAsync(pid, CancellationToken.None);
        return J(new { attached = driver.IsAttached, driver.AttachedProcessId });
    }

    [McpServerTool(Name = "nostale_status")]
    [Description("Report hook diagnostics: which signatures resolved, tick count, in-world state, whether a character is loaded, and the connect/manager/walk addresses.")]
    public static async Task<string> Status(ClientDriver driver)
        => J(new { attached = driver.IsAttached, clientPid = driver.ClientProcessId, diag = await driver.DiagnosticsAsync(Secs(10)) });

    [McpServerTool(Name = "nostale_position")]
    [Description("Read the live character id and map coordinates (x,y). Requires a character loaded in-world.")]
    public static async Task<string> Position(ClientDriver driver)
        => J(new { reply = await driver.PositionAsync(Secs(10)) });

    [McpServerTool(Name = "nostale_walk")]
    [Description("Move the character to map cell (x,y) by calling the client's own walk routine, so the client updates its position and emits the walk packet itself (checksum included). Requires a character loaded in-world.")]
    public static async Task<string> Walk(ClientDriver driver, [Description("target X")] int x, [Description("target Y")] int y)
        => J(new { reply = await driver.WalkAsync((ushort)x, (ushort)y, 0, 1, Secs(15)) });

    [McpServerTool(Name = "nostale_click")]
    [Description("Send a real left-click at a point in client-window coordinates (drives the actual cursor; the client ignores posted messages). Use with a screenshot to locate UI elements — e.g. to click through server/channel/character selection.")]
    public static async Task<string> Click(ClientDriver driver, [Description("client X")] int x, [Description("client Y")] int y)
        => J(new { reply = await driver.ClickAsync(x, y, null, Secs(15)) });

    [McpServerTool(Name = "nostale_screenshot")]
    [Description("Capture just the client window to a PNG and return its path (Read the path to view it). Uses PrintWindow, falling back to a screen grab if the accelerated surface renders blank.")]
    public static async Task<string> Screenshot(ClientDriver driver, [Description("Output PNG path (optional)")] string? path = null)
    {
        var outPath = path ?? Path.Combine(Path.GetTempPath(), $"nostale-{DateTime.Now:HHmmss}.png");
        var (saved, mode) = await driver.ScreenshotAsync(outPath, null, Secs(30));
        return J(new { path = saved, mode });
    }

    [McpServerTool(Name = "nostale_inject")]
    [Description("Send a raw packet through the client's own send/recv functions. direction: 'send' (client->server) or 'recv' (server->client, injected into the client). connection: 'world' (default) or 'login'. Useful for driving GM commands, e.g. inject send '$Teleport 1 100 100'.")]
    public static string Inject(
        ClientDriver driver,
        [Description("Raw packet text")] string payload,
        [Description("'send' or 'recv'")] string direction = "send",
        [Description("'world' or 'login'")] string connection = "world")
    {
        var dir = direction.StartsWith('r') ? PacketDirection.Receive : PacketDirection.Send;
        var conn = connection.StartsWith('l') ? PacketConnection.Login : PacketConnection.World;
        return J(new { sent = driver.Inject(dir, conn, payload) });
    }

    [McpServerTool(Name = "nostale_packets")]
    [Description("Return captured packets since a cursor (0 for all), optionally filtered by a substring. Returns the packets and the next cursor to poll from.")]
    public static string Packets(
        ClientDriver driver,
        [Description("Cursor to read from (0 = beginning)")] int since = 0,
        [Description("Only packets whose raw text contains this (optional)")] string? contains = null)
    {
        var (packets, next) = driver.Packets(since, contains);
        return J(new { next, packets = packets.Select(p => new { time = p.Timestamp.ToString("HH:mm:ss.fff"), connection = p.Connection.ToString(), source = p.Direction == PacketDirection.Send ? "client" : "server", raw = p.Raw }) });
    }

    [McpServerTool(Name = "nostale_packet_cursor")]
    [Description("Return the current end cursor of the packet buffer. Capture this BEFORE an action, then pass it to nostale_wait_for_packet so the wait only sees packets provoked by the action.")]
    public static string PacketCursor(ClientDriver driver) => J(new { cursor = driver.PacketCursor });

    [McpServerTool(Name = "nostale_wait_for_packet")]
    [Description("Block until a captured packet at/after 'since' matches the regex 'pattern' (over the raw wire text), or the timeout elapses. The assertion primitive for tests: act, then wait for the client's observable reaction instead of sleeping. Returns the matching packet or {matched:false} on timeout.")]
    public static async Task<string> WaitForPacket(
        ClientDriver driver,
        [Description("Regex to match against raw packet text")] string pattern,
        [Description("Cursor from nostale_packet_cursor (0 = from beginning)")] int since = 0,
        [Description("Timeout in seconds (default 10)")] double timeoutSeconds = 10)
    {
        var p = await driver.WaitForPacketAsync(pattern, since, Secs(timeoutSeconds));
        return p is null
            ? J(new { matched = false })
            : J(new { matched = true, time = p.Timestamp.ToString("HH:mm:ss.fff"), source = p.Direction == PacketDirection.Send ? "client" : "server", raw = p.Raw });
    }
}
