using System.Net;
using System.Text;
using System.Text.Json;
using NosCore.DeveloperTools.Models;

namespace NosCore.DeveloperTools.Cli;

/// <summary>
/// Localhost HTTP surface over <see cref="ClientDriver"/>. Each command is
/// a separate request so a caller can drive the client one step at a time
/// while the process holds the pipe session open between calls.
/// </summary>
public sealed class ControlServer
{
    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
    };

    private readonly ClientDriver _driver;
    private readonly HttpListener _listener = new();
    private readonly CancellationTokenSource _shutdown = new();

    public ControlServer(ClientDriver driver, int port)
    {
        _driver = driver;
        _listener.Prefixes.Add($"http://127.0.0.1:{port}/");
    }

    public CancellationToken Shutdown => _shutdown.Token;

    public async Task RunAsync()
    {
        _listener.Start();
        while (!_shutdown.IsCancellationRequested)
        {
            HttpListenerContext context;
            try
            {
                context = await _listener.GetContextAsync();
            }
            catch when (_shutdown.IsCancellationRequested)
            {
                break;
            }

            _ = Task.Run(() => HandleAsync(context));
        }

        _listener.Close();
    }

    private async Task HandleAsync(HttpListenerContext context)
    {
        try
        {
            var path = context.Request.Url?.AbsolutePath.TrimEnd('/').ToLowerInvariant() ?? "/";
            var query = context.Request.QueryString;
            var body = await ReadBodyAsync(context.Request);

            object payload = path switch
            {
                "" or "/" or "/status" => new
                {
                    attached = _driver.IsAttached,
                    attachedPid = _driver.AttachedProcessId,
                    clientPid = _driver.ClientProcessId,
                },
                "/launch" => await _driver.LaunchAsync(
                    Str(body, "serverUrl"), Str(body, "username") ?? "admin", Str(body, "password") ?? "test",
                    Str(body, "clientExe"), Str(body, "gfLang"), Str(body, "locale"), Str(body, "hooks"), CancellationToken.None),
                "/attach" => await AttachAsync(body),
                "/diag" => new { reply = await _driver.DiagnosticsAsync(Timeout(query)) },
                "/pos" => Position(await _driver.PositionAsync(Timeout(query))),
                "/walk" => new { reply = await WalkAsync(body, Timeout(query)) },
                "/window" => new { reply = await _driver.WindowAsync(query["mode"] ?? "show", Timeout(query)) },
                "/click" => new
                {
                    reply = await _driver.ClickAsync(
                        Int(body, "x") ?? throw new InvalidOperationException("click requires 'x'."),
                        Int(body, "y") ?? throw new InvalidOperationException("click requires 'y'."),
                        Str(body, "mode") ?? query["mode"],
                        Timeout(query)),
                },
                "/screenshot" => await ScreenshotAsync(query),
                "/scanplayer" => new { reply = await _driver.ScanPlayerAsync(Timeout(query)) },
                "/peek" => new
                {
                    reply = await _driver.PeekAsync(
                        Convert.ToInt64(query["addr"] ?? throw new InvalidOperationException("peek requires 'addr'."), 16),
                        Int(query, "len") ?? 64,
                        Timeout(query)),
                },
                "/inject" => new { sent = InjectPacket(body) },
                "/packets" => Packets(query),
                "/log" => new { lines = _driver.Statuses(Int(query, "since") ?? 0) },
                "/quit" => Quit(),
                _ => throw new InvalidOperationException($"Unknown endpoint '{path}'."),
            };

            await WriteAsync(context, HttpStatusCode.OK, payload);
        }
        catch (Exception ex)
        {
            await WriteAsync(context, HttpStatusCode.BadRequest, new { error = ex.Message, type = ex.GetType().Name });
        }
    }

    private async Task<object> ScreenshotAsync(System.Collections.Specialized.NameValueCollection query)
    {
        var path = query["path"] ?? Path.Combine(Path.GetTempPath(), "noscore-client.png");
        var (saved, mode) = await _driver.ScreenshotAsync(path, query["mode"], Timeout(query));
        var info = new FileInfo(saved);
        return new { path = saved, mode, bytes = info.Length };
    }

    private async Task<object> AttachAsync(JsonElement? body)
    {
        await _driver.AttachAsync(Int(body, "pid"), CancellationToken.None);
        return new { attached = _driver.IsAttached, attachedPid = _driver.AttachedProcessId };
    }

    private async Task<string> WalkAsync(JsonElement? body, TimeSpan timeout)
    {
        var x = Int(body, "x") ?? throw new InvalidOperationException("walk requires 'x'.");
        var y = Int(body, "y") ?? throw new InvalidOperationException("walk requires 'y'.");
        return await _driver.WalkAsync((ushort)x, (ushort)y, Int(body, "un0"), Int(body, "un1"), timeout);
    }

    private bool InjectPacket(JsonElement? body)
    {
        var payload = Str(body, "payload") ?? throw new InvalidOperationException("inject requires 'payload'.");
        var direction = (Str(body, "direction") ?? "send").StartsWith('r')
            ? PacketDirection.Receive
            : PacketDirection.Send;
        var connection = (Str(body, "connection") ?? "world").StartsWith('l')
            ? PacketConnection.Login
            : PacketConnection.World;
        return _driver.Inject(direction, connection, payload);
    }

    private object Packets(System.Collections.Specialized.NameValueCollection query)
    {
        var (packets, next) = _driver.Packets(Int(query, "since") ?? 0, query["contains"]);
        return new
        {
            next,
            packets = packets.Select(p => new
            {
                time = p.Timestamp.ToString("HH:mm:ss.fff"),
                connection = p.Connection.ToString(),
                source = p.Direction == PacketDirection.Send ? "client" : "server",
                raw = p.Raw,
            }),
        };
    }

    /// <summary>
    /// Splits "POS id x y" out into fields so a caller can assert on
    /// coordinates without reparsing the wire line.
    /// </summary>
    private static object Position(string reply)
    {
        var parts = reply.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 4 || !int.TryParse(parts[1], out var id)
            || !int.TryParse(parts[2], out var x) || !int.TryParse(parts[3], out var y))
        {
            return new { reply, available = false };
        }

        return new { reply, available = true, entityId = id, x, y };
    }

    private object Quit()
    {
        _shutdown.Cancel();
        // Cancelling alone leaves the accept loop parked in GetContextAsync;
        // stopping the listener is what actually unblocks it.
        _ = Task.Run(async () =>
        {
            await Task.Delay(250);
            _listener.Stop();
        });
        return new { stopping = true };
    }

    private static TimeSpan Timeout(System.Collections.Specialized.NameValueCollection query) =>
        TimeSpan.FromMilliseconds(Int(query, "timeoutMs") ?? 8000);

    private static async Task<JsonElement?> ReadBodyAsync(HttpListenerRequest request)
    {
        if (!request.HasEntityBody) return null;
        using var reader = new StreamReader(request.InputStream, Encoding.UTF8);
        var text = await reader.ReadToEndAsync();
        if (string.IsNullOrWhiteSpace(text)) return null;
        return JsonDocument.Parse(text).RootElement.Clone();
    }

    private static string? Str(JsonElement? body, string name) =>
        body is { } b && b.ValueKind == JsonValueKind.Object && b.TryGetProperty(name, out var value)
        && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static int? Int(JsonElement? body, string name)
    {
        if (body is not { } b || b.ValueKind != JsonValueKind.Object) return null;
        if (!b.TryGetProperty(name, out var value)) return null;
        return value.ValueKind switch
        {
            JsonValueKind.Number => value.GetInt32(),
            JsonValueKind.String when int.TryParse(value.GetString(), out var parsed) => parsed,
            _ => null,
        };
    }

    private static int? Int(System.Collections.Specialized.NameValueCollection query, string name) =>
        int.TryParse(query[name], out var value) ? value : null;

    private static async Task WriteAsync(HttpListenerContext context, HttpStatusCode status, object payload)
    {
        var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(payload, Json));
        context.Response.StatusCode = (int)status;
        context.Response.ContentType = "application/json";
        context.Response.ContentLength64 = bytes.Length;
        await context.Response.OutputStream.WriteAsync(bytes);
        context.Response.Close();
    }
}
