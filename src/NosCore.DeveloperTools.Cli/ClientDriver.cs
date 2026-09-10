using System.Diagnostics;
using NosCore.DeveloperTools.Models;
using NosCore.DeveloperTools.Remote;
using NosCore.DeveloperTools.Services;
using NosCore.Shared.Enumerations;

namespace NosCore.DeveloperTools.Cli;

public sealed record LaunchResult(int ProcessId, string AuthCode);

/// <summary>
/// Headless equivalent of the GUI's attach and control flow. Owns the one
/// pipe session the hook allows, buffers everything that arrives on it,
/// and turns the hook's fire-and-forget reply lines back into awaitable
/// results so a caller can issue a command and get its answer.
/// </summary>
public sealed class ClientDriver : IAsyncDisposable
{
    private const int PacketBufferCap = 20000;

    private readonly RemoteAttachmentService _injection = new();
    private readonly SettingsService _settings = new();
    private readonly object _gate = new();
    private readonly List<LoggedPacket> _packets = new();
    private readonly List<string> _statuses = new();
    private readonly List<Waiter> _waiters = new();

    private Process? _client;

    private sealed record Waiter(string Prefix, TaskCompletionSource<string> Completion);

    public ClientDriver()
    {
        _injection.PacketCaptured += (_, args) =>
        {
            lock (_gate)
            {
                _packets.Add(args.Packet);
                if (_packets.Count > PacketBufferCap)
                {
                    _packets.RemoveRange(0, _packets.Count - PacketBufferCap);
                }
            }
        };
        _injection.StatusChanged += (_, message) => Note(message);
        _injection.ControlReplyReceived += (_, line) => Resolve(line);
    }

    public bool IsAttached => _injection.IsAttached;

    public int? AttachedProcessId => _injection.AttachedProcessId;

    public int? ClientProcessId => _client is { HasExited: false } ? _client.Id : null;

    public IReadOnlyList<string> Statuses(int since)
    {
        lock (_gate)
        {
            return since >= _statuses.Count
                ? Array.Empty<string>()
                : _statuses.Skip(since).ToArray();
        }
    }

    public (IReadOnlyList<LoggedPacket> Packets, int Next) Packets(int since, string? contains)
    {
        lock (_gate)
        {
            var next = _packets.Count;
            IEnumerable<LoggedPacket> slice = since >= _packets.Count
                ? Array.Empty<LoggedPacket>()
                : _packets.Skip(since);

            if (!string.IsNullOrEmpty(contains))
            {
                slice = slice.Where(p => p.Raw.Contains(contains, StringComparison.OrdinalIgnoreCase));
            }

            return (slice.ToArray(), next);
        }
    }

    /// <summary>
    /// Authenticate against NosCore and start the patched client. Values
    /// left null fall back to whatever the GUI last saved, so the usual
    /// call carries only a password.
    /// </summary>
    public async Task<LaunchResult> LaunchAsync(
        string? serverUrl, string username, string password, string? clientExe, string? gfLang, string? locale,
        CancellationToken ct)
    {
        var saved = _settings.Load().Auth;
        serverUrl ??= saved.ServerUrl;
        clientExe ??= saved.ClientExePath;
        gfLang ??= saved.GfLang;
        locale ??= saved.Locale;

        if (string.IsNullOrWhiteSpace(clientExe) || !File.Exists(clientExe))
        {
            throw new FileNotFoundException($"Client executable not found: '{clientExe}'.");
        }

        using var auth = new NosCoreAuthClient(serverUrl, message => Note($"auth: {message}"));
        var result = await auth.AuthenticateAsync(username, password, gfLang, locale, null, ct);
        Note($"auth ok, code={result.AuthCode}");

        var region = Enum.TryParse<RegionType>(gfLang, true, out var parsed) ? parsed : default;
        var startInfo = new ProcessStartInfo
        {
            FileName = clientExe,
            // The client parses the second token as the numeric RegionType
            // ordinal, not the language code.
            Arguments = $"gf {(int)region}",
            WorkingDirectory = Path.GetDirectoryName(clientExe) ?? Environment.CurrentDirectory,
            UseShellExecute = false,
        };
        startInfo.EnvironmentVariables["_NC_AUTH_CODE"] = result.AuthCode;

        _client = Process.Start(startInfo) ?? throw new InvalidOperationException("Client failed to start.");
        Note($"client started pid={_client.Id}");
        return new LaunchResult(_client.Id, result.AuthCode);
    }

    /// <summary>
    /// Inject the hook and open the pipe. Waits for the client's window
    /// first — injecting before the process has finished initialising can
    /// leave the remote LoadLibrary thread hanging.
    /// </summary>
    public async Task AttachAsync(int? processId, CancellationToken ct)
    {
        var pid = processId ?? await WaitForClientAsync(ct);
        await _injection.AttachAsync(pid, ct);
    }

    public async Task<string> DiagnosticsAsync(TimeSpan timeout)
    {
        var waiter = Expect("DIAG");
        if (!_injection.RequestDiagnostics()) throw new InvalidOperationException("Not attached.");
        return await Await(waiter, timeout, "DIAG");
    }

    public async Task<string> PositionAsync(TimeSpan timeout)
    {
        var waiter = Expect("POS");
        if (!_injection.RequestPosition()) throw new InvalidOperationException("Not attached.");
        return await Await(waiter, timeout, "POS");
    }

    public async Task<string> WalkAsync(ushort x, ushort y, int? un0, int? un1, TimeSpan timeout)
    {
        var waiter = Expect("WALKRESULT");
        if (!_injection.Walk(x, y, un0, un1)) throw new InvalidOperationException("Not attached.");
        return await Await(waiter, timeout, "WALKRESULT");
    }

    public async Task<string> ScanPlayerAsync(TimeSpan timeout)
    {
        var waiter = Expect("SCANPLAYER");
        if (!_injection.RequestPlayerScan()) throw new InvalidOperationException("Not attached.");
        return await Await(waiter, timeout, "SCANPLAYER");
    }

    public async Task<string> PeekAsync(long address, int length, TimeSpan timeout)
    {
        var waiter = Expect("PEEK");
        if (!_injection.RequestPeek(address, length)) throw new InvalidOperationException("Not attached.");
        return await Await(waiter, timeout, "PEEK");
    }

    public bool Inject(PacketDirection direction, PacketConnection connection, string payload) =>
        _injection.InjectPacket(direction, connection, payload);

    public async ValueTask DisposeAsync()
    {
        await _injection.DetachAsync();
        _injection.Dispose();
    }

    private async Task<int> WaitForClientAsync(CancellationToken ct)
    {
        if (_client is null) throw new InvalidOperationException("No client launched; pass a process id.");

        var deadline = DateTime.UtcNow.AddSeconds(60);
        while (DateTime.UtcNow < deadline)
        {
            _client.Refresh();
            if (_client.HasExited) throw new InvalidOperationException("Client exited before it could be attached.");
            if (_client.MainWindowHandle != IntPtr.Zero) return _client.Id;
            await Task.Delay(250, ct);
        }

        throw new TimeoutException("Client never opened a window.");
    }

    private Waiter Expect(string prefix)
    {
        var waiter = new Waiter(
            prefix, new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously));
        lock (_gate)
        {
            _waiters.Add(waiter);
        }

        return waiter;
    }

    private static async Task<string> Await(Waiter waiter, TimeSpan timeout, string what)
    {
        var completed = await Task.WhenAny(waiter.Completion.Task, Task.Delay(timeout));
        if (completed != waiter.Completion.Task)
        {
            throw new TimeoutException($"No {what} reply within {timeout.TotalSeconds:0.#}s.");
        }

        return await waiter.Completion.Task;
    }

    private void Resolve(string line)
    {
        Waiter? match;
        lock (_gate)
        {
            _statuses.Add($"{DateTime.Now:HH:mm:ss} {line}");
            match = _waiters.FirstOrDefault(w => line.StartsWith(w.Prefix, StringComparison.Ordinal));
            if (match is not null) _waiters.Remove(match);
        }

        match?.Completion.TrySetResult(line);
    }

    private void Note(string message)
    {
        lock (_gate)
        {
            _statuses.Add($"{DateTime.Now:HH:mm:ss} {message}");
        }
    }
}
