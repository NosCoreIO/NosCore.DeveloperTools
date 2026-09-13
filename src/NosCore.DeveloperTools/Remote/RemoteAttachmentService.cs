using NosCore.DeveloperTools.Models;
using NosCore.DeveloperTools.Services;

namespace NosCore.DeveloperTools.Remote;

/// <summary>
/// Attaches to the target: installs the NativeAOT hook DLL payload to a
/// stable per-user path, injects it via remote LoadLibraryW, and
/// connects to the pipe it opens. Pipe lines drive StatusChanged and
/// PacketCaptured.
/// </summary>
public sealed class RemoteAttachmentService : IInjectionService
{
    private RemoteProcess? _process;
    private CancellationTokenSource? _pipeCts;
    private Task? _pipeTask;
    private PipeClientSession? _session;

    public event EventHandler<PacketCapturedEventArgs>? PacketCaptured;

    public event EventHandler<string>? StatusChanged;

    public event EventHandler<string>? NosMallUrlReceived;

    public event EventHandler<string>? ControlReplyReceived;

    public bool IsAttached => _process is not null;

    public int? AttachedProcessId => _process?.ProcessId;

    public async Task AttachAsync(int processId, CancellationToken cancellationToken = default)
    {
        DiagnosticLog.Info($"AttachAsync pid={processId} — enter");
        await DetachInternalAsync();

        try
        {
            _process = RemoteProcess.Open(processId, writable: true);
            DiagnosticLog.Info($"RemoteProcess.Open ok, IsWow64={_process.IsWow64}");
        }
        catch (Exception ex)
        {
            DiagnosticLog.Error("RemoteProcess.Open", ex);
            RaiseStatus($"Attach failed: {ex.Message}");
            throw;
        }

        RaiseStatus($"Attached to pid {processId} (x64={!_process.IsWow64}).");

        string hookPath;
        try
        {
            hookPath = PayloadInstaller.InstallHook();
            DiagnosticLog.Info($"PayloadInstaller.InstallHook -> {hookPath}");
        }
        catch (Exception ex)
        {
            DiagnosticLog.Error("PayloadInstaller.InstallHook", ex);
            RaiseStatus($"Payload install failed: {ex.Message}");
            await DetachInternalAsync();
            throw;
        }

        try
        {
            RaiseStatus("Injecting hook...");
            DiagnosticLog.Info("BootstrapInjector.Inject - enter");
            await Task.Run(() => BootstrapInjector.Inject(processId, hookPath, "NosCorePacketLoggerHookInit"), cancellationToken);
            DiagnosticLog.Info("BootstrapInjector.Inject - returned");
        }
        catch (Exception ex)
        {
            DiagnosticLog.Error("BootstrapInjector.Inject", ex);
            RaiseStatus($"Injection failed: {ex.Message}");
            await DetachInternalAsync();
            throw;
        }

        _pipeCts = new CancellationTokenSource();
        _pipeTask = Task.Run(
            () => PipeClient.RunAsync(processId, session => _session = session, OnPipeLine, _pipeCts.Token),
            _pipeCts.Token);
        DiagnosticLog.Info($"PipeClient started for pid {processId}");
    }

    public bool InjectPacket(PacketDirection direction, PacketConnection connection, string payload)
    {
        if (_session is null || string.IsNullOrEmpty(payload)) return false;
        var d = direction == PacketDirection.Send ? 'S' : 'R';
        var c = connection == PacketConnection.Login ? 'L' : 'W';
        return _session.SendCommand($"INJECT {d} {c} {payload}");
    }

    public bool RequestNosMallUrl()
    {
        if (_session is null) return false;
        return _session.SendCommand("NOSMALLURL");
    }

    public bool Walk(ushort x, ushort y, int? un0 = null, int? un1 = null)
    {
        if (_session is null) return false;
        var command = un0 is { } a && un1 is { } b ? $"WALK {x} {y} {a} {b}" : $"WALK {x} {y}";
        return _session.SendCommand(command);
    }

    public bool RequestPosition()
    {
        if (_session is null) return false;
        return _session.SendCommand("POS");
    }

    public bool RequestDiagnostics()
    {
        if (_session is null) return false;
        return _session.SendCommand("DIAG");
    }

    public bool RequestPlayerScan()
    {
        if (_session is null) return false;
        return _session.SendCommand("SCANPLAYER");
    }

    public bool RequestPeek(long address, int length)
    {
        if (_session is null) return false;
        return _session.SendCommand($"PEEK {address:X} {length}");
    }

    public bool RequestWindow(string mode)
    {
        if (_session is null) return false;
        return _session.SendCommand(string.IsNullOrWhiteSpace(mode) ? "WINDOW" : $"WINDOW {mode}");
    }

    public bool RequestClick(int x, int y)
    {
        if (_session is null) return false;
        return _session.SendCommand($"CLICK {x} {y}");
    }

    public bool RequestConnect(string host, int port)
    {
        if (_session is null) return false;
        return _session.SendCommand($"CONNECT {host} {port}");
    }

    public async Task DetachAsync()
    {
        await DetachInternalAsync();
        RaiseStatus("Detached.");
    }

    public void Dispose()
    {
        DetachInternalAsync().GetAwaiter().GetResult();
    }

    private async Task DetachInternalAsync()
    {
        if (_pipeCts is not null)
        {
            _pipeCts.Cancel();
            try
            {
                if (_pipeTask is not null)
                {
                    await _pipeTask.WaitAsync(TimeSpan.FromSeconds(1));
                }
            }
            catch
            {
                // best effort
            }

            _pipeCts.Dispose();
            _pipeCts = null;
            _pipeTask = null;
        }

        _session = null;
        _process?.Dispose();
        _process = null;
    }

    private void OnPipeLine(string line)
    {
        if (line.StartsWith("NOSMALLURL ", StringComparison.Ordinal))
        {
            NosMallUrlReceived?.Invoke(this, line[11..]);
            return;
        }
        if (line.StartsWith("STATUS ", StringComparison.Ordinal))
        {
            RaiseStatus(line[7..]);
            return;
        }

        if (line.StartsWith("POS", StringComparison.Ordinal)
            || line.StartsWith("WALKRESULT ", StringComparison.Ordinal)
            || line.StartsWith("DIAG ", StringComparison.Ordinal)
            || line.StartsWith("SCANPLAYER ", StringComparison.Ordinal)
            || line.StartsWith("PEEK ", StringComparison.Ordinal)
            || line.StartsWith("WINDOW ", StringComparison.Ordinal)
            || line.StartsWith("CLICK ", StringComparison.Ordinal)
            || line.StartsWith("CONNECTRESULT ", StringComparison.Ordinal))
        {
            ControlReplyReceived?.Invoke(this, line);
            return;
        }

        // "PACKET <S|R> <W|L> <payload>" — 11 chars minimum (inclusive of one payload char).
        if (line.StartsWith("PACKET ", StringComparison.Ordinal) && line.Length >= 12)
        {
            var direction = line[7] switch
            {
                'S' or 's' => PacketDirection.Send,
                _ => PacketDirection.Receive,
            };
            var connection = line[9] switch
            {
                'L' or 'l' => PacketConnection.Login,
                _ => PacketConnection.World,
            };
            var raw = line[11..];
            var header = raw.Split(' ', 2)[0];
            PacketCaptured?.Invoke(this, new PacketCapturedEventArgs(
                new LoggedPacket(DateTime.Now, connection, direction, header, raw)));
        }
    }

    private void RaiseStatus(string line)
    {
        StatusChanged?.Invoke(this, line);
    }
}
