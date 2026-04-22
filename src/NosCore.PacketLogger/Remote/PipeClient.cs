using System.IO.Pipes;
using System.Text;

namespace NosCore.PacketLogger.Remote;

/// <summary>
/// Consumer + command sender for the injected hook's bidirectional
/// named pipe. Pipe name is deterministic from target pid.
/// </summary>
public sealed class PipeClientSession : IAsyncDisposable
{
    private readonly NamedPipeClientStream _pipe;
    private readonly StreamReader _reader;
    private readonly object _writeLock = new();

    private PipeClientSession(NamedPipeClientStream pipe, StreamReader reader)
    {
        _pipe = pipe;
        _reader = reader;
    }

    public static async Task<PipeClientSession?> ConnectAsync(int processId, CancellationToken cancellationToken)
    {
        var pipe = new NamedPipeClientStream(
            ".", $"NosCore.PacketLogger.{processId}", PipeDirection.InOut, PipeOptions.Asynchronous);
        try
        {
            await pipe.ConnectAsync(10_000, cancellationToken);
        }
        catch
        {
            await pipe.DisposeAsync();
            return null;
        }
        var reader = new StreamReader(pipe, Encoding.UTF8, leaveOpen: true);
        return new PipeClientSession(pipe, reader);
    }

    public async Task<string?> ReadLineAsync(CancellationToken cancellationToken)
    {
        try
        {
            return await _reader.ReadLineAsync(cancellationToken);
        }
        catch
        {
            return null;
        }
    }

    public bool SendCommand(string line)
    {
        try
        {
            var bytes = Encoding.UTF8.GetBytes(line + "\n");
            lock (_writeLock)
            {
                _pipe.Write(bytes, 0, bytes.Length);
                _pipe.Flush();
            }
            return true;
        }
        catch
        {
            return false;
        }
    }

    public ValueTask DisposeAsync()
    {
        _reader.Dispose();
        return _pipe.DisposeAsync();
    }
}

internal static class PipeClient
{
    public static async Task RunAsync(
        int processId,
        Action<PipeClientSession> onConnected,
        Action<string> onLine,
        CancellationToken cancellationToken)
    {
        var session = await PipeClientSession.ConnectAsync(processId, cancellationToken);
        if (session is null)
        {
            onLine("STATUS pipe connect timed out — hook didn't come up?");
            return;
        }

        await using (session)
        {
            onConnected(session);

            while (!cancellationToken.IsCancellationRequested)
            {
                var line = await session.ReadLineAsync(cancellationToken);
                if (line is null) break;
                onLine(line);
            }
        }
    }
}
