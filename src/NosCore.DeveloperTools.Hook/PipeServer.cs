using System.IO.Pipes;
using System.Text;
using System.Threading;

namespace NosCore.DeveloperTools.Hook;

/// <summary>
/// Named pipe server running in the injected target. Bidirectional:
/// we write events (STATUS, PACKET) out to the UI, and we read commands
/// (INJECT ...) from the UI. Pipe name is
/// "NosCore.DeveloperTools.&lt;pid&gt;" — deterministic from the target pid
/// so the external logger connects without handshake.
///
/// Outbound protocol (newline-delimited UTF-8):
///   STATUS &lt;message&gt;
///   PACKET &lt;S|R&gt; &lt;W|L&gt; &lt;raw packet text&gt;
///
/// Inbound protocol:
///   INJECT &lt;S|R&gt; &lt;W|L&gt; &lt;raw packet text&gt;
///   NOSMALLURL                         # scan heap, reply with NOSMALLURL &lt;url&gt;
/// </summary>
internal static class PipeServer
{
    private static volatile bool _shutdown;
    private static int _lastDroppedSeen;

    public static void Shutdown() => _shutdown = true;

    public static void Announce(string message)
    {
        Hooks.Queue.Enqueue(new CapturedPacket(PacketDirection.Status, PacketConnection.World, "STATUS " + message));
    }

    public static void Run()
    {
        var pipeName = $"NosCore.DeveloperTools.{Environment.ProcessId}";
        while (!_shutdown)
        {
            try
            {
                using var pipe = new NamedPipeServerStream(
                    pipeName,
                    PipeDirection.InOut,
                    maxNumberOfServerInstances: 1,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous | PipeOptions.WriteThrough);

                pipe.WaitForConnection();
                if (_shutdown) return;

                WriteLine(pipe, $"STATUS connected pid={Environment.ProcessId}");

                // Fire off a reader thread so inbound commands don't starve behind
                // our outbound writer.
                var readerThread = new Thread(() => ReadCommands(pipe)) { IsBackground = true };
                readerThread.Start();

                while (pipe.IsConnected && !_shutdown)
                {
                    FlushDrops(pipe);

                    if (Hooks.Queue.TryDequeue(out var packet))
                    {
                        WritePacket(pipe, packet);
                    }
                    else
                    {
                        Thread.Sleep(1);
                    }
                }
            }
            catch
            {
                Thread.Sleep(200);
            }
        }
    }

    private static void ReadCommands(NamedPipeServerStream pipe)
    {
        try
        {
            using var reader = new StreamReader(pipe, Encoding.UTF8, leaveOpen: true);
            while (pipe.IsConnected && !_shutdown)
            {
                string? line;
                try
                {
                    line = reader.ReadLine();
                }
                catch
                {
                    break;
                }
                if (line is null) break;
                HandleCommand(line);
            }
        }
        catch
        {
            // Reader dies when the pipe closes — expected on detach.
        }
    }

    private static void HandleCommand(string line)
    {
        if (line.StartsWith("NOSMALLURL", StringComparison.Ordinal))
        {
            HandleNosMallUrl();
            return;
        }

        // "INJECT <S|R> <W|L> <payload>" — 11 chars minimum before payload.
        if (!line.StartsWith("INJECT ", StringComparison.Ordinal) || line.Length < 12) return;

        var direction = line[7];
        var connection = line[9];
        var payload = line[11..];
        if (payload.Length == 0) return;

        try
        {
            if (direction is 'S' or 's')
            {
                if (connection is 'W' or 'w')
                {
                    if (!Hooks.InjectWorldSend(payload))
                        Announce("inject world-send failed (no context captured yet?)");
                }
                else
                {
                    Announce("inject login-send not yet implemented");
                }
            }
            else
            {
                if (connection is 'W' or 'w')
                {
                    if (!Hooks.InjectWorldRecv(payload))
                        Announce("inject world-recv failed (no context captured yet?)");
                }
                else
                {
                    Announce("inject login-recv not yet implemented");
                }
            }
        }
        catch (Exception ex)
        {
            Announce($"inject error: {ex.Message}");
        }
    }

    private static void HandleNosMallUrl()
    {
        // Offload to a ThreadPool worker — the pipe reader thread must not
        // block on a full-heap scan, and any AV during the scan must not
        // take down the pipe.
        Hooks.TriggerNosMallRescan();
    }

    private static void FlushDrops(NamedPipeServerStream pipe)
    {
        var current = Volatile.Read(ref Hooks.QueueDropped);
        if (current != _lastDroppedSeen)
        {
            var delta = current - _lastDroppedSeen;
            _lastDroppedSeen = current;
            WriteLine(pipe, $"STATUS dropped {delta} packets (queue full)");
        }
    }

    private static void WritePacket(NamedPipeServerStream pipe, CapturedPacket packet)
    {
        if (packet.Direction == PacketDirection.Status)
        {
            WriteLine(pipe, packet.Payload);
            return;
        }

        var directionChar = (char)packet.Direction;
        var connectionChar = (char)packet.Connection;
        WriteLine(pipe, $"PACKET {directionChar} {connectionChar} {packet.Payload}");
    }

    private static void WriteLine(NamedPipeServerStream pipe, string line)
    {
        var bytes = Encoding.UTF8.GetBytes(line + "\n");
        pipe.Write(bytes, 0, bytes.Length);
        pipe.Flush();
    }
}
