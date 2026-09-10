using System.Runtime.InteropServices;

namespace NosCore.DeveloperTools.Cli;

internal static class Program
{
    private const int DefaultPort = 8787;

    // DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2
    private static readonly IntPtr PerMonitorAwareV2 = -4;

    [DllImport("user32.dll")]
    private static extern bool SetProcessDpiAwarenessContext(IntPtr context);

    [STAThread]
    private static async Task<int> Main(string[] args)
    {
        // The client is DPI-aware, so every coordinate it reports — window
        // rects, and the pixels in a capture — is physical. Left unaware,
        // this process would read and write logical coordinates instead,
        // and on a scaled display a click aimed from a screenshot lands
        // somewhere else entirely.
        try
        {
            SetProcessDpiAwarenessContext(PerMonitorAwareV2);
        }
        catch
        {
            // Pre-1703 hosts: coordinates stay logical, clicks need scaling.
        }

        var port = ParsePort(args) ?? DefaultPort;

        await using var driver = new ClientDriver();
        var server = new ControlServer(driver, port);

        Console.WriteLine($"NosCore client driver listening on http://127.0.0.1:{port}");
        Console.WriteLine("  POST /launch   {password}            auth + start the patched client");
        Console.WriteLine("  POST /attach   {pid?}                inject the hook, open the pipe");
        Console.WriteLine("  GET  /diag                           resolved signatures, tick count, in-world");
        Console.WriteLine("  GET  /pos                            live character id and coordinates");
        Console.WriteLine("  POST /walk     {x, y}                move via the client's own routine");
        Console.WriteLine("  POST /inject   {payload, direction}  raw packet injection");
        Console.WriteLine("  GET  /packets?since=N&contains=      captured traffic");
        Console.WriteLine("  GET  /log?since=N                    hook status lines");
        Console.WriteLine("  GET  /screenshot?path=&mode=         capture just the client window");
        Console.WriteLine("  GET  /quit                           stop the driver");

        try
        {
            await server.RunAsync();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Driver stopped: {ex.Message}");
            return 1;
        }

        return 0;
    }

    private static int? ParsePort(string[] args)
    {
        for (var i = 0; i < args.Length - 1; i++)
        {
            if (args[i] is "--port" or "-p" && int.TryParse(args[i + 1], out var port)) return port;
        }

        return null;
    }
}
